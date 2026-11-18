import ts from 'typescript';
import type {
  ApiRoute,
  FileMap,
  ProjectMap,
  RouteControlAssessment,
  RouteSecurityEvidence,
  RouteSecurityProfile,
} from '../shared/types.js';
import { sha1Hex } from '../shared/utils.js';
import { analyzeTaint } from '../shared/taint.js';
import { hasTrustedOwnership, parseEqChain, parseObjectFilter } from '../shared/ownership.js';
import { isRouteProtectedByMiddleware } from './middlewareMatchers.js';
import { isRlsSettledFromSource } from './detectRls.js';
import { resolvesRouteRootByMethodExport } from '../shared/frameworkModel.js';
import { cascadingGuardsForRoute, expressUseGuards } from '../shared/cascadingGuard.js';
import { andMoreFiles, MAX_FILES_NAMED } from '../shared/cappedNames.js';

const JS_TS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);
const MAX_UNPARSEABLE_NAMED = MAX_FILES_NAMED;

const MAX_FUNCTIONS = 5_000;
const MAX_CALL_EDGES = 25_000;
const MAX_ROUTE_FUNCTIONS = 500;
const MAX_CALL_DEPTH = 8;

export const ROUTE_CALL_GRAPH_LIMITS = [
  {
    reason: `Route call-graph function limit (${MAX_FUNCTIONS}) exceeded.`,
    words: `the project has more than ${MAX_FUNCTIONS.toLocaleString('en-US')} functions`,
  },
  {
    reason: `Route call-edge limit (${MAX_CALL_EDGES}) exceeded.`,
    words: `the project has more than ${MAX_CALL_EDGES.toLocaleString('en-US')} calls between its functions`,
  },
  {
    reason: `Route call-graph function limit (${MAX_ROUTE_FUNCTIONS}) exceeded.`,
    words: `a route reaches more than ${MAX_ROUTE_FUNCTIONS} functions`,
  },
  {
    reason: `Route call depth limit (${MAX_CALL_DEPTH}) exceeded.`,
    words: `a route's calls go more than ${MAX_CALL_DEPTH} levels deep`,
  },
] as const;

const [FUNCTION_LIMIT, CALL_EDGE_LIMIT, ROUTE_FUNCTION_LIMIT, CALL_DEPTH_LIMIT] = ROUTE_CALL_GRAPH_LIMITS;

export const UNRESOLVED_HANDLER_REASON = 'The route handler could not be resolved to a JavaScript/TypeScript function.';

export interface CallWalkFailure {
  filePath: string;
  line: number;
}

const callWalkFailuresByProject = new WeakMap<ProjectMap, readonly CallWalkFailure[]>();

export function routeCallWalkFailures(projectMap: ProjectMap): readonly CallWalkFailure[] {
  return callWalkFailuresByProject.get(projectMap) ?? [];
}

const BODY_USE = /\b(?:req\.body|request\.(?:json\s*\(|form|data)|await\s+(?:req|request)\.json\s*\(|Body\s*\()/i;
const VALIDATION = /(?:\b(?:z|yup|joi)\.\w+|\b\w*schema\w*)\.(?:parse|safeParse|validate|validateSync|validateAsync)\s*\(|\bvalidate\w*\s*\(|\bajv\.compile\s*\(|\b(?:pydantic|BaseModel|marshmallow|serializer\.is_valid)\b/i;
const RATE_LIMIT = /\b(?:rateLimit|rateLimiter|limiter|slowDown|throttle|upstash|ratelimit)\b|\.limit\s*\(/i;
const CSRF = /\b(?:csrf|csurf|verifyCsrf|validateCsrf|csrfProtection|antiForgery|timingSafeEqual)\b|sameSite\s*:\s*['"]strict['"]/i;
const COOKIE_AUTH = /\b(?:req\.session|request\.cookies|cookies\(\)\.get|session_cookie)\b/i;
const TRUSTED_IDENTITY = /\b(?:session|currentUser|verifiedUser|decodedToken|authUser|user)\s*[?.]\s*(?:id|uid)\b/i;
const OWNERSHIP_FIELD = /\b(?:user_?id|owner_?id|account_?id|tenant_?id|author_?id|created_?by|member_?id|org_?id)\b/i;
const RECORD_OPERATION = new Set(['select', 'update', 'delete', 'read', 'write']);
const MUTATION_METHOD = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

interface FunctionModel {
  key: string;
  filePath: string;
  name: string;
  line: number;
  startLine: number;
  endLine: number;
  start: number;
  end: number;
  content: string;
  calls: string[];
  walkFailed: boolean;
  importBindings: ImportBinding[];
  namespaceImports: Map<string, string>;
}

interface ImportBinding { local: string; targetFile: string; exported: string }

interface CallGraph {
  models: Map<string, FunctionModel>;
  edges: Map<string, Set<string>>;
  routeRoots: Map<string, string>;
  status: 'complete' | 'truncated';
  reason?: string;
}

interface Reachability {
  models: FunctionModel[];
  status: 'complete' | 'partial';
  reasons: string[];
}

export function buildRouteSecurityProfiles(fileMap: FileMap, projectMap: ProjectMap): RouteSecurityProfile[] {
  const graph = buildCallGraph(fileMap, projectMap);
  return projectMap.apiRoutes
    .flatMap((route) => route.methods.map((method) => buildProfile(route, method, fileMap, projectMap, graph)))
    .sort((a, b) => a.routePath.localeCompare(b.routePath) || a.method.localeCompare(b.method) || a.filePath.localeCompare(b.filePath));
}

function buildProfile(
  route: ApiRoute,
  method: string,
  fileMap: FileMap,
  projectMap: ProjectMap,
  graph: CallGraph,
): RouteSecurityProfile {
  const reachability = reachableForRoute(route, method, graph);
  const scopes = reachability.models;
  const reasons = [...reachability.reasons];
  if (graph.status === 'truncated' && graph.reason !== undefined) reasons.push(graph.reason);
  if (projectMap.crossFileTaint?.status === 'truncated') {
    reasons.push(projectMap.crossFileTaint.reason ?? 'Cross-file taint analysis was truncated.');
  }
  const analysisStatus = reasons.length === 0 ? 'complete' : 'partial';

  const authEvidence = projectMap.authSignals
    .filter((signal) => signal.protective && signal.checked && inScopes(signal.filePath, signal.line, scopes))
    .map((signal) => evidence(signal.filePath, signal.line, `auth:${signal.kind}`, signal.snippet));
  if (isRouteProtectedByMiddleware(projectMap, route.routePath)) {
    authEvidence.push(evidence(route.filePath, route.line, 'auth:middleware', `Middleware protects ${route.routePath}`));
  }
  const lookup = { fileMap, projectMap };
  for (const guard of [
    ...cascadingGuardsForRoute(lookup, {
      filePath: route.filePath,
      routePath: route.routePath,
      line: route.line,
      framework: route.framework,
      method,
    }),
    ...expressUseGuards(lookup, route.filePath, route.line, route.routePath),
  ]) {
    if (guard.control !== 'auth' && guard.control !== 'admin') continue;
    authEvidence.push(evidence(guard.filePath, guard.line, `auth:${guard.via}`,
      `A ${guard.via.replace(/_/g, ' ')} guard governs ${route.routePath}`));
  }
  const authentication = assessment(
    authEvidence.length > 0 ? 'present' : analysisStatus === 'partial' ? 'unknown' : 'absent',
    authEvidence,
    authEvidence.length > 0 ? 'A checked authentication guard protects this route.' :
      analysisStatus === 'partial' ? 'Authentication could not be determined from complete reachable code.' :
        'No checked authentication guard was found in the route or invoked local helpers.',
  );

  const databaseOperations = projectMap.databaseCalls
    .filter((call) => inScopes(call.filePath, call.line, scopes))
    .map((call) => ({ filePath: call.filePath, line: call.line, client: call.client, kind: call.kind, ...(call.table !== undefined ? { table: call.table } : {}) }));

  const scopeTexts = scopes.map((scope) => scope.content.slice(scope.start, scope.end));
  const joinedScopes = scopeTexts.join('\n');
  const ownershipEvidence = scopes.flatMap((scope) => {
    const text = scope.content.slice(scope.start, scope.end);
    const pairs = [...parseObjectFilter(text), ...parseEqChain(text)];
    const trusted = hasTrustedOwnership(pairs, analyzeTaint(text)) || (OWNERSHIP_FIELD.test(text) && TRUSTED_IDENTITY.test(text));
    return trusted ? [evidence(scope.filePath, scope.line, 'authorization:ownership', 'Database access is scoped to a trusted identity.')] : [];
  });
  const rlsTables = new Set(projectMap.supabaseRls.rlsEnabledTables.filter((table) =>
    projectMap.supabaseRls.policyTables.includes(table) && isRlsSettledFromSource(projectMap.supabaseRls, table)));
  const supabaseTables = databaseOperations.filter((operation) => operation.client === 'supabase' && operation.table !== undefined);
  if (supabaseTables.length > 0 && supabaseTables.every((operation) => operation.table !== undefined && rlsTables.has(operation.table))) {
    ownershipEvidence.push(evidence(route.filePath, route.line, 'authorization:rls', 'All visible Supabase tables used by this route have RLS and policy evidence.'));
  }
  const authorizationRelevant = databaseOperations.some((operation) => RECORD_OPERATION.has(operation.kind));
  const requestControlledRecord = authorizationRelevant && /\b(?:req|request)\.(?:body|query|params)|\bparams\./.test(joinedScopes);
  const authorization = !authorizationRelevant
    ? assessment('not_applicable', [], 'No record-level database access was associated with this route.')
    : ownershipEvidence.length > 0
      ? assessment('present', ownershipEvidence, 'A trusted ownership constraint or visible RLS policy scopes record access.')
      : requestControlledRecord && analysisStatus === 'complete'
        ? assessment('absent', [], 'Request-controlled record access has no trusted ownership constraint.')
        : assessment('unknown', [], 'Record-level authorization could not be established from the visible code.');

  const mutating = MUTATION_METHOD.has(method.toUpperCase()) || databaseOperations.some((operation) =>
    ['insert', 'update', 'delete', 'upsert', 'write'].includes(operation.kind));
  const bodyUsed = BODY_USE.test(joinedScopes);
  const validationEvidence = scopes
    .filter((scope) => VALIDATION.test(scope.content.slice(scope.start, scope.end)))
    .map((scope) => evidence(scope.filePath, scope.line, 'input:validation', 'A recognized schema validator runs in this invoked path.'));
  const inputValidation = !mutating || !bodyUsed
    ? assessment('not_applicable', [], 'The route has no visible state-changing request-body flow.')
    : validationEvidence.length > 0
      ? assessment('present', validationEvidence, 'Request data reaches a recognized schema-validation boundary.')
      : analysisStatus === 'partial'
        ? assessment('unknown', [], 'Input validation could not be determined from complete reachable code.')
        : assessment('absent', [], 'Request body data is used without a recognized schema validator in the invoked path.');

  const rateEvidence = scopes
    .filter((scope) => RATE_LIMIT.test(scope.content.slice(scope.start, scope.end)))
    .map((scope) => evidence(scope.filePath, scope.line, 'rate_limit', 'A recognized rate limiter is invoked in this route path.'));
  const rateLimit = rateEvidence.length > 0
    ? assessment('present', rateEvidence, 'A rate limiter is associated with this route.')
    : analysisStatus === 'partial'
      ? assessment('unknown', [], 'Rate-limit coverage could not be determined from complete reachable code.')
      : assessment('absent', [], 'No invoked rate limiter was found for this route.');

  const cookieAuthenticated = COOKIE_AUTH.test(joinedScopes) || projectMap.authSignals.some((signal) =>
    signal.kind === 'session_cookie_check' && inScopes(signal.filePath, signal.line, scopes));
  const csrfEvidence = scopes
    .filter((scope) => CSRF.test(scope.content.slice(scope.start, scope.end)))
    .map((scope) => evidence(scope.filePath, scope.line, 'csrf', 'A recognized CSRF defence is invoked in this route path.'));
  const csrfProtection = !mutating || !cookieAuthenticated
    ? assessment('not_applicable', [], 'CSRF protection is not applicable without a cookie-authenticated mutation.')
    : csrfEvidence.length > 0
      ? assessment('present', csrfEvidence, 'A CSRF defence is associated with this cookie-authenticated mutation.')
      : analysisStatus === 'partial'
        ? assessment('unknown', [], 'CSRF coverage could not be determined from complete reachable code.')
        : assessment('absent', [], 'No CSRF defence was found for this cookie-authenticated mutation.');

  const sensitiveEnvVars = [...new Set(projectMap.envUsage
    .filter((usage) => inScopes(usage.filePath, usage.line, scopes))
    .map((usage) => usage.name))].sort();
  const securitySinks = collectSecuritySinks(route, scopes, projectMap);

  return {
    id: `route_${sha1Hex(`${route.filePath}:${route.line}:${method}:${route.routePath}`).slice(0, 12)}`,
    filePath: route.filePath,
    framework: route.framework,
    routePath: route.routePath,
    method,
    line: route.line,
    analysisStatus,
    analysisReasons: [...new Set(reasons)].sort(),
    reachableFiles: [...new Set(scopes.map((scope) => scope.filePath))].sort(),
    authentication,
    authorization,
    inputValidation,
    rateLimit,
    csrfProtection,
    databaseOperations: databaseOperations.sort((a, b) => a.filePath.localeCompare(b.filePath) || a.line - b.line),
    sensitiveEnvVars,
    securitySinks,
  };
}

function collectSecuritySinks(route: ApiRoute, scopes: FunctionModel[], projectMap: ProjectMap): RouteSecurityEvidence[] {
  const out: RouteSecurityEvidence[] = [];
  for (const hit of projectMap.crossFileTaint?.hits ?? []) {
    if (inScopes(hit.filePath, hit.line, scopes) || (hit.sourceFilePath === route.filePath && scopes.some((scope) => scope.filePath === route.filePath))) {
      out.push(evidence(hit.filePath, hit.line, `sink:${hit.kind}`, `Request-derived data reaches a ${hit.kind} sink.`));
    }
  }
  for (const operation of projectMap.dangerousOperations) {
    if (inScopes(operation.filePath, operation.line, scopes)) {
      out.push(evidence(operation.filePath, operation.line, `sink:${operation.kind}`, operation.snippet));
    }
  }
  const unique = new Map(out.map((item) => [`${item.filePath}:${item.line}:${item.kind}`, item]));
  return [...unique.values()].sort((a, b) => a.filePath.localeCompare(b.filePath) || a.line - b.line || a.kind.localeCompare(b.kind));
}

function reachableForRoute(route: ApiRoute, method: string, graph: CallGraph): Reachability {
  const root = graph.routeRoots.get(routeKey(route, method));
  if (root === undefined) return { models: [], status: 'partial', reasons: [UNRESOLVED_HANDLER_REASON] };
  const visited = new Set<string>();
  let frontier = [root];
  const models: FunctionModel[] = [];
  for (let depth = 0; depth <= MAX_CALL_DEPTH && frontier.length > 0; depth += 1) {
    const next: string[] = [];
    for (const key of frontier.sort()) {
      if (visited.has(key)) continue;
      visited.add(key);
      const model = graph.models.get(key);
      if (model !== undefined) models.push(model);
      if (visited.size > MAX_ROUTE_FUNCTIONS) {
        return { models, status: 'partial', reasons: [ROUTE_FUNCTION_LIMIT.reason] };
      }
      next.push(...(graph.edges.get(key) ?? []));
    }
    frontier = next;
  }
  if (frontier.length > 0) return { models, status: 'partial', reasons: [CALL_DEPTH_LIMIT.reason] };
  return { models, status: 'complete', reasons: [] };
}

function buildCallGraph(fileMap: FileMap, projectMap: ProjectMap): CallGraph {
  callWalkFailuresByProject.delete(projectMap);
  const models = new Map<string, FunctionModel>();
  const localKeys = new Map<string, Map<string, string>>();
  const exportedKeys = new Map<string, Map<string, string>>();
  const routeRoots = new Map<string, string>();
  let unparseable = 0;
  const resolvedByFile = new Map(projectMap.imports.map((fileImports) => [fileImports.filePath,
    new Map(fileImports.imports.filter((ref) => ref.resolvedPath !== undefined).map((ref) => [ref.source, ref.resolvedPath as string]))]));

  for (const entry of fileMap.entries.filter((candidate) => JS_TS.has(candidate.extension))) {
    const locals = new Map<string, string>();
    const exports = new Map<string, string>();
    const pending: Array<[FunctionModel, ts.FunctionLikeDeclaration]> = [];
    try {
      const sf = ts.createSourceFile(entry.path, entry.content, ts.ScriptTarget.Latest, false, scriptKind(entry.extension));
      const imports = parseImports(sf, resolvedByFile.get(entry.path) ?? new Map());
      for (const statement of sf.statements) {
        if (ts.isFunctionDeclaration(statement) && statement.body !== undefined) {
          const name = statement.name?.text ?? (hasModifier(statement, ts.SyntaxKind.DefaultKeyword) ? 'default' : undefined);
          if (name !== undefined) {
            const model = makeModel(entry.path, entry.content, sf, statement, name, imports, pending);
            models.set(model.key, model); locals.set(name, model.key);
            if (hasModifier(statement, ts.SyntaxKind.ExportKeyword)) exports.set(hasModifier(statement, ts.SyntaxKind.DefaultKeyword) ? 'default' : name, model.key);
          }
        } else if (ts.isVariableStatement(statement)) {
          for (const declaration of statement.declarationList.declarations) {
            if (!ts.isIdentifier(declaration.name) || declaration.initializer === undefined ||
              (!ts.isArrowFunction(declaration.initializer) && !ts.isFunctionExpression(declaration.initializer))) continue;
            const model = makeModel(entry.path, entry.content, sf, declaration.initializer, declaration.name.text, imports, pending);
            models.set(model.key, model); locals.set(declaration.name.text, model.key);
            if (hasModifier(statement, ts.SyntaxKind.ExportKeyword)) exports.set(declaration.name.text, model.key);
          }
        } else if (ts.isExportAssignment(statement) && ts.isIdentifier(statement.expression)) {
          exports.set('default', `${entry.path}#${statement.expression.text}`);
        }
      }
      const findInline = (node: ts.Node): void => {
        if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) &&
          ts.isIdentifier(node.expression.expression) && /^(?:app|router)$/.test(node.expression.expression.text) &&
          /^(?:get|post|put|patch|delete|all)$/.test(node.expression.name.text)) {
          const handler = [...node.arguments].reverse().find((arg) => ts.isArrowFunction(arg) || ts.isFunctionExpression(arg));
          if (handler !== undefined && (ts.isArrowFunction(handler) || ts.isFunctionExpression(handler))) {
            const line = lineOf(sf, node);
            const name = `$route:${line}:${node.expression.name.text.toUpperCase()}`;
            const model = makeModel(entry.path, entry.content, sf, handler, name, imports, pending);
            models.set(model.key, model);
          }
        }
        node.forEachChild(findInline);
      };
      findInline(sf);
    } catch {
      unparseable += 1;
      if (unparseable <= MAX_UNPARSEABLE_NAMED) {
        fileMap.warnings.push(
          `"${entry.path}" could not be analysed for route protection. ` +
            'Protections on routes in that file were not checked; every other file in the scan is unaffected.',
        );
      }
      readCalls(pending);
      continue;
    }
    readCalls(pending);
    localKeys.set(entry.path, locals);
    exportedKeys.set(entry.path, exports);
  }
  const more = andMoreFiles(unparseable - MAX_UNPARSEABLE_NAMED, 'route protection');
  if (more !== undefined) fileMap.warnings.push(more);

  if (models.size > MAX_FUNCTIONS) return { models, edges: new Map(), routeRoots, status: 'truncated', reason: FUNCTION_LIMIT.reason };

  const edges = new Map<string, Set<string>>();
  let edgeCount = 0;
  const walkFailures: CallWalkFailure[] = [];
  for (const model of models.values()) {
    const targets = new Set<string>();
    if (model.walkFailed) walkFailures.push({ filePath: model.filePath, line: model.line });
    else for (const call of model.calls) {
      const target = resolveCallee(call, model, localKeys, exportedKeys);
      if (target !== undefined) targets.add(target);
    }
    edgeCount += targets.size;
    edges.set(model.key, targets);
  }
  if (walkFailures.length > 0) callWalkFailuresByProject.set(projectMap, walkFailures);
  const status = edgeCount > MAX_CALL_EDGES ? 'truncated' : 'complete';

  for (const route of projectMap.apiRoutes) {
    for (const method of route.methods) {
      let root: string | undefined;
      if (resolvesRouteRootByMethodExport(route.framework)) root = localKeys.get(route.filePath)?.get(method);
      else if (route.framework === 'nextjs_pages') root = exportedKeys.get(route.filePath)?.get('default');
      else if (route.framework === 'express') root = `${route.filePath}#$route:${route.line}:${method}`;
      else root = findModelAtLine(models, route.filePath, route.line)?.key;
      if (root !== undefined && models.has(root)) routeRoots.set(routeKey(route, method), root);
    }
  }
  return { models, edges, routeRoots, status, ...(status === 'truncated' ? { reason: CALL_EDGE_LIMIT.reason } : {}) };
}

function readCalls(pending: Array<[FunctionModel, ts.FunctionLikeDeclaration]>): void {
  for (const [model, node] of pending) {
    const calls: string[] = [];
    const walk = (child: ts.Node): void => {
      if (child !== node && ts.isFunctionLike(child)) return;
      if (ts.isCallExpression(child)) {
        const callee = child.expression;
        if (ts.isIdentifier(callee)) calls.push(callee.text);
        else if (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression)) calls.push(`${callee.expression.text}.${callee.name.text}`);
      }
      child.forEachChild(walk);
    };
    try {
      if (node.body !== undefined) walk(node.body);
      model.calls = calls;
    } catch {
      model.walkFailed = true;
    }
  }
  pending.length = 0;
}

function resolveCallee(
  call: string,
  model: FunctionModel,
  locals: Map<string, Map<string, string>>,
  exports: Map<string, Map<string, string>>,
): string | undefined {
  const dot = call.indexOf('.');
  if (dot === -1) {
    const local = locals.get(model.filePath)?.get(call);
    if (local !== undefined) return local;
    const binding = model.importBindings.find((candidate) => candidate.local === call);
    if (binding !== undefined) return exports.get(binding.targetFile)?.get(binding.exported);
    return undefined;
  }
  const target = model.namespaceImports.get(call.slice(0, dot));
  if (target !== undefined) return exports.get(target)?.get(call.slice(dot + 1));
  return undefined;
}

function parseImports(sf: ts.SourceFile, resolved: Map<string, string>): { bindings: ImportBinding[]; namespaces: Map<string, string> } {
  const bindings: ImportBinding[] = [];
  const namespaces = new Map<string, string>();
  for (const statement of sf.statements) {
    if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier) || statement.importClause === undefined) continue;
    const targetFile = resolved.get(statement.moduleSpecifier.text);
    if (targetFile === undefined) continue;
    if (statement.importClause.name !== undefined) bindings.push({ local: statement.importClause.name.text, targetFile, exported: 'default' });
    const named = statement.importClause.namedBindings;
    if (named !== undefined && ts.isNamespaceImport(named)) namespaces.set(named.name.text, targetFile);
    if (named !== undefined && ts.isNamedImports(named)) for (const item of named.elements) {
      bindings.push({ local: item.name.text, targetFile, exported: item.propertyName?.text ?? item.name.text });
    }
  }
  return { bindings, namespaces };
}

function makeModel(
  filePath: string,
  content: string,
  sf: ts.SourceFile,
  node: ts.FunctionLikeDeclaration,
  name: string,
  imports: { bindings: ImportBinding[]; namespaces: Map<string, string> },
  pending: Array<[FunctionModel, ts.FunctionLikeDeclaration]>,
): FunctionModel {
  const startLine = lineOf(sf, node);
  const endLine = sf.getLineAndCharacterOfPosition(node.end).line + 1;
  const model: FunctionModel = { key: `${filePath}#${name}`, filePath, name, line: startLine, startLine, endLine,
    start: node.getStart(sf), end: node.end, content, calls: [], walkFailed: false,
    importBindings: imports.bindings, namespaceImports: imports.namespaces };
  pending.push([model, node]);
  return model;
}

function inScopes(filePath: string, line: number, scopes: FunctionModel[]): boolean {
  return scopes.some((scope) => scope.filePath === filePath && line >= scope.startLine && line <= scope.endLine);
}

function assessment(status: RouteControlAssessment['status'], evidenceItems: RouteSecurityEvidence[], reason: string): RouteControlAssessment {
  return { status, evidence: evidenceItems.sort((a, b) => a.filePath.localeCompare(b.filePath) || a.line - b.line), reason };
}

function evidence(filePath: string, line: number, kind: string, detail: string): RouteSecurityEvidence {
  return { filePath, line, kind, detail: detail.slice(0, 240) };
}

function routeKey(route: ApiRoute, method: string): string { return `${route.filePath}\0${route.line}\0${method}`; }

function findModelAtLine(models: Map<string, FunctionModel>, filePath: string, line: number): FunctionModel | undefined {
  return [...models.values()].find((model) => model.filePath === filePath && line >= model.startLine && line <= model.endLine);
}

function hasModifier(node: ts.Node, kind: ts.SyntaxKind): boolean {
  return ts.canHaveModifiers(node) && (ts.getModifiers(node)?.some((modifier) => modifier.kind === kind) ?? false);
}

function lineOf(sf: ts.SourceFile, node: ts.Node): number { return sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1; }

function scriptKind(extension: string): ts.ScriptKind {
  if (extension === '.tsx') return ts.ScriptKind.TSX;
  if (extension === '.jsx') return ts.ScriptKind.JSX;
  if (extension === '.ts') return ts.ScriptKind.TS;
  return ts.ScriptKind.JS;
}
