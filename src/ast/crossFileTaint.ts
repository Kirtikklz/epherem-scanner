import ts from 'typescript';
import type { FileImports, FileMap } from '../shared/types.js';
import { referencesUserInput } from '../shared/userInput.js';
import { redirectDestination } from './astAnalysis.js';
import type { AstSinkHit, SinkKind } from './astAnalysis.js';
import { calleeProvenanceFor, isShellExecCallee } from '../shared/shellCommandSink.js';
import { andMoreFiles, CappedNames, MAX_FILES_NAMED } from '../shared/cappedNames.js';
import { RULE_REGISTRY } from '../rules/ruleRegistry.js';

const JS_TS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);
const MAX_UNPARSEABLE_NAMED = MAX_FILES_NAMED;

const MAX_FILES = 2_000;
const MAX_FUNCTIONS = 5_000;
const MAX_NODES = 2_000_000;
const MAX_FIXED_POINT_ROUNDS = 12;
const MAX_RETAINED_SOURCE_CHARS = 6_000_000;

const crossFileLossWarning = (filePath: string): string =>
  `"${filePath}" could not be analysed for cross-file data flow. ` +
  'Data passing through it was not followed; every other file in the scan is unaffected.';

function noteCrossFileLoss(warnings: string[], lost: CappedNames, filePath: string): void {
  if (lost.add(filePath)) warnings.push(crossFileLossWarning(filePath));
}

export interface CrossFileTaintHit {
  filePath: string;
  line: number;
  kind: SinkKind;
  sourceFilePath: string;
  confidence: 'high';
}

export interface CrossFileTaintResult {
  hits: CrossFileTaintHit[];
  status: 'complete' | 'truncated';
  reason?: string;
  limit?: CrossFileLimit;
}

export type CrossFileLimit =
  | { kind: 'files'; limit: number; observed: number }
  | { kind: 'nodes'; limit: number }
  | { kind: 'functions'; limit: number }
  | { kind: 'source'; limit: number }
  | { kind: 'rounds'; limit: number };

export function crossFileFlowRuleIds(): string[] {
  return RULE_REGISTRY.filter((rule) => rule.analysisMethod === 'ast_assisted').map((rule) => rule.ruleId);
}

const CHECK_NAMES: Readonly<Record<string, string>> = {
  sql_injection: 'SQL injection',
  command_injection: 'command injection',
  path_traversal: 'path traversal',
  ssrf: 'SSRF',
  open_redirect: 'open redirect',
  xss: 'XSS',
  unsafe_dynamic_code: 'unsafe code execution',
};

export function crossFileFlowChecks(): string {
  const names = crossFileFlowRuleIds().map(
    (ruleId) => CHECK_NAMES[ruleId] ?? RULE_REGISTRY.find((rule) => rule.ruleId === ruleId)?.title ?? ruleId,
  );
  if (names.length <= 1) return names.join('');
  return `${names.slice(0, -1).join(', ')} and ${names.at(-1)}`;
}

const count = (value: number): string => value.toLocaleString('en-US');

export function crossFileTruncationWarning(result: CrossFileTaintResult): string {
  const limit = result.limit;
  const why =
    limit === undefined
      ? 'Cross-file analysis stopped before it finished on this project'
      : limit.kind === 'files'
        ? `This project is larger than cross-file analysis supports (${count(limit.observed)} JavaScript/TypeScript files, against a limit of ${count(limit.limit)})`
        : limit.kind === 'nodes'
          ? `This project is larger than cross-file analysis supports (more than ${count(limit.limit)} syntax nodes)`
          : limit.kind === 'functions'
            ? `This project is larger than cross-file analysis supports (more than ${count(limit.limit)} functions)`
            : limit.kind === 'source'
              ? `This project is larger than cross-file analysis supports (more than ${count(limit.limit)} characters of JavaScript/TypeScript in files with functions)`
            : `Cross-file analysis could not finish on this project (data flow between its functions had not settled after ${limit.limit} passes)`;
  return (
    `${why}, so data passing from one function into another was not followed anywhere in the project — ` +
    "not between files, and not into a helper's parameters within one file. " +
    `${crossFileFlowChecks()} were checked within each file only.`
  );
}

export function crossFileAstHits(result: CrossFileTaintResult | undefined, filePath: string): AstSinkHit[] {
  if (result === undefined) return [];
  return result.hits
    .filter((hit) => hit.filePath === filePath)
    .map((hit) => ({
      kind: hit.kind,
      line: hit.line,
      taint: 'user' as const,
      callee: hit.sourceFilePath === filePath
        ? 'flow through a call in this file'
        : `cross-file flow from ${hit.sourceFilePath}`,
    }));
}

interface Dependency {
  params: Set<number>;
  user: boolean;
  crossed: boolean;
}

interface SinkFlow {
  filePath: string;
  line: number;
  kind: SinkKind;
  dependency: Dependency;
  crossesFile: boolean;
  viaCall: boolean;
}

interface FunctionSummary {
  returns: Dependency;
  sinks: SinkFlow[];
}

interface ImportBinding {
  local: string;
  targetFile: string;
  exported: string;
}

interface FunctionModel {
  key: string;
  filePath: string;
  name: string;
  node: ts.FunctionLikeDeclaration;
  sf: ts.SourceFile;
  content: string;
  paramBindings: string[][];
  imports: ImportBinding[];
  namespaceImports: Map<string, string>;
}

const emptyDependency = (): Dependency => ({ params: new Set(), user: false, crossed: false });
const cloneDependency = (value: Dependency): Dependency => ({ params: new Set(value.params), user: value.user, crossed: value.crossed });
const mergeDependency = (left: Dependency, right: Dependency): Dependency => ({
  params: new Set([...left.params, ...right.params]),
  user: left.user || right.user,
  crossed: left.crossed || right.crossed,
});

const SANITIZER = /(?:^|\.)(?:encodeURIComponent|encodeURI|parseInt|parseFloat|basename|secure_filename|slugify|sanitize|sanitizeHtml|escapeHtml|escape|cleanPath|cleanUrl|resolveSafe)$/i;
const TRUSTED = /\b(?:getServerSession|getSession|currentUser|auth|verifyIdToken|verifyToken)\s*\(/;

export function analyzeCrossFileTaint(fileMap: FileMap, imports: FileImports[]): CrossFileTaintResult {
  const lost = new CappedNames(MAX_UNPARSEABLE_NAMED);
  const result = followFlows(fileMap, imports, lost);
  const more = andMoreFiles(lost.unnamed, 'cross-file data flow');
  if (more !== undefined) fileMap.warnings.push(more);
  return result;
}

function followFlows(fileMap: FileMap, imports: FileImports[], lost: CappedNames): CrossFileTaintResult {
  const entries = fileMap.entries.filter((entry) => JS_TS.has(entry.extension));
  if (entries.length > MAX_FILES) {
    return {
      hits: [],
      status: 'truncated',
      reason: `Cross-file AST file limit (${MAX_FILES}) exceeded.`,
      limit: { kind: 'files', limit: MAX_FILES, observed: entries.length },
    };
  }

  const resolvedByFile = new Map<string, Map<string, string>>();
  for (const fileImports of imports) {
    const bySource = new Map<string, string>();
    for (const ref of fileImports.imports) {
      if (ref.resolvedPath !== undefined) bySource.set(ref.source, ref.resolvedPath);
    }
    resolvedByFile.set(fileImports.filePath, bySource);
  }

  const models: FunctionModel[] = [];
  const localKeys = new Map<string, Map<string, string>>();
  const exportedKeys = new Map<string, Map<string, string>>();
  let nodesVisited = 0;

  let retainedChars = 0;
  for (const entry of entries) {
    const modelsBefore = models.length;
    const locals = new Map<string, string>();
    const exports = new Map<string, string>();
    try {
      const sf = ts.createSourceFile(entry.path, entry.content, ts.ScriptTarget.Latest, false, scriptKind(entry.extension));
      const parsedImports = parseImportBindings(sf, resolvedByFile.get(entry.path) ?? new Map());

      for (const statement of sf.statements) {
        nodesVisited += 1;
        if (nodesVisited > MAX_NODES) {
          return {
            hits: [],
            status: 'truncated',
            reason: `Cross-file AST node limit (${MAX_NODES}) exceeded.`,
            limit: { kind: 'nodes', limit: MAX_NODES },
          };
        }
        if (ts.isFunctionDeclaration(statement) && statement.body !== undefined) {
          const name = statement.name?.text ?? (hasModifier(statement, ts.SyntaxKind.DefaultKeyword) ? 'default' : undefined);
          if (name !== undefined) addModel(entry.path, entry.content, sf, statement, name, parsedImports, models, locals);
          if (name !== undefined && hasModifier(statement, ts.SyntaxKind.ExportKeyword)) {
            exports.set(hasModifier(statement, ts.SyntaxKind.DefaultKeyword) ? 'default' : name, `${entry.path}#${name}`);
          }
        } else if (ts.isVariableStatement(statement)) {
          for (const declaration of statement.declarationList.declarations) {
            if (!ts.isIdentifier(declaration.name) || declaration.initializer === undefined) continue;
            if (!ts.isArrowFunction(declaration.initializer) && !ts.isFunctionExpression(declaration.initializer)) continue;
            const name = declaration.name.text;
            addModel(entry.path, entry.content, sf, declaration.initializer, name, parsedImports, models, locals);
            if (hasModifier(statement, ts.SyntaxKind.ExportKeyword)) exports.set(name, `${entry.path}#${name}`);
          }
        } else if (ts.isExportAssignment(statement) && ts.isIdentifier(statement.expression)) {
          exports.set('default', `${entry.path}#${statement.expression.text}`);
        }
      }
    } catch {
      noteCrossFileLoss(fileMap.warnings, lost, entry.path);
      continue;
    }
    localKeys.set(entry.path, locals);
    exportedKeys.set(entry.path, exports);
    if (models.length > MAX_FUNCTIONS) {
      return {
        hits: [],
        status: 'truncated',
        reason: `Cross-file function limit (${MAX_FUNCTIONS}) exceeded.`,
        limit: { kind: 'functions', limit: MAX_FUNCTIONS },
      };
    }
    if (models.length > modelsBefore) retainedChars += entry.content.length;
    if (retainedChars > MAX_RETAINED_SOURCE_CHARS) {
      return {
        hits: [],
        status: 'truncated',
        reason: `Cross-file source limit (${MAX_RETAINED_SOURCE_CHARS} characters) exceeded.`,
        limit: { kind: 'source', limit: MAX_RETAINED_SOURCE_CHARS },
      };
    }
  }

  let summaries = new Map<string, FunctionSummary>();
  for (const model of models) summaries.set(model.key, { returns: emptyDependency(), sinks: [] });

  const unwalkable = new Set<string>();

  let converged = false;
  for (let round = 0; round < MAX_FIXED_POINT_ROUNDS; round += 1) {
    const next = new Map<string, FunctionSummary>();
    for (const model of models) {
      if (unwalkable.has(model.key)) {
        next.set(model.key, { returns: emptyDependency(), sinks: [] });
        continue;
      }
      let result: FunctionSummary | undefined;
      try {
        result = summarize(model, summaries, localKeys, exportedKeys, () => {
          nodesVisited += 1;
          return nodesVisited <= MAX_NODES;
        });
      } catch {
        unwalkable.add(model.key);
        noteCrossFileLoss(fileMap.warnings, lost, model.filePath);
        next.set(model.key, { returns: emptyDependency(), sinks: [] });
        continue;
      }
      if (result === undefined) {
        return {
          hits: [],
          status: 'truncated',
          reason: `Cross-file AST node limit (${MAX_NODES}) exceeded.`,
          limit: { kind: 'nodes', limit: MAX_NODES },
        };
      }
      next.set(model.key, result);
    }
    if (summaryMapsEqual(summaries, next)) {
      summaries = next;
      converged = true;
      break;
    }
    summaries = next;
  }
  if (!converged) {
    return {
      hits: [],
      status: 'truncated',
      reason: `Cross-file data-flow depth limit (${MAX_FIXED_POINT_ROUNDS} rounds) exceeded.`,
      limit: { kind: 'rounds', limit: MAX_FIXED_POINT_ROUNDS },
    };
  }

  const hits = new Map<string, CrossFileTaintHit>();
  for (const model of models) {
    const summary = summaries.get(model.key);
    if (summary === undefined) continue;
    for (const sink of summary.sinks) {
      if ((!sink.crossesFile && !sink.viaCall) || !sink.dependency.user) continue;
      const key = `${sink.kind}\0${sink.filePath}\0${sink.line}\0${model.filePath}`;
      hits.set(key, {
        filePath: sink.filePath,
        line: sink.line,
        kind: sink.kind,
        sourceFilePath: model.filePath,
        confidence: 'high',
      });
    }
  }
  return {
    hits: [...hits.values()].sort((a, b) =>
      a.filePath.localeCompare(b.filePath) || a.line - b.line || a.kind.localeCompare(b.kind) ||
      a.sourceFilePath.localeCompare(b.sourceFilePath)),
    status: 'complete',
  };
}

function addModel(
  filePath: string,
  content: string,
  sf: ts.SourceFile,
  node: ts.FunctionLikeDeclaration,
  name: string,
  parsedImports: { imports: ImportBinding[]; namespaces: Map<string, string> },
  models: FunctionModel[],
  locals: Map<string, string>,
): void {
  const key = `${filePath}#${name}`;
  const paramBindings = node.parameters.map((parameter, index) => {
    const names = bindingNames(parameter.name);
    return names.length > 0 ? names : [`$${index}`];
  });
  models.push({ key, filePath, name, node, sf, content, paramBindings, imports: parsedImports.imports, namespaceImports: parsedImports.namespaces });
  locals.set(name, key);
}

function parseImportBindings(
  sf: ts.SourceFile,
  resolved: Map<string, string>,
): { imports: ImportBinding[]; namespaces: Map<string, string> } {
  const imports: ImportBinding[] = [];
  const namespaces = new Map<string, string>();
  for (const statement of sf.statements) {
    if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier)) continue;
    const targetFile = resolved.get(statement.moduleSpecifier.text);
    const clause = statement.importClause;
    if (targetFile === undefined || clause === undefined) continue;
    if (clause.name !== undefined) imports.push({ local: clause.name.text, targetFile, exported: 'default' });
    const bindings = clause.namedBindings;
    if (bindings !== undefined && ts.isNamespaceImport(bindings)) namespaces.set(bindings.name.text, targetFile);
    if (bindings !== undefined && ts.isNamedImports(bindings)) {
      for (const element of bindings.elements) {
        imports.push({ local: element.name.text, targetFile, exported: element.propertyName?.text ?? element.name.text });
      }
    }
  }
  return { imports, namespaces };
}

function summarize(
  model: FunctionModel,
  summaries: Map<string, FunctionSummary>,
  localKeys: Map<string, Map<string, string>>,
  exportedKeys: Map<string, Map<string, string>>,
  consumeNode: () => boolean,
): FunctionSummary | undefined {
  const env = new Map<string, Dependency>();
  model.paramBindings.forEach((names, index) => {
    for (const name of names) env.set(name, { params: new Set([index]), user: false, crossed: false });
  });
  let returns = emptyDependency();
  const sinks: SinkFlow[] = [];
  let exhausted = false;

  const resolveCallee = (expression: ts.Expression): string | undefined => {
    if (ts.isIdentifier(expression)) {
      const local = localKeys.get(model.filePath)?.get(expression.text);
      if (local !== undefined) return local;
      const binding = model.imports.find((candidate) => candidate.local === expression.text);
      if (binding !== undefined) return exportedKeys.get(binding.targetFile)?.get(binding.exported);
    }
    if (ts.isPropertyAccessExpression(expression) && ts.isIdentifier(expression.expression)) {
      const target = model.namespaceImports.get(expression.expression.text);
      if (target !== undefined) return exportedKeys.get(target)?.get(expression.name.text);
    }
    return undefined;
  };

  let enclosingScope: string | undefined;
  const constructionScope = (): string => (enclosingScope ??= model.node.getText(model.sf));

  const dependencyOf = (node: ts.Expression): Dependency => {
    const text = node.getText(model.sf);
    if (ts.isCallExpression(node) && SANITIZER.test(node.expression.getText(model.sf))) return emptyDependency();
    if (referencesUserInput(text) && referencesUserInput(text, constructionScope())) {
      return { params: new Set(), user: true, crossed: false };
    }
    if (TRUSTED.test(text) || ts.isLiteralExpression(node)) return emptyDependency();
    if (ts.isIdentifier(node)) return cloneDependency(env.get(node.text) ?? emptyDependency());
    if (ts.isCallExpression(node)) {
      const calleeText = node.expression.getText(model.sf);
      const calleeKey = resolveCallee(node.expression);
      const callee = calleeKey === undefined ? undefined : summaries.get(calleeKey);
      if (callee !== undefined) {
        const mapped = mapDependency(callee.returns, node.arguments, dependencyOf);
        const calleeFile = calleeKey?.slice(0, calleeKey.lastIndexOf('#'));
        if (calleeFile !== undefined && calleeFile !== model.filePath) mapped.crossed = true;
        return mapped;
      }
    }
    if (ts.isTemplateExpression(node)) {
      let result = emptyDependency();
      for (const span of node.templateSpans) result = mergeDependency(result, dependencyOf(span.expression));
      return result;
    }
    let result = emptyDependency();
    const collect = (child: ts.Node): void => {
      if (ts.isExpression(child)) result = mergeDependency(result, dependencyOf(child));
      else child.forEachChild(collect);
    };
    node.forEachChild(collect);
    return result;
  };

  const walk = (node: ts.Node): void => {
    if (!consumeNode()) { exhausted = true; return; }
    if (exhausted) return;
    if (node !== model.node && ts.isFunctionLike(node)) return;
    if (ts.isVariableDeclaration(node) && node.initializer !== undefined && ts.isIdentifier(node.name)) {
      env.set(node.name.text, dependencyOf(node.initializer));
    } else if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(node.left)) {
      env.set(node.left.text, dependencyOf(node.right));
    } else if (ts.isReturnStatement(node) && node.expression !== undefined) {
      returns = mergeDependency(returns, dependencyOf(node.expression));
    } else if (ts.isCallExpression(node)) {
      for (const direct of directCallSinks(node, model.sf)) {
        const dependency = dependencyOf(direct.argument);
        sinks.push({ filePath: model.filePath, line: lineOf(model.sf, node), kind: direct.kind,
          dependency, crossesFile: dependency.crossed, viaCall: false });
      }
      const calleeKey = resolveCallee(node.expression);
      const callee = calleeKey === undefined ? undefined : summaries.get(calleeKey);
      if (callee !== undefined) {
        const calleeFile = calleeKey?.slice(0, calleeKey.lastIndexOf('#')) ?? model.filePath;
        for (const flow of callee.sinks) {
          sinks.push({ ...flow, dependency: mapDependency(flow.dependency, node.arguments, dependencyOf),
            viaCall: true,
            crossesFile: flow.crossesFile || calleeFile !== model.filePath });
        }
      }
    } else if (
      ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isPropertyAccessExpression(node.left) && /^(?:innerHTML|outerHTML)$/.test(node.left.name.text)
    ) {
      const dependency = dependencyOf(node.right);
      sinks.push({ filePath: model.filePath, line: lineOf(model.sf, node), kind: 'html',
        dependency, crossesFile: dependency.crossed, viaCall: false });
    } else if (ts.isJsxAttribute(node) && node.name.getText(model.sf) === 'dangerouslySetInnerHTML') {
      const init = node.initializer;
      if (init !== undefined && ts.isJsxExpression(init) && init.expression !== undefined) {
        const dependency = dependencyOf(init.expression);
        sinks.push({ filePath: model.filePath, line: lineOf(model.sf, node), kind: 'html',
          dependency, crossesFile: dependency.crossed, viaCall: false });
      }
    }
    node.forEachChild(walk);
  };
  if (model.node.body !== undefined) walk(model.node.body);
  if (exhausted) return undefined;
  return { returns, sinks: dedupeFlows(sinks) };
}

function mapDependency(
  dependency: Dependency,
  args: readonly ts.Expression[],
  classify: (node: ts.Expression) => Dependency,
): Dependency {
  let result: Dependency = { params: new Set(), user: dependency.user, crossed: dependency.crossed };
  for (const index of dependency.params) {
    const arg = args[index];
    if (arg !== undefined) result = mergeDependency(result, classify(arg));
  }
  return result;
}

function directCallSinks(node: ts.CallExpression, sf: ts.SourceFile): Array<{ kind: SinkKind; argument: ts.Expression }> {
  const callee = node.expression.getText(sf);
  const arg0 = node.arguments[0];
  if (arg0 === undefined) return [];
  if (/(?:^|\.)(?:query|execute|raw)$/.test(callee) || /\$(?:queryRawUnsafe|executeRawUnsafe)$/.test(callee)) return [{ kind: 'sql', argument: arg0 }];
  if (/(?:^|\.)(?:exec|execSync)$/.test(callee)) {
    return isShellExecCallee(node.expression, calleeProvenanceFor(sf)) ? [{ kind: 'command', argument: arg0 }] : [];
  }
  if (/(?:^|\.)(?:spawn|spawnSync|execFile|execFileSync)$/.test(callee)) return [{ kind: 'command', argument: arg0 }];
  if (ts.isIdentifier(node.expression) && calleeProvenanceFor(sf).shellFn.has(callee)) {
    return [{ kind: 'command', argument: arg0 }];
  }
  if (/^(?:fs(?:\.promises)?|fsp)\.(?:readFile|readFileSync|createReadStream|createWriteStream|writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|rm|rmSync|readdir|readdirSync|stat|statSync|open|openSync|mkdir|mkdirSync|copyFile|copyFileSync)$/.test(callee) || /\.sendFile$/.test(callee)) return [{ kind: 'path', argument: arg0 }];
  if (/^(?:fetch|got|axios|request)$/.test(callee) || /^(?:axios|got|superagent|http|https|undici|ky|request)\.(?:get|post|put|delete|patch|head|request|fetch|stream)$/.test(callee)) return [{ kind: 'request', argument: arg0 }];
  if (/(?:^|\.)redirect$/.test(callee)) {
    const destination = redirectDestination(node.arguments);
    return destination === undefined ? [] : [{ kind: 'redirect', argument: destination }];
  }
  if (/^document\.write(?:ln)?$/.test(callee)) return [{ kind: 'html', argument: arg0 }];
  if (/\.insertAdjacentHTML$/.test(callee) && node.arguments[1] !== undefined) return [{ kind: 'html', argument: node.arguments[1] }];
  if (callee === 'eval' || /^(?:setTimeout|setInterval)$/.test(callee)) return [{ kind: 'dynamic_code', argument: arg0 }];
  return [];
}

function dedupeFlows(flows: SinkFlow[]): SinkFlow[] {
  const out = new Map<string, SinkFlow>();
  for (const flow of flows) {
    const params = [...flow.dependency.params].sort((a, b) => a - b).join(',');
    const key = `${flow.kind}\0${flow.filePath}\0${flow.line}\0${params}\0${flow.dependency.user}\0${flow.crossesFile}\0${flow.viaCall}`;
    out.set(key, flow);
  }
  return [...out.values()].sort((a, b) => a.filePath.localeCompare(b.filePath) || a.line - b.line || a.kind.localeCompare(b.kind));
}

function summaryMapsEqual(left: Map<string, FunctionSummary>, right: Map<string, FunctionSummary>): boolean {
  if (left.size !== right.size) return false;
  for (const [key, summary] of left) {
    const other = right.get(key);
    if (other === undefined || fingerprint(summary) !== fingerprint(other)) return false;
  }
  return true;
}

function fingerprint(summary: FunctionSummary): string {
  const dep = (value: Dependency): string => `${value.user}:${value.crossed}:${[...value.params].sort((a, b) => a - b).join(',')}`;
  return `${dep(summary.returns)}|${summary.sinks.map((sink) =>
    `${sink.kind}:${sink.filePath}:${sink.line}:${sink.crossesFile}:${dep(sink.dependency)}`).join('|')}`;
}

function hasModifier(node: ts.Node, kind: ts.SyntaxKind): boolean {
  return ts.canHaveModifiers(node) && (ts.getModifiers(node)?.some((modifier) => modifier.kind === kind) ?? false);
}

function lineOf(sf: ts.SourceFile, node: ts.Node): number {
  return sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
}

function scriptKind(extension: string): ts.ScriptKind {
  if (extension === '.tsx') return ts.ScriptKind.TSX;
  if (extension === '.jsx') return ts.ScriptKind.JSX;
  if (extension === '.ts') return ts.ScriptKind.TS;
  return ts.ScriptKind.JS;
}

function bindingNames(name: ts.BindingName): string[] {
  if (ts.isIdentifier(name)) return [name.text];
  const names: string[] = [];
  for (const element of name.elements) {
    if (ts.isOmittedExpression(element)) continue;
    names.push(...bindingNames(element.name));
  }
  return names;
}

