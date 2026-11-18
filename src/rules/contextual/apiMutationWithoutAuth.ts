import {
  databaseCallsInFile,
  directImportsOf,
  effectiveGuardsInFile,
} from '../../project-map/buildProjectMap.js';
import { enclosingFunctionBlock, stripCommentsAndStrings, type BlockRange } from '../../shared/source.js';
import { makeFinding } from '../../shared/findingFactory.js';
import { hasWebhookOrCronSegment } from '../../shared/routePath.js';
import { isAuthFlowRoute } from '../../candidates/absence/routeExemptions.js';
import { describeSiblings, siblingInconsistency } from '../../shared/siblingRouteInconsistency.js';
import { resolvesToRejection } from '../../shared/handlerGuardCall.js';
import { routeHandlerScopeForLine } from '../../shared/handlerScope.js';
import { routeControlProven } from '../../shared/routeControlModel.js';
import { cascadingControlProven } from '../../shared/cascadingGuard.js';
import { svelteKitDeclarationRange } from '../../shared/frameworkModel.js';
import { pythonHandlerSpan, pythonRouteGuard } from '../../shared/pythonGuards.js';
import { SIGNATURE_HEADER, WEBHOOK_SIGNATURE_VERIFIED } from '../../shared/webhookSignature.js';
import type { ApiRoute, AuthSignal, DatabaseCall, Finding, RuleContext, ScanRule } from '../../shared/types.js';

export const MUTATION_KINDS = new Set(['insert', 'update', 'delete', 'upsert', 'write', 'raw_sql']);
const MAX_IMPORT_DEPTH = 6;

const WRITE_SQL = /\b(?:INSERT|UPDATE|DELETE|REPLACE|MERGE|UPSERT|DROP|CREATE|ALTER|TRUNCATE|GRANT|REVOKE)\b/i;

function isReadOnlyRawSql(snippet: string): boolean {
  return /\bSELECT\b/i.test(snippet) && !WRITE_SQL.test(snippet);
}

function isMachineAuthenticatedRoute(filePath: string, routePath: string | undefined, content: string): boolean {
  const pathNamesAWebhook =
    hasWebhookOrCronSegment(filePath) ||
    (routePath !== undefined && routePath !== '' && hasWebhookOrCronSegment(routePath));
  if (pathNamesAWebhook) return true;
  return SIGNATURE_HEADER.test(content) && WEBHOOK_SIGNATURE_VERIFIED.test(content);
}

function isAuthFlowApiRoute(route: Pick<ApiRoute, 'routePath' | 'filePath'>): boolean {
  return route.routePath !== '' && isAuthFlowRoute({ fullPath: route.routePath, relPath: route.routePath, filePath: route.filePath });
}

export const apiMutationWithoutAuth: ScanRule = {
  id: 'api_mutation_without_auth',
  title: 'API route writes to the database without an authentication check',
  category: 'authentication',
  kind: 'contextual',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const apiFiles = new Set(context.projectMap.apiRoutes.map((route) => route.filePath));

    for (const filePath of [...apiFiles].sort()) {
      const mutations = withoutPythonGuarded(context, filePath, databaseCallsInFile(context.projectMap, filePath).filter(
        (call) => MUTATION_KINDS.has(call.kind) && !(call.kind === 'raw_sql' && isReadOnlyRawSql(call.snippet)),
      ));
      if (mutations.length === 0) continue;

      const entry = context.fileMap.entries.find((candidate) => candidate.path === filePath);
      if (entry === undefined) continue;
      const routePath = context.projectMap.apiRoutes.find((route) => route.filePath === filePath)?.routePath;
      if (isMachineAuthenticatedRoute(filePath, routePath, entry.content)) continue;
      const stripped = stripCommentsAndStrings(entry.content);
      const lineStarts = computeLineStarts(entry.content);
      const guards = effectiveGuardsInFile(context.projectMap, filePath);
      const moduleScopeGuard = guards.some(
        (guard) => enclosingFunctionBlock(stripped, guard.index ?? lineStarts[guard.line - 1] ?? 0) === undefined,
      );

      const groups = new Map<string, DatabaseCall[]>();
      for (const mutation of mutations) {
        const idx = mutation.index ?? lineStarts[mutation.line - 1] ?? 0;
        const block = enclosingFunctionBlock(stripped, idx);
        const key = block ? `${block.start}:${block.end}` : 'module';
        const list = groups.get(key) ?? [];
        list.push(mutation);
        groups.set(key, list);
      }

      const importedGuardFile = findGuardedImport(context, filePath);

      for (const [key, groupMutations] of [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
        const block = blockFromKey(key);
        const guardedInScope =
          moduleScopeGuard || guards.some((guard) => guardInBlock(guard, block, lineStarts));
        if (guardedInScope) continue;

        const routeProvenAuthenticated = groupMutations.every((mutation) =>
          routeControlProven(context, filePath, mutation.line, 'auth'));
        if (routeProvenAuthenticated) continue;

        const coveringRoutes = routesCoveringBlock(context, filePath, block, entry.content);
        const cascadeAuthenticated = coveringRoutes.length > 0 && coveringRoutes.every((route) =>
          cascadingControlProven(context, {
            filePath: route.filePath,
            routePath: route.routePath,
            line: route.line,
            framework: route.framework,
            ...(route.methods[0] !== undefined ? { method: route.methods[0] } : {}),
          }, 'auth'));
        if (cascadeAuthenticated) continue;
        if (coveringRoutes.length > 0 && coveringRoutes.every(isAuthFlowApiRoute)) continue;

        const handlerText = block === undefined
          ? ''
          : entry.content.slice(block.start, Math.min(entry.content.length, block.end));
        if (resolvesToRejection(context, filePath, handlerText)) continue;

        const first = groupMutations[0];
        if (first === undefined) continue;
        const last = groupMutations[groupMutations.length - 1] ?? first;

        const inconsistency = importedGuardFile === undefined
          ? siblingInconsistency(
            context.projectMap,
            filePath,
            entry.content,
            first.index ?? lineStarts[first.line - 1] ?? 0,
          )
          : undefined;

        const baseTechnical = importedGuardFile !== undefined
          ? `${filePath} performs ${groupMutations.length} mutation(s) in a handler with no in-scope auth guard, but the file imports ${importedGuardFile}, which contains a checked auth guard. Protection may be applied there — flagged at low confidence; verify the guard is actually invoked for this handler.`
          : `${filePath} performs ${groupMutations.length} database mutation(s) in a handler that contains no effective auth guard (a session lookup or token verification whose result is checked) — and neither its module scope nor its resolved imports do. Add a session check before the mutation and return 401 when absent.`;

        findings.push(
          makeFinding({
            ruleId: this.id,
            title: this.title,
            severity: 'high',
            confidence: inconsistency !== undefined
              ? 'high'
              : importedGuardFile !== undefined ? 'low' : 'medium',
            detectionKind: 'absence',
            filePath,
            lineStart: first.line,
            lineEnd: last.line,
            evidence: groupMutations.map((call) => `${call.client} ${call.kind} @ line ${call.line}`).join('; '),
            userExplanation: inconsistency !== undefined
              ? 'The other API endpoints in this folder check who is making the request — this one does not. It changes data in your database, so anyone who calls it can modify your data. This looks like an endpoint that was missed when authentication was added to the rest of the group; add the same session check here.'
              : 'This API endpoint changes data in your database, but the code never checks who is making the request. Anyone who calls the endpoint can modify your data. Verify the user\'s session before performing the write.',
            technicalExplanation: inconsistency !== undefined
              ? `${baseTechnical} Every other route under ${inconsistency.groupPath} has a checked authentication guard in its complete call graph (${describeSiblings(inconsistency.siblingRoutePaths)}), so this endpoint is the exception among protected siblings rather than one unguarded route in an unguarded application.`
              : baseTechnical,
            fixHint:
              'At the top of the handler, resolve the caller\'s identity (getServerSession(), supabase.auth.getUser(), or jwt.verify on the request token), return a 401 response when it is missing, and only then run the mutation.',
            category: this.category,
          }),
        );
      }
    }

    for (const profile of context.projectMap.routeSecurityProfiles ?? []) {
      if (profile.analysisStatus !== 'complete' || profile.authentication.status !== 'absent') continue;
      const importedMutations = profile.databaseOperations.filter(
        (operation) => operation.filePath !== profile.filePath && MUTATION_KINDS.has(operation.kind),
      );
      if (importedMutations.length === 0) continue;
      const profileEntry = context.fileMap.entries.find((candidate) => candidate.path === profile.filePath);
      if (isMachineAuthenticatedRoute(profile.filePath, profile.routePath, profileEntry?.content ?? '')) continue;
      if (routeControlProven(context, profile.filePath, profile.line, 'auth')) continue;
      if (profileEntry !== undefined && resolvesToRejection(
        context, profile.filePath, routeHandlerScopeForLine(profileEntry.content, profile.line))) continue;
      findings.push(makeFinding({
        ruleId: this.id,
        title: this.title,
        severity: 'high',
        confidence: 'high',
        detectionKind: 'absence',
        filePath: profile.filePath,
        lineStart: profile.line,
        evidence: importedMutations.map((operation) =>
          `${operation.client} ${operation.kind} in ${operation.filePath}:${operation.line}`).join('; '),
        userExplanation:
          'This API endpoint changes data through an imported service, but neither the endpoint nor the invoked helper path checks who is making the request. Anyone who calls it may be able to modify data.',
        technicalExplanation:
          `${profile.method} ${profile.routePath} reaches ${importedMutations.length} database mutation(s) through invoked local helpers, and the complete route call graph contains no checked authentication guard.`,
        fixHint:
          'Authenticate at the route boundary, reject unauthenticated requests, and pass only the trusted identity into the service/repository operation.',
        category: this.category,
      }));
    }
    return findings;
  },
};

function withoutPythonGuarded(context: RuleContext, filePath: string, mutations: DatabaseCall[]): DatabaseCall[] {
  if (!filePath.endsWith('.py') || mutations.length === 0) return mutations;
  const handlers = context.projectMap.apiRoutes
    .filter((route) => route.filePath === filePath)
    .map((route) => ({ route, span: pythonHandlerSpan(context, route) }));
  if (handlers.length === 0) return mutations;
  const guardedAt = (route: ApiRoute, line?: number): boolean => pythonRouteGuard(context, route, line) !== undefined;
  const everyRouteGuarded = handlers.every(({ route, span }) => span !== undefined && guardedAt(route));
  return mutations.filter((mutation) => {
    const owner = handlers.find(({ span }) =>
      span !== undefined && mutation.line >= span.startLine && mutation.line <= span.endLine);
    if (owner === undefined) return !everyRouteGuarded;
    if (isAuthFlowApiRoute(owner.route)) return false;
    return !guardedAt(owner.route, mutation.line);
  });
}

function computeLineStarts(content: string): number[] {
  const starts = [0];
  for (let i = 0; i < content.length; i += 1) {
    if (content.charCodeAt(i) === 10) starts.push(i + 1);
  }
  return starts;
}

const BLOCK_DECLARATION_SLACK = 2;

function routesCoveringBlock(
  context: RuleContext,
  filePath: string,
  block: BlockRange | undefined,
  content: string,
): ApiRoute[] {
  if (block === undefined) return [];
  const starts = computeLineStarts(content);
  const lineOf = (index: number): number => {
    let line = 1;
    for (let i = 0; i < starts.length; i += 1) {
      const start = starts[i];
      if (start === undefined || start > index) break;
      line = i + 1;
    }
    return line;
  };
  const startLine = lineOf(block.start) - BLOCK_DECLARATION_SLACK;
  const endLine = lineOf(Math.max(block.start, block.end - 1));
  return context.projectMap.apiRoutes.filter((route) => {
    if (route.filePath !== filePath) return false;
    if (route.line >= startLine && route.line <= endLine) return true;
    const range = svelteKitDeclarationRange(content, route.line);
    return range !== undefined && block.start >= range.start && block.end <= range.end;
  });
}

function blockFromKey(key: string): BlockRange | undefined {
  if (key === 'module') return undefined;
  const [start, end] = key.split(':').map((value) => Number(value));
  if (start === undefined || end === undefined) return undefined;
  return { start, end };
}

function guardInBlock(guard: AuthSignal, block: BlockRange | undefined, lineStarts: number[]): boolean {
  if (block === undefined) return false;
  const idx = guard.index ?? lineStarts[guard.line - 1] ?? 0;
  return idx >= block.start && idx <= block.end;
}

function findGuardedImport(context: RuleContext, filePath: string): string | undefined {
  const visited = new Set<string>([filePath]);
  let frontier = directImportsOf(context.projectMap, filePath);
  for (let depth = 0; depth < MAX_IMPORT_DEPTH && frontier.length > 0; depth += 1) {
    const next: string[] = [];
    for (const imported of frontier) {
      if (visited.has(imported)) continue;
      visited.add(imported);
      if (effectiveGuardsInFile(context.projectMap, imported).length > 0) return imported;
      next.push(...directImportsOf(context.projectMap, imported));
    }
    frontier = next;
  }
  return undefined;
}
