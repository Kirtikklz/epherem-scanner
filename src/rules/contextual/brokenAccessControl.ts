import { makeFinding } from '../../shared/findingFactory.js';
import type { Finding, RuleContext, ScanRule } from '../../shared/types.js';
import { findMatches, lineAt } from '../../shared/utils.js';
import { isScannerInternalPath } from '../../input/fileFilters.js';
import { pythonOrmUpdates } from '../../shared/pythonDelete.js';
import { hasStrongAdminAuthorization } from '../../shared/routeAuthorization.js';
import { cascadingControlProven, cascadingGuardsForFile } from '../../shared/cascadingGuard.js';
import { referencesUserInput, windowAround } from '../../shared/userInput.js';
import { analyzeTaint, classifyExpression, type TaintMap } from '../../shared/taint.js';
import { enclosingFunctionScope, enclosingFunctionScopeRange } from '../../shared/handlerScope.js';
import { guardOnlyModules } from '../../shared/handlerGuardCall.js';
import {
  selectionBoundToIdentity,
  verifiedSessionIdentities,
} from '../../shared/importedVerifier.js';
import {
  hasRequestControlledId,
  hasTrustedOwnership,
  parseEqChain,
  parseObjectFilter,
} from '../../shared/ownership.js';
import { modelFromReceiver, modelHasNoOwner } from '../../shared/modelOwnership.js';
import { isUnauthenticatedMutationRoute } from '../../shared/unauthenticatedRoute.js';

const CODE_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py']);

function handlerScopeAt(content: string, line: number): string {
  let offset = 0;
  for (let seen = 1; seen < line; seen += 1) {
    const next = content.indexOf('\n', offset);
    if (next === -1) return '';
    offset = next + 1;
  }
  return enclosingFunctionScope(content, offset);
}

const RECORD_ACCESS =
  /\.(?:findUnique|findFirst|findByPk|findById|findOne|findMany|select|update|updateOne|updateMany|findOneAndUpdate)\s*\(|\.find\s*\(\s*\{/g;

const OWNER_PROPERTY =
  'user_?id|owner_?id|owner|author_?id|account_?id|created_?by|team_?id|member_?id|org(?:anisation|anization)?_?id';
const TRUSTED_IDENTITY =
  "session\\s*[?.]|currentUser|req(?:uest)?\\.user\\b|\\buser\\.id\\b|\\buser\\?\\.id\\b|auth\\s*\\(\\s*\\)|claims\\.|token\\.sub|locals\\.user|ctx\\.state\\.user|\\buid\\b";
const EXPLICIT_OWNERSHIP_GUARD = new RegExp(
  `\\.\\s*(?:${OWNER_PROPERTY})\\b[\\s\\S]{0,50}?(?:===?|!==?)[\\s\\S]{0,50}?(?:${TRUSTED_IDENTITY})` +
    `|(?:${TRUSTED_IDENTITY})[\\s\\S]{0,50}?(?:===?|!==?)[\\s\\S]{0,50}?\\.\\s*(?:${OWNER_PROPERTY})\\b`,
  'i',
);

function callArgs(content: string, openParenIndex: number): string {
  let depth = 0;
  let out = '';
  for (let i = openParenIndex; i < content.length && i < openParenIndex + 400; i += 1) {
    const ch = content[i] ?? '';
    if (ch === '(') { depth += 1; if (depth === 1) continue; }
    if (ch === ')') { depth -= 1; if (depth === 0) break; }
    out += ch;
  }
  return out;
}

function whereRegion(argRegion: string): string {
  const where = /where\s*:\s*\{([\s\S]*?)\}/.exec(argRegion);
  return where?.[1] ?? argRegion;
}

const GUARD_BINDING = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?[A-Za-z_$][\w$.$[\]'"]*$/;

const BINDING_LOOKBACK = 160;

function earlyReturnOnFalsy(scope: string, name: string): boolean {
  const n = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(
    `if\\s*\\([^;{]{0,240}?(?:!\\s*${n}\\b|\\b${n}\\s*===?\\s*(?:null|undefined)\\b)` +
      `[^;{]{0,240}?\\)\\s*(?:\\{[^}]{0,240}?)?\\b(?:return|throw)\\b`,
  ).test(scope);
}

const UNIQUE_KEY = /^_?(?:id|uuid)$/i;

function receiverOf(scope: string, callIndex: number): string {
  let index = callIndex - 1;
  const floor = Math.max(0, callIndex - 80);
  while (index >= floor && /[\w$.'"()[\]]/.test(scope[index] ?? '')) index -= 1;
  return scope.slice(index + 1, callIndex).trim();
}

function guardedModels(scope: string, taint: TaintMap, scopeStart: number): Set<string> {
  const models = new Set<string>();
  for (const load of findMatches(scope, RECORD_ACCESS)) {
    const openParen = scope.indexOf('(', load.index);
    if (openParen === -1) continue;
    const args = callArgs(scope, openParen);
    const pairs = [...parseObjectFilter(whereRegion(args)), ...parseEqChain(args)];
    if (!hasTrustedOwnership(pairs, taint, scopeStart + load.index)) continue;
    const before = scope.slice(Math.max(0, load.index - BINDING_LOOKBACK), load.index);
    const name = GUARD_BINDING.exec(before)?.[1];
    if (name === undefined) continue;
    if (!earlyReturnOnFalsy(scope, name)) continue;
    models.add(receiverOf(scope, load.index));
  }
  return models;
}

function guardCoversSink(
  guards: Set<string>,
  sinkModel: string,
  sinkPairs: readonly { key: string }[],
): boolean {
  if (guards.size === 0) return false;
  if (sinkPairs.some((pair) => UNIQUE_KEY.test(pair.key))) return true;
  return !guards.has(sinkModel);
}


function recordAccessFinding(filePath: string, line: number, evidence: string): Finding {
  return makeFinding({
    ruleId: brokenAccessControl.id,
    title: brokenAccessControl.title,
    severity: 'high',
    confidence: 'medium',
    detectionKind: 'absence',
    filePath,
    lineStart: line,
    evidence,
    userExplanation:
      'This endpoint looks up or changes a record using an id from the request, without confirming the record belongs to the signed-in user. Note that a field like "userId" does not help if its value also comes from the request; an attacker can set it to anyone. Scope the query using the identity from the session/token.',
    technicalExplanation:
      `${filePath}:${line} accesses a record by a request-supplied id. No ownership field is bound to a trusted identity (session/verified token), and no proven admin-authorised route middleware was visible for this handler. Authentication alone is not authorization; scope the query with the server-side user id, e.g. where: { id, userId: session.user.id }.`,
    fixHint:
      'Filter by the authenticated identity taken from the session/verified token, not from the request body/query (e.g. where: { id, userId: session.user.id }), or load the row and verify ownership before returning/updating it. For admin routes, enforce explicit admin middleware.',
    category: brokenAccessControl.category,
  });
}

export const brokenAccessControl: ScanRule = {
  id: 'broken_access_control',
  title: 'Record accessed by id without an ownership check (IDOR)',
  category: 'authorization',
  kind: 'contextual',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const apiFiles = new Set(context.projectMap.apiRoutes.map((route) => route.filePath));

    const pythonJudged = new Map<string, Set<number>>();
    for (const entry of context.fileMap.entries) {
      if (entry.extension !== '.py') continue;
      if (isScannerInternalPath(entry.path, context.projectMap.scannerRootPrefix)) continue;
      const judged = new Set<number>();
      const reported = new Set<number>();
      for (const site of pythonOrmUpdates(context, entry)) {
        judged.add(site.line);
        if (!site.owned) reported.add(site.line);
      }
      pythonJudged.set(entry.path, judged);
      for (const line of [...reported].sort((a, b) => a - b)) {
        findings.push(recordAccessFinding(entry.path, line, lineAt(entry.content, line).trim()));
      }
    }

    for (const entry of context.fileMap.entries) {
      if (!CODE_EXTENSIONS.has(entry.extension)) continue;
      if (!apiFiles.has(entry.path) && !entry.isLikelyApiRoute) continue;
      const taint = analyzeTaint(entry.content);
      const seen = new Set<number>();

      for (const match of findMatches(entry.content, RECORD_ACCESS)) {
        if (seen.has(match.line)) continue;
        if (pythonJudged.get(entry.path)?.has(match.line) === true) continue;
        const openParen = entry.content.indexOf('(', match.index);
        if (openParen === -1) continue;
        const args = callArgs(entry.content, openParen);
        const filterText = whereRegion(args);
        const pairs = [...parseObjectFilter(filterText), ...parseEqChain(args)];

        const byRequestId =
          hasRequestControlledId(pairs, taint, match.index) ||
          (pairs.length === 0 &&
            (classifyExpression(args, taint, match.index) === 'user' || referencesUserInput(args)));
        if (!byRequestId) continue;

        if (hasTrustedOwnership(pairs, taint, match.index)) continue;
        if (hasStrongAdminAuthorization(context, entry.path, match.line)) continue;
        if (cascadingGuardsForFile(context, entry.path).some((guard) => guard.control === 'admin')) continue;
        if (EXPLICIT_OWNERSHIP_GUARD.test(windowAround(entry.content, match.index, 900))) continue;
        const handler = enclosingFunctionScopeRange(entry.content, match.index);
        const handlerText = entry.content.slice(handler.start, handler.end);
        const guards = guardedModels(handlerText, taint, handler.start);
        const receiver = receiverOf(entry.content, match.index);
        if (guardCoversSink(guards, receiver, pairs)) continue;
        if (modelHasNoOwner(context.projectMap, modelFromReceiver(receiver))) continue;
        if (isUnauthenticatedMutationRoute(context.projectMap, entry.path, entry.content, match.index)) continue;
        const identities = verifiedSessionIdentities(context, entry.path, handlerText);
        if (selectionBoundToIdentity(filterText, identities, true)) continue;

        seen.add(match.line);
        findings.push(recordAccessFinding(entry.path, match.line, match.snippet));
      }
    }
    for (const profile of context.projectMap.routeSecurityProfiles ?? []) {
      if (profile.analysisStatus !== 'complete' || profile.authorization.status !== 'absent') continue;
      const routeEntry = context.fileMap.entries.find((candidate) => candidate.path === profile.filePath);
      if (routeEntry !== undefined && hasStrongAdminAuthorization(context, routeEntry.path, profile.line)) continue;
      if (cascadingControlProven(context, {
        filePath: profile.filePath,
        routePath: profile.routePath,
        line: profile.line,
        framework: profile.framework,
        method: profile.method,
      }, 'admin')) continue;
      const guardModules = routeEntry === undefined
        ? []
        : guardOnlyModules(context, routeEntry.path, handlerScopeAt(routeEntry.content, profile.line));
      const importedAccess = profile.databaseOperations.filter((operation) =>
        operation.filePath !== profile.filePath &&
        !guardModules.includes(operation.filePath) &&
        ['select', 'update', 'read', 'write'].includes(operation.kind));
      if (importedAccess.length === 0) continue;
      findings.push(makeFinding({
        ruleId: this.id,
        title: this.title,
        severity: 'high',
        confidence: 'high',
        detectionKind: 'absence',
        filePath: profile.filePath,
        lineStart: profile.line,
        evidence: importedAccess.map((operation) => `${operation.kind} in ${operation.filePath}:${operation.line}`).join('; '),
        userExplanation:
          'This endpoint accesses a record through an imported service using request-controlled data, but no trusted ownership check, admin authorisation, or visible RLS policy protects the operation.',
        technicalExplanation:
          `${profile.method} ${profile.routePath} reaches record access in invoked local helpers. The complete route call graph has request-derived record selection but no ownership constraint bound to a trusted session/token identity and no proven admin-authorised route middleware was visible.`,
        fixHint:
          'Pass the authenticated user id into the repository and include it in the database filter, enforce explicit admin middleware for admin endpoints, or enforce and verify an equivalent RLS policy.',
        category: this.category,
      }));
    }
    return findings;
  },
};
