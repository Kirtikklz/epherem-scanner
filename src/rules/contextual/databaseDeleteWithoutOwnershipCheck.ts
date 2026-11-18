import { isScannerInternalPath } from '../../input/fileFilters.js';
import { pythonUnreachableFromRequests } from '../../shared/pythonReach.js';
import { pythonOrmDeletes } from '../../shared/pythonDelete.js';
import { pythonFileNoRequestRuns } from '../../shared/pythonNoRequest.js';
import { pythonSqlTakesNothingFromOutside } from '../../shared/pythonSql.js';
import { makeFinding } from '../../shared/findingFactory.js';
import type { Finding, RuleContext, ScanRule } from '../../shared/types.js';
import { findMatches, isInsideStringLiteral, lineAt } from '../../shared/utils.js';
import { analyzeTaint, classifyExpression, type TaintMap } from '../../shared/taint.js';
import { enclosingFunctionScope } from '../../shared/handlerScope.js';
import {
  isCommandCallerBound,
  isCommandDefaultDenied,
  isCommandIdentityScoped,
} from '../../project-map/detectRls.js';
import { operationBypassesRls } from '../../shared/rlsBoundClient.js';
import {
  isRlsUnsettledFromSource,
  isRlsUnverifiableFromSource,
  supabaseRlsUnsettledPolicy,
  supabaseRlsUnverifiablePolicy,
  unsettledCommandExplanation,
  verifyInDashboardExplanation,
} from './supabaseRlsUnverifiable.js';
import {
  hasTrustedOwnership,
  parseEqChain,
  parseObjectFilter,
} from '../../shared/ownership.js';
import { modelHasNoOwner } from '../../shared/modelOwnership.js';
import { isUnauthenticatedMutationRoute } from '../../shared/unauthenticatedRoute.js';

const SUPABASE_DELETE_CHAIN = /\.\s*delete\s*\(\s*\)[\s\S]{0,200}?(?=;|\n\s*\n|$)/g;
const SUPABASE_FROM_TABLE = /\.\s*from\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/g;
const CHAIN_OWNER_COLUMN = /^(user_?id|owner_?id|owner|account_?id|tenant_?id|author_?id|created_?by|host_?id|member_?id|profile_?id|org_?id|organization_?id|uid)$/i;
const IDENTITY_VALUE = /(?:^|[.?\]])\s*(id|uid|sub|user_?id|userId)\s*$/i;
const PRISMA_DELETE = /prisma\.(\w+)\.delete(?:Many)?\s*\(\s*\{[\s\S]{0,300}?\}\s*\)/g;
const RAW_SQL_DELETE = /DELETE\s+FROM\s+([\w."`]+)\s+WHERE\s+([^;`'\"\n]{1,200})/gi;
const CODE_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py']);

const OWNERSHIP_BUILDER =
  /\b(?:buildTeamWhereQuery|getEnvelopeWhereInput|canAccess\w*|getTeamById|getMemberRoles|require(?:Team|Owner|Access|Permission|Role|Member|Auth)\w*|assert(?:Team|Owner|Access|Permission|Role)\w*|build\w*WhereQuery|get\w+ById)\s*\(/;
const PRIVILEGED_PROCEDURE = /\b(?:admin|superAdmin|super_admin|root)\w*Procedure\b/i;
const OWNERSHIP_COLUMN_SOURCE =
  'user_?id|owner_?id|account_?id|tenant_?id|team_?id|author_?id|created_?by|host_?id|member_?id|profile_?id|org(?:anisation|anization)?_?id|group_?id|workspace_?id';
const OWNERSHIP_KV = new RegExp(`\\b(?:${OWNERSHIP_COLUMN_SOURCE})\\b\\s*:\\s*([^,}\\n]{1,100})`, 'gi');
const OWNERSHIP_SHORTHAND = new RegExp(`[{,]\\s*(${OWNERSHIP_COLUMN_SOURCE})\\s*[,}]`, 'gi');

const CAPABILITY_TABLE =
  /session|token|verification|passkey|credential|challenge|otp|reset|magic|apikey|api_?token|invite|refresh/i;
const CAPABILITY_CONTEXT =
  /\b(?:getOptionalSession|getSession|validateSession|verifyToken|verify\w*Token|sessionToken|hashToken|createHash|sha256|expiresAt|isAuthenticated|params\.token|query\.token|req(?:uest)?\.(?:cookies|headers|signedCookies))\b/;
// Deleting by an unguessable token: holding the token is the authorization.
const CAPABILITY_KEY_COLUMN = /\b(?:token|code|otp|secret|hash|nonce|challenge|magic_?link)\b\s*[,:}]/i;

// Seeds and migrations are run by the operator, not by users.
const NON_APP_DIR = /(^|\/)(seeds?|migrations?|__seeds__)(\/)/i;
const NON_APP_FILE = /(^|\/)(seed|seeds)\.[cm]?[jt]sx?$|\.seed\.[cm]?[jt]sx?$/i;

const RULE_ID = 'database_delete_without_ownership_check';
const RULE_TITLE = 'Delete operation without ownership check';
const RULE_CATEGORY = 'authorization' as const;

export const SERVICE_ROLE_DELETE_EXPLANATION =
  'A row is deleted using the Supabase service-role key, which ignores Row Level Security, so no database policy can stop this delete. Only the code can: confirm the row belongs to the signed-in user before deleting it, or run the delete with the user\'s own client so your policies apply.';

function ownershipFinding(
  filePath: string,
  line: number,
  evidence: string,
  userExplanation: string,
  technicalExplanation: string,
): Finding {
  return makeFinding({
    ruleId: RULE_ID,
    title: RULE_TITLE,
    severity: 'high',
    confidence: 'medium',
    detectionKind: 'absence',
    filePath,
    lineStart: line,
    evidence,
    userExplanation,
    technicalExplanation,
    fixHint:
      'Verify the session first, then scope the delete by the trusted user id (e.g. .eq("user_id", session.user.id), where: { id, userId: session.user.id }, or AND user_id = $trustedUserId) so users can only delete rows they own.',
    category: RULE_CATEGORY,
  });
}

function sqlOwnershipIsTrusted(whereClause: string, statementScope: string): boolean {
  const namesOwnershipColumn = /\b(user_?id|owner_?id|owner|account_?id|tenant_?id|author_?id|created_?by|member_?id)\b/i.test(
    whereClause,
  );
  if (!namesOwnershipColumn) return false;
  // An owner column bound to request data is not proof of ownership.
  const requestBound = /\breq(?:uest)?\.(?:body|query|params|headers|cookies)\b/.test(statementScope);
  return !requestBound;
}

function tableForChain(content: string, chainIndex: number): string | undefined {
  const windowStart = Math.max(0, chainIndex - 600);
  const preceding = content.slice(windowStart, chainIndex);
  let table: string | undefined;
  SUPABASE_FROM_TABLE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = SUPABASE_FROM_TABLE.exec(preceding)) !== null) {
    table = match[1];
  }
  return table;
}

function scopeEstablishesOwnership(scope: string, taint: TaintMap, at: number): boolean {
  if (PRIVILEGED_PROCEDURE.test(scope)) return true;
  if (OWNERSHIP_BUILDER.test(scope)) return true;
  for (const match of scope.matchAll(OWNERSHIP_KV)) {
    if (classifyExpression(match[1] ?? '', taint, at) !== 'user') return true;
  }
  for (const match of scope.matchAll(OWNERSHIP_SHORTHAND)) {
    if (classifyExpression(match[1] ?? '', taint, at) !== 'user') return true;
  }
  return false;
}

function isCapabilityTokenDelete(model: string, scope: string, whereText: string): boolean {
  if (!CAPABILITY_TABLE.test(model)) return false;
  return CAPABILITY_CONTEXT.test(scope) || CAPABILITY_KEY_COLUMN.test(whereText);
}

export const databaseDeleteWithoutOwnershipCheck: ScanRule = {
  id: RULE_ID,
  title: RULE_TITLE,
  category: RULE_CATEGORY,
  kind: 'contextual',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const routeAttributedDeleteFiles = new Set(
      (context.projectMap.routeSecurityProfiles ?? []).flatMap((profile) =>
        profile.databaseOperations
          .filter((operation) => operation.kind === 'delete' && operation.filePath !== profile.filePath)
          .map((operation) => operation.filePath)),
    );
    const deleteFiles = new Set(
      context.projectMap.databaseCalls
        .filter((call) => call.kind === 'delete' || call.kind === 'raw_sql')
        .map((call) => call.filePath),
    );

    const pythonJudged = new Map<string, Set<number>>();
    for (const entry of context.fileMap.entries) {
      if (entry.extension !== '.py') continue;
      if (NON_APP_DIR.test(entry.path) || isScannerInternalPath(entry.path, context.projectMap.scannerRootPrefix)) continue;
      if (pythonFileNoRequestRuns(context, entry)) continue;
      for (const site of pythonOrmDeletes(context, entry)) {
        const judged = pythonJudged.get(entry.path) ?? new Set<number>();
        judged.add(site.line);
        pythonJudged.set(entry.path, judged);
        if (site.owned) continue;
        findings.push(ownershipFinding(entry.path, site.line, lineAt(entry.content, site.line).trim(),
          'A record is deleted by id alone (or with a request-controlled owner field), without confirming the requester truly owns it. Include the current user\'s trusted id in the where clause.',
          `Python ORM delete at ${entry.path}:${site.line} has no ownership field bound to a trusted identity. Use a compound where (id + session user id) or verify ownership before deleting.`));
      }
    }

    for (const entry of context.fileMap.entries) {
      if (!deleteFiles.has(entry.path)) continue;
      if (routeAttributedDeleteFiles.has(entry.path)) continue;
      if (!CODE_EXTENSIONS.has(entry.extension)) continue;
      if (NON_APP_DIR.test(entry.path) || NON_APP_FILE.test(entry.path)) continue;
      if (isScannerInternalPath(entry.path, context.projectMap.scannerRootPrefix)) continue;
      if (entry.extension === '.py' && pythonFileNoRequestRuns(context, entry)) continue;
      const taint: TaintMap = analyzeTaint(entry.content);
      const unreached = (line: number): boolean =>
        entry.extension === '.py' && pythonUnreachableFromRequests(context, entry.path, entry.content, line);

      for (const match of findMatches(entry.content, SUPABASE_DELETE_CHAIN)) {
        if (isInsideStringLiteral(entry.content, match.index)) continue;
        if (unreached(match.line)) continue;
        if (pythonJudged.get(entry.path)?.has(match.line) === true) continue;
        const chain = match.matchText;
        if (!/\.eq\s*\(/.test(chain)) continue;
        const pairs = parseEqChain(chain);
        if (hasTrustedOwnership(pairs, taint, match.index)) continue;
        if (
          pairs.some(
            (pair) =>
              classifyExpression(pair.value, taint, match.index) === 'trusted' &&
              (CHAIN_OWNER_COLUMN.test(pair.key) || IDENTITY_VALUE.test(pair.value)),
          )
        ) {
          continue;
        }
        const chainTable = tableForChain(entry.content, match.index);
        if (isCommandIdentityScoped(context.projectMap.supabaseRls, chainTable, 'delete')) {
          continue;
        }
        if (isCommandDefaultDenied(context.projectMap.supabaseRls, chainTable, 'delete')) {
          continue;
        }
        if (
          !operationBypassesRls(entry.content, match.index) &&
          isCommandCallerBound(context.projectMap.supabaseRls, chainTable, 'delete')
        ) {
          continue;
        }
        if (modelHasNoOwner(context.projectMap, chainTable)) continue;
        if (isUnauthenticatedMutationRoute(context.projectMap, entry.path, entry.content, match.index)) continue;
        if (
          operationBypassesRls(entry.content, match.index) &&
          (isRlsUnsettledFromSource(context.projectMap.supabaseRls, chainTable) ||
            isRlsUnverifiableFromSource(context.projectMap.supabaseRls, chainTable))
        ) {
          const table = chainTable as string;
          findings.push(ownershipFinding(entry.path, match.line, match.snippet,
            SERVICE_ROLE_DELETE_EXPLANATION,
            `Supabase .delete() chain at ${entry.path}:${match.line} runs on a client holding BYPASSRLS (the service-role key) and has no ownership filter bound to a trusted identity, so any committed or dashboard Row Level Security policy on "${table}" is irrelevant to it: Postgres does not consult policies for this client.`));
          continue;
        }
        if (isRlsUnsettledFromSource(context.projectMap.supabaseRls, chainTable)) {
          const table = chainTable as string;
          findings.push({
            ...ownershipFinding(entry.path, match.line, match.snippet,
              unsettledCommandExplanation(
                table,
                'delete',
                `A row is deleted from "${table}" without the delete itself confirming the row belongs to the signed-in user.`,
              ),
              `Supabase .delete() chain at ${entry.path}:${match.line} has no ownership filter bound to a trusted identity, and "${table}" is in the scan's uncertain tables: a statement that changes its row-level security has no knowable order, so whether a live DELETE policy scopes this table to auth.uid() cannot be determined from the committed source.`),
            adjudication: supabaseRlsUnsettledPolicy(
              `A client-side Supabase delete on "${table}" with no ownership filter`,
              `${entry.path}:${match.line}`,
              table,
            ),
          });
          continue;
        }
        if (isRlsUnverifiableFromSource(context.projectMap.supabaseRls, chainTable)) {
          const table = chainTable as string;
          findings.push({
            ...ownershipFinding(entry.path, match.line, match.snippet,
              verifyInDashboardExplanation(
                table,
                'delete',
                `A row is deleted from "${table}" without the delete itself confirming the row belongs to the signed-in user.`,
              ),
              `Supabase .delete() chain at ${entry.path}:${match.line} has no ownership filter bound to a trusted identity, and no CREATE POLICY naming "${table}" exists in the project's ${context.projectMap.supabaseRls.sqlFileCount} SQL file(s). Whether a DELETE policy scopes this table to auth.uid() cannot be determined from the committed source.`),
            adjudication: supabaseRlsUnverifiablePolicy(
              `A client-side Supabase delete on "${table}" with no ownership filter`,
              `${entry.path}:${match.line}`,
              table,
            ),
          });
          continue;
        }
        findings.push(ownershipFinding(entry.path, match.line, match.snippet,
          'A row is deleted without confirming it belongs to the signed-in user. A "user_id" filter does not help if its value comes from the request. Scope the delete using the session/token identity.',
          `Supabase .delete() chain at ${entry.path}:${match.line} has no ownership filter bound to a trusted identity. Add .eq("user_id", session.user.id) or enforce RLS delete policies.`));
      }

      for (const match of findMatches(entry.content, PRISMA_DELETE)) {
        if (isInsideStringLiteral(entry.content, match.index)) continue;
        if (unreached(match.line)) continue;
        const call = match.matchText;
        if (!/where/i.test(call)) continue;
        const pairs = parseObjectFilter(call);
        if (hasTrustedOwnership(pairs, taint, match.index)) continue;
        const scope = enclosingFunctionScope(entry.content, match.index);
        if (scopeEstablishesOwnership(scope, taint, match.index)) continue;
        if (isCapabilityTokenDelete(match.groups[0] ?? '', scope, call)) continue;
        if (modelHasNoOwner(context.projectMap, match.groups[0])) continue;
        if (isUnauthenticatedMutationRoute(context.projectMap, entry.path, entry.content, match.index)) continue;
        findings.push(ownershipFinding(entry.path, match.line, match.snippet,
          'A record is deleted by id alone (or with a request-controlled owner field), without confirming the requester truly owns it. Include the current user\'s trusted id in the where clause.',
          `Prisma delete at ${entry.path}:${match.line} has no ownership field bound to a trusted identity. Use a compound where (id + session user id) or verify ownership before deleting.`));
      }

      for (const match of findMatches(entry.content, RAW_SQL_DELETE)) {
        const sqlTable = match.groups[0];
        const whereClause = match.groups[1] ?? '';
        const statementScope = entry.content.slice(Math.max(0, match.index - 40), match.index + 220);
        if (sqlOwnershipIsTrusted(whereClause, statementScope)) continue;
        if (unreached(match.line)) continue;
        if (entry.extension === '.py' && pythonSqlTakesNothingFromOutside(entry.content, match.index)) continue;
        if (modelHasNoOwner(context.projectMap, sqlTable)) continue;
        if (isUnauthenticatedMutationRoute(context.projectMap, entry.path, entry.content, match.index)) continue;
        findings.push(ownershipFinding(entry.path, match.line, match.snippet,
          'A SQL DELETE removes rows without a trusted ownership check. Add the signed-in user to the WHERE clause using a server-side identity so users can only delete their own records.',
          `Raw SQL DELETE at ${entry.path}:${match.line} filters on "${whereClause.trim()}" with no ownership column bound to a trusted identity. Append e.g. AND user_id = $trustedUserId.`));
      }
    }
    for (const profile of context.projectMap.routeSecurityProfiles ?? []) {
      if (profile.analysisStatus !== 'complete' || profile.authorization.status !== 'absent') continue;
      const importedDeletes = profile.databaseOperations.filter(
        (operation) => operation.filePath !== profile.filePath && operation.kind === 'delete');
      if (importedDeletes.length === 0) continue;
      const first = importedDeletes[0];
      if (first === undefined) continue;
      findings.push(ownershipFinding(
        profile.filePath,
        profile.line,
        importedDeletes.map((operation) => `delete in ${operation.filePath}:${operation.line}`).join('; '),
        'This endpoint deletes a record through an imported service without proving that the signed-in user owns it.',
        `${profile.method} ${profile.routePath} reaches a delete in invoked local helpers, but its complete route call graph has no trusted ownership constraint or visible RLS policy.`,
      ));
    }
    return findings;
  },
};
