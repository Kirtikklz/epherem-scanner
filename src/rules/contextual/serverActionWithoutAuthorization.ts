import { makeFinding } from '../../shared/findingFactory.js';
import type { Finding, RuleContext, ScanRule } from '../../shared/types.js';
import { stripCommentsAndStrings, stripCommentsOnly } from '../../shared/source.js';
import {
  selectionBoundToIdentity,
  statementFrom,
  verifiedSessionIdentities,
} from '../../shared/importedVerifier.js';
import { isCallerBoundCreditWithheldAsUnsettled, isCommandCallerBound } from '../../project-map/detectRls.js';
import { supabaseRlsUnsettledPolicy, unsettledTableExplanation } from './supabaseRlsUnverifiable.js';
import { operationBypassesRls } from '../../shared/rlsBoundClient.js';
import type { RlsPolicyCommand } from '../../shared/types.js';

const CODE_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);

const FILE_USE_SERVER = /^\s*['"]use server['"]\s*;?/m;
const CLIENT_DIRECTIVE = /^\s*['"]use client['"]/m;

const MUTATION_SINK =
  /\bprisma\s*\.\s*\w+\s*\.\s*(?:create|createMany|update|updateMany|upsert)\s*\(|\.\s*(?:insert|update|upsert)\s*\(|\bdb\s*\.\s*(?:insert|update)\s*\(|\b(?:INSERT\s+INTO|UPDATE\s+\w+\s+SET)\b/i;

const MUTATION_SINK_GLOBAL = new RegExp(MUTATION_SINK.source, `${MUTATION_SINK.flags}g`);

const SUPABASE_FROM_TABLE = /\.\s*from\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/g;

function statementBefore(body: string, index: number): string {
  let start = 0;
  for (let i = index - 1; i >= 0 && i > index - 2_000; i -= 1) {
    const ch = body[i];
    if (ch === ';' || ch === '}' || ch === '{') {
      start = i + 1;
      break;
    }
  }
  return body.slice(start, index);
}

const IDENTITY =
  "session\\s*[?.]|currentUser|\\buser\\.id\\b|\\buser\\?\\.id\\b|req(?:uest)?\\.user\\b|auth\\s*\\(\\s*\\)|getServerSession\\s*\\(|claims\\s*[.[]|token\\.sub|locals\\.user|ctx\\.state\\.user|\\.uid\\b|getUserId\\s*\\(";
const OWNER_OR_ID_COLUMN =
  "id|user_?id|owner_?id|owner|account_?id|tenant_?id|team_?id|author_?id|created_?by|member_?id|profile_?id|org(?:anisation|anization)?_?id";
const OWNER_COLUMN_ONLY =
  "user_?id|owner_?id|owner|account_?id|tenant_?id|team_?id|author_?id|created_?by|member_?id|profile_?id|org(?:anisation|anization)?_?id";

const OWNER_CONSTRAINT = new RegExp(
  `\\b(?:${OWNER_OR_ID_COLUMN})\\b\\s*:\\s*[^,}\\n]{0,60}?(?:${IDENTITY})` +
    `|\\.\\s*eq\\s*\\(\\s*['"](?:${OWNER_COLUMN_ONLY})['"]\\s*,\\s*[^)]{0,80}?(?:${IDENTITY})` +
    `|\\beq\\s*\\(\\s*\\w+\\s*\\.\\s*(?:${OWNER_COLUMN_ONLY})\\s*,\\s*[^)]{0,80}?(?:${IDENTITY})`,
  'i',
);

const OWNERSHIP_COMPARISON = new RegExp(
  `\\.\\s*(?:${OWNER_COLUMN_ONLY})\\b[\\s\\S]{0,40}?(?:===?|!==?)[\\s\\S]{0,40}?(?:${IDENTITY})` +
    `|(?:${IDENTITY})[\\s\\S]{0,40}?(?:===?|!==?)[\\s\\S]{0,40}?\\.\\s*(?:${OWNER_COLUMN_ONLY})\\b`,
  'i',
);

const ROLE_GUARD =
  /\b(?:role|roles)\b[^;\n]{0,40}(?:===|!==|==|!=|\.\s*includes|\badmin\b)|\bis_?admin\b|\bhasRole\s*\(|\bhasPermission\s*\(|\bhasAnyRole\s*\(|\bability\b|\.\s*can\s*\(|\bpermissions?\b[^;\n]{0,30}(?:includes|has|===|!==)/i;

const AUTHZ_HELPER =
  /\brequire(?:Role|Permission|Admin|Owner|Ownership|Access)\w*\s*\(|\bassert(?:Owner|Role|Permission|Can|Access|Admin)\w*\s*\(|\bensure(?:Owner|Role|Permission|Admin|Access)\w*\s*\(|\bauthorize\s*\(|\bcheckPermission\s*\(|\bcheckAccess\s*\(|\bcanAccess\s*\(|\bcan(?:Edit|Delete|Update|Modify|Manage|Mutate)\w*\s*\(/i;

const AUTHZ_WRAPPER =
  /=\s*(?:async\s+)?(?:adminAction\w*|withRole\w*|withPermission\w*|withAdmin\w*|authorize\w*|requireRole\w*|requirePermission\w*|requireAdmin\w*|adminProcedure|withOwnership\w*|protectedByRole\w*)\s*\(/i;

function isAuthorized(strippedBody: string, fileContent: string): boolean {
  return (
    OWNER_CONSTRAINT.test(strippedBody) ||
    OWNERSHIP_COMPARISON.test(strippedBody) ||
    ROLE_GUARD.test(strippedBody) ||
    AUTHZ_HELPER.test(strippedBody) ||
    AUTHZ_WRAPPER.test(fileContent)
  );
}

function hasCrossFileOwnerConstraint(
  context: RuleContext,
  filePath: string,
  body: string,
  sinkIndex: number,
): boolean {
  const identities = verifiedSessionIdentities(context, filePath, body);
  if (identities.size === 0) return false;
  return selectionBoundToIdentity(statementFrom(body, sinkIndex), identities);
}

function everyMutationIsCallerBound(
  context: RuleContext,
  fileContent: string,
  action: Action,
  bodyWithStrings: string,
  sinks: readonly RegExpMatchArray[],
): boolean {
  if (sinks.length === 0) return false;
  return sinks.every((sink) => {
    const index = sink.index;
    if (index === undefined) return false;
    if (operationBypassesRls(fileContent, action.bodyStart + index)) return false;
    const command = rlsCommandFor(sink[0] ?? '');
    if (command === undefined) return false;
    const table = supabaseTableFor(bodyWithStrings, index);
    if (table === undefined) return false;
    return isCommandCallerBound(context.projectMap.supabaseRls, table, command);
  });
}

function rlsCommandFor(sinkText: string): Exclude<RlsPolicyCommand, 'all'> | undefined {
  if (/\bprisma\b/i.test(sinkText)) return undefined;
  if (/^\s*\.\s*(?:insert|upsert)\s*\($/i.test(sinkText)) return 'insert';
  if (/^\s*\.\s*update\s*\($/i.test(sinkText)) return 'update';
  return undefined;
}

function supabaseTableFor(body: string, sinkIndex: number): string | undefined {
  const statement = statementBefore(body, sinkIndex);
  let table: string | undefined;
  SUPABASE_FROM_TABLE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = SUPABASE_FROM_TABLE.exec(statement)) !== null) table = match[1];
  return table;
}

function readBlock(
  content: string,
  fromIndex: number,
): { body: string; start: number; end: number } | undefined {
  const open = content.indexOf('{', fromIndex);
  if (open === -1) return undefined;
  let depth = 0;
  for (let i = open; i < content.length && i < open + 20_000; i += 1) {
    const ch = content[i];
    if (ch === '{') depth += 1;
    else if (ch === '}') {
      depth -= 1;
      if (depth === 0) return { body: content.slice(open, i + 1), start: open, end: i + 1 };
    }
  }
  return undefined;
}

interface Action {
  name: string;
  line: number;
  body: string;
  bodyStart: number;
}

const FUNCTION_DEF =
  /(export\s+)?(?:async\s+function\s+([A-Za-z_$][\w$]*)|(?:async\s+)?function\s+([A-Za-z_$][\w$]*))\s*\([^)]*\)|(export\s+)?const\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*(?:[A-Za-z_$][\w$]*\s*\(\s*)?(?:async\s*)?\([^)]*\)\s*(?::[^=>\n]{0,120})?=>/g;

function collectServerActions(content: string): Action[] {
  const fileLevel = FILE_USE_SERVER.test(content) && !CLIENT_DIRECTIVE.test(content);
  const actions: Action[] = [];
  FUNCTION_DEF.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = FUNCTION_DEF.exec(content)) !== null) {
    const exported = match[1] !== undefined || match[4] !== undefined;
    const name = match[2] ?? match[3] ?? match[5] ?? '(anonymous)';
    const header = match[0];
    const block = readBlock(content, match.index + header.length);
    if (block === undefined) continue;
    const inlineAction = /^\s*\{\s*['"]use server['"]/.test(block.body);
    const isAsync = /async/.test(header);
    if (!((fileLevel && exported && isAsync) || inlineAction)) continue;
    const line = content.slice(0, match.index).split('\n').length;
    actions.push({ name, line, body: block.body, bodyStart: block.start });
  }
  return actions;
}

export const serverActionWithoutAuthorization: ScanRule = {
  id: 'server_action_without_authorization',
  title: 'Server action mutates data without an authorization check',
  category: 'authorization',
  kind: 'contextual',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    for (const entry of context.fileMap.entries) {
      if (!CODE_EXTENSIONS.has(entry.extension)) continue;
      if (!/['"]use server['"]/.test(entry.content)) continue;
      const actions = collectServerActions(entry.content);
      if (actions.length === 0) continue;

      for (const action of actions) {
        const bodyNoStrings = stripCommentsAndStrings(action.body);
        const sinks = [...bodyNoStrings.matchAll(MUTATION_SINK_GLOBAL)];
        const sink = sinks[0];
        if (sink === undefined || sink.index === undefined) continue;
        const bodyNoComments = stripCommentsOnly(action.body);
        if (isAuthorized(bodyNoComments, entry.content)) continue;
        if (hasCrossFileOwnerConstraint(context, entry.path, bodyNoComments, sink.index)) continue;
        if (everyMutationIsCallerBound(context, entry.content, action, bodyNoComments, sinks)) continue;
        const unsettledTables = tablesWithheldAsUnsettled(context, entry.content, action, bodyNoComments, sinks);

        const finding = makeFinding({
            ruleId: this.id,
            title: this.title,
            severity: 'high',
            confidence: 'medium',
            detectionKind: 'absence',
            filePath: entry.path,
            lineStart: action.line,
            evidence: `export ${action.name} mutates a record with no ownership or role authorization`,
            userExplanation: unsettledTables !== undefined
              ? unsettledTableExplanation(
                  unsettledTables.join('", "'),
                  'This server action creates or changes data without itself confirming the caller may do so. The database may do it instead: the row-level security policies in your SQL would tie each row to its owner.',
                  'If the live policies still do that, this finding is already handled and you can close it. If not, any logged-in user may be able to change data that is not theirs.',
                )
              :
              'This server action creates or changes data, but it never confirms the caller is allowed to. Checking that someone is logged in is not enough: if the record, or who it belongs to, comes from the caller\'s input, any logged-in user could change someone else\'s data. Server actions are callable from the browser like an API endpoint, so being in a server file does not protect them. Scope the change to the signed-in user (e.g. include their id in the where filter) or require the right role.',
            technicalExplanation:
              `${entry.path}:${action.line} exports the server action "${action.name}", which performs a create/update/upsert but contains no AUTHORIZATION — no ownership constraint binding the row to the authenticated identity, no ownership comparison, no role/permission guard, and no invoked authorization helper/wrapper. Authentication (a session lookup) is not authorization; a 'use server' directive marks the execution boundary, not an access-control boundary.`,
            fixHint:
              'Bind the mutation to the authenticated user — e.g. where: { id, userId: session.user.id } — or load the row and verify ownership (if (row.userId !== session.user.id) throw) before mutating, or enforce a role guard (requireRole(\'admin\')). A bare session check does not authorize a mutation against an attacker-selectable id.',
            category: this.category,
          });
        findings.push(
          unsettledTables !== undefined
            ? {
                ...finding,
                adjudication: supabaseRlsUnsettledPolicy(
                  `Server action ${action.name}, whose Supabase writes are caller-bound only by policies the SQL does not settle`,
                  `${entry.path}:${action.line}`,
                  unsettledTables.join('", "'),
                ),
              }
            : finding,
        );
      }
    }
    return findings;
  },
};

function tablesWithheldAsUnsettled(
  context: RuleContext,
  fileContent: string,
  action: Action,
  bodyWithStrings: string,
  sinks: readonly RegExpMatchArray[],
): string[] | undefined {
  if (sinks.length === 0) return undefined;
  const withheld = new Set<string>();
  for (const sink of sinks) {
    const index = sink.index;
    if (index === undefined) return undefined;
    if (operationBypassesRls(fileContent, action.bodyStart + index)) return undefined;
    const command = rlsCommandFor(sink[0] ?? '');
    if (command === undefined) return undefined;
    const table = supabaseTableFor(bodyWithStrings, index);
    if (table === undefined) return undefined;
    const rls = context.projectMap.supabaseRls;
    if (isCallerBoundCreditWithheldAsUnsettled(rls, table, command)) withheld.add(table.toLowerCase());
    else if (!isCommandCallerBound(rls, table, command)) return undefined;
  }
  return withheld.size > 0 ? [...withheld].sort() : undefined;
}
