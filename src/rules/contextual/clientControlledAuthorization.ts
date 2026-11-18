import { directImportsOf, effectiveGuardsInFile } from '../../project-map/buildProjectMap.js';
import { stripCommentsOnly, usesHashComments } from '../../shared/source.js';
import { findMatches, lineAt, lineNumberAt } from '../../shared/utils.js';
import {
  AUTHORIZATION_REJECTION,
  CREDENTIAL_VERIFICATION,
  HEADER_READ,
  PERMISSION_PREDICATE,
  PRINCIPAL_LOOKUP,
  PRIVILEGE_ATTRIBUTE,
  PRIVILEGE_COLUMN_NAME,
  REQUEST_FIELD_READ,
  REQUEST_PAYLOAD_EXPRESSION,
  isPrincipalFieldName,
  isSpoofableIdentityHeader,
} from '../../shared/clientIdentity.js';
import { makeFinding } from '../../shared/findingFactory.js';
import { grantsUnconstrainedPrivilegeColumn, isPolicyCertainlyLive } from '../../project-map/detectRls.js';
import { supabaseRlsUnsettledPolicy, unsettledTableExplanation } from './supabaseRlsUnverifiable.js';
import type { Finding, RuleContext, ScanRule, SupabaseRlsPolicy } from '../../shared/types.js';

const LOOKUP_PROJECTION_WINDOW = 400;
const SOURCE_TO_LOOKUP_WINDOW = 1200;
const MAX_IMPORT_DEPTH = 6;

interface IdentitySite {
  kind: 'header' | 'request_field';
  line: number;
  index: number;
  label: string;
  tokens: string[];
  snippet: string;
}

export const clientControlledAuthorization: ScanRule = {
  id: 'client_controlled_authorization',
  title: 'Authorization decided from a client-controlled identity value',
  category: 'authentication',
  kind: 'contextual',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const clientFiles = new Set(context.projectMap.publicClientUsage);
    const serverFiles = new Set(context.projectMap.serverSideUsage);

    for (const entry of [...context.fileMap.entries].sort((a, b) => a.path.localeCompare(b.path))) {
      if (clientFiles.has(entry.path)) continue;
      if (!entry.isLikelyApiRoute && !serverFiles.has(entry.path)) continue;

      const source = stripCommentsOnly(entry.content, usesHashComments(entry.extension, entry.label));
      const sites = collectIdentitySites(source);
      if (sites.length === 0) continue;

      if (CREDENTIAL_VERIFICATION.test(source)) continue;
      if (effectiveGuardsInFile(context.projectMap, entry.path).length > 0) continue;
      if (hasGuardedImport(context, entry.path)) continue;
      if (!AUTHORIZATION_REJECTION.test(source)) continue;

      const lookups = findMatches(source, PRINCIPAL_LOOKUP);
      if (lookups.length === 0) continue;

      const consumed: IdentitySite[] = [];
      let privilegeEvidence: string | undefined;
      const filePermissionPredicate = PERMISSION_PREDICATE.test(source);

      for (const site of sites) {
        for (const lookup of lookups) {
          if (lookup.index < site.index) continue;
          if (lookup.index - site.index > SOURCE_TO_LOOKUP_WINDOW) continue;
          const projection = source.slice(lookup.index, lookup.index + LOOKUP_PROJECTION_WINDOW);
          if (!site.tokens.some((token) => containsToken(projection, token))) continue;
          const privileged = PRIVILEGE_ATTRIBUTE.exec(projection)?.[0];
          if (privileged === undefined && !filePermissionPredicate) continue;
          privilegeEvidence ??=
            privileged !== undefined
              ? `"${privileged}" read from the looked-up record at line ${lookup.line}`
              : `a permission predicate applied to the looked-up record`;
          consumed.push(site);
          break;
        }
      }
      if (consumed.length === 0) continue;

      const first = consumed[0] as IdentitySite;
      const headerSites = consumed.filter((site) => site.kind === 'header');
      const label = headerSites.length > 0 ? headerSites[0]?.label : first.label;
      const isHeader = headerSites.length > 0;
      const sourcePhrase = isHeader
        ? `the "${label}" request header`
        : `the "${label}" field in the request`;

      findings.push(
        makeFinding({
          ruleId: this.id,
          title: this.title,
          severity: 'high',
          confidence: 'high',
          filePath: entry.path,
          lineStart: first.line,
          lineEnd: (consumed[consumed.length - 1] as IdentitySite).line,
          evidence: consumed
            .map((site) => `${site.kind === 'header' ? 'header' : 'request field'} "${site.label}" @ line ${site.line}: ${site.snippet}`)
            .join('; '),
          userExplanation:
            `This route decides who you are from ${sourcePhrase} — a value the person making ` +
            'the request controls. Anyone can set it to another user\'s ID and act as that ' +
            'person, with that person\'s role and permissions; setting it to an administrator\'s ' +
            'ID grants administrator access. The permission check that follows is not protecting ' +
            'anything, because it is checking the permissions of whoever the caller claimed to be. ' +
            'Identity must come from a verified session — a signed token or a session cookie the ' +
            'server checks — never from a header or a request body field.',
          technicalExplanation:
            `${entry.path} resolves the caller's identity from ${sourcePhrase}, looks the principal ` +
            `record up with that value, and makes an authorization decision from it ` +
            `(${privilegeEvidence ?? 'privilege attribute read from the record'}), ` +
            'while the file contains no effective authentication guard — no checked session lookup, ' +
            'token verification or session-cookie check, in this file or in any module it imports — ' +
            'and no credential verification. The identifier is attacker-chosen, so the lookup returns ' +
            'whichever principal the attacker names and the privilege check evaluates that principal\'s rights.',
          fixHint:
            'Resolve the caller from the verified session at the top of the handler ' +
            '(getServerSession(), supabase.auth.getUser(), Clerk getAuth(req), or jwt.verify on the ' +
            'request token), return 401 when it is absent, and use ONLY that identity for the ' +
            `lookup and the permission check. Delete the ${isHeader ? 'header' : 'request-body field'} ` +
            'as an identity source; if a client genuinely needs to act for another user, authorize ' +
            'that impersonation against the verified caller\'s own privileges first.',
          category: this.category,
          extraFixRequirements: [
            'Do not merely validate the client-supplied identifier — remove it as the source of identity.',
            'Every downstream permission or ownership check must read the session-derived identity, not the request value.',
          ],
        }),
      );
    }

    findings.push(...userWritableRoleFindings(context));
    return findings;
  },
};

function collectIdentitySites(source: string): IdentitySite[] {
  const sites: IdentitySite[] = [];

  for (const match of findMatches(source, HEADER_READ)) {
    const name = match.groups[1];
    if (name === undefined || !isSpoofableIdentityHeader(name)) continue;
    const tokens = declaredNamesOnLine(source, match.index);
    sites.push({
      kind: 'header',
      line: match.line,
      index: match.index,
      label: name.toLowerCase(),
      tokens: tokens.length > 0 ? tokens : [match.matchText],
      snippet: match.snippet.trim().slice(0, 160),
    });
  }

  const payloadVariables = collectPayloadVariables(source);
  for (const match of findMatches(source, DESTRUCTURING_DECLARATION)) {
    const pattern = match.groups[0];
    const initializer = (match.groups[1] ?? '').trim();
    if (pattern === undefined) continue;
    const fromRequest = REQUEST_PAYLOAD_EXPRESSION.test(initializer);
    const fromPayloadVariable = payloadVariables.has(leadingIdentifier(initializer) ?? '');
    if (!fromRequest && !fromPayloadVariable) continue;
    for (const { key, binding } of destructuredBindings(pattern)) {
      if (!isPrincipalFieldName(key)) continue;
      sites.push({
        kind: 'request_field',
        line: match.line,
        index: match.index,
        label: key,
        tokens: [binding],
        snippet: match.snippet.trim().slice(0, 160),
      });
    }
  }

  for (const match of findMatches(source, REQUEST_FIELD_READ)) {
    const name = match.groups[0] ?? match.groups[1];
    if (name === undefined || !isPrincipalFieldName(name)) continue;
    const tokens = declaredNamesOnLine(source, match.index);
    sites.push({
      kind: 'request_field',
      line: match.line,
      index: match.index,
      label: name,
      tokens: tokens.length > 0 ? tokens : [match.matchText],
      snippet: match.snippet.trim().slice(0, 160),
    });
  }

  sites.sort((a, b) => a.index - b.index);
  return dedupeSites(sites);
}

const DESTRUCTURING_DECLARATION = /\b(?:const|let|var)\s+(\{[^{}]{0,400}\})\s*=\s*([^\n;]{0,200})/g;
const SIMPLE_DECLARATION = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^\n;]{0,200})/g;

function collectPayloadVariables(source: string): Set<string> {
  const names = new Set<string>();
  for (const match of findMatches(source, SIMPLE_DECLARATION)) {
    const name = match.groups[0];
    const initializer = match.groups[1] ?? '';
    if (name === undefined) continue;
    if (REQUEST_PAYLOAD_EXPRESSION.test(initializer)) names.add(name);
  }
  return names;
}

function destructuredBindings(pattern: string): { key: string; binding: string }[] {
  const inner = pattern.replace(/^\{/, '').replace(/\}$/, '');
  const result: { key: string; binding: string }[] = [];
  for (const part of inner.split(',')) {
    const trimmed = part.trim();
    if (trimmed === '') continue;
    const renamed = /^([A-Za-z_$][\w$]*)\s*:\s*([A-Za-z_$][\w$]*)/.exec(trimmed);
    if (renamed !== null && renamed[1] !== undefined && renamed[2] !== undefined) {
      result.push({ key: renamed[1], binding: renamed[2] });
      continue;
    }
    const plain = /^([A-Za-z_$][\w$]*)/.exec(trimmed);
    if (plain?.[1] !== undefined) result.push({ key: plain[1], binding: plain[1] });
  }
  return result;
}

function declaredNamesOnLine(source: string, index: number): string[] {
  const line = lineAt(source, lineNumberAt(source, index));
  const simple = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=/.exec(line);
  if (simple?.[1] !== undefined) return [simple[1]];
  const destructured = /\b(?:const|let|var)\s+(\{[^{}]{0,400}\})\s*=/.exec(line);
  if (destructured?.[1] !== undefined) {
    return destructuredBindings(destructured[1]).map((pair) => pair.binding);
  }
  return [];
}

function leadingIdentifier(expression: string): string | undefined {
  return /^\s*([A-Za-z_$][\w$]*)\s*$/.exec(expression)?.[1];
}

function containsToken(haystack: string, token: string): boolean {
  if (/^[A-Za-z_$][\w$]*$/.test(token)) {
    return new RegExp(`(?<![\\w$])${token}(?![\\w$])`).test(haystack);
  }
  return haystack.includes(token);
}

function dedupeSites(sites: IdentitySite[]): IdentitySite[] {
  const seen = new Set<string>();
  const result: IdentitySite[] = [];
  for (const site of sites) {
    const key = `${site.kind}:${site.line}:${site.label}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(site);
  }
  return result;
}

function hasGuardedImport(context: RuleContext, filePath: string): boolean {
  const visited = new Set<string>([filePath]);
  let frontier = directImportsOf(context.projectMap, filePath);
  for (let depth = 0; depth < MAX_IMPORT_DEPTH && frontier.length > 0; depth += 1) {
    const next: string[] = [];
    for (const imported of frontier) {
      if (visited.has(imported)) continue;
      visited.add(imported);
      if (effectiveGuardsInFile(context.projectMap, imported).length > 0) return true;
      next.push(...directImportsOf(context.projectMap, imported));
    }
    frontier = next;
  }
  return false;
}

const DROP_COLUMN =
  /ALTER\s+TABLE\s+(?:ONLY\s+)?(?:IF\s+EXISTS\s+)?([\w."]+)\s+DROP\s+COLUMN\s+(?:IF\s+EXISTS\s+)?"?([\w]+)"?/gi;
const COLUMN_SCOPED_WRITE_GRANT =
  /GRANT\s+([\s\S]{0,300}?)\s+ON\s+(?:TABLE\s+)?([\w."]+)\s+TO\s+([\w",\s]+)/gi;

function userWritableRoleFindings(context: RuleContext): Finding[] {
  const rls = context.projectMap.supabaseRls;
  if (rls.policies.length === 0) return [];
  const droppedColumns = collectDroppedColumns(context);
  const grantedWriteColumns = collectColumnScopedWriteGrants(context);
  const findings: Finding[] = [];

  for (const policy of rls.policies) {
    if (!policy.identityScoped) continue;
    const columns = rls.tableColumns[policy.table] ?? [];
    if (!grantsUnconstrainedPrivilegeColumn(policy, columns)) continue;
    const guard = `${policy.withCheckExpression ?? ''} ${policy.usingExpression ?? ''}`;

    for (const column of columns) {
      if (!PRIVILEGE_COLUMN_NAME.test(column)) continue;
      if (new RegExp(`\\b${escapeRegExp(column)}\\b`, 'i').test(guard)) continue;
      if (droppedColumns.has(`${policy.table}.${column}`)) continue;
      const columnGrant = grantedWriteColumns.get(policy.table);
      if (columnGrant !== undefined && !columnGrant.has(column)) continue;
      const trusting = findTrustingPolicy(rls.policies, policy, policy.table, column);
      if (trusting === undefined) continue;
      const writeVerb = policy.command === 'insert' ? 'create their own row in' : 'write their own row in';
      const unsettledPolicy = [policy, trusting].find((candidate) => !isPolicyCertainlyLive(rls, candidate));

      const finding = makeFinding({
          ruleId: clientControlledAuthorization.id,
          title: clientControlledAuthorization.title,
          severity: 'high',
          confidence: 'medium',
          filePath: policy.filePath,
          lineStart: policy.line,
          evidence:
            `"${policy.table}" ${policy.command.toUpperCase()} policy at ${policy.filePath}:${policy.line} ` +
            `leaves "${column}" unconstrained; "${trusting.table}" policy at ${trusting.filePath}:${trusting.line} ` +
            `grants access based on it`,
          userExplanation: unsettledPolicy !== undefined
            ? unsettledTableExplanation(
                unsettledPolicy.table,
                `A policy in your SQL lets any signed-in user ${writeVerb} "${policy.table}" and set its "${column}" column freely (${policy.filePath}:${policy.line}), and another grants privileged access to anyone whose "${column}" says so (${trusting.filePath}:${trusting.line}).`,
                `If both policies are still live, any account can promote itself in one step, because the key that performs the write ships inside your app.`,
              )
            :
            `Any signed-in user can ${writeVerb} "${policy.table}", and nothing stops them setting ` +
            `the "${column}" column to whatever they like while they do it. A separate database ` +
            `security policy then grants privileged access to anyone whose "${column}" says so. ` +
            'The key that performs this write ships inside your app in the browser, so a user does ' +
            'not need your app to do it — they can send the request themselves. In one step, any ' +
            'account can promote itself and the privilege check will believe it. A permission must ' +
            'never be decided from a value the person it applies to is allowed to set.',
          technicalExplanation:
            `Policy on "${policy.table}" at ${policy.filePath}:${policy.line} governs ` +
            `${policy.command.toUpperCase()} scoped to the caller's own row ` +
            `(${policy.withCheckExpression ?? policy.usingExpression ?? ''}) but places no constraint ` +
            `on "${column}", and no column-scoped GRANT withholds it — so the caller's own payload ` +
            `sets it. The policy on "${trusting.table}" at ${trusting.filePath}:${trusting.line} then ` +
            `reads "${policy.table}"."${column}" to grant access ` +
            `(${trusting.usingExpression ?? trusting.withCheckExpression ?? ''}). The authorization ` +
            'decision is therefore made from a value under the subject\'s own control.',
          fixHint:
            `Constrain "${column}" in the ${policy.command.toUpperCase()} policy on "${policy.table}" ` +
            `(${policy.filePath}:${policy.line}) — e.g. WITH CHECK (auth.uid() = id AND ${column} = ` +
            `(SELECT ${column} FROM ${policy.table} WHERE id = auth.uid())) — or revoke column-level ` +
            `write on it (GRANT UPDATE (col, ...) listing only the safe columns), or move "${column}" ` +
            'into a separate roles table only a service-role process or a trigger may write.',
          category: 'authorization',
          extraFixRequirements: [
            `Do not rely on the application never sending "${column}" — the browser holds the key and can send any payload.`,
          ],
        });
      findings.push(
        unsettledPolicy !== undefined
          ? {
              ...finding,
              adjudication: supabaseRlsUnsettledPolicy(
                `A privilege column "${policy.table}"."${column}" that one policy leaves writable and another trusts`,
                `${policy.filePath}:${policy.line}`,
                unsettledPolicy.table,
              ),
            }
          : finding,
      );
    }
  }
  return findings;
}

function collectDroppedColumns(context: RuleContext): Set<string> {
  const dropped = new Set<string>();
  for (const entry of context.fileMap.entries) {
    if (entry.extension !== '.sql') continue;
    for (const match of findMatches(entry.content, DROP_COLUMN)) {
      const table = normalizeName(match.groups[0]);
      const column = match.groups[1]?.toLowerCase();
      if (table === undefined || column === undefined) continue;
      dropped.add(`${table}.${column}`);
    }
  }
  return dropped;
}

function collectColumnScopedWriteGrants(context: RuleContext): Map<string, Set<string>> {
  const grants = new Map<string, Set<string>>();
  const unrestricted = new Set<string>();
  for (const entry of context.fileMap.entries) {
    if (entry.extension !== '.sql') continue;
    for (const match of findMatches(entry.content, COLUMN_SCOPED_WRITE_GRANT)) {
      const privileges = match.groups[0] ?? '';
      const table = normalizeName(match.groups[1]);
      const grantees = (match.groups[2] ?? '').toLowerCase();
      if (table === undefined) continue;
      if (!/\b(?:authenticated|anon|public)\b/.test(grantees)) continue;
      const writeGrant = /\b(?:UPDATE|INSERT|ALL)\b\s*(\([^)]*\))?/gi;
      let write: RegExpExecArray | null;
      while ((write = writeGrant.exec(privileges)) !== null) {
        const columnList = write[1];
        if (columnList === undefined) {
          unrestricted.add(table);
          continue;
        }
        const columns = grants.get(table) ?? new Set<string>();
        for (const raw of columnList.replace(/[()]/g, '').split(',')) {
          const name = raw.trim().replace(/"/g, '').toLowerCase();
          if (name !== '') columns.add(name);
        }
        grants.set(table, columns);
      }
    }
  }
  for (const table of unrestricted) grants.delete(table);
  return grants;
}

function findTrustingPolicy(
  policies: readonly SupabaseRlsPolicy[],
  writable: SupabaseRlsPolicy,
  table: string,
  column: string,
): SupabaseRlsPolicy | undefined {
  const tablePattern = new RegExp(`\\b${escapeRegExp(table)}\\b`, 'i');
  const columnPattern = new RegExp(`\\b${escapeRegExp(column)}\\b`, 'i');
  for (const policy of policies) {
    if (policy === writable) continue;
    const predicate = `${policy.usingExpression ?? ''} ${policy.withCheckExpression ?? ''}`;
    if (predicate.trim() === '') continue;
    if (tablePattern.test(predicate) && columnPattern.test(predicate)) return policy;
  }
  return undefined;
}

function normalizeName(raw: string | undefined): string | undefined {
  if (raw === undefined) return undefined;
  const parts = raw.replace(/"/g, '').split('.');
  const name = parts[parts.length - 1]?.toLowerCase();
  return name === undefined || name.length === 0 ? undefined : name;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
