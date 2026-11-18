import type { FileMap, SupabaseRlsInfo, SupabaseRlsPolicy, RlsPolicyCommand } from '../shared/types.js';
import { findMatches } from '../shared/utils.js';
import { expandDynamicRlsStatements, findPolicySweeps } from './dynamicRlsSql.js';
import { bindsOnEveryBranch, evaluatePredicate, type RlsCaller } from './rlsPredicate.js';

const ENABLE_RLS = /ALTER\s+TABLE\s+(?:ONLY\s+)?(?:IF\s+EXISTS\s+)?([\w."]+)\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY/gi;
const DISABLE_RLS = /ALTER\s+TABLE\s+(?:ONLY\s+)?(?:IF\s+EXISTS\s+)?([\w."]+)\s+DISABLE\s+ROW\s+LEVEL\s+SECURITY/gi;

const CREATE_POLICY_STATEMENT = /CREATE\s+POLICY\s+([\s\S]{0,2000}?);/gi;

const POLICY_NAME = String.raw`("(?:[^"]|"")+"|[A-Za-z_][\w$]*)`;

const DROP_POLICY = new RegExp(String.raw`DROP\s+POLICY\s+(?:IF\s+EXISTS\s+)?${POLICY_NAME}\s+ON\s+([\w."]+)`, 'gi');

const DROP_TABLE =
  /(?<!PUBLICATION\s+[\w."]+\s+)\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?([\w."]+(?:\s*,\s*[\w."]+)*)/gi;

const ALTER_POLICY = new RegExp(String.raw`ALTER\s+POLICY\s+${POLICY_NAME}\s+ON\s+([\w."]+)`, 'gi');

const RLS_STATEMENT_KEYWORD =
  /\b(?:(?:EN|DIS)ABLE\s+ROW\s+LEVEL\s+SECURITY|(?:CREATE|DROP|ALTER)\s+POLICY\b(?=[^;]{0,300}?\bON\b))/gi;

const CREATE_TABLE_STATEMENT =
  /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([\w."]+)\s*\(([\s\S]{0,8000}?)\)\s*;/gi;
const ALTER_ADD_COLUMN =
  /ALTER\s+TABLE\s+(?:ONLY\s+)?(?:IF\s+EXISTS\s+)?([\w."]+)\s+ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?"?([\w]+)"?/gi;

const COMMANDS: readonly RlsPolicyCommand[] = ['all', 'select', 'insert', 'update', 'delete'];

const IDENTITY_EXPRESSION = /\bauth\s*\.\s*(?:uid|jwt|role)\s*\(\s*\)|current_setting\s*\(\s*'request\.jwt/i;

const CALLER_IDENTITY_BINDING =
  /\bauth\s*\.\s*(?:uid|jwt)\s*\(\s*\)|current_setting\s*\(\s*'request\.jwt/i;
const JWT_ROLE_CLAIM_SETTING = /current_setting\s*\(\s*'request\.jwt\.claims?\.role'\s*\)/gi;

const SQL_FUNCTION_DEFINITION =
  /CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+([\w."]+)\s*\([\s\S]{0,2000}?\bAS\s+(\$[A-Za-z_]*\$)([\s\S]{0,8000}?)\2/gi;

const SQL_FUNCTION_CALL = /\b([A-Za-z_][\w.$"]*)\s*\(/g;

const MEMBERSHIP_HELPER_NAME =
  /^(?:is|has|can|check|user_is|user_has|current_user_is|current|active|requesting|auth)_[a-z0-9_]*(?:member|membership|org|organisation|organization|tenant|team|workspace|project|account|group|company|role|admin|owner|ownership|access|permission)[a-z0-9_]*$/i;

const UNRESTRICTED_EXPRESSION = /^[\s(]*true[\s)]*$/i;

const POLICY_ROLES = /\bTO\s+((?:"?[\w$]+"?\s*,\s*)*"?[\w$]+"?)\s*(?=USING\b|WITH\s+CHECK\b|\s*$)/i;

const DEFAULT_POLICY_ROLES = ['public'];

const ANONYMOUS_ROLES = new Set(['public', 'anon']);
const AUTHENTICATED_ROLES = new Set(['public', 'authenticated']);

function policyAppliesTo(roles: readonly string[], caller: RlsCaller): boolean {
  const grantable = caller === 'anonymous' ? ANONYMOUS_ROLES : AUTHENTICATED_ROLES;
  return roles.some((role) => grantable.has(role));
}

const PRIVILEGE_COLUMN =
  /^(role|roles|is_admin|isadmin|admin|is_superuser|is_staff|permissions?|scopes?|privileges?|access_level|user_type|account_type)$/i;

export function detectSupabaseRls(fileMap: FileMap): SupabaseRlsInfo {
  const columnsByTable = new Map<string, Set<string>>();
  const committedFunctions = new Set<string>();
  const identityBoundFunctions = new Set<string>();
  const events: RlsEvent[] = [];
  const unreadRlsStatements: { filePath: string; line: number }[] = [];
  const rollbackFilesNotApplied: string[] = [];
  let sqlFileCount = 0;
  let unparsedPolicyCount = 0;

  const sqlEntries = fileMap.entries.filter((entry) => entry.extension === '.sql');
  const positionOf = migrationPositions(sqlEntries.map((entry) => entry.path));

  for (const entry of sqlEntries) {
    sqlFileCount += 1;
    const place = positionOf(entry.path);
    const at = (offset: number): SqlPosition => ({ ...place, offset });
    for (const match of findMatches(entry.content, CREATE_TABLE_STATEMENT)) {
      const table = normalizeTableName(match.groups[0]);
      if (table === undefined) continue;
      const columns = columnsByTable.get(table) ?? new Set<string>();
      for (const column of parseColumnNames(match.groups[1] ?? '')) columns.add(column);
      columnsByTable.set(table, columns);
    }
    for (const match of findMatches(entry.content, ALTER_ADD_COLUMN)) {
      const table = normalizeTableName(match.groups[0]);
      const column = match.groups[1]?.toLowerCase();
      if (table === undefined || column === undefined) continue;
      const columns = columnsByTable.get(table) ?? new Set<string>();
      columns.add(column);
      columnsByTable.set(table, columns);
    }
    const functionBodies: [number, number][] = [];
    for (const match of findMatches(entry.content, SQL_FUNCTION_DEFINITION)) {
      functionBodies.push([match.index, match.index + match.matchText.length]);
      const name = bareFunctionName(match.groups[0]);
      if (name === undefined) continue;
      committedFunctions.add(name);
      if (bodyBindsToCallerIdentity(match.groups[2] ?? '')) identityBoundFunctions.add(name);
    }
    const inFunction = (offset: number): boolean =>
      functionBodies.some(([start, end]) => offset >= start && offset < end);
    if (!place.applied) {
      rollbackFilesNotApplied.push(entry.path);
      continue;
    }
    const comments = commentSpans(entry.content);
    const inComment = (offset: number): boolean =>
      comments.some(([start, end]) => offset >= start && offset < end);

    const dynamic = expandDynamicRlsStatements(entry.content);
    const insideTemplate = (index: number): boolean =>
      dynamic.some((statement) => index >= statement.templateStart && index < statement.templateEnd);
    const read: [number, number][] = [];

    for (const match of findMatches(entry.content, ENABLE_RLS)) {
      const table = normalizeTableName(match.groups[0]);
      if (table === undefined) continue;
      read.push([match.index, match.index + match.matchText.length]);
      events.push({ kind: 'enable', table, position: at(match.index), inFunction: inFunction(match.index) });
    }
    for (const match of findMatches(entry.content, DISABLE_RLS)) {
      const table = normalizeTableName(match.groups[0]);
      if (table === undefined) continue;
      read.push([match.index, match.index + match.matchText.length]);
      events.push({ kind: 'disable', table, position: at(match.index), inFunction: inFunction(match.index) });
    }
    const createScan = blankInComments(entry.content, /CREATE\s+POLICY/gi, inComment);
    for (const match of findMatches(createScan, CREATE_POLICY_STATEMENT)) {
      if (insideTemplate(match.index)) continue;
      const bodyEnd = match.index + match.matchText.length - 1;
      const body = entry.content.slice(bodyEnd - (match.groups[0] ?? '').length, bodyEnd);
      const parsed = parsePolicy(body, entry.path, match.line);
      const name = readPolicyName(body)?.name;
      if (parsed === undefined || name === undefined) {
        unparsedPolicyCount += 1;
        continue;
      }
      read.push([match.index, match.index + match.matchText.length]);
      events.push({ kind: 'create', table: parsed.table, name, policy: parsed, position: at(match.index), inFunction: inFunction(match.index) });
    }
    for (const match of findMatches(entry.content, DROP_POLICY)) {
      if (inComment(match.index) || insideTemplate(match.index)) continue;
      const table = normalizeTableName(match.groups[1]);
      const name = normalizePolicyName(match.groups[0]);
      if (table === undefined || name === undefined) continue;
      read.push([match.index, match.index + match.matchText.length]);
      events.push({ kind: 'drop-policy', table, name, position: at(match.index), inFunction: inFunction(match.index) });
    }
    for (const match of findMatches(entry.content, DROP_TABLE)) {
      if (inComment(match.index) || insideTemplate(match.index)) continue;
      for (const raw of (match.groups[0] ?? '').split(',')) {
        const table = normalizeTableName(raw.trim());
        if (table === undefined) continue;
        events.push({ kind: 'drop-table', table, position: at(match.index), inFunction: inFunction(match.index) });
      }
    }
    for (const match of findMatches(entry.content, ALTER_POLICY)) {
      if (inComment(match.index) || insideTemplate(match.index)) continue;
      const table = normalizeTableName(match.groups[1]);
      const name = normalizePolicyName(match.groups[0]);
      if (table === undefined || name === undefined) continue;
      read.push([match.index, match.index + match.matchText.length]);
      events.push({ kind: 'alter-policy', table, name, position: at(match.index), inFunction: inFunction(match.index) });
    }

    for (const statement of dynamic) {
      const position = (index: number): SqlPosition => at(statement.templateStart + index / (statement.sql.length + 1));
      const loopInFunction = inFunction(statement.templateStart);
      for (const match of findMatches(statement.sql, ENABLE_RLS)) {
        const table = normalizeTableName(match.groups[0]);
        if (table !== undefined) events.push({ kind: 'enable', table, position: position(match.index), inFunction: loopInFunction });
      }
      for (const match of findMatches(statement.sql, DISABLE_RLS)) {
        const table = normalizeTableName(match.groups[0]);
        if (table !== undefined) events.push({ kind: 'disable', table, position: position(match.index), inFunction: loopInFunction });
      }
      for (const match of findMatches(statement.sql, CREATE_POLICY_STATEMENT)) {
        const parsed = parsePolicy(match.groups[0] ?? '', entry.path, statement.line);
        const name = readPolicyName(match.groups[0] ?? '')?.name;
        if (parsed === undefined || name === undefined) {
          unparsedPolicyCount += 1;
          continue;
        }
        events.push({ kind: 'create', table: parsed.table, name, policy: parsed, position: position(match.index), inFunction: loopInFunction });
      }
      for (const match of findMatches(statement.sql, DROP_POLICY)) {
        const table = normalizeTableName(match.groups[1]);
        const name = normalizePolicyName(match.groups[0]);
        if (table !== undefined && name !== undefined) {
          events.push({ kind: 'drop-policy', table, name, position: position(match.index), inFunction: loopInFunction });
        }
      }
      for (const match of findMatches(statement.sql, ALTER_POLICY)) {
        const table = normalizeTableName(match.groups[1]);
        const name = normalizePolicyName(match.groups[0]);
        if (table !== undefined && name !== undefined) {
          events.push({ kind: 'alter-policy', table, name, position: position(match.index), inFunction: loopInFunction });
        }
      }
    }

    for (const sweep of findPolicySweeps(entry.content)) {
      if (inComment(sweep.start) || sweep.tables === undefined) continue;
      if (sweep.decidable) read.push([sweep.start, sweep.end]);
      events.push({
        kind: 'sweep',
        tables: sweep.tables,
        keep: sweep.decidable ? new Set(sweep.keep) : undefined,
        position: at(sweep.start),
        inFunction: inFunction(sweep.start),
      });
    }

    const unreadLines = new Set<number>();
    for (const match of findMatches(entry.content, RLS_STATEMENT_KEYWORD)) {
      if (inComment(match.index) || insideTemplate(match.index)) continue;
      if (read.some(([start, end]) => match.index >= start && match.index < end)) continue;
      unreadLines.add(match.line);
    }
    for (const line of [...unreadLines].sort((a, b) => a - b)) unreadRlsStatements.push({ filePath: entry.path, line });
  }

  const settled = replayRlsEvents(events);
  const info: SupabaseRlsInfo = {
    rlsEnabledTables: settled.enabled,
    rlsDisabledTables: settled.disabled,
    policyTables: [...new Set(settled.policies.map((policy) => policy.table))].sort(),
    policies: settled.policies.sort(
      (a, b) => a.table.localeCompare(b.table) || a.command.localeCompare(b.command) || a.line - b.line,
    ),
    sqlFileCount,
    unparsedPolicyCount,
    tableColumns: Object.fromEntries(
      [...columnsByTable.entries()]
        .sort((a, b) => a[0].localeCompare(b[0]))
        .map(([table, columns]) => [table, [...columns].sort()]),
    ),
    committedFunctions: [...committedFunctions].sort(),
    identityBoundFunctions: [...identityBoundFunctions].sort(),
    uncertainTables: settled.uncertain,
    uncertainSwitchTables: settled.uncertainSwitch,
    unsettledPolicies: settled.unsettled,
    unreadRlsStatements,
    rollbackFilesNotApplied: rollbackFilesNotApplied.sort(),
  };
  for (const warning of rlsReadingWarnings(info)) fileMap.warnings.push(warning);
  return info;
}

type RlsEvent =
  | { kind: 'enable' | 'disable' | 'drop-table'; table: string; position: SqlPosition; inFunction: boolean }
  | { kind: 'drop-policy'; table: string; name: string; position: SqlPosition; inFunction: boolean }
  | { kind: 'alter-policy'; table: string; name: string; position: SqlPosition; inFunction: boolean }
  | { kind: 'sweep'; tables: readonly string[]; keep: ReadonlySet<string> | undefined; position: SqlPosition; inFunction: boolean }
  | { kind: 'create'; table: string; name: string; policy: SupabaseRlsPolicy; position: SqlPosition; inFunction: boolean };

export interface SqlPosition {
  file: string;
  version: string | undefined;
  offset: number;
}

const MIGRATIONS_FOLDER = /(?:^|\/)supabase\/migrations\/$/;

export function migrationPositions(
  paths: readonly string[],
): (path: string) => Omit<SqlPosition, 'offset'> & { applied: boolean } {
  const folders = new Set<string>();
  for (const path of paths) {
    const folder = path.slice(0, path.lastIndexOf('/') + 1);
    if (MIGRATIONS_FOLDER.test(folder)) folders.add(folder);
  }
  const depth = (folder: string): number => folder.split('/').length;
  const shallowest = Math.min(...[...folders].map(depth));
  const candidates = [...folders].filter((folder) => depth(folder) === shallowest);
  const ordered = candidates.length === 1 ? candidates[0] : undefined;
  const versionOf = (path: string): string | undefined => {
    const folder = path.slice(0, path.lastIndexOf('/') + 1);
    return folder === ordered ? /^(\d+)/.exec(path.slice(folder.length))?.[1] : undefined;
  };
  const forwardVersions = new Set(
    paths.filter((path) => !ROLLBACK_FILE.test(path)).map(versionOf).filter((version) => version !== undefined),
  );
  return (path) => {
    const version = versionOf(path);
    const applied = !(version !== undefined && ROLLBACK_FILE.test(path) && forwardVersions.has(version));
    return { file: path, version, applied };
  };
}

const ROLLBACK_FILE = /[._]down\.sql$/i;

export function compareRunOrder(a: SqlPosition, b: SqlPosition): 'before' | 'after' | 'unknown' {
  if (a.file === b.file) {
    if (a.offset === b.offset) return 'unknown';
    return a.offset < b.offset ? 'before' : 'after';
  }
  if (a.version === undefined || b.version === undefined || a.version === b.version) return 'unknown';
  return a.file < b.file ? 'before' : 'after';
}

function replayRlsEvents(events: readonly RlsEvent[]): {
  enabled: string[];
  disabled: string[];
  policies: SupabaseRlsPolicy[];
  uncertain: string[];
  uncertainSwitch: string[];
  unsettled: { table: string; filePath: string; line: number }[];
} {
  const uncertain = new Set<string>();
  const uncertainSwitch = new Set<string>();
  const unsettledPolicies = new Set<SupabaseRlsPolicy>();
  const removers = events.filter(
    (event): event is Extract<RlsEvent, { kind: 'drop-policy' | 'drop-table' }> =>
      event.kind === 'drop-policy' || event.kind === 'drop-table',
  );
  const sweeps = events.filter((event): event is Extract<RlsEvent, { kind: 'sweep' }> => event.kind === 'sweep');
  const alters = events.filter(
    (event): event is Extract<RlsEvent, { kind: 'alter-policy' }> => event.kind === 'alter-policy',
  );

  const policies: SupabaseRlsPolicy[] = [];
  for (const create of events) {
    if (create.kind !== 'create') continue;
    let unsettled = create.inFunction || create.position.version === undefined;
    if (create.inFunction) uncertain.add(create.table);
    let removed = false;
    for (const drop of removers) {
      if (drop.table !== create.table) continue;
      if (drop.kind === 'drop-policy' && drop.name !== create.name) continue;
      const order = drop.inFunction ? 'unknown' : compareRunOrder(create.position, drop.position);
      if (order === 'before') removed = true;
      else if (order === 'unknown') {
        uncertain.add(create.table);
        unsettled = true;
      }
    }
    for (const sweep of sweeps) {
      if (!sweep.tables.includes(create.table)) continue;
      if (sweep.keep?.has(create.name) === true) continue;
      const order = sweep.inFunction ? 'unknown' : compareRunOrder(create.position, sweep.position);
      if (order === 'after') continue;
      if (order === 'before' && sweep.keep !== undefined) removed = true;
      else {
        uncertain.add(create.table);
        unsettled = true;
      }
    }
    for (const alter of alters) {
      if (alter.table !== create.table || alter.name !== create.name) continue;
      if (alter.inFunction || compareRunOrder(create.position, alter.position) !== 'after') unsettled = true;
    }
    if (removed) continue;
    policies.push(create.policy);
    if (unsettled) unsettledPolicies.add(create.policy);
  }

  const switches = new Map<string, RlsEvent[]>();
  for (const event of events) {
    if (event.kind === 'alter-policy') uncertain.add(event.table);
    if (event.kind !== 'enable' && event.kind !== 'disable' && event.kind !== 'drop-table') continue;
    if (event.inFunction) {
      uncertain.add(event.table);
      uncertainSwitch.add(event.table);
    }
    if (event.kind === 'drop-table' && event.inFunction) continue;
    switches.set(event.table, [...(switches.get(event.table) ?? []), event]);
  }
  const enabled: string[] = [];
  const disabled: string[] = [];
  for (const [table, history] of switches) {
    const last = history.filter(
      (event) => !history.some((other) => other !== event && compareRunOrder(event.position, other.position) === 'before'),
    );
    const outcomes = new Set(last.map((event) => event.kind));
    if (outcomes.size === 1) {
      if (outcomes.has('enable')) enabled.push(table);
      else if (outcomes.has('disable')) disabled.push(table);
      continue;
    }
    uncertain.add(table);
    uncertainSwitch.add(table);
    if (history.some((event) => event.kind === 'enable')) enabled.push(table);
    if (history.some((event) => event.kind === 'disable')) disabled.push(table);
  }

  return {
    enabled: enabled.sort(),
    disabled: disabled.sort(),
    policies,
    uncertain: [...uncertain].sort(),
    uncertainSwitch: [...uncertainSwitch].sort(),
    unsettled: policies
      .filter((policy) => unsettledPolicies.has(policy) && uncertain.has(policy.table))
      .map((policy) => ({ table: policy.table, filePath: policy.filePath, line: policy.line }))
      .sort((a, b) => a.table.localeCompare(b.table) || a.filePath.localeCompare(b.filePath) || a.line - b.line),
  };
}

function blankInComments(content: string, pattern: RegExp, inComment: (offset: number) => boolean): string {
  return content.replace(pattern, (text: string, offset: number) => (inComment(offset) ? ' '.repeat(text.length) : text));
}

function commentSpans(content: string): [number, number][] {
  const spans: [number, number][] = [];
  for (const match of content.matchAll(/--[^\n]*|\/\*[\s\S]*?(?:\*\/|$)/g)) {
    spans.push([match.index ?? 0, (match.index ?? 0) + match[0].length]);
  }
  return spans;
}

const MAX_NAMED_IN_WARNING = 5;

function namedList(items: readonly string[]): string {
  const shown = items.slice(0, MAX_NAMED_IN_WARNING);
  const rest = items.length - shown.length;
  return rest > 0 ? `${shown.join(', ')} and ${rest} more` : shown.join(', ');
}

export function rlsReadingWarnings(info: SupabaseRlsInfo): string[] {
  const warnings: string[] = [];
  if (info.unreadRlsStatements.length > 0) {
    const count = info.unreadRlsStatements.length;
    warnings.push(
      `${count} row-level security statement${count === 1 ? '' : 's'} in your SQL could not be read — ` +
        'built at run time, or written in a form the scanner does not parse — so the tables ' +
        `${count === 1 ? 'it touches are' : 'they touch are'} unknown. A table reported as having no row-level ` +
        `security, or a policy reported as live, may be changed by one of them. ${
          count > MAX_NAMED_IN_WARNING ? `The first ${MAX_NAMED_IN_WARNING}: ` : ''
        }${namedList(info.unreadRlsStatements.map((statement) => `${statement.filePath}:${statement.line}`))}.`,
    );
  }
  if (info.rollbackFilesNotApplied.length > 0) {
    const count = info.rollbackFilesNotApplied.length;
    warnings.push(
      `${count} rollback migration${count === 1 ? ' was' : 's were'} not treated as applied when reading row-level ` +
        `security, because ${count === 1 ? 'it shares its' : 'each shares its'} version number with a forward ` +
        'migration and the database records only one migration per version. If one of them was applied instead, ' +
        `the policies reported for its tables may be wrong. ${
          count > MAX_NAMED_IN_WARNING ? `The first ${MAX_NAMED_IN_WARNING}: ` : ''
        }${namedList(info.rollbackFilesNotApplied)}.`,
    );
  }
  if (info.uncertainTables.length > 0) {
    const count = info.uncertainTables.length;
    warnings.push(
      `Row-level security for ${count} table${count === 1 ? '' : 's'} could not be settled from your SQL, because ` +
        'statements that change it have no knowable order: they sit outside the ordered supabase/migrations ' +
        'folder, in migrations that share a version number, inside a function, in an ALTER POLICY, or in a sweep ' +
        'over pg_policies that could not be read. For ' +
        `${count === 1 ? 'this table' : 'these tables'} the scan keeps every policy that was not definitely removed, ` +
        'credits none of them as protection, and asks you to check the table in your Supabase dashboard rather than ' +
        `stating a verdict. ${
          count > MAX_NAMED_IN_WARNING ? `The first ${MAX_NAMED_IN_WARNING}: ` : ''
        }${namedList(info.uncertainTables)}.`,
    );
  }
  return warnings;
}

function bareFunctionName(raw: string | undefined): string | undefined {
  if (raw === undefined) return undefined;
  const cleaned = raw.replace(/"/g, '');
  const name = cleaned.split('.').pop()?.toLowerCase();
  return name === undefined || name.length === 0 ? undefined : name;
}

function bodyBindsToCallerIdentity(body: string): boolean {
  return CALLER_IDENTITY_BINDING.test(body.replace(JWT_ROLE_CLAIM_SETTING, ' '));
}

function parseColumnNames(body: string): string[] {
  const names: string[] = [];
  let depth = 0;
  let start = 0;
  const items: string[] = [];
  for (let index = 0; index < body.length; index += 1) {
    const char = body[index];
    if (char === '(') depth += 1;
    else if (char === ')') depth -= 1;
    else if (char === ',' && depth === 0) {
      items.push(body.slice(start, index));
      start = index + 1;
    }
  }
  items.push(body.slice(start));
  for (const item of items) {
    const trimmed = item.trim();
    if (trimmed === '') continue;
    if (/^(constraint|primary\s+key|unique|foreign\s+key|check|exclude|like)\b/i.test(trimmed)) continue;
    const name = /^"?([A-Za-z_][\w]*)"?/.exec(trimmed)?.[1];
    if (name !== undefined) names.push(name.toLowerCase());
  }
  return names;
}

function afterPolicyName(body: string): string | undefined {
  return readPolicyName(body)?.rest;
}

function readPolicyName(body: string): { name: string; rest: string } | undefined {
  const trimmed = body.replace(/^\s*(?:IF\s+NOT\s+EXISTS\s+)?/i, '');
  const quote = trimmed[0];
  if (quote === '"' || quote === "'" || quote === '`') {
    for (let index = 1; index < trimmed.length; index += 1) {
      if (trimmed[index] !== quote) continue;
      if (trimmed[index + 1] === quote) {
        index += 1;
        continue;
      }
      const name = normalizePolicyName(trimmed.slice(0, index + 1));
      return name === undefined ? undefined : { name, rest: trimmed.slice(index + 1) };
    }
    return undefined;
  }
  const bare = /^[A-Za-z_][\w$]*/.exec(trimmed);
  if (bare === null) return undefined;
  return { name: bare[0].toLowerCase(), rest: trimmed.slice(bare[0].length) };
}

function normalizePolicyName(raw: string | undefined): string | undefined {
  if (raw === undefined || raw.length === 0) return undefined;
  const quote = raw[0];
  if ((quote === '"' || quote === "'" || quote === '`') && raw.length >= 2 && raw.endsWith(quote)) {
    const inner = raw.slice(1, -1).split(quote + quote).join(quote);
    return inner.length === 0 ? undefined : inner;
  }
  return raw.toLowerCase();
}

function parsePolicy(body: string, filePath: string, line: number): SupabaseRlsPolicy | undefined {
  const clauses = afterPolicyName(body);
  if (clauses === undefined) return undefined;

  const onMatch = /\bON\s+([\w."]+)/i.exec(clauses);
  const table = normalizeTableName(onMatch?.[1]);
  if (table === undefined) return undefined;

  const forMatch = /\bFOR\s+(ALL|SELECT|INSERT|UPDATE|DELETE)\b/i.exec(clauses);
  const rawCommand = forMatch?.[1]?.toLowerCase();
  const command: RlsPolicyCommand =
    rawCommand !== undefined && (COMMANDS as readonly string[]).includes(rawCommand)
      ? (rawCommand as RlsPolicyCommand)
      : 'all';

  const usingExpression = extractParenthesised(clauses, /\bUSING\s*\(/i);
  const withCheckExpression = extractParenthesised(clauses, /\bWITH\s+CHECK\s*\(/i);

  const rolesMatch = POLICY_ROLES.exec(clauses);
  const roles =
    rolesMatch === null
      ? [...DEFAULT_POLICY_ROLES]
      : [
          ...new Set(
            (rolesMatch[1] ?? '')
              .split(',')
              .map((role) => role.trim().replace(/"/g, '').toLowerCase())
              .filter((role) => role.length > 0),
          ),
        ].sort();

  const permissive = (expression: string | undefined, caller: RlsCaller): boolean => {
    if (expression === undefined) return false;
    if (!policyAppliesTo(roles, caller)) return false;
    const verdict = evaluatePredicate(expression, caller);
    return verdict.readable && verdict.value === 'true';
  };
  const unreadable = (expression: string | undefined): boolean =>
    expression !== undefined && !evaluatePredicate(expression, 'anonymous').readable;

  return {
    table,
    command,
    filePath,
    line,
    ...(usingExpression !== undefined ? { usingExpression } : {}),
    ...(withCheckExpression !== undefined ? { withCheckExpression } : {}),
    roles,
    identityScoped:
      (usingExpression !== undefined && IDENTITY_EXPRESSION.test(usingExpression)) ||
      (withCheckExpression !== undefined && IDENTITY_EXPRESSION.test(withCheckExpression)),
    usingUnrestricted: usingExpression !== undefined && UNRESTRICTED_EXPRESSION.test(usingExpression),
    withCheckUnrestricted:
      withCheckExpression !== undefined && UNRESTRICTED_EXPRESSION.test(withCheckExpression),
    anonymousUsingPermissive: permissive(usingExpression, 'anonymous'),
    anonymousWithCheckPermissive: permissive(withCheckExpression, 'anonymous'),
    authenticatedUsingPermissive: permissive(usingExpression, 'authenticated'),
    authenticatedWithCheckPermissive: permissive(withCheckExpression, 'authenticated'),
    unreadableExpression: unreadable(usingExpression) || unreadable(withCheckExpression),
    missingCheckExpression:
      command === 'insert'
        ? withCheckExpression === undefined
        : (command === 'update' || command === 'all') &&
          withCheckExpression === undefined &&
          usingExpression === undefined,
  };
}

function extractParenthesised(body: string, opener: RegExp): string | undefined {
  const match = opener.exec(body);
  if (match === null) return undefined;
  const start = match.index + match[0].length;
  let depth = 1;
  const limit = Math.min(body.length, start + 2000);
  for (let index = start; index < limit; index += 1) {
    const char = body[index];
    if (char === '(') depth += 1;
    else if (char === ')') {
      depth -= 1;
      if (depth === 0) return body.slice(start, index).trim();
    }
  }
  return undefined;
}

export function policiesFor(
  info: SupabaseRlsInfo,
  table: string,
  command: Exclude<RlsPolicyCommand, 'all'>,
): SupabaseRlsPolicy[] {
  const normalized = table.toLowerCase();
  return info.policies.filter(
    (policy) => policy.table === normalized && (policy.command === command || policy.command === 'all'),
  );
}

export function policyExposure(
  policy: SupabaseRlsPolicy,
  command: Exclude<RlsPolicyCommand, 'all'>,
): 'anonymous' | 'authenticated' | 'none' {
  if (policy.unreadableExpression) return 'none';
  if (policy.missingCheckExpression && command !== 'select' && command !== 'delete') {
    return policy.roles.includes('public') || policy.roles.includes('anon')
      ? 'anonymous'
      : 'authenticated';
  }
  const checkInheritsUsing =
    policy.withCheckExpression === undefined && (policy.command === 'update' || policy.command === 'all');
  const anonymousCheck = checkInheritsUsing
    ? policy.anonymousUsingPermissive
    : policy.anonymousWithCheckPermissive;
  const authenticatedCheck = checkInheritsUsing
    ? policy.authenticatedUsingPermissive
    : policy.authenticatedWithCheckPermissive;

  let anonymous: boolean;
  let authenticated: boolean;
  if (command === 'insert') {
    anonymous = anonymousCheck;
    authenticated = authenticatedCheck;
  } else if (command === 'update') {
    anonymous = policy.anonymousUsingPermissive || anonymousCheck;
    authenticated = policy.authenticatedUsingPermissive || authenticatedCheck;
  } else {
    anonymous = policy.anonymousUsingPermissive;
    authenticated = policy.authenticatedUsingPermissive;
  }
  if (anonymous) return 'anonymous';
  if (authenticated) return 'authenticated';
  return 'none';
}

export function isUnrestrictedForCommand(
  policy: SupabaseRlsPolicy,
  command: Exclude<RlsPolicyCommand, 'all'>,
): boolean {
  return policyExposure(policy, command) === 'anonymous';
}

export function isCommandIdentityScoped(
  info: SupabaseRlsInfo,
  table: string | undefined,
  command: Exclude<RlsPolicyCommand, 'all'>,
): boolean {
  if (table === undefined) return false;
  const normalized = table.toLowerCase();
  if (!info.rlsEnabledTables.includes(normalized)) return false;
  if (info.rlsDisabledTables.includes(normalized)) return false;
  if (!isRlsSettledFromSource(info, normalized)) return false;
  if (info.unparsedPolicyCount > 0) return false;
  const governing = policiesFor(info, normalized, command);
  if (governing.length === 0) return false;
  return governing.every(
    (policy) => policy.identityScoped && policyExposure(policy, command) === 'none',
  );
}

export function policyBindsRowsToCaller(
  info: SupabaseRlsInfo,
  policy: SupabaseRlsPolicy,
  command: Exclude<RlsPolicyCommand, 'all'>,
): boolean {
  if (policy.unreadableExpression) return false;
  if (policy.missingCheckExpression) return false;
  if (policyExposure(policy, command) !== 'none') return false;

  const checkInheritsUsing =
    policy.withCheckExpression === undefined && (policy.command === 'update' || policy.command === 'all');
  const checkExpression = checkInheritsUsing ? policy.usingExpression : policy.withCheckExpression;
  const bound = (expression: string | undefined): boolean =>
    expression !== undefined &&
    bindsOnEveryBranch(expression, (leaf) => leafBindsRowsToCaller(leaf, info));

  if (command === 'insert') return bound(checkExpression);
  if (command === 'update') return bound(policy.usingExpression) && bound(checkExpression);
  return bound(policy.usingExpression);
}

function leafBindsRowsToCaller(leaf: string, info: SupabaseRlsInfo): boolean {
  if (CALLER_IDENTITY_BINDING.test(leaf.replace(JWT_ROLE_CLAIM_SETTING, ' '))) return true;
  return callsCallerBoundHelper(leaf, info);
}

function callsCallerBoundHelper(leaf: string, info: SupabaseRlsInfo): boolean {
  SQL_FUNCTION_CALL.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = SQL_FUNCTION_CALL.exec(leaf)) !== null) {
    const name = bareFunctionName(match[1]);
    if (name === undefined) continue;
    if (info.identityBoundFunctions.includes(name)) return true;
    if (info.committedFunctions.includes(name)) continue;
    if (MEMBERSHIP_HELPER_NAME.test(name)) return true;
  }
  return false;
}

export function isCommandCallerBound(
  info: SupabaseRlsInfo,
  table: string | undefined,
  command: Exclude<RlsPolicyCommand, 'all'>,
): boolean {
  if (table === undefined || table === '') return false;
  if (!isRlsSettledFromSource(info, table)) return false;
  return callerBoundOnThePicture(info, table, command);
}

export function isCallerBoundCreditWithheldAsUnsettled(
  info: SupabaseRlsInfo,
  table: string | undefined,
  command: Exclude<RlsPolicyCommand, 'all'>,
): boolean {
  if (table === undefined || table === '') return false;
  return !isRlsSettledFromSource(info, table) && callerBoundOnThePicture(info, table, command);
}

function callerBoundOnThePicture(
  info: SupabaseRlsInfo,
  table: string,
  command: Exclude<RlsPolicyCommand, 'all'>,
): boolean {
  const normalized = table.toLowerCase();
  if (!info.rlsEnabledTables.includes(normalized)) return false;
  if (info.rlsDisabledTables.includes(normalized)) return false;
  if (info.unparsedPolicyCount > 0) return false;
  const governing = policiesFor(info, normalized, command);
  if (governing.length === 0) return false;
  return governing.every((policy) => policyBindsRowsToCaller(info, policy, command));
}

export function isCommandDefaultDenied(
  info: SupabaseRlsInfo,
  table: string | undefined,
  command: Exclude<RlsPolicyCommand, 'all'>,
): boolean {
  if (table === undefined) return false;
  const normalized = table.toLowerCase();
  if (!info.rlsEnabledTables.includes(normalized)) return false;
  if (info.rlsDisabledTables.includes(normalized)) return false;
  if (!isRlsSettledFromSource(info, normalized)) return false;
  if (info.unparsedPolicyCount > 0) return false;
  return policiesFor(info, normalized, command).length === 0;
}

export function isRlsSettledFromSource(info: SupabaseRlsInfo, table: string | undefined): boolean {
  if (table === undefined || table === '') return true;
  return !info.uncertainTables.includes(table.toLowerCase());
}

export function isRlsSwitchSettled(info: SupabaseRlsInfo, table: string): boolean {
  return !info.uncertainSwitchTables.includes(table.toLowerCase());
}

export function isPolicyCertainlyLive(info: SupabaseRlsInfo, policy: SupabaseRlsPolicy): boolean {
  if (isRlsSettledFromSource(info, policy.table)) return true;
  return !info.unsettledPolicies.some(
    (entry) => entry.table === policy.table && entry.filePath === policy.filePath && entry.line === policy.line,
  );
}

export function grantsUnconstrainedPrivilegeColumn(
  policy: SupabaseRlsPolicy,
  writableColumns: readonly string[],
): boolean {
  if (policy.command !== 'insert' && policy.command !== 'update' && policy.command !== 'all') return false;
  const privileged = writableColumns.filter((column) => PRIVILEGE_COLUMN.test(column));
  if (privileged.length === 0) return false;
  const guard = `${policy.withCheckExpression ?? ''} ${policy.usingExpression ?? ''}`;
  return privileged.some((column) => !new RegExp(`\\b${escapeRegExp(column)}\\b`, 'i').test(guard));
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function normalizeTableName(raw: string | undefined): string | undefined {
  if (raw === undefined) return undefined;
  const cleaned = raw.replace(/"/g, '');
  const parts = cleaned.split('.');
  const name = parts[parts.length - 1]?.toLowerCase();
  return name === undefined || name.length === 0 ? undefined : name;
}

export function emptySupabaseRlsInfo(): SupabaseRlsInfo {
  return {
    rlsEnabledTables: [],
    rlsDisabledTables: [],
    policyTables: [],
    policies: [],
    sqlFileCount: 0,
    unparsedPolicyCount: 0,
    tableColumns: {},
    committedFunctions: [],
    identityBoundFunctions: [],
    uncertainTables: [],
    uncertainSwitchTables: [],
    unsettledPolicies: [],
    unreadRlsStatements: [],
    rollbackFilesNotApplied: [],
  };
}

export function hasNoCommittedPolicyEvidence(
  info: SupabaseRlsInfo,
  table: string | undefined,
): boolean {
  if (table === undefined || table === '') return false;
  const normalized = table.toLowerCase();
  if (info.policyTables.includes(normalized)) return false;
  if (info.rlsDisabledTables.includes(normalized)) return false;
  return true;
}

export function hasPolicyWithoutRlsEnabled(
  info: SupabaseRlsInfo,
  table: string | undefined,
): boolean {
  if (table === undefined || table === '') return false;
  const normalized = table.toLowerCase();
  if (!info.policyTables.includes(normalized)) return false;
  if (info.rlsDisabledTables.includes(normalized)) return false;
  return !info.rlsEnabledTables.includes(normalized);
}
