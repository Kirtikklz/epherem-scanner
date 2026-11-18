import { databaseCallsInFile } from '../../project-map/buildProjectMap.js';
import {
  grantsUnconstrainedPrivilegeColumn,
  isCommandDefaultDenied,
  isCommandIdentityScoped,
  isPolicyCertainlyLive,
  isRlsSwitchSettled,
  isUnrestrictedForCommand,
  policiesFor,
} from '../../project-map/detectRls.js';
import { makeFinding } from '../../shared/findingFactory.js';
import {
  isRlsUnsettledFromSource,
  isRlsUnverifiableFromSource,
  supabaseRlsUnsettledPolicy,
  supabaseRlsUnverifiablePolicy,
  unsettledCommandExplanation,
  verifyInDashboardExplanation,
} from './supabaseRlsUnverifiable.js';
import type {
  DatabaseCall,
  Finding,
  RlsPolicyCommand,
  RuleContext,
  ScanRule,
  SupabaseRlsInfo,
  SupabaseRlsPolicy,
} from '../../shared/types.js';

const PRIVILEGED_KINDS = new Set(['insert', 'update', 'delete', 'upsert']);

const PRIVILEGE_COLUMN_HINT =
  /^(role|roles|is_admin|isadmin|admin|is_superuser|is_staff|permissions?|scopes?|privileges?|access_level|user_type|account_type)$/i;

function commandFor(kind: string): Exclude<RlsPolicyCommand, 'all'> {
  if (kind === 'delete') return 'delete';
  if (kind === 'update') return 'update';
  return 'insert';
}

interface CallSite {
  filePath: string;
  line: number;
  kind: string;
  snippet: string;
}

export const supabaseClientPrivilegedOperation: ScanRule = {
  id: 'supabase_client_used_for_privileged_operation',
  title: 'Privileged database operation from client-side code',
  category: 'data_exposure',
  kind: 'contextual',
  run(context: RuleContext): Finding[] {
    const rls = context.projectMap.supabaseRls;

    const groups = new Map<
      string,
      { table: string; command: Exclude<RlsPolicyCommand, 'all'>; sites: CallSite[] }
    >();
    for (const filePath of context.projectMap.publicClientUsage) {
      const mutations: DatabaseCall[] = databaseCallsInFile(context.projectMap, filePath).filter(
        (call) => call.client === 'supabase' && PRIVILEGED_KINDS.has(call.kind),
      );
      for (const call of mutations) {
        const table = call.table ?? '';
        const command = commandFor(call.kind);
        const key = `${table} ${command}`;
        let group = groups.get(key);
        if (group === undefined) {
          group = { table, command, sites: [] };
          groups.set(key, group);
        }
        group.sites.push({ filePath, line: call.line, kind: call.kind, snippet: call.snippet });
      }
    }

    const findings: Finding[] = [];
    for (const { table, command, sites } of groups.values()) {
      const escalates = policiesFor(rls, table, command).some((policy) =>
        grantsUnconstrainedPrivilegeColumn(policy, rls.tableColumns[table] ?? []),
      );
      const named = table === '' ? undefined : table;
      if (!escalates && isCommandIdentityScoped(rls, named, command)) continue;
      if (isCommandDefaultDenied(rls, named, command)) continue;

      const first = sites[0];
      if (first === undefined) continue;
      const diagnosis = diagnose(rls, table, command);
      const references = sites.map((site) => `${site.filePath}:${site.line} (${site.kind})`).join('; ');

      const unsettled =
        named !== undefined && isRlsUnsettledFromSource(rls, named) && !restsOnSettledFacts(rls, named, diagnosis);
      const unverifiable = !unsettled && isRlsUnverifiableFromSource(rls, named);
      const operationSentence = `Browser code performs ${command === 'insert' ? 'a write' : command === 'update' ? 'an update' : 'a delete'} on the "${named}" table directly.`;
      const base = makeFinding({
        ruleId: this.id,
        title: this.title,
        severity: diagnosis.severity,
        confidence: diagnosis.confidence,
        filePath: first.filePath,
        lineStart: first.line,
        evidence: `${first.snippet} — ${sites.length} client call site(s) on "${table || 'unknown table'}": ${references}`,
        userExplanation:
          unsettled && named !== undefined
            ? unsettledCommandExplanation(named, command, operationSentence)
            : unverifiable && named !== undefined
            ? verifyInDashboardExplanation(named, command, operationSentence)
            : diagnosis.userExplanation,
        technicalExplanation: unsettled
          ? `${diagnosis.technicalExplanation} Client call sites: ${references}. "${table}" is in the scan's uncertain tables: a statement that changes its row-level security has no knowable order, so which of its policies are live cannot be determined from the committed source, and no protection credit was given.`
          : unverifiable
          ? `${diagnosis.technicalExplanation} Client call sites: ${references}. No CREATE POLICY naming "${table}" exists in the project's ${rls.sqlFileCount} SQL file(s), so whether this operation is constrained cannot be determined from the committed source.`
          : `${diagnosis.technicalExplanation} Client call sites: ${references}.`,
        fixHint: diagnosis.fixHint,
        category: this.category,
      });
      findings.push(
        unsettled && named !== undefined
          ? {
              ...base,
              adjudication: supabaseRlsUnsettledPolicy(
                `A client-side Supabase ${command} on "${named}"`,
                `${first.filePath}:${first.line}`,
                named,
              ),
            }
          : unverifiable && named !== undefined
          ? {
              ...base,
              adjudication: supabaseRlsUnverifiablePolicy(
                `A client-side Supabase ${command} on "${named}"`,
                `${first.filePath}:${first.line}`,
                named,
              ),
            }
          : base,
      );
    }
    return findings;
  },
};

interface Diagnosis {
  severity: 'critical' | 'high' | 'medium' | 'low';
  confidence: 'high' | 'medium' | 'low';
  userExplanation: string;
  technicalExplanation: string;
  fixHint: string;
  restsOn: { kind: 'switch' } | { kind: 'policy'; policy: SupabaseRlsPolicy } | { kind: 'withheld-credit' };
}

function diagnose(
  rls: SupabaseRlsInfo,
  table: string,
  command: Exclude<RlsPolicyCommand, 'all'>,
): Diagnosis {
  const label = table === '' ? 'the target table' : `"${table}"`;
  const verb = command === 'insert' ? 'insert/upsert' : command;

  if (table !== '' && rls.rlsDisabledTables.includes(table)) {
    return {
      severity: 'critical',
      confidence: 'high',
      userExplanation: `Row Level Security is explicitly switched OFF for ${label}, and browser code writes to it. Anyone holding your public key can change any row in this table.`,
      technicalExplanation: `ALTER TABLE ${table} DISABLE ROW LEVEL SECURITY was found in the project SQL, so no policy constrains ${verb} on ${label}. Client calls run with the anon key.`,
      fixHint: `Re-enable RLS (ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY;) and add a ${command.toUpperCase()} policy scoped to auth.uid(), or move this mutation to a server route using the service-role key.`,
      restsOn: { kind: 'switch' },
    };
  }

  if (table === '' || !rls.rlsEnabledTables.includes(table)) {
    const noSql = rls.sqlFileCount === 0;
    return {
      severity: command === 'delete' || command === 'update' ? 'high' : 'medium',
      confidence: noSql ? 'low' : 'medium',
      userExplanation: noSql
        ? `Browser code writes to ${label} directly, and the upload contains no SQL migrations, so the scan could not check whether Row Level Security protects it. Confirm RLS is enabled in your Supabase dashboard.`
        : `Browser code writes to ${label} directly and the scan found no Row Level Security setup for it. Without RLS, anyone holding your public key can modify this table.`,
      technicalExplanation: noSql
        ? `No SQL files were present, so no ENABLE ROW LEVEL SECURITY evidence could be read for ${label}. This is a coverage limitation, not proof of exposure.`
        : `No ENABLE ROW LEVEL SECURITY statement was found for ${label} across ${rls.sqlFileCount} SQL file(s). Client-side ${verb} runs with the anon key.`,
      fixHint: `Enable RLS for the table (ALTER TABLE ${table || '<table>'} ENABLE ROW LEVEL SECURITY;) and add a ${command.toUpperCase()} policy scoped to auth.uid(), or move this mutation into a server route.`,
      restsOn: { kind: 'switch' },
    };
  }

  const governing = policiesFor(rls, table, command);

  if (governing.length === 0) {
    return {
      severity: 'medium',
      confidence: 'medium',
      userExplanation: `Row Level Security is on for ${label}, but no policy covers ${verb}. Postgres denies by default, so this operation silently fails for every user — including the row's owner.`,
      technicalExplanation: `${label} has ENABLE ROW LEVEL SECURITY but no ${command.toUpperCase()} or FOR ALL policy. RLS default-deny applies: the client ${verb} is blocked rather than exposed.`,
      fixHint: `Add a ${command.toUpperCase()} policy scoped to auth.uid() for ${label}, or remove the client call if the operation is not meant to be possible.`,
      restsOn: { kind: 'withheld-credit' },
    };
  }

  const unrestricted = governing.find((policy) => isUnrestrictedForCommand(policy, command));
  if (unrestricted !== undefined) {
    const clause = command === 'insert' || command === 'update' ? 'WITH CHECK (true)' : 'USING (true)';
    return {
      severity: 'high',
      confidence: 'high',
      userExplanation: `${label} has a Row Level Security policy for ${verb}, but it places no restriction on who may do it — it evaluates to "true" for everyone. Any visitor can ${verb} rows in this table.`,
      technicalExplanation: `Policy on ${label} at ${unrestricted.filePath}:${unrestricted.line} governs ${command.toUpperCase()} with ${clause}. Permissive policies are OR-ed, so this one alone exposes the table regardless of any stricter sibling.`,
      fixHint: `Replace the ${clause} on ${label} (${unrestricted.filePath}:${unrestricted.line}) with a predicate bound to the caller, e.g. WITH CHECK (auth.uid() = user_id).`,
      restsOn: { kind: 'policy', policy: unrestricted },
    };
  }

  const escalating = governing.find((policy) =>
    grantsUnconstrainedPrivilegeColumn(policy, rls.tableColumns[table] ?? []),
  );
  if (escalating !== undefined) {
    const unconstrained = (rls.tableColumns[table] ?? []).filter(
      (column) =>
        PRIVILEGE_COLUMN_HINT.test(column) &&
        !new RegExp(`\\b${column.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i').test(
          `${escalating.withCheckExpression ?? ''} ${escalating.usingExpression ?? ''}`,
        ),
    );
    const columnList = unconstrained.join(', ');
    return {
      severity: 'high',
      confidence: 'medium',
      userExplanation: `${label} correctly limits ${verb} to the signed-in user's own rows, but it never constrains the "${columnList}" column. Because the browser supplies that value, a user can write their own row and set "${columnList}" to anything — including a privileged value.`,
      technicalExplanation: `Policy on ${label} at ${escalating.filePath}:${escalating.line} scopes rows via ${escalating.withCheckExpression ?? escalating.usingExpression ?? ''} but places no constraint on ${columnList}, which ${label} declares as a column and the client ${verb} payload can set.`,
      fixHint: `Constrain ${columnList} in the ${command.toUpperCase()} policy on ${label} (${escalating.filePath}:${escalating.line}) — e.g. WITH CHECK (auth.uid() = user_id AND ${unconstrained[0] ?? 'role'} = 'member') — or move assignment of that column to a server route or a trigger.`,
      restsOn: { kind: 'policy', policy: escalating },
    };
  }

  const policy = governing[0] as SupabaseRlsPolicy;
  const usingText = policy.usingExpression !== undefined ? ` USING (${policy.usingExpression})` : '';
  const checkText =
    policy.withCheckExpression !== undefined ? ` WITH CHECK (${policy.withCheckExpression})` : '';
  return {
    severity: 'high',
    confidence: 'medium',
    userExplanation: `${label} has a Row Level Security policy for ${verb}, but it does not tie rows to the signed-in user. Whatever it checks, it is not "is this row mine?".`,
    technicalExplanation: `No policy governing ${command.toUpperCase()} on ${label} references auth.uid(), auth.jwt() or request.jwt claims. Nearest policy: ${policy.filePath}:${policy.line}${usingText}${checkText}.`,
    fixHint: `Scope the ${command.toUpperCase()} policy on ${label} to the caller, e.g. USING (auth.uid() = user_id), or move the mutation to a server route if it legitimately needs to cross users.`,
    restsOn: { kind: 'withheld-credit' },
  };
}

function restsOnSettledFacts(rls: SupabaseRlsInfo, table: string, diagnosis: Diagnosis): boolean {
  if (diagnosis.restsOn.kind === 'switch') return isRlsSwitchSettled(rls, table);
  if (diagnosis.restsOn.kind === 'policy') return isPolicyCertainlyLive(rls, diagnosis.restsOn.policy);
  return false;
}
