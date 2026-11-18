import { hasPolicyWithoutRlsEnabled, isRlsSwitchSettled } from '../../project-map/detectRls.js';
import { hasStack } from '../../stack-detection/detectStack.js';
import { makeFinding } from '../../shared/findingFactory.js';
import {
  isRlsUnverifiableFromSource,
  supabaseRlsUnsettledPolicy,
  supabaseRlsUnverifiablePolicy,
  unsettledTableExplanation,
  verifyInDashboardExplanation,
} from './supabaseRlsUnverifiable.js';
import type {
  DatabaseCall,
  Finding,
  RlsPolicyCommand,
  RuleContext,
  ScanRule,
} from '../../shared/types.js';

function readCommandFor(kind: string): Exclude<RlsPolicyCommand, 'all'> {
  if (kind === 'delete') return 'delete';
  if (kind === 'update') return 'update';
  if (kind === 'insert' || kind === 'upsert') return 'insert';
  return 'select';
}

export const supabaseRlsNotDetected: ScanRule = {
  id: 'supabase_rls_not_detected',
  title: 'No Row Level Security detected for Supabase tables',
  category: 'authorization',
  kind: 'contextual',
  run(context: RuleContext): Finding[] {
    if (!hasStack(context.stack, 'supabase')) return [];
    const { supabaseRls, publicClientUsage, databaseCalls } = context.projectMap;

    const clientFiles = new Set(publicClientUsage);
    const clientCalls = databaseCalls.filter(
      (call) => call.client === 'supabase' && clientFiles.has(call.filePath),
    );
    if (clientCalls.length === 0) return [];

    const protectedTables = new Set(
      supabaseRls.rlsEnabledTables.filter((table) => isRlsSwitchSettled(supabaseRls, table)),
    );
    const hadSqlToInspect = supabaseRls.sqlFileCount > 0;

    const firstCallByUnprotectedTable = new Map<string, DatabaseCall>();
    let firstUnknownTableCall: DatabaseCall | undefined;
    for (const call of clientCalls) {
      if (call.table === undefined) {
        firstUnknownTableCall ??= call;
        continue;
      }
      if (protectedTables.has(call.table)) continue;
      if (!firstCallByUnprotectedTable.has(call.table)) {
        firstCallByUnprotectedTable.set(call.table, call);
      }
    }

    const findings: Finding[] = [];
    for (const [table, call] of [...firstCallByUnprotectedTable.entries()].sort(([a], [b]) =>
      a.localeCompare(b),
    )) {
      const switchUnsettled = !isRlsSwitchSettled(supabaseRls, table);
      const unverifiable = !switchUnsettled && isRlsUnverifiableFromSource(supabaseRls, table);
      const policiesButNoRls = hasPolicyWithoutRlsEnabled(supabaseRls, table);
      const switchedOff = !switchUnsettled && supabaseRls.rlsDisabledTables.includes(table);
      const unread = supabaseRls.unreadRlsStatements.length;
      const unreadClause =
        unread > 0
          ? `${unread} row-level security statement${unread === 1 ? '' : 's'} in your SQL could not be read (listed in the scan warnings), and ${unread === 1 ? 'it' : 'any of them'} may switch it on.`
          : '';
      const declaredPolicies = supabaseRls.policies.filter((policy) => policy.table === table);
      const base = makeFinding({
          ruleId: this.id,
          title: policiesButNoRls
            ? `Row Level Security policies exist but were never enabled: "${table}"`
            : `${this.title}: "${table}"`,
          severity: 'high',
          confidence: policiesButNoRls ? 'high' : hadSqlToInspect ? 'medium' : 'low',
          detectionKind: policiesButNoRls ? 'pattern' : 'absence',
          filePath: call.filePath,
          lineStart: call.line,
          evidence: policiesButNoRls
            ? `Client code calls Supabase table "${table}" (${call.kind}); ${declaredPolicies.length} CREATE POLICY statement(s) name it but no ALTER TABLE ... ENABLE ROW LEVEL SECURITY does${unread > 0 ? ` that could be read; ${unread} row-level security statement(s) could not be read` : ''}`
            : switchUnsettled
            ? `Client code calls Supabase table "${table}" (${call.kind}); ${supabaseRls.sqlFileCount} SQL file(s) both ENABLE and DISABLE ROW LEVEL SECURITY for it with no knowable order`
            : switchedOff
            ? `Client code calls Supabase table "${table}" (${call.kind}), and the project SQL switches ROW LEVEL SECURITY off for it (ALTER TABLE ... DISABLE ROW LEVEL SECURITY)`
            : hadSqlToInspect && unread > 0
            ? `Client code calls Supabase table "${table}" (${call.kind}), but the ${supabaseRls.sqlFileCount} SQL file(s) contain no ENABLE ROW LEVEL SECURITY for it that could be read; ${unread} row-level security statement(s) could not be read`
            : hadSqlToInspect
            ? `Client code calls Supabase table "${table}" (${call.kind}), but ${supabaseRls.sqlFileCount} SQL file(s) contain no ENABLE ROW LEVEL SECURITY for it`
            : `Client code calls Supabase table "${table}" (${call.kind}) and no SQL files exist to verify RLS`,
          userExplanation: policiesButNoRls
            ? `Your project writes Row Level Security policies for the "${table}" table, but never turns Row Level Security ON for it — and Postgres ignores policies on a table where it is off. The rules you wrote are not running. Anyone with your public key can read and change every row of "${table}", exactly as if you had written no policies at all. This is a one-line fix.${unread > 0 ? ` One caveat: ${unreadClause} If one of them does, these policies are running after all — check the table in your Supabase dashboard before you change anything.` : ''}`
            : switchUnsettled
            ? unsettledTableExplanation(
                table,
                `Your app accesses the "${table}" table directly from the browser, and your SQL both switches Row Level Security on and switches it off for it.`,
                `If it is off in your live database, anyone holding your public anon key can read or modify "${table}".`,
              )
            : switchedOff
            ? `Your app accesses the "${table}" table directly from the browser, and your project's SQL switches Row Level Security OFF for it (ALTER TABLE ${table} DISABLE ROW LEVEL SECURITY). Unless it was switched back on in your Supabase dashboard, anyone holding your public anon key can read or modify every row of "${table}".`
            : unverifiable
            ? `${verifyInDashboardExplanation(
                table,
                readCommandFor(call.kind),
                `Your app accesses the "${table}" table directly from the browser.`,
              )}${unread > 0 ? ` Part of your SQL could not be read: ${unreadClause}` : ''}`
            : unread > 0
            ? `Your app accesses the "${table}" table directly from the browser, and the scan found no Row Level Security (RLS) setup for that table in the parts of your project's SQL it could read. ${unreadClause} If RLS is disabled in your live database, anyone can read or modify "${table}" with the public anon key — even if your other tables are protected.`
            : `Your app accesses the "${table}" table directly from the browser, but the scan found no Row Level Security (RLS) setup for that table in your project's SQL. If RLS is also disabled in your live database, anyone can read or modify "${table}" with the public anon key — even if your other tables are protected.`,
          technicalExplanation: switchUnsettled
            ? `${call.filePath}:${call.line} performs a client-side supabase ${call.kind} on "${table}". The project SQL contains both ENABLE and DISABLE ROW LEVEL SECURITY for "${table}", and the order the database applied them cannot be determined from the committed source, so whether RLS is on for it is not known.`
            : policiesButNoRls
            ? `${call.filePath}:${call.line} performs a client-side supabase ${call.kind} on "${table}". The project SQL defines ${declaredPolicies.length} policy statement(s) on "${table}" (${declaredPolicies.map((policy) => `${policy.filePath}:${policy.line}`).join(', ')}) but contains no ALTER TABLE ... ENABLE ROW LEVEL SECURITY for it. Row level security is off by default; policies on a table with RLS disabled are stored and never evaluated, so the table is fully exposed to the anon key.`
            : switchedOff
            ? `${call.filePath}:${call.line} performs a client-side supabase ${call.kind} on "${table}". The project SQL contains ALTER TABLE ... DISABLE ROW LEVEL SECURITY for "${table}", and it is the last switch statement for that table in migration order, so RLS is off for it at the end of the committed history. Client calls run with the anon key.`
            : hadSqlToInspect
            ? `${call.filePath}:${call.line} performs a client-side supabase ${call.kind} on "${table}". The project's ${supabaseRls.sqlFileCount} SQL file(s) enable RLS for [${supabaseRls.rlsEnabledTables.join(', ') || 'no tables'}] but not for "${table}". Each table needs its own RLS; protection of one table does not extend to another.${unread > 0 ? ` ${unread} row-level security statement(s) could not be read (${supabaseRls.unreadRlsStatements.slice(0, 5).map((statement) => `${statement.filePath}:${statement.line}`).join(', ')}${unread > 5 ? ', …' : ''}); the tables they touch are unknown, so one of them may enable RLS for "${table}".` : ''} Verify in the Supabase dashboard.`
            : `${call.filePath}:${call.line} performs a client-side supabase ${call.kind} on "${table}" and the project contains no SQL files, so RLS could not be verified statically. Check the Supabase dashboard.`,
          fixHint: policiesButNoRls
            ? `Add ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY; to a migration. The policies already written for "${table}" then start being enforced — check them before you enable it, because until now nothing has been running them.`
            : `Run ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY; and add CREATE POLICY statements scoping select/insert/update/delete on "${table}" to auth.uid(). Commit them as SQL migrations so future scans can verify them.`,
          category: this.category,
      });
      findings.push(
        switchUnsettled
          ? {
              ...base,
              adjudication: supabaseRlsUnsettledPolicy(
                `A client-side Supabase ${call.kind} on "${table}", whose RLS switch the committed SQL does not settle`,
                `${call.filePath}:${call.line}`,
                table,
              ),
            }
          : unverifiable
          ? {
              ...base,
              adjudication: supabaseRlsUnverifiablePolicy(
                `A client-side Supabase ${call.kind} on "${table}", with no RLS evidence for it in the committed SQL`,
                `${call.filePath}:${call.line}`,
                table,
              ),
            }
          : base,
      );
    }

    if (findings.length === 0 && protectedTables.size === 0 && firstUnknownTableCall !== undefined) {
      const call = firstUnknownTableCall;
      findings.push(
        makeFinding({
          ruleId: this.id,
          title: this.title,
          severity: 'high',
          confidence: 'low',
          detectionKind: 'absence',
          filePath: call.filePath,
          lineStart: call.line,
          evidence: 'Client code calls Supabase (table not statically determinable) and no RLS evidence exists in the project',
          userExplanation:
            'Your app calls Supabase directly from the browser and the scan found no Row Level Security setup anywhere in your project\'s SQL. If RLS is also disabled in your live database, the public anon key grants broad access to your data.',
          technicalExplanation:
            `${call.filePath}:${call.line} performs a client-side Supabase call whose target table could not be extracted statically, and no ENABLE ROW LEVEL SECURITY statements exist in the project. Verify RLS status in the Supabase dashboard.`,
          fixHint:
            'In the Supabase dashboard (or a migration), run ALTER TABLE <table> ENABLE ROW LEVEL SECURITY; for every table the client touches, then CREATE POLICY statements scoping each operation to auth.uid().',
          category: this.category,
        }),
      );
    }
    return findings;
  },
};
