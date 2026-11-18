import { hasNoCommittedPolicyEvidence, isRlsSettledFromSource } from '../../project-map/detectRls.js';
import type {
  FindingAdjudicationPolicy,
  RlsPolicyCommand,
  SupabaseRlsInfo,
} from '../../shared/types.js';

export function commandLabel(command: Exclude<RlsPolicyCommand, 'all'>): string {
  return command === 'insert' ? 'insert' : command;
}

function article(word: string): string {
  return /^[aeiou]/i.test(word) ? 'an' : 'a';
}

export function policyToCheck(table: string, command: Exclude<RlsPolicyCommand, 'all'>): string {
  const clause =
    command === 'insert'
      ? `WITH CHECK (auth.uid() = user_id)`
      : command === 'update'
        ? `USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id)`
        : `USING (auth.uid() = user_id)`;
  const named = command.toUpperCase();
  return `${article(named)} ${named} policy on "${table}" with ${clause}`;
}

export function verifyInDashboardExplanation(
  table: string,
  command: Exclude<RlsPolicyCommand, 'all'>,
  operationSentence: string,
): string {
  return (
    `${operationSentence} This is safe only if you have a Row Level Security policy scoping "${table}" to its owner. ` +
    `Your policies live in your Supabase dashboard, not your code, so we cannot see them — we found no policy for ` +
    `"${table}" anywhere in your committed SQL. Verify this policy exists: ${policyToCheck(table, command)}. ` +
    `If it does, this finding is already handled and you can close it. If it does not, anyone holding your public ` +
    `anon key can ${commandLabel(command)} rows in this table.`
  );
}

export function supabaseRlsUnverifiablePolicy(
  what: string,
  where: string,
  table: string,
): FindingAdjudicationPolicy {
  return {
    required: false,
    reason: 'supabase_rls_unverifiable_from_source',
    basis:
      `${what} at ${where}. COMPOSITION OF THE ARGUMENT: the committed SQL contains no CREATE POLICY naming ` +
      `"${table}" and no DISABLE ROW LEVEL SECURITY for it, so the source states nothing about how this table is ` +
      `governed. Supabase policies are commonly authored in the hosted dashboard and never committed, so this ` +
      `absence is equally consistent with a wide-open table and a correctly protected one, and nothing else in the ` +
      `repository can decide it. The question is therefore put to the app's owner in userExplanation, which names ` +
      `the exact policy to look for. NOT CLAIMED: nothing has been measured for this class; the exemption rests only ` +
      `on the deciding evidence living outside the repository. NOT APPLIED when any policy for this table IS ` +
      `committed: those findings stay definitive and are judged normally.`,
  };
}

export function isRlsUnverifiableFromSource(
  rls: SupabaseRlsInfo,
  table: string | undefined,
): boolean {
  return hasNoCommittedPolicyEvidence(rls, table);
}

export const UNSETTLED_BASIS_MARKER = 'RLS NOT SETTLED FROM SOURCE';

export function isRlsUnsettledFromSource(rls: SupabaseRlsInfo, table: string | undefined): boolean {
  return table !== undefined && table !== '' && !isRlsSettledFromSource(rls, table);
}

export function unsettledTableExplanation(table: string, operationSentence: string, ifNot: string): string {
  return (
    `${operationSentence} Epherem could not settle how the "${table}" table is protected from your SQL, because ` +
    `some of the statements that change its policies could not be put in order (they are named in the scan ` +
    `warnings), so a policy we read may since have been dropped or rewritten. Check this table's policies in your ` +
    `Supabase dashboard. ${ifNot}`
  );
}

export function unsettledCommandExplanation(
  table: string,
  command: Exclude<RlsPolicyCommand, 'all'>,
  operationSentence: string,
): string {
  return unsettledTableExplanation(
    table,
    operationSentence,
    `It is safe if the live table has ${policyToCheck(table, command)} and no looser ${command.toUpperCase()} ` +
      `policy beside it. If it does not, anyone holding your public anon key may be able to ` +
      `${commandLabel(command)} rows in this table.`,
  );
}

export function supabaseRlsUnsettledPolicy(what: string, where: string, table: string): FindingAdjudicationPolicy {
  return {
    required: false,
    reason: 'supabase_rls_unverifiable_from_source',
    basis:
      `${UNSETTLED_BASIS_MARKER}: ${what} at ${where}. COMPOSITION OF THE ARGUMENT: the committed SQL does ` +
      `name "${table}", but at least one statement that changes its row-level security has no knowable place in ` +
      `the order the database applied them (outside the ordered supabase/migrations folder, in a migration sharing ` +
      `a version, inside a function body, an ALTER POLICY, or a policy sweep that cannot be read), so which of its ` +
      `policies are live cannot be decided from the source. The scanner therefore credits none of them and states ` +
      `no verdict, and nothing else in the repository holds the missing order. The question is put to the app's ` +
      `owner in userExplanation. NOT CLAIMED: nothing has been measured for this class. NOT APPLIED when the finding rests only on ` +
      `settled facts — an exposing policy that is certainly live, or a switch whose state is known: those stay ` +
      `definitive and are judged normally.`,
  };
}
