import { isPolicyCertainlyLive, policiesFor, policyExposure } from '../../project-map/detectRls.js';
import { makeFinding } from '../../shared/findingFactory.js';
import { supabaseRlsUnsettledPolicy, unsettledTableExplanation } from './supabaseRlsUnverifiable.js';
import { classifySensitiveColumns, sensitiveCategories } from '../../shared/sensitiveData.js';
import type { Finding, RuleContext, ScanRule, SupabaseRlsPolicy } from '../../shared/types.js';

export const supabaseReadableSensitiveData: ScanRule = {
  id: 'supabase_readable_sensitive_data',
  title: 'Sensitive table is readable beyond its owners through a permissive RLS policy',
  category: 'authorization',
  kind: 'contextual',
  run(context: RuleContext): Finding[] {
    const rls = context.projectMap.supabaseRls;
    if (rls.sqlFileCount === 0) return [];

    const findings: Finding[] = [];
    for (const [table, columns] of Object.entries(rls.tableColumns).sort((a, b) => a[0].localeCompare(b[0]))) {
      const exposed = permissiveSelectPolicy(policiesFor(rls, table, 'select'));
      if (exposed === undefined) continue;
      const permissive = exposed.policy;

      const sensitive = classifySensitiveColumns(columns);
      if (sensitive.critical.length === 0 && sensitive.high.length === 0) continue;

      const anonymous = exposed.exposure === 'anonymous';
      const isCritical = sensitive.critical.length > 0;
      const severity = anonymous ? (isCritical ? 'critical' : 'high') : isCritical ? 'high' : 'medium';
      const named = [...sensitive.critical, ...sensitive.high];
      const categories = sensitiveCategories(named);
      const commandLabel = permissive.command === 'all' ? 'FOR ALL' : 'FOR SELECT';
      const clause = exposed.literal
        ? 'USING (true)'
        : `USING (${(permissive.usingExpression ?? '').replace(/\s+/g, ' ').trim()})`;

      const unsettled = !isPolicyCertainlyLive(rls, permissive);
      const who = anonymous ? 'anyone holding your public key, signed in or not,' : 'any signed-in account';
      const finding = makeFinding({
          ruleId: this.id,
          title: this.title,
          severity,
          confidence: 'high',
          detectionKind: 'pattern',
          filePath: permissive.filePath,
          lineStart: permissive.line,
          evidence: `${commandLabel} ${clause} on "${table}" exposes ${named.join(', ')}`,
          userExplanation: unsettled
            ? unsettledTableExplanation(
                table,
                `The "${table}" table stores ${describe(categories)} (${named.join(', ')}), and a row-level security policy in your SQL lets ${who} read every row of it (\`${clause}\`, at ${permissive.filePath}:${permissive.line}).`,
                `If that policy, or one like it, is still on the table, ${who} can download every user's ${categories.join(', ')}.`,
              )
            : anonymous
            ? `Anyone can read every row of the "${table}" table — including people who are not logged in — because its row-level security policy allows all reads (\`${clause}\`). ` +
              `This table stores ${describe(categories)} (${named.join(', ')}), so those details are effectively public. ` +
              `A visitor can download every user's ${categories.join(', ')} by calling your database directly with the public key.`
            : `Every signed-in user can read every row of the "${table}" table, not just their own, because its row-level security policy only checks that someone is logged in (\`${clause}\`). ` +
              `This table stores ${describe(categories)} (${named.join(', ')}). ` +
              `Anyone who creates an account on your app can download every other user's ${categories.join(', ')}.`,
          technicalExplanation: (unsettled
            ? `"${table}" is in the scan's uncertain tables: a statement that changes its row-level security has no knowable order, so whether the policy below is still live cannot be determined from the committed source. `
            : '') + (anonymous
            ? `Policy on "${table}" (${permissive.filePath}:${permissive.line}) is ${commandLabel} with \`${clause}\`, granting unconditional read to the PUBLIC/anon role. ` +
              `The table defines sensitive column(s): ${named.join(', ')}. With the publishable (anon) key, an unauthenticated client can \`select *\` the whole table. ` +
              `RLS being "enabled" is not protection when the read policy is unconditional.`
            : `Policy on "${table}" (${permissive.filePath}:${permissive.line}) is ${commandLabel} with \`${clause}\`. ` +
              `Evaluated for an arbitrary signed-in caller (auth.uid() non-null, auth.role() = 'authenticated') the predicate is TRUE for every row, so it is a login check rather than an authorization check. ` +
              `The table defines sensitive column(s): ${named.join(', ')}. Sign-up is open, so the set of people who satisfy this policy is not bounded by anything.`),
          fixHint:
            `Replace \`${clause}\` on "${table}" with a predicate that scopes rows to the caller — e.g. \`USING (auth.uid() = user_id)\` for owner-only reads, or restrict to \`authenticated\` and expose only non-sensitive columns through a view. If some columns are genuinely public, move them to a separate public table/view and keep ${named.join(', ')} behind an owner-scoped policy.`,
          category: this.category,
        });
      findings.push(
        unsettled
          ? {
              ...finding,
              adjudication: supabaseRlsUnsettledPolicy(
                `A ${commandLabel} policy exposing sensitive columns of "${table}"`,
                `${permissive.filePath}:${permissive.line}`,
                table,
              ),
            }
          : finding,
      );
    }
    return findings;
  },
};

interface ExposedPolicy {
  policy: SupabaseRlsPolicy;
  exposure: 'anonymous' | 'authenticated';
  literal: boolean;
}

function permissiveSelectPolicy(policies: readonly SupabaseRlsPolicy[]): ExposedPolicy | undefined {
  const anonymous = policies.filter((policy) => policyExposure(policy, 'select') === 'anonymous');
  const literal = anonymous.find((policy) => policy.usingUnrestricted);
  if (literal !== undefined) return { policy: literal, exposure: 'anonymous', literal: true };
  const first = anonymous[0];
  if (first !== undefined) return { policy: first, exposure: 'anonymous', literal: false };
  const authenticated = policies.find((policy) => policyExposure(policy, 'select') === 'authenticated');
  return authenticated === undefined
    ? undefined
    : { policy: authenticated, exposure: 'authenticated', literal: false };
}

function describe(categories: readonly string[]): string {
  if (categories.length === 0) return 'sensitive data';
  if (categories.length === 1) return `${categories[0]} data`;
  return `${categories.slice(0, -1).join(', ')} and ${categories[categories.length - 1]} data`;
}
