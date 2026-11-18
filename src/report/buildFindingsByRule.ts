import { isSqlDumpReadAndFound } from '../archive-findings/archiveEntryFindings.js';
import { RULE_CATALOG, impactForRule, labelForRule } from '../rules/ruleCatalog.js';
import { SEVERITY_ORDER } from '../shared/constants.js';
import type { Finding, RuleFindingSummary, Severity } from '../shared/types.js';

export function buildFindingsByRule(findings: readonly Finding[]): RuleFindingSummary[] {
  const byRuleId = new Map<string, RuleFindingSummary>();

  for (const finding of findings) {
    const current = byRuleId.get(finding.ruleId);
    if (current === undefined) {
      byRuleId.set(finding.ruleId, {
        ruleId: finding.ruleId,
        label: labelForRule(finding.ruleId),
        occurrences: 1,
        highestSeverity: finding.severity,
      });
      continue;
    }

    current.occurrences += 1;
    if (severityRank(finding.severity) < severityRank(current.highestSeverity)) {
      current.highestSeverity = finding.severity;
    }
  }

  return [...byRuleId.values()].sort(
    (a, b) =>
      severityRank(a.highestSeverity) - severityRank(b.highestSeverity) ||
      a.ruleId.localeCompare(b.ruleId),
  );
}

export function buildRuleImpacts(rows: readonly RuleFindingSummary[]): Record<string, string> {
  const impacts: Record<string, string> = {};
  for (const row of rows) {
    const impact = impactForRule(row.ruleId);
    if (impact !== undefined) impacts[row.ruleId] = impact;
  }
  return impacts;
}

export function withReadDumpImpact(
  impacts: Record<string, string>,
  findings: readonly Finding[],
): Record<string, string> {
  const ruleId = 'data_artefact_committed';
  const read = RULE_CATALOG[ruleId].impactWhenRead;
  if (impacts[ruleId] === undefined) return impacts;
  const ofRule = findings.filter((finding) => finding.ruleId === ruleId);
  if (ofRule.length === 0 || !ofRule.every(isSqlDumpReadAndFound)) return impacts;
  return { ...impacts, [ruleId]: read };
}

function severityRank(severity: Severity): number {
  return SEVERITY_ORDER[severity] ?? Number.MAX_SAFE_INTEGER;
}
