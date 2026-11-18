import { emptySupabaseRlsInfo } from '../../src/project-map/detectRls.js';
import { describe, expect, it } from 'vitest';
import { buildFindingsByRule } from '../../src/report/buildFindingsByRule.js';
import { buildReport } from '../../src/report/buildReport.js';
import { basicRules, contextualRules } from '../../src/rules/index.js';
import { NON_REGISTRY_RULE_IDS, RULE_CATALOG } from '../../src/rules/ruleCatalog.js';
import { makeFinding } from '../../src/shared/findingFactory.js';
import type { Finding, Severity } from '../../src/shared/types.js';

const emptyFileMap = { rootPath: '/', entries: [], skipped: [], skippedCount: 0, warnings: [] };
const emptyStack = { stacks: [] };
const emptyProjectMap = {
  apiRoutes: [], frontendComponents: [], authFiles: [], middlewareFiles: [], middlewareMatchers: [],
  databaseFiles: [], envFiles: [], configFiles: [], supabaseUsage: [], firebaseUsage: [],
  supabaseRls: emptySupabaseRlsInfo(), databaseCalls: [], imports: [],
  dangerousOperations: [], publicClientUsage: [], serverSideUsage: [], authSignals: [], envUsage: [],
};

function finding(ruleId: string, severity: Severity, occurrence: number, category: Finding['category'] = 'configuration'): Finding {
  return makeFinding({
    ruleId,
    title: `Finding ${occurrence}`,
    severity,
    confidence: 'high',
    filePath: `src/file-${occurrence}.ts`,
    lineStart: occurrence + 1,
    evidence: `evidence-${ruleId}-${occurrence}`,
    userExplanation: 'user explanation',
    technicalExplanation: 'technical explanation',
    fixHint: 'fix it',
    category,
  });
}

const reportBase = { fileMap: emptyFileMap, detectedStack: emptyStack, projectMap: emptyProjectMap };

describe('findingsByRule aggregation', () => {
  it('returns an empty list when there are no findings', () => {
    expect(buildFindingsByRule([])).toEqual([]);
  });

  it('returns one fixed catalog entry for one finding', () => {
    expect(buildFindingsByRule([finding('supabase_rls_not_detected', 'high', 0)])).toEqual([{
      ruleId: 'supabase_rls_not_detected',
      label: 'Row Level Security (RLS) was not detected',
      occurrences: 1,
      highestSeverity: 'high',
    }]);
  });

  it('collapses repeated findings and keeps the highest severity', () => {
    expect(buildFindingsByRule([
      finding('missing_rate_limit', 'low', 0),
      finding('missing_rate_limit', 'critical', 1),
      finding('missing_rate_limit', 'medium', 2),
    ])).toEqual([{
      ruleId: 'missing_rate_limit',
      label: 'Sensitive endpoint has no rate limiting',
      occurrences: 3,
      highestSeverity: 'critical',
    }]);
  });

  it('orders different rules by severity and then stable rule id', () => {
    const result = buildFindingsByRule([
      finding('xss', 'medium', 0),
      finding('sql_injection', 'critical', 1),
      finding('broken_access_control', 'high', 2),
      finding('api_mutation_without_auth', 'high', 3),
    ]);
    expect(result.map((entry) => entry.ruleId)).toEqual([
      'sql_injection', 'api_mutation_without_auth', 'broken_access_control', 'xss',
    ]);
  });

  it('aggregates dependency advisories under the dependency rule id', () => {
    expect(buildFindingsByRule([
      finding('dependency_vulnerability', 'high', 0, 'dependencies'),
      finding('dependency_vulnerability', 'critical', 1, 'dependencies'),
    ])).toEqual([{
      ruleId: 'dependency_vulnerability',
      label: 'A dependency has a known vulnerability',
      occurrences: 2,
      highestSeverity: 'critical',
    }]);
  });

  it('counts retained findings only when the final report is truncated', () => {
    const report = buildReport({
      ...reportBase,
      findings: [
        finding('hardcoded_secret', 'critical', 0),
        finding('hardcoded_secret', 'critical', 1),
        finding('hardcoded_secret', 'critical', 2),
      ],
      findingLimit: 2,
    });
    expect(report.scanStatus).toBe('incomplete');
    expect(report.findings).toHaveLength(2);
    expect(report.findingsByRule[0]).toMatchObject({
      ruleId: 'hardcoded_secret', occurrences: 2, highestSeverity: 'critical',
    });
  });

  it('remains present and JSON-compatible when a scan is incomplete', () => {
    const report = buildReport({
      ...reportBase,
      findings: [finding('unsafe_file_upload', 'high', 0)],
      codeScanTruncated: true,
    });
    expect(report.scanStatus).toBe('incomplete');
    expect(report.findingsByRule).toHaveLength(1);
    expect(JSON.parse(JSON.stringify(report))).toEqual(report);
  });

  it('uses a deterministic fixed fallback for custom, uncatalogued rules', () => {
    expect(buildFindingsByRule([finding('custom_rule', 'low', 0)])[0]?.label).toBe(
      'Security issue found by an uncatalogued rule (custom_rule)',
    );
  });
});

describe('rule catalog consistency', () => {
  it('has unique registered ids and catalogs every finding producer exactly once', () => {
    const registeredIds = [...basicRules, ...contextualRules].map((rule) => rule.id);
    expect(new Set(registeredIds).size).toBe(registeredIds.length);
    const expectedCatalogIds = new Set([...registeredIds, ...NON_REGISTRY_RULE_IDS]);
    expect(Object.keys(RULE_CATALOG).sort()).toEqual([...expectedCatalogIds].sort());
  });

  it('uses non-empty fixed labels', () => {
    for (const entry of Object.values(RULE_CATALOG)) {
      expect(entry.error.trim().length).toBeGreaterThan(0);
    }
  });
});
