import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { emptySupabaseRlsInfo } from '../../src/project-map/detectRls.js';
import { buildRuleImpacts } from '../../src/report/buildFindingsByRule.js';
import { buildReport, buildTimeoutReport } from '../../src/report/buildReport.js';
import { validateScanReport } from '../../src/report/validateReport.js';
import { RULE_CATALOG, impactForRule, type CatalogRuleId } from '../../src/rules/ruleCatalog.js';
import { makeFinding } from '../../src/shared/findingFactory.js';
import type { Finding, Severity } from '../../src/shared/types.js';

const APPROVED_SHA256 = '4dd06b6c64ff8645abc0951abed08c98b9d37427666d9d193d404631d67cb7a5';
const fixtureBytes = readFileSync(
  fileURLToPath(new URL('../fixtures/approved-impact-texts.json', import.meta.url)),
);
const approved = JSON.parse(fixtureBytes.toString('utf8')) as Record<string, string>;
const catalogIds = Object.keys(RULE_CATALOG) as CatalogRuleId[];
const catalogImpacts = catalogIds.map((id) => RULE_CATALOG[id].impact);

const emptyFileMap = { rootPath: '/', entries: [], skipped: [], skippedCount: 0, warnings: [] };
const emptyStack = { stacks: [] };
const emptyProjectMap = {
  apiRoutes: [], frontendComponents: [], authFiles: [], middlewareFiles: [], middlewareMatchers: [],
  databaseFiles: [], envFiles: [], configFiles: [], supabaseUsage: [], firebaseUsage: [],
  supabaseRls: emptySupabaseRlsInfo(), databaseCalls: [], imports: [],
  dangerousOperations: [], publicClientUsage: [], serverSideUsage: [], authSignals: [], envUsage: [],
};
const reportBase = { fileMap: emptyFileMap, detectedStack: emptyStack, projectMap: emptyProjectMap };

function finding(ruleId: string, severity: Severity, occurrence: number): Finding {
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
    category: 'configuration',
  });
}

const THREE_RULES = (): Finding[] => [
  finding('sql_injection', 'critical', 0),
  finding('xss', 'high', 1),
  finding('xss', 'medium', 2),
  finding('missing_rate_limit', 'low', 3),
];

describe('the approved impact texts', () => {
  it('the fixture is the approved file, by its fingerprint', () => {
    expect(createHash('sha256').update(fixtureBytes).digest('hex')).toBe(APPROVED_SHA256);
  });

  it('the fixture names exactly the 55 catalog rules', () => {
    expect(Object.keys(approved)).toHaveLength(55);
    expect(Object.keys(approved).sort()).toEqual([...catalogIds].sort());
  });

  it('every catalog rule has an impact text, and none is empty', () => {
    const missing = catalogIds.filter((id) => {
      const text: unknown = (RULE_CATALOG[id] as { impact?: unknown }).impact;
      return typeof text !== 'string' || text.trim().length === 0;
    });
    expect(missing).toEqual([]);
  });

  it('every catalog impact is the approved text, byte for byte', () => {
    expect(catalogIds.filter((id) => RULE_CATALOG[id].impact !== approved[id])).toEqual([]);
  });

  it('impactForRule gives the catalog text, and nothing for a rule the catalog does not know', () => {
    expect(impactForRule('sql_injection')).toBe(approved.sql_injection);
    expect(impactForRule('custom_rule')).toBeUndefined();
    expect(impactForRule('toString')).toBeUndefined();
  });
});

describe('the report carries each rule\'s impact once, in ruleImpacts', () => {
  it('lists exactly the rules that have a finding, in findingsByRule order, with the catalog text', () => {
    const report = buildReport({ ...reportBase, findings: THREE_RULES() });
    expect(Object.keys(report.ruleImpacts ?? {})).toEqual(report.findingsByRule.map((row) => row.ruleId));
    expect(report.ruleImpacts).toEqual({
      sql_injection: approved.sql_injection,
      xss: approved.xss,
      missing_rate_limit: approved.missing_rate_limit,
    });
  });

  it('names no rule that has no finding', () => {
    const report = buildReport({ ...reportBase, findings: [finding('xss', 'high', 0)] });
    expect(Object.keys(report.ruleImpacts ?? {})).toEqual(['xss']);
  });

  it('a truncated report explains only the rules its retained findings belong to', () => {
    const report = buildReport({
      ...reportBase,
      findings: [finding('hardcoded_secret', 'critical', 0), finding('hardcoded_secret', 'critical', 1), finding('xss', 'low', 2)],
      findingLimit: 2,
    });
    expect(report.findings.map((entry) => entry.ruleId)).toEqual(['hardcoded_secret', 'hardcoded_secret']);
    expect(report.ruleImpacts).toEqual({ hardcoded_secret: approved.hardcoded_secret });
  });

  it('a report with no findings, and the timeout report, carry an empty map rather than none', () => {
    expect(buildReport({ ...reportBase, findings: [] }).ruleImpacts).toEqual({});
    expect(buildTimeoutReport({ reason: 'deadline', kind: 'deadline' }).ruleImpacts).toEqual({});
  });

  it('an uncatalogued rule gets a findingsByRule row but no invented paragraph', () => {
    const report = buildReport({ ...reportBase, findings: [finding('custom_rule', 'low', 0), finding('xss', 'high', 1)] });
    expect(report.findingsByRule.map((row) => row.ruleId)).toContain('custom_rule');
    expect(report.ruleImpacts).toEqual({ xss: approved.xss });
    expect(buildRuleImpacts([{ ruleId: 'custom_rule', label: 'x', occurrences: 1, highestSeverity: 'low' }])).toEqual({});
  });

  it('validates against the report schema, and the schema holds the map to non-empty text', () => {
    const report = buildReport({ ...reportBase, findings: THREE_RULES() });
    expect(validateScanReport(report).errors).toEqual([]);
    expect(validateScanReport(buildTimeoutReport({ reason: 'failed', kind: 'failed' })).errors).toEqual([]);
    const { ruleImpacts: _dropped, ...older } = report;
    expect(validateScanReport(older).errors).toEqual([]);
    expect(validateScanReport({ ...report, ruleImpacts: { xss: '' } }).errors).not.toEqual([]);
    expect(validateScanReport({ ...report, ruleImpacts: { xss: 3 } }).errors).not.toEqual([]);
  });

  it('the finding objects carry no impact text, and are the findings the report was given', () => {
    const findings = THREE_RULES();
    const expected = JSON.stringify(findings);
    const report = buildReport({ ...reportBase, findings });
    expect(JSON.stringify(report.findings)).toBe(expected);
    expect(report.findings.filter((entry) => 'impact' in entry)).toEqual([]);
    const findingsJson = JSON.stringify(report.findings);
    expect(catalogImpacts.filter((text) => findingsJson.includes(text))).toEqual([]);
  });
});
