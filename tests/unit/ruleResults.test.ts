import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { emptySupabaseRlsInfo } from '../../src/project-map/detectRls.js';
import { describe, expect, it } from 'vitest';
import { buildFileMap } from '../../src/file-map/buildFileMap.js';
import { prepareInput } from '../../src/input/prepareInput.js';
import { buildReport, buildTimeoutReport } from '../../src/report/buildReport.js';
import { RULE_REGISTRY } from '../../src/rules/ruleRegistry.js';
import { makeFinding } from '../../src/shared/findingFactory.js';
import { CURRENT_REPORT_VERSION } from '../../src/shared/reportVersion.js';
import type { DependencyAuditSummary, Finding, Severity } from '../../src/shared/types.js';

const fileMap = {
  rootPath: '/',
  entries: [{
    path: 'src/app.ts', extension: '.ts', label: 'unknown_useful' as const, size: 10,
    isLikelyConfig: false, isLikelyApiRoute: false, isLikelyAuthRelated: false,
    isLikelyDatabaseRelated: false, isLikelyMiddleware: false, usesEnvVariables: false,
    technologyHints: [], content: 'const ok = true;',
  }],
  skipped: [], skippedCount: 0, warnings: [],
};
const emptyStack = { stacks: [] };
const emptyProjectMap = {
  apiRoutes: [], frontendComponents: [], authFiles: [], middlewareFiles: [], middlewareMatchers: [],
  databaseFiles: [], envFiles: [], configFiles: [], supabaseUsage: [], firebaseUsage: [],
  supabaseRls: emptySupabaseRlsInfo(), databaseCalls: [], imports: [],
  dangerousOperations: [], publicClientUsage: [], serverSideUsage: [], authSignals: [], envUsage: [],
};
const completeAudit: DependencyAuditSummary = {
  performed: true, incomplete: false, source: 'osv.dev', dependenciesCollected: 1,
  checked: 1, notChecked: [], vulnerabilities: [], diagnostics: [], note: 'complete',
};

function finding(ruleId: string, severity: Severity, index: number, category: Finding['category'] = 'configuration'): Finding {
  return makeFinding({
    ruleId, title: `Finding ${index}`, severity, confidence: 'high',
    filePath: `src/file-${index}.ts`, lineStart: index + 1, evidence: `evidence-${index}`,
    userExplanation: 'user', technicalExplanation: 'technical', fixHint: 'fix', category,
  });
}

const base = (dependencyAudit: DependencyAuditSummary = completeAudit) => ({
  fileMap, detectedStack: emptyStack, projectMap: emptyProjectMap, dependencyAudit,
});

function status(report: ReturnType<typeof buildReport>, ruleId: string): string | undefined {
  return report.ruleResults.find((entry) => entry.ruleId === ruleId)?.status;
}

describe('report schema and per-rule outcomes', () => {
  it('returns the versioned report contract and one result per catalogued rule', () => {
    const report = buildReport({ ...base(), findings: [] });
    expect(report.reportVersion).toBe(CURRENT_REPORT_VERSION);
    expect(report.ruleResults).toHaveLength(RULE_REGISTRY.length);
    expect(report.ruleResults.map((entry) => entry.ruleId)).toEqual(
      [...report.ruleResults.map((entry) => entry.ruleId)].sort((a, b) => a.localeCompare(b)),
    );
  });

  it('marks findings failed, generic completed checks passed, and irrelevant technology checks not applicable', () => {
    const report = buildReport({ ...base(), findings: [finding('xss', 'high', 0, 'xss')] });
    expect(status(report, 'xss')).toBe('failed');
    expect(status(report, 'hardcoded_secret')).toBe('passed');
    expect(status(report, 'firebase_open_rules')).toBe('not_applicable');
    expect(status(report, 'supabase_rls_not_detected')).toBe('not_applicable');
  });

  it('never claims absent checks passed when the code scan is incomplete', () => {
    const report = buildReport({
      ...base(), findings: [finding('xss', 'high', 0, 'xss')], codeScanTruncated: true,
    });
    expect(status(report, 'xss')).toBe('failed');
    expect(status(report, 'hardcoded_secret')).toBe('not_completed');
    expect(report.scanStatus).toBe('incomplete');
  });

  it('marks a skipped or crashed rule not completed when execution metadata is supplied', () => {
    const report = buildReport({
      ...base(), findings: [], completedRuleIds: ['hardcoded_secret'],
    });
    expect(status(report, 'hardcoded_secret')).toBe('passed');
    expect(status(report, 'xss')).toBe('not_completed');
  });

  it('uses complete dependency coverage to distinguish passed from not applicable', () => {
    const checked = buildReport({ ...base(), findings: [] });
    expect(status(checked, 'dependency_vulnerability')).toBe('passed');

    const none = buildReport({
      ...base({ ...completeAudit, dependenciesCollected: 0, checked: 0 }), findings: [],
    });
    expect(status(none, 'dependency_vulnerability')).toBe('not_applicable');
  });

  it('marks an incomplete dependency audit not completed unless a vulnerability is already known', () => {
    const incomplete = { ...completeAudit, incomplete: true, note: 'network failure' };
    const noKnownVulnerability = buildReport({ ...base(incomplete), findings: [] });
    expect(status(noKnownVulnerability, 'dependency_vulnerability')).toBe('not_completed');

    const knownVulnerability = buildReport({
      ...base(incomplete),
      findings: [finding('dependency_vulnerability', 'critical', 0, 'dependencies')],
    });
    expect(status(knownVulnerability, 'dependency_vulnerability')).toBe('failed');
  });

  it('retains failed outcomes for findings hidden by the final report cap', () => {
    const report = buildReport({
      ...base(),
      findings: [finding('hardcoded_secret', 'critical', 0, 'secrets'), finding('xss', 'low', 1, 'xss')],
      findingLimit: 1,
    });
    expect(report.findingsByRule.map((entry) => entry.ruleId)).toEqual(['hardcoded_secret']);
    expect(status(report, 'hardcoded_secret')).toBe('failed');
    expect(status(report, 'xss')).toBe('failed');
    expect(report.scanStatus).toBe('incomplete');
  });

  it('marks every rule not completed in a hard-timeout report', () => {
    const report = buildTimeoutReport({ reason: 'deadline exceeded' });
    expect(report.reportVersion).toBe(CURRENT_REPORT_VERSION);
    expect(report.findingsByRule).toEqual([]);
    expect(report.ruleResults).toHaveLength(RULE_REGISTRY.length);
    expect(report.ruleResults.every((entry) => entry.status === 'not_completed')).toBe(true);
    expect(report.coverage.partiallyCoveredRules).toHaveLength(RULE_REGISTRY.length);
  });

  async function scanDir(write: (dir: string) => Promise<void>) {
    const dir = await mkdtemp(path.join(tmpdir(), 'epherem-rule-results-'));
    try {
      await write(dir);
      return buildReport({ ...base(), fileMap: buildFileMap(await prepareInput(dir)), findings: [] });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }

  it('never reports language-specific rules passed for unsupported source languages', async () => {
    const report = await scanDir(async (dir) => {
      await writeFile(path.join(dir, 'schema.sql'), 'select 1;');
      await writeFile(path.join(dir, 'main.go'), 'package main');
    });
    const xss = report.ruleResults.find((entry) => entry.ruleId === 'xss');
    expect(xss).toMatchObject({ status: 'not_completed', coverage: 'none' });
    expect(report.coverage.unsupportedLanguages).toEqual(['go']);
    expect(report.coverage.reasons.join(' ')).toContain('go');
    expect(report.coverage.filesAnalysed).toBe(1);
  });

  it('reports partial coverage for mixed supported and unsupported source', async () => {
    const report = await scanDir(async (dir) => {
      await mkdir(path.join(dir, 'src'), { recursive: true });
      await writeFile(path.join(dir, 'src', 'app.ts'), 'const ok = true;');
      await writeFile(path.join(dir, 'main.rb'), 'puts :ok');
    });
    expect(report.ruleResults.find((entry) => entry.ruleId === 'xss')).toMatchObject({
      status: 'not_completed', coverage: 'partial',
    });
    expect(report.coverage.filesAnalysed).toBe(1);
  });
});
