import { describe, expect, it } from 'vitest';
import { buildReport } from '../../src/report/buildReport.js';
import { runRules } from '../../src/rules/index.js';
import { RULE_REGISTRY } from '../../src/rules/ruleRegistry.js';
import { scanProject } from '../../src/scanProject.js';
import { validateScanReport } from '../../src/report/validateReport.js';
import type { ScanRule } from '../../src/shared/types.js';
import { fixturePath, loadFixtureContext } from './helpers.js';
import { CURRENT_REPORT_VERSION } from '../../src/shared/reportVersion.js';

describe('scanProject / buildReport', () => {
  it('produces a JSON-compatible report; a partial dependency audit is never reported "complete"', async () => {
    const report = await scanProject(fixturePath('next-supabase-insecure'));

    expect(report.reportVersion).toBe(CURRENT_REPORT_VERSION);
    expect(report.scanId).toMatch(/^scan_[0-9a-f]{16}$/);
    expect(new Date(report.createdAt).toString()).not.toBe('Invalid Date');
    expect(report.codeScanStatus).toBe('complete');
    expect(report.dependencyAuditStatus).toBe('incomplete');
    expect(report.scanStatus).toBe('incomplete');
    expect(report.warnings.some((warning) => /Dependency audit is incomplete/i.test(warning))).toBe(true);
    expect(report.warnings.some((warning) => /Rule "/.test(warning) || /truncated/i.test(warning))).toBe(false);
    expect(report.summary.totalFindings).toBeGreaterThan(0);
    expect(report.ruleResults).toHaveLength(RULE_REGISTRY.length);
    expect(report.ruleResults.some((rule) => rule.status === 'failed')).toBe(true);
    expect(report.summary.critical).toBeGreaterThan(0);
    expect(report.summary.detectedStacks).toContain('nextjs');
    expect(report.summary.detectedStacks).toContain('supabase');
    expect(report.summary.totalFindings).toBe(
      report.summary.critical + report.summary.high + report.summary.medium + report.summary.low,
    );

    for (const finding of report.findings) {
      expect(finding.id).toMatch(/^f_[0-9a-f]{12}$/);
      expect(finding.ruleId.length).toBeGreaterThan(0);
      expect(['critical', 'high', 'medium', 'low']).toContain(finding.severity);
      expect(['high', 'medium', 'low']).toContain(finding.confidence);
      expect(finding.lineStart).toBeGreaterThan(0);
      expect(finding.lineEnd).toBeGreaterThanOrEqual(finding.lineStart);
      expect(finding.evidence.length).toBeGreaterThan(0);
      expect(finding.userExplanation.length).toBeGreaterThan(0);
      expect(finding.technicalExplanation.length).toBeGreaterThan(0);
      expect(finding.fixHint.length).toBeGreaterThan(0);
    }

    expect(report.fileMapSummary.totalFiles).toBeGreaterThan(0);
    expect(report.fileMapSummary.byLabel['env']).toBe(1);
    expect(report.projectMapSummary.apiRoutes).toBeGreaterThan(0);
    expect(report.routeSecurityProfiles.length).toBeGreaterThan(0);
    expect(report.routeSecurityProfiles.every((profile) => profile.id.startsWith('route_'))).toBe(true);
    expect(report.routeSecurityProfiles.some((profile) => profile.databaseOperations.length > 0)).toBe(true);

    expect(report.dependencyAudit.performed).toBe(true);
    expect(report.dependencyAudit.incomplete).toBe(true);
    expect(report.dependencyAudit.dependenciesCollected).toBeGreaterThan(0);
    expect(report.dependencyAudit.checkCoverage?.skipped ?? []).toEqual([]);
    expect(report.dependencyAudit.diagnostics.some((d) => /No lockfile was found in this project, so 4 exact version pin\(s\) in package\.json/.test(d))).toBe(true);
    expect(report.findings.filter((f) => f.ruleId === 'dependency_vulnerability').every((f) => f.filePath === 'package.json')).toBe(true);
    expect(report.dependencyAudit.note).toMatch(/Incomplete dependency check/i);

    expect(JSON.parse(JSON.stringify(report))).toEqual(report);
  });

  it('a real full-scan report validates against its own shipped JSON schema', async () => {
    for (const fixture of ['next-supabase-insecure', 'clean-basic-project']) {
      const report = await scanProject(fixturePath(fixture));
      expect(validateScanReport(report)).toEqual({ valid: true, errors: [] });
      expect(report.reportVersion).toBe(CURRENT_REPORT_VERSION);
      expect(report.statusSummary.headline.length).toBeGreaterThan(0);
    }
  });

  it('low-confidence findings keep their confidence and are NOT routed through any AI reviewer', async () => {
    const report = await scanProject(fixturePath('sibling-forgotten-route'));
    const lowConfidence = report.findings.filter((finding) => finding.confidence === 'low');
    expect(lowConfidence.length).toBeGreaterThan(0);
    for (const finding of report.findings) {
      expect((finding as unknown as Record<string, unknown>)['aiFallback']).toBeUndefined();
      expect(finding.fixPrompt.length).toBeGreaterThan(0);
    }
  });

  it('is deterministic: two scans of the same project produce identical results', async () => {
    const now = () => new Date('2026-01-01T00:00:00Z');
    const first = await scanProject(fixturePath('next-supabase-insecure'), { now });
    const second = await scanProject(fixturePath('next-supabase-insecure'), { now });
    expect(second).toEqual(first);
  });

  it('reports zero findings and a clean CODE scan for the clean project', async () => {
    const report = await scanProject(fixturePath('clean-basic-project'));
    const codeFindings = report.findings.filter((finding) => finding.ruleId !== 'dependency_vulnerability');
    expect(codeFindings).toEqual([]);
    expect(report.findings.every((finding) => finding.filePath === 'package.json')).toBe(true);
    expect(report.summary.totalFindings).toBe(report.findings.length);
    expect(report.codeScanStatus).toBe('complete');
    expect(report.dependencyAuditStatus).toBe('incomplete');
    expect(report.scanStatus).toBe('incomplete');
    expect(report.summary.detectedStacks).toContain('nextjs');
    expect(report.routeSecurityProfiles).toEqual([
      expect.objectContaining({
        method: 'POST',
        routePath: '/api/items',
        authentication: expect.objectContaining({ status: 'present' }),
        inputValidation: expect.objectContaining({ status: 'present' }),
      }),
    ]);
  });

  it('marks the report incomplete and lists a warning when a rule fails', async () => {
    const context = await loadFixtureContext('clean-basic-project');
    const brokenRule: ScanRule = {
      id: 'broken_rule',
      title: 'Broken rule',
      category: 'configuration',
      kind: 'basic',
      run() {
        throw new Error('boom');
      },
    };
    const result = runRules([brokenRule], context);
    expect(result.failures).toEqual([{ ruleId: 'broken_rule', message: 'boom' }]);

    const report = buildReport({
      findings: result.findings,
      fileMap: context.fileMap,
      detectedStack: context.stack,
      projectMap: context.projectMap,
      ruleFailures: result.failures,
    });
    expect(report.scanStatus).toBe('incomplete');
    expect(report.codeScanStatus).toBe('incomplete');
    expect(report.warnings.some((warning) => warning.includes('broken_rule'))).toBe(true);
  });

  it('marks the report incomplete when input limits truncated the scan', async () => {
    const report = await scanProject(fixturePath('next-supabase-insecure'), {
      inputLimits: { maxTotalFiles: 2 },
    });
    expect(report.scanStatus).toBe('incomplete');
    expect(report.codeScanStatus).toBe('incomplete');
    expect(report.warnings.some((warning) => warning.includes('truncated'))).toBe(true);
  });

  it('finds the expected issues in every insecure fixture', async () => {
    const firebase = await scanProject(fixturePath('firebase-open-rules'));
    expect(firebase.findings.some((finding) => finding.ruleId === 'firebase_open_rules')).toBe(true);

    const express = await scanProject(fixturePath('express-cors-insecure'));
    const expressRuleIds = new Set(express.findings.map((finding) => finding.ruleId));
    expect(expressRuleIds.has('dangerous_cors_wildcard')).toBe(true);
    expect(expressRuleIds.has('hardcoded_secret')).toBe(true);
    expect(expressRuleIds.has('api_mutation_without_auth')).toBe(true);

    const nextReport = await scanProject(fixturePath('next-supabase-insecure'));
    const nextRuleIds = new Set(nextReport.findings.map((finding) => finding.ruleId));
    expect(nextRuleIds.has('supabase_rls_not_detected')).toBe(true);
  });
});
