import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { scanProject } from '../../src/scanProject.js';
import { fixturePath } from './helpers.js';
import { buildTimeoutReport } from '../../src/report/buildReport.js';
import { assertValidScanReport, validateScanReport } from '../../src/report/validateReport.js';
import { CURRENT_REPORT_VERSION } from '../../src/shared/reportVersion.js';

describe('ScanReport 2.1 JSON Schema', () => {
  it('accepts reports produced at runtime', () => {
    const report = buildTimeoutReport({ reason: 'fixture timeout', now: () => new Date('2026-01-01T00:00:00Z') });
    expect(validateScanReport(report)).toEqual({ valid: true, errors: [] });
    expect(() => assertValidScanReport(report)).not.toThrow();
  });

  it('rejects false passes and reports from unsupported versions', () => {
    const report = buildTimeoutReport({ reason: 'fixture timeout' });
    const falsePass = structuredClone(report) as unknown as Record<string, unknown>;
    const results = falsePass['ruleResults'] as Record<string, unknown>[];
    results[0] = { ...results[0], status: 'passed', coverage: 'none' };
    const invalid = validateScanReport(falsePass);
    expect(invalid.valid).toBe(false);
    expect(invalid.errors.length).toBeGreaterThan(0);
    expect(validateScanReport({ ...report, reportVersion: '3.0' }).valid).toBe(false);
    const missingProfiles = structuredClone(report) as unknown as Record<string, unknown>;
    delete missingProfiles['routeSecurityProfiles'];
    expect(validateScanReport(missingProfiles).valid).toBe(false);
  });

  describe('report 2.0: the two undeclared fields, and the misnamed one', () => {
    it('a real report carries findingsByRule and never failedRules or a row called error', async () => {
      const report = (await scanProject(fixturePath('next-supabase-insecure'))) as unknown as Record<
        string,
        unknown
      >;
      expect(report['failedRules']).toBeUndefined();
      const rows = report['findingsByRule'] as Record<string, unknown>[];
      expect(rows.length).toBeGreaterThan(0);
      for (const row of rows) {
        expect(row['error']).toBeUndefined();
        expect(typeof row['label']).toBe('string');
      }
      expect(validateScanReport(report)).toEqual({ valid: true, errors: [] });
    });

    it('DECLARES stableId and adjudication rather than letting them ride out undeclared', () => {
      const report = buildTimeoutReport({ reason: 'fixture timeout' }) as unknown as Record<string, unknown>;
      const finding = {
        id: 'f_0123456789ab', ruleId: 'hardcoded_secret', title: 't', severity: 'high', confidence: 'high',
        filePath: 'a.ts', lineStart: 1, lineEnd: 1, evidence: 'e', userExplanation: 'u',
        technicalExplanation: 'x', fixHint: 'f', category: 'secrets', detectionKind: 'pattern', fixPrompt: 'p',
        stableId: `fi1_${'0123456789abcdef'}`,
        adjudication: { required: false, reason: 'database_backed_dependency_advisory', basis: 'b' },
      };
      expect(validateScanReport({ ...report, findings: [finding] })).toEqual({ valid: true, errors: [] });
    });

    it('REFUSES a malformed stableId and an undeclared field on a finding', () => {
      const report = buildTimeoutReport({ reason: 'fixture timeout' }) as unknown as Record<string, unknown>;
      const base = {
        id: 'f_0123456789ab', ruleId: 'hardcoded_secret', title: 't', severity: 'high', confidence: 'high',
        filePath: 'a.ts', lineStart: 1, lineEnd: 1, evidence: 'e', userExplanation: 'u',
        technicalExplanation: 'x', fixHint: 'f', category: 'secrets', detectionKind: 'pattern', fixPrompt: 'p',
      };
      expect(validateScanReport({ ...report, findings: [{ ...base, somethingNobodyDeclared: 1 }] }).valid).toBe(false);
      expect(validateScanReport({ ...report, findings: [{ ...base, stableId: 'not-an-identity' }] }).valid).toBe(false);
      expect(validateScanReport({ ...report, findings: [{ ...base, adjudication: { required: false } }] }).valid).toBe(false);
    });

    it('still accepts a 1.x report carrying failedRules, per the migration window', () => {
      const fixtures = join(__dirname, '..', 'fixtures', 'reports');
      const legacy = JSON.parse(readFileSync(join(fixtures, 'scan-report-1.1-minimal.json'), 'utf8'));
      expect(legacy.failedRules).toBeDefined();
      expect(validateScanReport(legacy).valid).toBe(true);
    });
  });

  it('ships a parseable canonical schema whose version matches CURRENT_REPORT_VERSION', () => {
    const schema = JSON.parse(readFileSync(join(__dirname, '..', '..', 'src', 'report', 'scan-report.schema.json'), 'utf8')) as Record<string, unknown>;
    expect(schema['$schema']).toBe('https://json-schema.org/draft/2020-12/schema');
    expect(schema['$id']).toBe(`https://epherem.dev/schemas/scan-report-${CURRENT_REPORT_VERSION}.json`);
    expect(schema['title']).toBe(`Epherem ScanReport ${CURRENT_REPORT_VERSION}`);

    const properties = schema['properties'] as Record<string, { enum?: string[] }>;
    expect(properties['reportVersion']?.enum).toContain(CURRENT_REPORT_VERSION);
  });

  it('accepts a report at the current version, so no version gate excludes it', () => {
    const report = buildTimeoutReport({ reason: 'fixture timeout', now: () => new Date('2026-01-01T00:00:00Z') });
    expect(report.reportVersion).toBe(CURRENT_REPORT_VERSION);
    expect(validateScanReport(report)).toEqual({ valid: true, errors: [] });
  });

  describe('report 2.1: aiReview and aiAdjudication', () => {
    const base = (): Record<string, unknown> =>
      structuredClone(
        buildTimeoutReport({ reason: 'fixture timeout', now: () => new Date('2026-01-01T00:00:00Z') }),
      ) as unknown as Record<string, unknown>;

    it('writes aiAdjudication on every report, and a scanner-only report says NOT ATTEMPTED', () => {
      const report = base();
      expect(report['aiAdjudication']).toEqual({ state: 'not_run', reason: 'not_attempted' });
      expect(validateScanReport(report).valid).toBe(true);
    });

    it('REFUSES a 2.1 report with no aiAdjudication, so absence cannot mean two things', () => {
      const report = base();
      delete report['aiAdjudication'];
      expect(validateScanReport(report).valid).toBe(false);
    });

    it('requires a ran report to account for itself, and a not_run report to say why', () => {
      const ran = base();
      ran['aiAdjudication'] = { state: 'ran' };
      expect(validateScanReport(ran).valid).toBe(false);
      const silent = base();
      silent['aiAdjudication'] = { state: 'not_run' };
      expect(validateScanReport(silent).valid).toBe(false);
    });

    it('accepts each placement and refuses an aiReview that states no outcome', () => {
      const withReview = (aiReview: unknown): Record<string, unknown> => {
        const report = base();
        report['findings'] = [
          {
            id: 'f_0123456789ab',
            ruleId: 'dangerous_cors_wildcard',
            title: 'T',
            severity: 'high',
            confidence: 'medium',
            filePath: 'src/a.ts',
            lineStart: 1,
            lineEnd: 1,
            evidence: 'e',
            userExplanation: 'u',
            technicalExplanation: 't',
            fixHint: 'f',
            fixPrompt: 'p',
            category: 'configuration',
            aiReview,
          },
        ];
        return report;
      };

      expect(
        validateScanReport(
          withReview({ placement: 'rules_only', reason: 'not_required', aiJudged: false, outcome: 'not-required', cache: 'not-consulted' }),
        ).valid,
      ).toBe(true);
      expect(
        validateScanReport(
          withReview({ placement: 'needs_review', reason: 'untrusted_input_markers', outcome: 'withheld', cache: 'not-consulted' }),
        ).valid,
      ).toBe(true);

      expect(
        validateScanReport(withReview({ placement: 'needs_review', reason: 'model_unsure', cache: 'hit' })).valid,
      ).toBe(false);
      expect(
        validateScanReport(
          withReview({ placement: 'rules_only', reason: 'budget_exhausted', outcome: 'budget-exhausted', cache: 'miss' }),
        ).valid,
      ).toBe(false);
      expect(
        validateScanReport(
          withReview({ placement: 'dismissed_visible', severityClass: 'serious', outcome: 'verified', cache: 'miss' }),
        ).valid,
      ).toBe(false);
    });
  });

  it('accepts the previous 1.1 compatibility fixture and fails closed on legacy 1.0', () => {
    const fixtures = join(__dirname, '..', 'fixtures', 'reports');
    const current = JSON.parse(readFileSync(join(fixtures, 'scan-report-1.1-minimal.json'), 'utf8'));
    const legacy = JSON.parse(readFileSync(join(fixtures, 'scan-report-1.0-legacy.json'), 'utf8'));
    expect(validateScanReport(current).valid).toBe(true);
    expect(validateScanReport(legacy).valid).toBe(false);
  });
});
