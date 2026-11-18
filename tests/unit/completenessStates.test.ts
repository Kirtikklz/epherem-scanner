import { emptySupabaseRlsInfo } from '../../src/project-map/detectRls.js';
import { describe, expect, it } from 'vitest';
import { buildReport, buildTimeoutReport } from '../../src/report/buildReport.js';
import { validateScanReport } from '../../src/report/validateReport.js';
import { makeFinding } from '../../src/shared/findingFactory.js';
import type {
  CompletionReasonCode,
  DependencyAuditSummary,
  Finding,
  Severity,
} from '../../src/shared/types.js';

const emptyFileMap = { rootPath: '/', entries: [], skipped: [], skippedCount: 0, warnings: [] };
const emptyStack = { stacks: [] };
const emptyProjectMap = {
  apiRoutes: [], frontendComponents: [], authFiles: [], middlewareFiles: [], middlewareMatchers: [],
  databaseFiles: [], envFiles: [], configFiles: [], supabaseUsage: [], firebaseUsage: [],
  supabaseRls: emptySupabaseRlsInfo(), databaseCalls: [], imports: [],
  dangerousOperations: [], publicClientUsage: [], serverSideUsage: [], authSignals: [], envUsage: [],
};

const completeAudit: DependencyAuditSummary = {
  performed: true, incomplete: false, source: 'osv.dev', dependenciesCollected: 1, checked: 1,
  notChecked: [], vulnerabilities: [], diagnostics: [], note: 'ok',
};
const noLockfileAudit: DependencyAuditSummary = {
  performed: true, incomplete: true, source: 'osv.dev', dependenciesCollected: 3, checked: 0,
  notChecked: ['npm:next', 'npm:react', 'npm:zod'], vulnerabilities: [], diagnostics: [],
  note: 'Incomplete dependency check: no exact versions (no lockfile).',
};
const notPerformedAudit: DependencyAuditSummary = {
  performed: false, incomplete: true, source: 'none', dependenciesCollected: 0, checked: 0,
  notChecked: [], vulnerabilities: [], diagnostics: [], note: 'Dependency audit was not run.',
};

function codeFinding(severity: Severity, i: number): Finding {
  return makeFinding({
    ruleId: 'sql_injection', title: `Code finding ${i}`, severity, confidence: 'high',
    filePath: `src/code${i}.ts`, lineStart: i + 1, evidence: `ev-${i}`,
    userExplanation: 'u', technicalExplanation: 't', fixHint: 'f', category: 'injection',
  });
}

const base = () => ({
  fileMap: emptyFileMap, detectedStack: emptyStack, projectMap: emptyProjectMap,
});

function build(input: Parameters<typeof buildReport>[0]) {
  const report = buildReport(input);
  expect(validateScanReport(report)).toEqual({ valid: true, errors: [] });
  return report;
}

const codes = (report: { statusSummary: { reasonCodes: CompletionReasonCode[] } }) =>
  report.statusSummary.reasonCodes;

const OVERSTATED_COVERAGE =
  /whole project|entire project|whole codebase|entire codebase|the fully analysed|across the project/i;

describe('Section 7 — the twelve completeness states each have a message + reason', () => {
  it('1. complete scan, NO findings → clean headline, complete_no_findings', () => {
    const report = build({ ...base(), findings: [], dependencyAudit: completeAudit, codeScanTruncated: false, findingLimit: 10 });
    expect(report.scanStatus).toBe('complete');
    expect(report.statusSummary.state).toBe('complete_clean');
    expect(codes(report)).toContain('complete_no_findings');
    expect(report.statusSummary.headline).toMatch(/No issues were found in the files this scan analysed/i);
    expect(report.statusSummary.headline).not.toMatch(OVERSTATED_COVERAGE);
  });

  it('2. complete scan, findings found → findings headline, complete_with_findings', () => {
    const report = build({ ...base(), findings: [codeFinding('high', 0)], dependencyAudit: completeAudit, findingLimit: 10 });
    expect(report.scanStatus).toBe('complete');
    expect(report.statusSummary.state).toBe('complete_with_findings');
    expect(codes(report)).toContain('complete_with_findings');
    expect(report.statusSummary.headline).toMatch(/potential issue/i);
    expect(report.statusSummary.headline).not.toMatch(OVERSTATED_COVERAGE);
  });

  it('3. partial scan → state partial, headline is coverage-qualified', () => {
    const report = build({ ...base(), findings: [], dependencyAudit: completeAudit, codeScanTruncated: true, findingLimit: 10 });
    expect(report.scanStatus).toBe('incomplete');
    expect(report.statusSummary.state).toBe('partial');
    expect(report.statusSummary.headline).toMatch(/successfully analysed portion/i);
  });

  it('4. scan failed → state failed, scan_failed, never an all-clear', () => {
    const report = buildTimeoutReport({ reason: 'worker died', kind: 'failed' });
    expect(validateScanReport(report)).toEqual({ valid: true, errors: [] });
    expect(report.statusSummary.state).toBe('failed');
    expect(codes(report)).toEqual(['scan_failed']);
    expect(report.statusSummary.headline).toMatch(/incomplete|not an all-clear/i);
    expect(report.statusSummary.headline).not.toMatch(/no vulnerabilities/i);
  });

  it('5. rule not applicable → ruleResults carries not_applicable', () => {
    const report = build({ ...base(), findings: [], dependencyAudit: completeAudit, findingLimit: 10 });
    const na = report.ruleResults.filter((r) => r.status === 'not_applicable');
    expect(na.length).toBeGreaterThan(0);
    expect(na.some((r) => r.ruleId === 'firebase_open_rules')).toBe(true);
  });

  it('6. rule not completed → ruleResults carries not_completed + a coverage reason', () => {
    const report = build({
      ...base(), findings: [], dependencyAudit: completeAudit, findingLimit: 10,
      ruleFailures: [{ ruleId: 'sql_injection', message: 'boom' }],
    });
    const nc = report.ruleResults.find((r) => r.ruleId === 'sql_injection');
    expect(nc?.status).toBe('not_completed');
    expect(nc?.coverageReason).toMatch(/failed during execution/i);
    expect(codes(report)).toContain('rule_execution_failed');
  });

  it('7. dependency audit incomplete → dependencyAuditStatus + dependency_audit_incomplete + warning', () => {
    const report = build({ ...base(), findings: [], dependencyAudit: noLockfileAudit, findingLimit: 10 });
    expect(report.dependencyAuditStatus).toBe('incomplete');
    expect(codes(report)).toContain('dependency_audit_incomplete');
    expect(report.warnings.some((w) => /Dependency audit is incomplete/i.test(w))).toBe(true);
  });

  it('8. no lockfile → dependency_versions_unresolved (collected but nothing checkable)', () => {
    const report = build({ ...base(), findings: [], dependencyAudit: noLockfileAudit, findingLimit: 10 });
    expect(codes(report)).toContain('dependency_versions_unresolved');
    const clean = build({ ...base(), findings: [], dependencyAudit: completeAudit, findingLimit: 10 });
    expect(codes(clean)).not.toContain('dependency_versions_unresolved');
  });

  it('  (dependency audit not performed is distinct from incomplete)', () => {
    const report = build({ ...base(), findings: [], dependencyAudit: notPerformedAudit, findingLimit: 10 });
    expect(report.dependencyAuditStatus).toBe('not_performed');
    expect(codes(report)).toContain('dependency_audit_not_performed');
  });

  it('9. files skipped → coverage counts + files_skipped + a reason sentence', () => {
    const fileMap = { ...emptyFileMap, skippedCount: 4 };
    const report = build({ ...base(), fileMap, findings: [], dependencyAudit: completeAudit, findingLimit: 10 });
    expect(report.coverage.filesSkipped).toBe(4);
    expect(codes(report)).toContain('files_skipped');
    expect(report.coverage.reasons.some((r) => /skipped/i.test(r))).toBe(true);
  });

  it('  (unsafe archive-skipped files are a distinct reason)', () => {
    const report = build({ ...base(), findings: [], dependencyAudit: completeAudit, findingLimit: 10, archiveSkippedFileCount: 2 });
    expect(report.coverage.filesSkippedUnsafe).toBe(2);
    expect(codes(report)).toContain('unsafe_files_skipped');
    expect(report.coverage.reasons.some((r) => /could not be safely extracted/i.test(r))).toBe(true);
  });

  it('10. cross-file analysis budget exhausted → its OWN message + reason, not the finding-cap message', () => {
    const report = build({ ...base(), findings: [], dependencyAudit: completeAudit, crossFileBudgetTruncated: true, findingLimit: 10 });
    expect(report.codeScanStatus).toBe('incomplete');
    expect(codes(report)).toContain('cross_file_budget_exhausted');
    expect(report.warnings.some((w) => /cross-file analysis budget was exhausted/i.test(w))).toBe(true);
    expect(report.warnings.some((w) => /Finding limit \(/i.test(w))).toBe(false);
    expect(codes(report)).not.toContain('finding_budget_exhausted');
  });

  it('11. finding cap reached → truncation stated, not clean, own reason', () => {
    const findings = [codeFinding('critical', 0), codeFinding('high', 1), codeFinding('medium', 2)];
    const report = build({ ...base(), findings, dependencyAudit: completeAudit, findingLimit: 2 });
    expect(report.scanStatus).toBe('incomplete');
    expect(codes(report)).toContain('report_findings_truncated');
    expect(report.warnings.some((w) => /report shows the first 2 findings out of 3/i.test(w))).toBe(true);
    expect(report.findings).toHaveLength(2);
  });

  it('  (finding BUDGET exhausted during rules is distinct from the report cap)', () => {
    const report = build({ ...base(), findings: [codeFinding('high', 0)], dependencyAudit: completeAudit, codeScanTruncated: true, findingLimit: 10 });
    expect(codes(report)).toContain('finding_budget_exhausted');
    expect(report.warnings.some((w) => /Finding limit \(10\) reached while code rules were running/i.test(w))).toBe(true);
  });

  it('12. scan deadline reached → state failed, scan_deadline_exceeded, distinct from generic failure', () => {
    const report = buildTimeoutReport({ reason: 'hard deadline exceeded', kind: 'deadline' });
    expect(validateScanReport(report)).toEqual({ valid: true, errors: [] });
    expect(report.statusSummary.state).toBe('failed');
    expect(codes(report)).toEqual(['scan_deadline_exceeded']);
    expect(report.statusSummary.headline).toMatch(/ran out of time/i);
  });
});

describe('Section 7 — the crucial UI headline contract', () => {
  it('a PARTIAL scan with zero findings NEVER reads as an unconditional all-clear', () => {
    const partialInputs: Parameters<typeof buildReport>[0][] = [
      { ...base(), findings: [], dependencyAudit: completeAudit, codeScanTruncated: true, findingLimit: 10 },
      { ...base(), findings: [], dependencyAudit: completeAudit, crossFileBudgetTruncated: true, findingLimit: 10 },
      { ...base(), findings: [], dependencyAudit: noLockfileAudit, findingLimit: 10 },
      { ...base(), findings: [], dependencyAudit: notPerformedAudit, findingLimit: 10 },
      { ...base(), findings: [], dependencyAudit: completeAudit, findingLimit: 10, ruleFailures: [{ ruleId: 'xss', message: 'x' }] },
    ];
    for (const input of partialInputs) {
      const report = build(input);
      expect(report.statusSummary.state).toBe('partial');
      expect(report.statusSummary.headline).toMatch(/successfully analysed portion of the project/i);
      expect(report.statusSummary.headline).not.toMatch(/^no vulnerabilities found\.?$/i);
      expect(report.statusSummary.headline).toMatch(/not a clean bill of health/i);
    }
  });

  it('only a fully-complete zero-finding scan may state an unconditional all-clear', () => {
    const report = build({ ...base(), findings: [], dependencyAudit: completeAudit, findingLimit: 10 });
    expect(report.statusSummary.state).toBe('complete_clean');
    expect(report.statusSummary.headline).not.toMatch(/successfully analysed portion/i);
  });

  it('ordinary skipped files (node_modules, images) are surfaced but do NOT make the verdict partial', () => {
    const report = build({ ...base(), fileMap: { ...emptyFileMap, skippedCount: 30 }, findings: [], dependencyAudit: completeAudit, findingLimit: 10 });
    expect(report.statusSummary.state).toBe('complete_clean');
    expect(codes(report)).toContain('files_skipped');
    expect(report.coverage.reasons.some((r) => /skipped/i.test(r))).toBe(true);
  });
});

describe('Section 7 — finding-truncation honesty', () => {
  const findings = [codeFinding('critical', 0), codeFinding('high', 1), codeFinding('medium', 2)];

  it('at the cap: truncation stated, scan not clean, warning present', () => {
    const report = build({ ...base(), findings, dependencyAudit: completeAudit, findingLimit: 2 });
    expect(report.scanStatus).toBe('incomplete');
    expect(report.statusSummary.state).not.toBe('complete_clean');
    expect(report.warnings.some((w) => /not shown because the report reached its size limit/i.test(w))).toBe(true);
  });

  it('rule result counts do NOT imply only retained findings existed', () => {
    const mixed = [
      codeFinding('critical', 0),
      makeFinding({ ruleId: 'xss', title: 'x', severity: 'high', confidence: 'high', filePath: 'a.ts', lineStart: 2, evidence: 'e', userExplanation: 'u', technicalExplanation: 't', fixHint: 'f', category: 'injection' }),
    ];
    const report = build({ ...base(), findings: mixed, dependencyAudit: completeAudit, findingLimit: 1 });
    expect(report.findings).toHaveLength(1);
    const xss = report.ruleResults.find((r) => r.ruleId === 'xss');
    expect(xss?.status).toBe('failed');
  });
});

describe('Section 7 — no headline claims coverage it has no evidence for', () => {
  it('the clean complete headline says what was found, and over what — never how much of the project that was', () => {
    const report = build({ ...base(), findings: [], dependencyAudit: completeAudit, findingLimit: 10 });
    expect(report.statusSummary.state).toBe('complete_clean');
    expect(report.statusSummary.headline).toBe(
      'No issues were found in the files this scan analysed. ' +
        'This is not a statement about any file it did not analyse.',
    );
  });

  it('the with-findings complete headline carries the same qualifier, so a count never reads as a total', () => {
    const report = build({ ...base(), findings: [codeFinding('high', 0)], dependencyAudit: completeAudit, findingLimit: 10 });
    expect(report.statusSummary.state).toBe('complete_with_findings');
    expect(report.statusSummary.headline).toBe(
      '1 potential issue found in the files this scan analysed. ' +
        'This is not a statement about any file it did not analyse.',
    );
  });

  it('NOT ONE of the four states can produce a whole-project claim', () => {
    const reports = [
      build({ ...base(), findings: [], dependencyAudit: completeAudit, findingLimit: 10 }),
      build({ ...base(), findings: [codeFinding('high', 0)], dependencyAudit: completeAudit, findingLimit: 10 }),
      build({ ...base(), findings: [], dependencyAudit: completeAudit, codeScanTruncated: true, findingLimit: 10 }),
      build({ ...base(), findings: [codeFinding('high', 0)], dependencyAudit: completeAudit, codeScanTruncated: true, findingLimit: 10 }),
      buildTimeoutReport({ reason: 'worker died', kind: 'failed' }),
    ];
    const states = reports.map((r) => r.statusSummary.state);
    expect([...new Set(states)].sort()).toEqual(
      ['complete_clean', 'complete_with_findings', 'failed', 'partial'],
    );
    for (const report of reports) {
      expect(report.statusSummary.headline).not.toMatch(OVERSTATED_COVERAGE);
    }
  });
});
