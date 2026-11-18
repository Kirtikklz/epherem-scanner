import { emptySupabaseRlsInfo } from '../../src/project-map/detectRls.js';
import { describe, expect, it } from 'vitest';
import { buildReport } from '../../src/report/buildReport.js';
import { makeFinding } from '../../src/shared/findingFactory.js';
import type { DependencyAuditSummary, Finding, Severity } from '../../src/shared/types.js';

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

function codeFinding(severity: Severity, i: number): Finding {
  return makeFinding({
    ruleId: 'sql_injection',
    title: `Code finding ${i}`,
    severity,
    confidence: 'high',
    filePath: `src/code${i}.ts`,
    lineStart: i + 1,
    evidence: `code-evidence-${i}`,
    userExplanation: 'user',
    technicalExplanation: 'technical',
    fixHint: 'fix',
    category: 'injection',
  });
}

function dependencyFinding(severity: Severity, i: number): Finding {
  return makeFinding({
    ruleId: 'dependency_vulnerability',
    title: `Vulnerable dependency ${i}`,
    severity,
    confidence: 'high',
    filePath: '(dependencies)',
    lineStart: 1,
    evidence: `dep-evidence-${i}`,
    userExplanation: 'user',
    technicalExplanation: 'technical',
    fixHint: 'fix',
    category: 'dependencies',
  });
}

const base = () => ({
  fileMap: emptyFileMap,
  detectedStack: emptyStack,
  projectMap: emptyProjectMap,
  dependencyAudit: completeAudit,
});

describe('buildReport truncation semantics (code / dependency / final-report)', () => {
  it('NO truncation: everything complete, no truncation warnings', () => {
    const findings = [codeFinding('critical', 0), codeFinding('high', 1), dependencyFinding('high', 0)];
    const report = buildReport({ ...base(), findings, codeScanTruncated: false, findingLimit: 10 });

    expect(report.codeScanStatus).toBe('complete');
    expect(report.dependencyAuditStatus).toBe('complete');
    expect(report.scanStatus).toBe('complete');
    expect(report.findings).toHaveLength(3);
    expect(report.warnings.some((w) => /truncated|not shown/i.test(w))).toBe(false);
  });

  it('CODE-ONLY truncation: code rules stopped early -> code scan incomplete, deps still complete', () => {
    const findings = [codeFinding('critical', 0), codeFinding('high', 1)];
    const report = buildReport({ ...base(), findings, codeScanTruncated: true, findingLimit: 10 });

    expect(report.codeScanStatus).toBe('incomplete');
    expect(report.dependencyAuditStatus).toBe('complete');
    expect(report.scanStatus).toBe('incomplete');
    expect(report.warnings.some((w) => /code rules were running/i.test(w))).toBe(true);
    expect(report.warnings.some((w) => /report shows the first/i.test(w))).toBe(false);
  });

  it('DEPENDENCY-ONLY truncation: dep findings hidden by the cap does NOT mark the code scan incomplete', () => {
    const findings = [
      codeFinding('critical', 0),
      codeFinding('critical', 1),
      dependencyFinding('low', 0),
      dependencyFinding('low', 1),
      dependencyFinding('low', 2),
    ];
    const report = buildReport({ ...base(), findings, codeScanTruncated: false, findingLimit: 2 });

    expect(report.codeScanStatus).toBe('complete');
    expect(report.scanStatus).toBe('incomplete');
    expect(report.warnings.some((w) => /dependency issue\(s\) are not shown/i.test(w))).toBe(true);
    expect(report.warnings.some((w) => /report shows the first/i.test(w))).toBe(true);
    expect(report.warnings.some((w) => /code rules were running/i.test(w))).toBe(false);
    expect(report.findings).toHaveLength(2);
    expect(report.findings.every((f) => f.severity === 'critical')).toBe(true);
  });

  it('COMBINED truncation: both a code-rule warning and a dependency-truncation warning', () => {
    const findings = [
      codeFinding('critical', 0),
      codeFinding('critical', 1),
      dependencyFinding('low', 0),
      dependencyFinding('low', 1),
      dependencyFinding('low', 2),
    ];
    const report = buildReport({ ...base(), findings, codeScanTruncated: true, findingLimit: 2 });

    expect(report.codeScanStatus).toBe('incomplete');
    expect(report.scanStatus).toBe('incomplete');
    expect(report.warnings.some((w) => /code rules were running/i.test(w))).toBe(true);
    expect(report.warnings.some((w) => /dependency issue\(s\) are not shown/i.test(w))).toBe(true);
    expect(report.findings).toHaveLength(2);
  });
});
