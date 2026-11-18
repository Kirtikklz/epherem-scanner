import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildFileMap } from '../../src/file-map/buildFileMap.js';
import { prepareInput } from '../../src/input/prepareInput.js';
import { emptySupabaseRlsInfo } from '../../src/project-map/detectRls.js';
import { buildReport } from '../../src/report/buildReport.js';
import { validateScanReport } from '../../src/report/validateReport.js';
import type { DependencyAuditSummary, ScanReport } from '../../src/shared/types.js';

const emptyStack = { stacks: [] };
const emptyProjectMap = {
  apiRoutes: [], frontendComponents: [], authFiles: [], middlewareFiles: [], middlewareMatchers: [],
  databaseFiles: [], envFiles: [], configFiles: [], supabaseUsage: [], firebaseUsage: [],
  supabaseRls: emptySupabaseRlsInfo(), databaseCalls: [], imports: [],
  dangerousOperations: [], publicClientUsage: [], serverSideUsage: [], authSignals: [], envUsage: [],
};

const completeAudit: DependencyAuditSummary = {
  performed: true, incomplete: false, source: 'osv.dev', dependenciesCollected: 1, checked: 1,
  notChecked: [], vulnerabilities: [], diagnostics: [], note: 'complete',
};

async function scan(projectDir: string): Promise<ScanReport> {
  const fileMap = buildFileMap(await prepareInput(projectDir));
  const report = buildReport({
    findings: [],
    fileMap,
    detectedStack: emptyStack,
    projectMap: emptyProjectMap,
    dependencyAudit: completeAudit,
  });
  expect(validateScanReport(report)).toEqual({ valid: true, errors: [] });
  return report;
}

const ruleStatus = (report: ScanReport, ruleId: string): string | undefined =>
  report.ruleResults.find((entry) => entry.ruleId === ruleId)?.status;

const ruleCoverage = (report: ScanReport, ruleId: string): string | undefined =>
  report.ruleResults.find((entry) => entry.ruleId === ruleId)?.coverage;

describe('source in a language the scanner cannot read', () => {
  let projectDir: string;
  let report: ScanReport;

  beforeAll(async () => {
    projectDir = await mkdtemp(path.join(tmpdir(), 'epherem-unread-lang-'));
    await mkdir(path.join(projectDir, 'src'), { recursive: true });
    await mkdir(path.join(projectDir, 'api'), { recursive: true });
    await writeFile(path.join(projectDir, 'src', 'app.ts'), 'export const answer = 42;');
    await writeFile(
      path.join(projectDir, 'api', 'server.go'),
      'package main\n\nfunc main() {\n\tdb.Query("SELECT * FROM users WHERE id = " + r.URL.Query().Get("id"))\n}\n',
    );
    report = await scan(projectDir);
  });

  afterAll(async () => {
    await rm(projectDir, { recursive: true, force: true });
  });

  it('NOTHING ABOUT WHICH FILES ARE READ CHANGED: the .go file is still refused, unopened', () => {
    expect(report.coverage.filesAnalysed).toBe(1);
    expect(report.coverage.filesSkipped).toBe(1);
    expect(report.fileMapSummary.totalFiles).toBe(1);
  });

  it('names the language it could not read', () => {
    expect(report.coverage.unsupportedLanguages).toContain('go');
    expect(report.coverage.languagesDetected).toContain('go');
  });

  it('names the file count for that language, so the gap can be sized', () => {
    expect(report.coverage.reasons.join(' ')).toContain('go (1 file(s))');
  });

  it('sql_injection is NOT passed', () => {
    expect(ruleStatus(report, 'sql_injection')).toBe('not_completed');
    expect(ruleStatus(report, 'sql_injection')).not.toBe('passed');
    expect(ruleCoverage(report, 'sql_injection')).toBe('partial');
  });

  it('the scan is not reported as complete, and the headline is not an all-clear', () => {
    expect(report.scanStatus).toBe('incomplete');
    expect(report.statusSummary.state).toBe('partial');
    expect(report.statusSummary.reasonCodes).toContain('unsupported_languages');
    expect(report.statusSummary.headline).not.toMatch(/whole project|entire project|whole codebase|entire codebase|the fully analysed|across the project/i);
    expect(report.statusSummary.headline).toMatch(/not a clean bill of health/i);
  });

  it('the code scan itself is still complete: the rules that ran, ran', () => {
    expect(report.codeScanStatus).toBe('complete');
    expect(report.warnings).toEqual([]);
  });
});

describe('non-code files the scanner deliberately skips', () => {
  let projectDir: string;
  let report: ScanReport;

  beforeAll(async () => {
    projectDir = await mkdtemp(path.join(tmpdir(), 'epherem-noncode-'));
    await mkdir(path.join(projectDir, 'src'), { recursive: true });
    await writeFile(path.join(projectDir, 'src', 'app.ts'), 'export const answer = 42;');
    await writeFile(path.join(projectDir, 'README.md'), '# Project\n\nSome prose about helmet and CSP.\n');
    await writeFile(path.join(projectDir, 'logo.png'), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00]));
    await writeFile(path.join(projectDir, 'font.woff2'), Buffer.from([0x77, 0x4f, 0x46, 0x32, 0x00]));
    report = await scan(projectDir);
  });

  afterAll(async () => {
    await rm(projectDir, { recursive: true, force: true });
  });

  it('reads exactly the same one file as the polyglot fixture', () => {
    expect(report.coverage.filesAnalysed).toBe(1);
    expect(report.coverage.filesSkipped).toBe(3);
  });

  it('claims no unsupported language', () => {
    expect(report.coverage.unsupportedLanguages).toEqual([]);
    expect(report.coverage.languagesDetected).toEqual(['typescript']);
  });

  it('THE OVERCORRECTION GUARD FOR unreadExtensions: a README is not unread code', () => {
    expect(report.coverage.unreadExtensions).toEqual({});
    expect(report.statusSummary.reasonCodes).not.toContain('unread_extensions');
  });

  it('sql_injection is passed with full coverage', () => {
    expect(ruleStatus(report, 'sql_injection')).toBe('passed');
    expect(ruleCoverage(report, 'sql_injection')).toBe('full');
  });

  it('the verdict is a clean, complete scan', () => {
    expect(report.scanStatus).toBe('complete');
    expect(report.statusSummary.state).toBe('complete_clean');
    expect(report.statusSummary.reasonCodes).not.toContain('unsupported_languages');
  });

  it('the skipped files are still reported for honesty, in the sentence that already said so', () => {
    expect(report.statusSummary.reasonCodes).toContain('files_skipped');
    expect(report.coverage.reasons).toContain('3 unsupported or non-code file(s) were skipped.');
  });
});

describe('source in a file type the walk refuses to open', () => {
  let projectDir: string;
  let report: ScanReport;

  beforeAll(async () => {
    projectDir = await mkdtemp(path.join(tmpdir(), 'epherem-unread-ext-'));
    await mkdir(path.join(projectDir, 'src'), { recursive: true });
    await writeFile(path.join(projectDir, 'package.json'), '{"name":"unread-fixture","version":"1.0.0"}\n');
    await writeFile(path.join(projectDir, 'tsconfig.json'), '{"compilerOptions":{"strict":true}}\n');
    await writeFile(path.join(projectDir, 'src', 'server.mts'), 'export const port = 3000;\n');
    await writeFile(path.join(projectDir, 'src', 'db.mts'), 'export const url = process.env.DATABASE_URL;\n');
    report = await scan(projectDir);
  });

  afterAll(async () => {
    await rm(projectDir, { recursive: true, force: true });
  });

  it('NOTHING ABOUT WHICH FILES ARE READ CHANGED: the .mts files are still refused, unopened', () => {
    expect(report.coverage.filesAnalysed).toBe(2);
    expect(report.coverage.filesSkipped).toBe(2);
  });

  it('names the file type it could not open, and sizes it', () => {
    expect(report.coverage.unreadExtensions).toEqual({ '.mts': 2 });
    expect(report.coverage.reasons.join(' ')).toContain('.mts (2 file(s))');
  });

  it('THE FIELD THAT SPEAKS TO EXAMINATION SAYS NOTHING WAS EXAMINED', () => {
    expect(report.coverage.languagesDetected).toEqual(['typescript']);
    expect(report.coverage.languagesAnalysed).toEqual([]);
    expect(report.coverage.unsupportedLanguages).toEqual([]);
  });

  it('the scan is not reported as complete, and the headline is not an all-clear', () => {
    expect(report.scanStatus).toBe('incomplete');
    expect(report.statusSummary.state).toBe('partial');
    expect(report.statusSummary.reasonCodes).toContain('unread_extensions');
    expect(report.statusSummary.headline).not.toMatch(/whole project|entire project|whole codebase|entire codebase|the fully analysed|across the project/i);
    expect(report.statusSummary.headline).toMatch(/not a clean bill of health/i);
  });

  it('does NOT also call them non-code: the two counts partition filesSkipped', () => {
    expect(report.statusSummary.reasonCodes).not.toContain('files_skipped');
    expect(report.coverage.reasons.join(' ')).not.toContain('unsupported or non-code');
  });

  it('the code scan itself is still complete: the rules that ran, ran', () => {
    expect(report.codeScanStatus).toBe('complete');
    expect(report.warnings).toEqual([]);
  });
});

describe('a project that is partly read and partly refused', () => {
  let projectDir: string;
  let report: ScanReport;

  beforeAll(async () => {
    projectDir = await mkdtemp(path.join(tmpdir(), 'epherem-mixed-ext-'));
    await mkdir(path.join(projectDir, 'src'), { recursive: true });
    await writeFile(path.join(projectDir, 'src', 'app.ts'), 'export const answer = 42;');
    await writeFile(path.join(projectDir, 'src', 'server.mts'), 'export const port = 3000;\n');
    await writeFile(path.join(projectDir, 'src', 'db.mts'), 'export const url = process.env.DATABASE_URL;\n');
    await writeFile(path.join(projectDir, 'README.md'), '# Project\n');
    report = await scan(projectDir);
  });

  afterAll(async () => {
    await rm(projectDir, { recursive: true, force: true });
  });

  it('KEEPS THE COVERAGE IT EARNED: typescript was analysed, because a .ts file was read', () => {
    expect(report.coverage.languagesAnalysed).toContain('typescript');
    expect(report.coverage.unsupportedLanguages).toEqual([]);
    expect(report.coverage.filesAnalysed).toBe(1);
  });

  it('AND STILL ADMITS THE GAP: the refused file type is named and sized', () => {
    expect(report.coverage.unreadExtensions).toEqual({ '.mts': 2 });
    expect(report.scanStatus).toBe('incomplete');
    expect(report.statusSummary.reasonCodes).toContain('unread_extensions');
  });

  it('THE BREAKDOWN ADDS UP: 3 skipped = 2 unread source + 1 non-code', () => {
    expect(report.coverage.filesSkipped).toBe(3);
    expect(report.coverage.reasons).toContain('1 unsupported or non-code file(s) were skipped.');
    expect(report.statusSummary.reasonCodes).toContain('files_skipped');
  });
});
