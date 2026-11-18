import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { buildFileMap } from '../../src/file-map/buildFileMap.js';
import { prepareInput } from '../../src/input/prepareInput.js';
import { buildProjectMap } from '../../src/project-map/buildProjectMap.js';
import { buildReport } from '../../src/report/buildReport.js';
import { DATABASE_RULE_CHECK_IDS } from '../../src/report/buildRuleResults.js';
import { validateScanReport } from '../../src/report/validateReport.js';
import { RULE_REGISTRY } from '../../src/rules/ruleRegistry.js';
import { makeFinding } from '../../src/shared/findingFactory.js';
import { DECLARATIVE_LANGUAGES } from '../../src/shared/languages.js';
import type { DependencyAuditSummary, Finding, InputLimits, RuleResult, ScanReport } from '../../src/shared/types.js';
import { detectStack } from '../../src/stack-detection/detectStack.js';

const completeAudit: DependencyAuditSummary = {
  performed: true, incomplete: false, source: 'osv.dev', dependenciesCollected: 1, checked: 1,
  notChecked: [], vulnerabilities: [], diagnostics: [], note: 'complete',
};

type Files = Readonly<Record<string, string>>;

async function scan(files: Files, limits: Partial<InputLimits> = {}, findings: Finding[] = []): Promise<ScanReport> {
  const dir = await mkdtemp(path.join(tmpdir(), 'epherem-sql-coverage-'));
  try {
    for (const [relative, content] of Object.entries(files)) {
      await mkdir(path.dirname(path.join(dir, relative)), { recursive: true });
      await writeFile(path.join(dir, relative), content);
    }
    const fileMap = buildFileMap(await prepareInput(dir, { limits }));
    const detectedStack = detectStack(fileMap);
    const report = buildReport({
      findings,
      fileMap,
      detectedStack,
      projectMap: buildProjectMap(fileMap, detectedStack),
      dependencyAudit: completeAudit,
      archiveObserved: true,
    });
    expect(validateScanReport(report)).toEqual({ valid: true, errors: [] });
    return report;
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

const row = (report: ScanReport, ruleId: string): RuleResult => {
  const found = report.ruleResults.find((entry) => entry.ruleId === ruleId);
  if (found === undefined) throw new Error(`no rule row for ${ruleId}`);
  return found;
};

const CODE_RULES = RULE_REGISTRY.filter((meta) => meta.languages.includes('javascript')).map((meta) => meta.ruleId);
const SQL_ONLY_RULES = RULE_REGISTRY.filter(
  (meta) => meta.languages.length === 1 && meta.languages[0] === 'sql',
).map((meta) => meta.ruleId);
const DATABASE_RULES = [...DATABASE_RULE_CHECK_IDS];
const codeRows = (report: ScanReport) => report.ruleResults.filter((entry) => CODE_RULES.includes(entry.ruleId as never));

const APP = 'export const answer = 42;\n';
const SUPABASE_CLIENT =
  "import { createClient } from '@supabase/supabase-js';\n" +
  'export const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY);\n';
const MIGRATION =
  'create table public.notes (id uuid primary key, owner uuid not null, body text);\n' +
  'alter table public.notes enable row level security;\n' +
  'create policy "owner reads" on public.notes for select using (auth.uid() = owner);\n';
const PLAIN_MIGRATION_PATH = 'db/migrations/0001_init.sql';
const PLAIN_MIGRATION =
  'create table public.notes (id uuid primary key, owner uuid not null, body text);\n' +
  'alter table public.notes enable row level security;\n';

describe('the premise, pinned so a change to it is seen', () => {
  it('config and SQL are the declarative-file languages, and nothing else is', () => {
    expect([...DECLARATIVE_LANGUAGES].sort()).toEqual(['config', 'sql']);
  });

  it('one rule reads SQL and nothing else, and every code rule reads JavaScript and TypeScript', () => {
    expect(SQL_ONLY_RULES.sort()).toEqual(['supabase_readable_sensitive_data']);
    for (const meta of RULE_REGISTRY.filter((entry) => entry.languages.includes('javascript'))) {
      expect(meta.languages).toContain('typescript');
    }
  });
});

describe('a JavaScript/TypeScript project with a SQL migration', () => {
  it('every code check reports full coverage, and no reason names SQL', async () => {
    const report = await scan({
      'src/app.ts': APP,
      'src/lib/supabase.ts': SUPABASE_CLIENT,
      'supabase/migrations/0001_init.sql': MIGRATION,
    });
    expect(report.coverage.languagesDetected).toEqual(['sql', 'typescript']);
    expect(report.coverage.languagesAnalysed).toEqual(['sql', 'typescript']);
    for (const entry of codeRows(report)) {
      if (entry.status === 'not_applicable') continue;
      expect(entry, entry.ruleId).toMatchObject({ status: 'passed', coverage: 'full' });
      expect(entry.coverageReason, entry.ruleId).toBeUndefined();
    }
    expect(report.coverage.partiallyCoveredRules).toEqual([]);
    expect(report.statusSummary.reasonCodes).not.toContain('partial_rule_coverage');
    expect(report.scanStatus).toBe('complete');
  });

  it('the two SQL-only checks are not made partial by the TypeScript', async () => {
    const report = await scan({
      'src/app.ts': APP,
      'src/lib/supabase.ts': SUPABASE_CLIENT,
      'supabase/migrations/0001_init.sql': MIGRATION,
    });
    for (const ruleId of SQL_ONLY_RULES) {
      expect(row(report, ruleId), ruleId).toEqual(expect.objectContaining({ status: 'passed', coverage: 'full' }));
      expect(row(report, ruleId).coverageReason, ruleId).toBeUndefined();
    }
  });

  it('nor by Python or Go: a code language never makes a SQL-only check partial', async () => {
    const report = await scan({
      'src/app.ts': APP,
      'src/lib/supabase.ts': SUPABASE_CLIENT,
      'worker/job.py': 'x = 1\n',
      'api/server.go': 'package main\n',
      'supabase/migrations/0001_init.sql': MIGRATION,
    });
    for (const ruleId of SQL_ONLY_RULES) {
      expect(row(report, ruleId), ruleId).toEqual(expect.objectContaining({ status: 'passed', coverage: 'full' }));
    }
    expect(report.scanStatus).toBe('incomplete');
    expect(report.coverage.unsupportedLanguages).toEqual(['go']);
  });
});

describe('a real gap still counts, word for word as before', () => {
  it('Python makes a JavaScript/TypeScript-only check partial, with the Python reason', async () => {
    const report = await scan({ 'src/app.ts': APP, 'worker/job.py': 'x = 1\n' });
    expect(row(report, 'prototype_pollution')).toEqual({
      ruleId: 'prototype_pollution',
      label: row(report, 'prototype_pollution').label,
      status: 'not_completed',
      coverage: 'partial',
      coverageReason: 'python is detected but this rule currently supports javascript, typescript only.',
    });
    expect(row(report, 'xss')).toMatchObject({ status: 'passed', coverage: 'full' });
    expect(report.statusSummary.reasonCodes).toContain('partial_rule_coverage');
  });

  it('and a SQL migration beside the Python changes no code check at all', async () => {
    const without = await scan({ 'src/app.ts': APP, 'worker/job.py': 'x = 1\n' });
    const withSql = await scan({
      'src/app.ts': APP,
      'worker/job.py': 'x = 1\n',
      [PLAIN_MIGRATION_PATH]: PLAIN_MIGRATION,
    });
    expect(codeRows(withSql)).toEqual(codeRows(without));
  });

  it('Go makes every code check partial, with the Go reason', async () => {
    const report = await scan({ 'src/app.ts': APP, 'api/server.go': 'package main\n' });
    expect(row(report, 'xss')).toMatchObject({
      status: 'not_completed',
      coverage: 'partial',
      coverageReason: 'go is detected but this rule currently supports javascript, typescript, python only.',
    });
    expect(report.scanStatus).toBe('incomplete');
    expect(report.coverage.unsupportedLanguages).toEqual(['go']);
  });

  it('and a SQL migration beside the Go changes no code check at all', async () => {
    const without = await scan({ 'src/app.ts': APP, 'api/server.go': 'package main\n' });
    const withSql = await scan({
      'src/app.ts': APP,
      'api/server.go': 'package main\n',
      [PLAIN_MIGRATION_PATH]: PLAIN_MIGRATION,
    });
    expect(codeRows(withSql)).toEqual(codeRows(without));
  });

  it('Go with SQL and no JavaScript/TypeScript: the code checks covered none of it, and say it is the Go', async () => {
    const report = await scan({ 'api/server.go': 'package main\n', 'supabase/migrations/0001_init.sql': MIGRATION });
    expect(row(report, 'xss')).toMatchObject({
      status: 'not_completed',
      coverage: 'none',
      coverageReason: 'go is detected but this rule currently supports javascript, typescript, python only.',
    });
  });

  it('an unread .mts file still stops the TypeScript checks passing, SQL or not', async () => {
    const without = await scan({ 'src/app.ts': APP, 'src/server.mts': 'export const port = 3000;\n' });
    const withSql = await scan({
      'src/app.ts': APP,
      'src/server.mts': 'export const port = 3000;\n',
      [PLAIN_MIGRATION_PATH]: PLAIN_MIGRATION,
    });
    expect(withSql.coverage.unreadExtensions).toEqual({ '.mts': 1 });
    expect(row(withSql, 'xss')).toMatchObject({
      status: 'not_completed',
      coverage: 'partial',
      coverageReason:
        "Some of this project's typescript source was never opened by this scan " +
        '(see the unread file types in the coverage section), so no finding from this check covers it.',
    });
    expect(codeRows(withSql)).toEqual(codeRows(without));
  });
});

describe('an unread .sql file still means the SQL checks did not see all of it', () => {
  const limits = { maxFileSizeBytes: 400 };
  const bigMigration = `${MIGRATION}${'-- padding\n'.repeat(60)}`;

  it('the SQL-only checks do not pass over it, and the code checks are not touched by it', async () => {
    const report = await scan(
      { 'src/app.ts': APP, 'src/lib/supabase.ts': SUPABASE_CLIENT, 'supabase/migrations/0001_init.sql': bigMigration },
      limits,
    );
    expect(report.coverage.unreadExtensions).toEqual({ '.sql': 1 });
    for (const ruleId of SQL_ONLY_RULES) {
      expect(row(report, ruleId), ruleId).toMatchObject({
        status: 'not_completed',
        coverage: 'none',
        coverageReason:
          "Some of this project's sql source was never opened by this scan " +
          '(see the unread file types in the coverage section), so no finding from this check covers it.',
      });
    }
    expect(row(report, 'hardcoded_secret')).toMatchObject({ status: 'passed', coverage: 'full' });
    expect(report.scanStatus).toBe('incomplete');
  });

  it('with another migration read, the SQL-only checks are partial rather than none', async () => {
    const report = await scan(
      {
        'src/app.ts': APP,
        'src/lib/supabase.ts': SUPABASE_CLIENT,
        'supabase/migrations/0001_init.sql': bigMigration,
        'supabase/migrations/0002_more.sql': MIGRATION,
      },
      limits,
    );
    for (const ruleId of SQL_ONLY_RULES) {
      expect(row(report, ruleId), ruleId).toMatchObject({
        status: 'not_completed',
        coverage: 'partial',
        coverageReason:
          "Some of this project's sql source was never opened by this scan " +
          '(see the unread file types in the coverage section), so no finding from this check covers it.',
      });
    }
  });
});

describe('a project with SQL and no code does not start passing the code checks', () => {
  const expectCodeChecksNotPassed = (report: ScanReport) => {
    let judged = 0;
    for (const entry of codeRows(report)) {
      if (entry.status === 'not_applicable') continue;
      judged += 1;
      const meta = RULE_REGISTRY.find((candidate) => candidate.ruleId === entry.ruleId);
      const supports = meta?.languages.filter((language) => language !== 'config').join(', ');
      if (meta?.languages.includes('sql')) {
        expect(entry, entry.ruleId).toMatchObject({ status: 'passed', coverage: 'full' });
        continue;
      }
      expect(entry, entry.ruleId).toEqual({
        ruleId: entry.ruleId,
        label: entry.label,
        status: 'not_completed',
        coverage: 'none',
        coverageReason: `sql is detected but this rule currently supports ${supports} only.`,
      });
    }
    expect(judged).toBeGreaterThan(30);
  };

  it('SQL only', async () => {
    const report = await scan({ 'supabase/migrations/0001_init.sql': MIGRATION, 'README.md': '# notes\n' });
    expect(report.coverage.languagesDetected).toEqual(['sql']);
    expectCodeChecksNotPassed(report);
    expect(row(report, 'supabase_readable_sensitive_data')).toMatchObject({ status: 'passed', coverage: 'full' });
  });

  it('SQL and configuration only', async () => {
    const report = await scan({
      'supabase/migrations/0001_init.sql': MIGRATION,
      'supabase/config.toml': '[api]\nport = 54321\n',
      'settings.json': '{"name":"notes"}\n',
    });
    expect(report.coverage.languagesDetected).toEqual(['sql']);
    expectCodeChecksNotPassed(report);
  });
});

describe('a database-rule check given no SQL did not pass', () => {
  const NO_SQL_REASON =
    'No database SQL was found in this project, so its row-level security rules could not be read. ' +
    'Rules set only in the Supabase dashboard cannot be checked from the code.';
  const PACKAGE = '{"name":"app","dependencies":{"next":"14.2.0"}}\n';
  const OTHER_CLIENT =
    "import { createClient } from '@libsql/client';\n" + "export const db = createClient({ url: 'file:local.db' });\n";

  const expectNoSqlRow = (report: ScanReport, ruleId: string) =>
    expect(row(report, ruleId), ruleId).toEqual({
      ruleId,
      label: row(report, ruleId).label,
      status: 'not_completed',
      coverage: 'none',
      coverageReason: NO_SQL_REASON,
    });

  it('Supabase detected by its client library, no SQL: both checks not_completed with the approved reason', async () => {
    const report = await scan({ 'package.json': PACKAGE, 'src/app.ts': APP, 'src/lib/supabase.ts': SUPABASE_CLIENT });
    expect(report.coverage.languagesDetected).toEqual(['typescript']);
    for (const ruleId of DATABASE_RULES) expectNoSqlRow(report, ruleId);
    expect(row(report, 'public_cloud_storage')).toMatchObject({ status: 'passed', coverage: 'full' });
  });

  it('Supabase detected by supabase/config.toml alone, no SQL: the same', async () => {
    const report = await scan({ 'package.json': PACKAGE, 'src/app.ts': APP, 'supabase/config.toml': '[api]\nport = 54321\n' });
    for (const ruleId of DATABASE_RULES) expectNoSqlRow(report, ruleId);
  });

  it('Supabase and SQL read: the checks report their real result, as before', async () => {
    const report = await scan({ 'src/app.ts': APP, 'src/lib/supabase.ts': SUPABASE_CLIENT, 'supabase/migrations/0001_init.sql': MIGRATION });
    for (const ruleId of DATABASE_RULES) {
      expect(row(report, ruleId), ruleId).toEqual(expect.objectContaining({ status: 'passed', coverage: 'full' }));
      expect(row(report, ruleId).coverageReason, ruleId).toBeUndefined();
    }
  });

  it('a finding still means failed, SQL or no SQL', async () => {
    const finding = makeFinding({
      ruleId: 'supabase_rls_not_detected', title: 'No RLS', severity: 'high', confidence: 'low',
      filePath: 'src/lib/supabase.ts', lineStart: 2, evidence: 'createClient', userExplanation: 'u',
      technicalExplanation: 't', fixHint: 'f', category: 'authorization',
    });
    const report = await scan({ 'src/app.ts': APP, 'src/lib/supabase.ts': SUPABASE_CLIENT }, {}, [finding]);
    expect(row(report, 'supabase_rls_not_detected').status).toBe('failed');
  });

  it('neither Supabase nor SQL: both checks not_applicable', async () => {
    const report = await scan({ 'package.json': PACKAGE, 'src/app.ts': APP });
    for (const ruleId of DATABASE_RULES) expect(row(report, ruleId).status, ruleId).toBe('not_applicable');
    const noCode = await scan({ 'README.md': '# notes\n', 'settings.json': '{"name":"notes"}\n' });
    for (const ruleId of DATABASE_RULES) expect(row(noCode, ruleId).status, ruleId).toBe('not_applicable');
  });

  it('another library\'s createClient( is not Supabase: without SQL both checks are not_applicable', async () => {
    const report = await scan({ 'package.json': PACKAGE, 'src/db.ts': OTHER_CLIENT });
    for (const ruleId of DATABASE_RULES) expect(row(report, ruleId).status, ruleId).toBe('not_applicable');
  });

  it('another library\'s createClient( with SQL: the RLS check does not claim a pass it never ran; the policy check runs', async () => {
    const report = await scan({ 'package.json': PACKAGE, 'src/db.ts': OTHER_CLIENT, [PLAIN_MIGRATION_PATH]: PLAIN_MIGRATION });
    expect(row(report, 'supabase_rls_not_detected').status).toBe('not_applicable');
    expect(row(report, 'supabase_readable_sensitive_data')).toMatchObject({ status: 'passed', coverage: 'full' });
  });

  it('SQL read and no Supabase detected: the policy check reports its real result', async () => {
    const report = await scan({ 'package.json': PACKAGE, [PLAIN_MIGRATION_PATH]: PLAIN_MIGRATION });
    expect(report.summary.detectedStacks).not.toContain('supabase');
    expect(row(report, 'supabase_readable_sensitive_data')).toMatchObject({ status: 'passed', coverage: 'full' });
  });

  it('SQL present but none read, no Supabase: the policy check says it was not opened, never not_applicable', async () => {
    const report = await scan(
      { 'package.json': PACKAGE, 'src/app.ts': APP, 'db/migrations/0001_init.sql': `${MIGRATION}${'-- padding\n'.repeat(60)}` },
      { maxFileSizeBytes: 400 },
    );
    expect(report.coverage.unreadExtensions).toEqual({ '.sql': 1 });
    expect(row(report, 'supabase_readable_sensitive_data')).toMatchObject({
      status: 'not_completed',
      coverage: 'none',
      coverageReason:
        "Some of this project's sql source was never opened by this scan " +
        '(see the unread file types in the coverage section), so no finding from this check covers it.',
    });
  });
});
