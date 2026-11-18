import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { buildFileMap } from '../../src/file-map/buildFileMap.js';
import { prepareInput } from '../../src/input/prepareInput.js';
import { buildProjectMap } from '../../src/project-map/buildProjectMap.js';
import { buildReport } from '../../src/report/buildReport.js';
import * as ruleResults from '../../src/report/buildRuleResults.js';
import { validateScanReport } from '../../src/report/validateReport.js';
import { ruleMetadata } from '../../src/rules/ruleRegistry.js';
import type { DependencyAuditSummary, FileMap, ProjectMap, RuleResult, ScanReport } from '../../src/shared/types.js';
import { detectStack } from '../../src/stack-detection/detectStack.js';
import { probeStacks } from '../../src/stack-detection/detectors.js';

const completeAudit: DependencyAuditSummary = {
  performed: true, incomplete: false, source: 'osv.dev', dependenciesCollected: 1, checked: 1,
  notChecked: [], vulnerabilities: [], diagnostics: [], note: 'complete',
};

type Files = Readonly<Record<string, string>>;
interface Scanned { report: ScanReport; projectMap: ProjectMap; evidence: string[] }

async function scan(files: Files): Promise<Scanned> {
  const dir = await mkdtemp(path.join(tmpdir(), 'epherem-supabase-recognised-'));
  try {
    for (const [relative, content] of Object.entries(files)) {
      await mkdir(path.dirname(path.join(dir, relative)), { recursive: true });
      await writeFile(path.join(dir, relative), content);
    }
    const fileMap = buildFileMap(await prepareInput(dir));
    const detectedStack = detectStack(fileMap);
    const projectMap = buildProjectMap(fileMap, detectedStack);
    const report = buildReport({
      findings: [],
      fileMap,
      detectedStack,
      projectMap,
      dependencyAudit: completeAudit,
      archiveObserved: true,
    });
    expect(validateScanReport(report)).toEqual({ valid: true, errors: [] });
    const evidence = detectedStack.stacks.find((stack) => stack.name === 'supabase')?.evidence ?? [];
    return { report, projectMap, evidence };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

const isSupabase = ({ report }: Scanned) => report.summary.detectedStacks.includes('supabase');

const row = (report: ScanReport, ruleId: string): RuleResult => {
  const found = report.ruleResults.find((entry) => entry.ruleId === ruleId);
  if (found === undefined) throw new Error(`no rule row for ${ruleId}`);
  return found;
};

const DATABASE_RULES = ['supabase_readable_sensitive_data', 'supabase_rls_not_detected'] as const;
const SUPABASE_CHECKS = [
  ...DATABASE_RULES,
  'supabase_service_role_exposed',
  'supabase_client_used_for_privileged_operation',
  'public_cloud_storage',
] as const;

const APP = 'export const answer = 42;\n';
const PACKAGE = '{"name":"app","dependencies":{"react":"18.3.1"}}\n';
const SUPABASE_PACKAGE = '{"name":"app","dependencies":{"@supabase/supabase-js":"2.45.0"}}\n';
const SUPABASE_CLIENT =
  "import { createClient } from '@supabase/supabase-js';\n" +
  'export const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY);\n';
const PLAIN_SQL =
  'create table public.notes (id uuid primary key, owner uuid not null, body text);\n' +
  'alter table public.notes enable row level security;\n';
const SUPABASE_SQL = `${PLAIN_SQL}create policy "owner reads" on public.notes for select using (auth.uid() = owner);\n`;
const PUBSPEC =
  'name: app\n' +
  'environment:\n  sdk: ">=3.0.0 <4.0.0"\n' +
  'dependencies:\n  flutter:\n    sdk: flutter\n  supabase_flutter: ^2.5.0\n';
const DART_MAIN =
  "import 'package:supabase_flutter/supabase_flutter.dart';\n" +
  "Future<void> main() async { await Supabase.initialize(url: 'u', anonKey: 'k'); }\n";
const LIBSQL_CLIENT =
  "import { createClient } from '@libsql/client';\n" + "export const db = createClient({ url: 'file:local.db' });\n";
const BASE44_CLIENT =
  "import { createClient } from '@base44/sdk';\n" + "export const base44 = createClient({ appId: 'x' });\n";

describe('the premise, pinned so a change to it is seen', () => {
  it('the database-rule checks are named once, and are exactly the two RLS checks', () => {
    const named = (ruleResults as Record<string, unknown>)['DATABASE_RULE_CHECK_IDS'] as ReadonlySet<string> | undefined;
    expect(named).toBeDefined();
    expect([...(named ?? [])].sort()).toEqual([...DATABASE_RULES]);
    expect(named?.has('public_cloud_storage')).toBe(false);
  });

  it('supabase_rls_not_detected declares the JavaScript/TypeScript it reads, and SQL', () => {
    expect([...(ruleMetadata('supabase_rls_not_detected')?.languages ?? [])].sort()).toEqual([
      'javascript', 'sql', 'typescript',
    ]);
  });
});

describe('the Supabase project folder is Supabase', () => {
  it.each([
    ['supabase/migrations/0001_init.sql', PLAIN_SQL],
    ['apps/web/supabase/migrations/0001_init.sql', PLAIN_SQL],
    ['supabase/seed.sql', PLAIN_SQL],
    ['supabase/functions/hello/index.ts', 'export default () => new Response("ok");\n'],
  ])('%s, and nothing else Supabase-shaped', async (file, content) => {
    const scanned = await scan({ 'package.json': PACKAGE, 'src/app.ts': APP, [file]: content });
    expect(isSupabase(scanned)).toBe(true);
    expect(scanned.evidence).toEqual([`supabase project folder present (${file})`]);
  });

  it('SQL of the same shape elsewhere is not (guard)', async () => {
    const scanned = await scan({ 'package.json': PACKAGE, 'src/app.ts': APP, 'db/migrations/0001_init.sql': PLAIN_SQL });
    expect(isSupabase(scanned)).toBe(false);
  });
});

describe('config.toml counts only as supabase/config.toml', () => {
  it('supabase/config.toml is Supabase (guard: it always was)', async () => {
    const scanned = await scan({ 'package.json': PACKAGE, 'supabase/config.toml': 'project_id = "abcd"\n' });
    expect(isSupabase(scanned)).toBe(true);
    expect(scanned.evidence).toEqual(['supabase config.toml present (supabase/config.toml)']);
  });

  it.each([
    ['.streamlit/config.toml', '[theme]\nprimaryColor = "#F63366"\n'],
    ['config.toml', 'baseURL = "https://example.org/"\nlanguageCode = "en-us"\ntitle = "My Hugo Site"\n'],
    ['.cargo/config.toml', '[build]\ntarget = "wasm32-unknown-unknown"\n'],
  ])('%s is not', async (file, content) => {
    const scanned = await scan({ 'package.json': PACKAGE, 'src/app.ts': APP, [file]: content });
    expect(isSupabase(scanned)).toBe(false);
  });
});

describe('Supabase from Dart', () => {
  it('pubspec.yaml naming supabase_flutter is Supabase', async () => {
    const scanned = await scan({ 'pubspec.yaml': PUBSPEC, 'lib/main.dart': DART_MAIN });
    expect(isSupabase(scanned)).toBe(true);
    expect(scanned.evidence).toEqual(['supabase dependency in pubspec.yaml (pubspec.yaml)']);
  });

  it('and naming supabase alone', async () => {
    const scanned = await scan({ 'pubspec.yaml': 'name: app\ndependencies:\n  supabase: 2.3.0\n' });
    expect(isSupabase(scanned)).toBe(true);
  });

  it('a pubspec.yaml without it is not (guard)', async () => {
    const scanned = await scan({
      'pubspec.yaml': 'name: app\ndescription: talks to supabase\ndependencies:\n  supabase_auth_ui: ^0.5.0\n  http: ^1.2.0\n',
    });
    expect(isSupabase(scanned)).toBe(false);
  });

  it('the probe counts a .dart file importing package:supabase_flutter/', () => {
    const fileMap = {
      entries: [{ path: 'lib/backend/supabase.dart', extension: '.dart', content: DART_MAIN }],
      skipped: [],
      skippedCount: 0,
      warnings: [],
    } as unknown as FileMap;
    expect(probeStacks(fileMap).find((stack) => stack.name === 'supabase')?.evidence).toEqual([
      'supabase dart import (lib/backend/supabase.dart)',
    ]);
  });

  it('guard, and a declared residual: through the real walk a .dart file is not read, so without pubspec.yaml it is not a signal', async () => {
    const scanned = await scan({ 'lib/main.dart': DART_MAIN, 'web/app.js': 'window.x = 1;\n' });
    expect(scanned.report.coverage.languagesDetected).toEqual(['dart', 'javascript']);
    expect(scanned.report.coverage.languagesAnalysed).toEqual(['javascript']);
    expect(isSupabase(scanned)).toBe(false);
  });
});

describe('Supabase from Python', () => {
  it.each([
    ['requirements.txt', 'fastapi==0.110.0\nsupabase==2.3.0\n'],
    ['requirements.txt', 'supabase\n'],
    ['pyproject.toml', '[project]\nname = "api"\ndependencies = [\n  "fastapi>=0.110",\n  "supabase>=2.0",\n]\n'],
    ['pyproject.toml', '[tool.poetry.dependencies]\npython = "^3.11"\nsupabase = "^2.0"\n'],
  ])('%s requiring supabase is Supabase', async (file, content) => {
    const scanned = await scan({ [file]: content, 'app/main.py': 'print("hello")\n' });
    expect(isSupabase(scanned)).toBe(true);
  });

  it('a .py file with from supabase import create_client is Supabase', async () => {
    const scanned = await scan({ 'app/db.py': 'from supabase import create_client, Client\n' });
    expect(isSupabase(scanned)).toBe(true);
    expect(scanned.evidence).toEqual(['supabase python import (app/db.py)']);
  });

  it('packages that only share the name are not (guard)', async () => {
    const scanned = await scan({
      'requirements.txt': 'supabase-auth==2.0.0\npostgrest==0.16.0\n',
      'app/db.py': 'import supabase_auth\nprint("supabase")\n',
    });
    expect(isSupabase(scanned)).toBe(false);
  });
});

describe('the Supabase CLI', () => {
  it('"supabase" in devDependencies is Supabase: the dependency collector returns devDependencies', async () => {
    const scanned = await scan({
      'package.json': '{"name":"app","dependencies":{"react":"18.3.1"},"devDependencies":{"supabase":"^1.200.0"}}\n',
      'src/app.ts': APP,
    });
    expect(isSupabase(scanned)).toBe(true);
    expect(scanned.evidence).toEqual(['dependency "supabase" in package.json']);
  });
});

describe('SQL calling a function only Supabase provides', () => {
  it.each([
    'using (auth.uid() = owner)',
    "using ((auth.jwt() ->> 'role') = 'admin')",
    'USING (("auth"."uid"() = "owner"))',
  ])('%s in a .sql file is Supabase', async (clause) => {
    const scanned = await scan({
      'package.json': PACKAGE,
      'db/schema.sql': `${PLAIN_SQL}create policy "p" on public.notes for select ${clause};\n`,
    });
    expect(isSupabase(scanned)).toBe(true);
    expect(scanned.evidence).toEqual(['supabase auth functions in SQL (db/schema.sql)']);
  });

  it('the same text in a .ts or .md file alone is not (guard)', async () => {
    const scanned = await scan({
      'package.json': PACKAGE,
      'src/policy.ts': 'export const rule = "using (auth.uid() = owner)";\n',
      'docs/rls.md': 'Write `using (auth.uid() = owner)` in your policy.\n',
    });
    expect(isSupabase(scanned)).toBe(false);
  });
});

describe('another library\'s createClient( is not Supabase', () => {
  it.each([
    ['libSQL', LIBSQL_CLIENT],
    ['Base44', BASE44_CLIENT],
  ])('%s: no Supabase usage, and every Supabase check not_applicable', async (_name, client) => {
    const scanned = await scan({ 'package.json': PACKAGE, 'src/db.ts': client });
    expect(isSupabase(scanned)).toBe(false);
    expect(scanned.projectMap.supabaseUsage).toEqual([]);
    for (const ruleId of SUPABASE_CHECKS) expect(row(scanned.report, ruleId).status, ruleId).toBe('not_applicable');
  });

  it('guard: on a Supabase project, a createClient( file is still Supabase usage', async () => {
    const scanned = await scan({
      'package.json': SUPABASE_PACKAGE,
      'src/lib/client.ts': "import { createClient } from './factory';\nexport const db = createClient(URL, KEY);\n",
    });
    expect(isSupabase(scanned)).toBe(true);
    expect(scanned.projectMap.supabaseUsage).toContain('src/lib/client.ts');
  });
});

describe('supabase_rls_not_detected does not pass over code it cannot read', () => {
  const reason = (language: string) =>
    `${language} is detected but this rule currently supports javascript, typescript, sql only.`;

  it('Python client, SQL read: not_completed with the Python reason', async () => {
    const { report } = await scan({
      'app/main.py': 'import os\nurl = os.environ["SUPABASE_URL"]\n',
      'supabase/migrations/0001_init.sql': SUPABASE_SQL,
    });
    expect(row(report, 'supabase_rls_not_detected')).toEqual({
      ruleId: 'supabase_rls_not_detected',
      label: row(report, 'supabase_rls_not_detected').label,
      status: 'not_completed',
      coverage: 'partial',
      coverageReason: reason('python'),
    });
    expect(row(report, 'supabase_readable_sensitive_data')).toMatchObject({ status: 'passed', coverage: 'full' });
  });

  it('Dart client, SQL read: not_completed with the Dart reason', async () => {
    const { report } = await scan({
      'pubspec.yaml': PUBSPEC,
      'lib/main.dart': DART_MAIN,
      'supabase/config.toml': 'project_id = "abcd"\n',
      'supabase/migrations/0001_init.sql': SUPABASE_SQL,
    });
    expect(row(report, 'supabase_rls_not_detected')).toMatchObject({
      status: 'not_completed',
      coverage: 'partial',
      coverageReason: reason('dart'),
    });
  });

  it('guard: a JavaScript/TypeScript Supabase app with SQL, both checks give their real result', async () => {
    const { report } = await scan({
      'package.json': SUPABASE_PACKAGE,
      'src/app.ts': APP,
      'src/lib/supabase.ts': SUPABASE_CLIENT,
      'supabase/migrations/0001_init.sql': SUPABASE_SQL,
    });
    for (const ruleId of DATABASE_RULES) {
      expect(row(report, ruleId), ruleId).toMatchObject({ status: 'passed', coverage: 'full' });
      expect(row(report, ruleId).coverageReason, ruleId).toBeUndefined();
    }
  });
});

describe('a database-rule check given no SQL says so, before anything else', () => {
  const expectNoSqlRow = (report: ScanReport, ruleId: string) =>
    expect(row(report, ruleId), ruleId).toEqual({
      ruleId,
      label: row(report, ruleId).label,
      status: 'not_completed',
      coverage: 'none',
      coverageReason: ruleResults.NO_SQL_COVERAGE_REASON,
    });

  it('a Dart Supabase app with no SQL (Proyecto_Final\'s shape): both checks give the no-SQL sentence', async () => {
    const { report } = await scan({ 'pubspec.yaml': PUBSPEC, 'lib/main.dart': DART_MAIN, 'web/app.js': 'window.x = 1;\n' });
    expect(report.coverage.languagesDetected).toEqual(['dart', 'javascript']);
    for (const ruleId of DATABASE_RULES) expectNoSqlRow(report, ruleId);
  });

  it('and where Supabase was already recognised, the sentence still wins over "dart is detected" (guard)', async () => {
    const { report } = await scan({
      'pubspec.yaml': PUBSPEC,
      'lib/main.dart': DART_MAIN,
      'web/app.js': 'window.x = 1;\n',
      'supabase/config.toml': 'project_id = "abcd"\n',
    });
    for (const ruleId of DATABASE_RULES) expectNoSqlRow(report, ruleId);
  });

  it('guard: public_cloud_storage on a no-SQL Supabase app is unchanged, and not told there was no SQL', async () => {
    const { report } = await scan({ 'package.json': SUPABASE_PACKAGE, 'src/app.ts': APP, 'src/lib/supabase.ts': SUPABASE_CLIENT });
    expect(row(report, 'public_cloud_storage')).toEqual({
      ruleId: 'public_cloud_storage',
      label: row(report, 'public_cloud_storage').label,
      status: 'passed',
      coverage: 'full',
    });
  });

  it('SQL present but unread is not "no SQL": the unread sentence, and the RLS check read the TypeScript', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'epherem-supabase-unread-'));
    try {
      const files: Files = {
        'package.json': SUPABASE_PACKAGE,
        'src/lib/supabase.ts': SUPABASE_CLIENT,
        'supabase/migrations/0001_init.sql': `${SUPABASE_SQL}${'-- padding\n'.repeat(60)}`,
      };
      for (const [relative, content] of Object.entries(files)) {
        await mkdir(path.dirname(path.join(dir, relative)), { recursive: true });
        await writeFile(path.join(dir, relative), content);
      }
      const fileMap = buildFileMap(await prepareInput(dir, { limits: { maxFileSizeBytes: 400 } }));
      const detectedStack = detectStack(fileMap);
      const report = buildReport({
        findings: [], fileMap, detectedStack, projectMap: buildProjectMap(fileMap, detectedStack),
        dependencyAudit: completeAudit, archiveObserved: true,
      });
      expect(report.coverage.unreadExtensions).toEqual({ '.sql': 1 });
      const unreadSentence =
        "Some of this project's sql source was never opened by this scan " +
        '(see the unread file types in the coverage section), so no finding from this check covers it.';
      expect(row(report, 'supabase_readable_sensitive_data')).toMatchObject({
        status: 'not_completed', coverage: 'none', coverageReason: unreadSentence,
      });
      expect(row(report, 'supabase_rls_not_detected')).toMatchObject({
        status: 'not_completed', coverage: 'partial', coverageReason: unreadSentence,
      });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe('a migrations-only Supabase project (rfc\'s shape)', () => {
  it('every Supabase check applies, and each gives its real result', async () => {
    const scanned = await scan({
      'package.json': PACKAGE,
      'src/App.tsx': 'export default function App() { return null; }\n',
      'supabase/migrations/20250930213926_profiles.sql': SUPABASE_SQL,
    });
    expect(isSupabase(scanned)).toBe(true);
    expect(scanned.projectMap.supabaseUsage).toEqual([]);
    for (const ruleId of SUPABASE_CHECKS) {
      expect(row(scanned.report, ruleId), ruleId).toMatchObject({ status: 'passed', coverage: 'full' });
    }
  });
});
