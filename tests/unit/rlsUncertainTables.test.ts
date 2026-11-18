import { describe, expect, it } from 'vitest';
import { memoryContext } from './helpers.js';
import {
  detectSupabaseRls,
  isCommandCallerBound,
  isCommandDefaultDenied,
  isCommandIdentityScoped,
  isPolicyCertainlyLive,
  isRlsSettledFromSource,
} from '../../src/project-map/detectRls.js';
import { supabaseClientPrivilegedOperation } from '../../src/rules/contextual/supabaseClientPrivilegedOperation.js';
import { databaseDeleteWithoutOwnershipCheck } from '../../src/rules/contextual/databaseDeleteWithoutOwnershipCheck.js';
import { supabaseReadableSensitiveData } from '../../src/rules/contextual/supabaseReadableSensitiveData.js';
import { supabaseRlsNotDetected } from '../../src/rules/contextual/supabaseRlsNotDetected.js';
import { UNSETTLED_BASIS_MARKER } from '../../src/rules/contextual/supabaseRlsUnverifiable.js';

const PKG: [string, string] = ['package.json', '{"name":"x","dependencies":{"@supabase/supabase-js":"2.0.0"}}'];
const EXEMPT = 'supabase_rls_unverifiable_from_source';

const TABLE = 'CREATE TABLE public.notes (id uuid PRIMARY KEY, user_id uuid, body text);\n';
const ENABLE = 'ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;\n';
const OWN_UPDATE =
  'CREATE POLICY "own update" ON public.notes FOR UPDATE USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);\n';
const OWN_DELETE = 'CREATE POLICY "own delete" ON public.notes FOR DELETE USING (auth.uid() = user_id);\n';

const MIGRATION: [string, string] = ['supabase/migrations/001_notes.sql', TABLE + ENABLE + OWN_UPDATE + OWN_DELETE];
const UNPLACED_DROP: [string, string] = ['scripts/fix.sql', 'DROP POLICY IF EXISTS "own update" ON public.notes;\n'];

const UPDATE_CLIENT: [string, string] = [
  'src/components/NoteEditor.tsx',
  [
    "import { supabase } from '../lib/supabase';",
    'export function NoteEditor() {',
    "  const save = async () => { await supabase.from('notes').update({ body: 'x' }).eq('id', 1); };",
    '  return null;',
    '}',
  ].join('\n'),
];
const DELETE_CLIENT: [string, string] = [
  'src/components/DeleteNote.tsx',
  [
    "import { supabase } from '../lib/supabase';",
    "export const remove = async (id: string) => { await supabase.from('notes').delete().eq('id', id); };",
  ].join('\n'),
];

function rlsOf(files: [string, string][]) {
  return detectSupabaseRls(memoryContext([PKG, ...files]).fileMap);
}

describe('an uncertain table gets no protection credit', () => {
  it('every credit predicate refuses it; the settled twin is credited', () => {
    const settled = rlsOf([MIGRATION]);
    expect(isRlsSettledFromSource(settled, 'notes')).toBe(true);
    expect(isCommandIdentityScoped(settled, 'notes', 'update')).toBe(true);
    expect(isCommandCallerBound(settled, 'notes', 'delete')).toBe(true);
    expect(isCommandDefaultDenied(settled, 'notes', 'insert')).toBe(true);

    const uncertain = rlsOf([MIGRATION, UNPLACED_DROP]);
    expect(uncertain.uncertainTables).toEqual(['notes']);
    expect(isRlsSettledFromSource(uncertain, 'notes')).toBe(false);
    expect(isCommandIdentityScoped(uncertain, 'notes', 'update')).toBe(false);
    expect(isCommandCallerBound(uncertain, 'notes', 'delete')).toBe(false);
    expect(isCommandDefaultDenied(uncertain, 'notes', 'insert')).toBe(false);
  });
});

describe("an uncertain table's would-be finding goes to the unsettled route", () => {
  it('privileged operation: fires, visible, exempt, and says why', () => {
    expect(supabaseClientPrivilegedOperation.run(memoryContext([PKG, MIGRATION, UPDATE_CLIENT]))).toHaveLength(0);

    const findings = supabaseClientPrivilegedOperation.run(memoryContext([PKG, MIGRATION, UNPLACED_DROP, UPDATE_CLIENT]));
    expect(findings).toHaveLength(1);
    const finding = findings[0];
    expect(finding?.adjudication?.required).toBe(false);
    expect(finding?.adjudication?.reason).toBe(EXEMPT);
    expect(finding?.adjudication?.basis.startsWith(UNSETTLED_BASIS_MARKER)).toBe(true);
    expect(finding?.userExplanation).toMatch(/could not settle how the "notes" table is protected/);
    expect(finding?.userExplanation).toMatch(/could not be put in order/);
    expect(finding?.userExplanation).toMatch(/Supabase dashboard/);
    expect(finding?.userExplanation).not.toMatch(/we found no policy/);
  });

  it('delete without ownership: fires on the unsettled route', () => {
    expect(
      databaseDeleteWithoutOwnershipCheck
        .run(memoryContext([PKG, MIGRATION, DELETE_CLIENT]))
        .filter((f) => f.filePath === DELETE_CLIENT[0]),
    ).toHaveLength(0);

    const findings = databaseDeleteWithoutOwnershipCheck
      .run(memoryContext([PKG, MIGRATION, UNPLACED_DROP, DELETE_CLIENT]))
      .filter((f) => f.filePath === DELETE_CLIENT[0]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.adjudication?.required).toBe(false);
    expect(findings[0]?.adjudication?.basis.startsWith(UNSETTLED_BASIS_MARKER)).toBe(true);
    expect(findings[0]?.userExplanation).toMatch(/a DELETE policy on "notes"/);
    expect(findings[0]?.severity).toBe('high');
  });

  it('a switch in doubt: rls_not_detected fires on the unsettled route, not as "no ENABLE"', () => {
    const disable: [string, string] = ['scripts/off.sql', 'ALTER TABLE public.notes DISABLE ROW LEVEL SECURITY;\n'];
    expect(supabaseRlsNotDetected.run(memoryContext([PKG, MIGRATION, UPDATE_CLIENT]))).toHaveLength(0);

    const rls = rlsOf([MIGRATION, disable]);
    expect(rls.uncertainSwitchTables).toEqual(['notes']);
    const findings = supabaseRlsNotDetected.run(memoryContext([PKG, MIGRATION, disable, UPDATE_CLIENT]));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.adjudication?.basis.startsWith(UNSETTLED_BASIS_MARKER)).toBe(true);
    expect(findings[0]?.evidence).toMatch(/both ENABLE and DISABLE/);
    expect(findings[0]?.evidence).not.toMatch(/contain no ENABLE/);
  });

  it('an uncertain table whose SWITCH is settled keeps the "RLS is on" credit in rls_not_detected', () => {
    expect(supabaseRlsNotDetected.run(memoryContext([PKG, MIGRATION, UNPLACED_DROP, UPDATE_CLIENT]))).toHaveLength(0);
  });
});

describe('an exposing policy: certainly live stays definitive, possibly dropped does not', () => {
  const PROFILES =
    'CREATE TABLE public.profiles (id uuid PRIMARY KEY, phone_number text, date_of_birth date);\n' +
    'ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;\n' +
    'CREATE POLICY "public profiles" ON public.profiles FOR SELECT USING (true);\n' +
    'CREATE POLICY "own profile" ON public.profiles FOR UPDATE USING (auth.uid() = id);\n';
  const profiles: [string, string] = ['supabase/migrations/001_profiles.sql', PROFILES];

  it('a certainly-live exposing policy stays definitive on an uncertain table', () => {
    const other: [string, string] = ['scripts/fix.sql', 'DROP POLICY IF EXISTS "own profile" ON public.profiles;\n'];
    const context = memoryContext([PKG, profiles, other]);
    const rls = context.projectMap.supabaseRls;
    expect(rls.uncertainTables).toEqual(['profiles']);
    const open = rls.policies.find((policy) => policy.command === 'select');
    expect(open !== undefined && isPolicyCertainlyLive(rls, open)).toBe(true);

    const findings = supabaseReadableSensitiveData.run(context);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.adjudication).toBeUndefined();
    expect(findings[0]?.userExplanation).toMatch(/Anyone can read every row/);
  });

  it('a possibly-dropped exposing policy is unsettled, and still visible', () => {
    const settled = supabaseReadableSensitiveData.run(memoryContext([PKG, profiles]));
    const drop: [string, string] = ['scripts/fix.sql', 'DROP POLICY IF EXISTS "public profiles" ON public.profiles;\n'];
    const context = memoryContext([PKG, profiles, drop]);
    const rls = context.projectMap.supabaseRls;
    const open = rls.policies.find((policy) => policy.command === 'select');
    expect(open !== undefined && isPolicyCertainlyLive(rls, open)).toBe(false);

    const findings = supabaseReadableSensitiveData.run(context);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.adjudication?.required).toBe(false);
    expect(findings[0]?.adjudication?.basis.startsWith(UNSETTLED_BASIS_MARKER)).toBe(true);
    expect(findings[0]?.userExplanation).toMatch(/could not settle how the "profiles" table is protected/);
    expect(findings[0]?.id).toBe(settled[0]?.id);
    expect(findings[0]?.severity).toBe(settled[0]?.severity);
  });

  it('a policy created outside the ordered folder is not certainly live', () => {
    const scriptPolicy: [string, string] = [
      'scripts/extra.sql',
      'CREATE POLICY "script open" ON public.profiles FOR SELECT USING (true);\n',
    ];
    const other: [string, string] = ['scripts/fix.sql', 'DROP POLICY IF EXISTS "own profile" ON public.profiles;\n'];
    const rls = rlsOf([profiles, scriptPolicy, other]);
    const fromScript = rls.policies.find((policy) => policy.filePath === 'scripts/extra.sql');
    expect(fromScript !== undefined && isPolicyCertainlyLive(rls, fromScript)).toBe(false);
  });

  it('an ALTER POLICY of the exposing policy makes it unsettled', () => {
    const alter: [string, string] = [
      'supabase/migrations/002_alter.sql',
      'ALTER POLICY "public profiles" ON public.profiles USING (auth.uid() = id);\n',
    ];
    const rls = rlsOf([profiles, alter]);
    expect(rls.uncertainTables).toEqual(['profiles']);
    const open = rls.policies.find((policy) => policy.command === 'select');
    expect(open !== undefined && isPolicyCertainlyLive(rls, open)).toBe(false);
  });
});

describe('a comment never starts a policy', () => {
  it('"-- Create policy for …" is not read as a policy named "for"', () => {
    const create: [string, string] = [
      'supabase/migrations/001_notes.sql',
      TABLE + ENABLE + '-- Create policy for public data only\nCREATE POLICY "real" ON public.notes FOR SELECT USING (true);\n',
    ];
    const rls = rlsOf([create]);
    expect(rls.policies.map((policy) => `${policy.table}:${policy.line}`)).toEqual(['notes:4']);
    const drop: [string, string] = ['supabase/migrations/002_drop.sql', 'DROP POLICY "real" ON public.notes;\n'];
    expect(rlsOf([create, drop]).policies).toEqual([]);
  });

  it('a block comment mentioning create policy starts nothing either', () => {
    const create: [string, string] = [
      'supabase/migrations/001_notes.sql',
      TABLE + '/* we create policy rows below */\nCREATE POLICY own ON public.notes FOR SELECT USING (auth.uid() = user_id);\n',
    ];
    const rls = rlsOf([create]);
    expect(rls.policies.map((policy) => `${policy.table}:${policy.line}`)).toEqual(['notes:3']);
    expect(rls.unparsedPolicyCount).toBe(0);
  });
});

describe('rls_not_detected says what the absence actually is', () => {
  const NOTES_CLIENT: [string, string] = [
    'src/components/Notes.tsx',
    [
      "import { supabase } from '../lib/supabase';",
      "export const load = async () => supabase.from('notes').select('*');",
    ].join('\n'),
  ];

  it('part of the RLS SQL could not be read: the finding says so', () => {
    const unread: [string, string] = [
      'supabase/migrations/001_loop.sql',
      "DO $$ DECLARE t text; BEGIN FOR t IN SELECT tablename FROM pg_tables LOOP\n" +
        "  EXECUTE 'ALTER TABLE ' || t || ' ENABLE ROW LEVEL SECURITY';\nEND LOOP; END $$;\n",
    ];
    expect(rlsOf([unread]).unreadRlsStatements.length).toBeGreaterThan(0);
    const findings = supabaseRlsNotDetected.run(memoryContext([PKG, unread, NOTES_CLIENT]));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toMatch(/could not be read/);
    expect(findings[0]?.userExplanation).toMatch(/could not be read/);

    const plain: [string, string] = ['supabase/migrations/001_other.sql', 'CREATE TABLE public.other (id uuid);\n'];
    const before = supabaseRlsNotDetected.run(memoryContext([PKG, plain, NOTES_CLIENT]));
    expect(before[0]?.evidence).toMatch(/contain no ENABLE ROW LEVEL SECURITY for it$/);
  });

  it('policies but no ENABLE, with unread SQL: the finding says the ENABLE may be in what could not be read', () => {
    const policies: [string, string] = [
      'supabase/migrations/001_notes.sql',
      TABLE + 'CREATE POLICY own ON public.notes FOR SELECT USING (auth.uid() = user_id);\n',
    ];
    const unread: [string, string] = [
      'supabase/migrations/002_loop.sql',
      "DO $$ DECLARE t text; BEGIN FOR t IN SELECT tablename FROM pg_tables LOOP\n" +
        "  EXECUTE 'ALTER TABLE ' || t || ' ENABLE ROW LEVEL SECURITY';\nEND LOOP; END $$;\n",
    ];
    const plain = supabaseRlsNotDetected.run(memoryContext([PKG, policies, NOTES_CLIENT]));
    expect(plain[0]?.evidence).toMatch(/but no ALTER TABLE \.\.\. ENABLE ROW LEVEL SECURITY does$/);
    const findings = supabaseRlsNotDetected.run(memoryContext([PKG, policies, unread, NOTES_CLIENT]));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.title).toMatch(/policies exist but were never enabled/);
    expect(findings[0]?.evidence).toMatch(/could not be read/);
    expect(findings[0]?.userExplanation).toMatch(/could not be read/);
  });

  it('enabled and later disabled: the finding says switched off, not "no ENABLE"', () => {
    const on: [string, string] = ['supabase/migrations/001_on.sql', TABLE + ENABLE];
    const off: [string, string] = ['supabase/migrations/002_off.sql', 'ALTER TABLE public.notes DISABLE ROW LEVEL SECURITY;\n'];
    const rls = rlsOf([on, off]);
    expect(rls.rlsDisabledTables).toEqual(['notes']);
    expect(rls.rlsEnabledTables).toEqual([]);
    expect(rls.uncertainTables).toEqual([]);
    const findings = supabaseRlsNotDetected.run(memoryContext([PKG, on, off, NOTES_CLIENT]));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toMatch(/switches ROW LEVEL SECURITY off/);
    expect(findings[0]?.evidence).not.toMatch(/no ENABLE/);
    expect(findings[0]?.userExplanation).toMatch(/switches Row Level Security OFF/);
  });
});

describe('a sweep over pg_policies', () => {
  const OPEN_NOTES = 'CREATE POLICY stale_open ON public.notes FOR SELECT USING (true);\n' +
    'CREATE POLICY keep_me ON public.notes FOR SELECT USING (auth.uid() = user_id);\n';
  const created: [string, string] = ['supabase/migrations/001_notes.sql', TABLE + ENABLE + OPEN_NOTES];
  const SWEEP_BODY =
    '  LOOP\n    EXECUTE format(\'drop policy %I on public.%I\', r.policyname, r.tablename);\n  END LOOP;\nEND $$;\n';

  it('with a literal table list and a literal keep list, it is rendered: unkept policies are dropped in order', () => {
    const sweep: [string, string] = [
      'supabase/migrations/002_sweep.sql',
      'do $$\ndeclare\n  r record;\n  keep text[] := array[\n    -- notes\n    \'keep_me\'\n  ];\nbegin\n' +
        '  for r in select policyname, tablename from pg_policies\n' +
        "   where schemaname = 'public' and tablename in ('notes') and not (policyname = any (keep))\n" +
        SWEEP_BODY,
    ];
    const rls = rlsOf([created, sweep]);
    expect(rls.policies.map((policy) => `${policy.table}:${policy.line}`)).toEqual(['notes:4']);
    expect(rls.unreadRlsStatements).toEqual([]);
    expect(rls.uncertainTables).toEqual([]);
    const later: [string, string] = [
      'supabase/migrations/003_again.sql',
      'CREATE POLICY stale_open ON public.notes FOR SELECT USING (true);\n',
    ];
    expect(rlsOf([created, sweep, later]).policies).toHaveLength(2);
  });

  it('with a filter that is not a literal list, it stays unread and its literal tables are uncertain', () => {
    const sweep: [string, string] = [
      'supabase/migrations/002_sweep.sql',
      'do $$\ndeclare r record;\nbegin\n' +
        '  for r in select policyname, tablename from pg_policies\n' +
        "   where schemaname = 'public' and tablename = 'notes' and cmd = 'SELECT'\n" +
        SWEEP_BODY,
    ];
    const rls = rlsOf([created, sweep]);
    expect(rls.policies).toHaveLength(2);
    expect(rls.unreadRlsStatements).toEqual([{ filePath: 'supabase/migrations/002_sweep.sql', line: 7 }]);
    expect(rls.uncertainTables).toEqual(['notes']);
  });

  it('with no table named at all, it stays unread and makes nothing uncertain', () => {
    const sweep: [string, string] = [
      'supabase/migrations/002_sweep.sql',
      'do $$\ndeclare r record;\nbegin\n' +
        "  for r in select policyname, tablename from pg_policies where schemaname = 'public' and qual = 'true'\n" +
        SWEEP_BODY,
    ];
    const rls = rlsOf([created, sweep]);
    expect(rls.policies).toHaveLength(2);
    expect(rls.unreadRlsStatements).toHaveLength(1);
    expect(rls.uncertainTables).toEqual([]);
  });
});
