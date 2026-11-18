import { describe, expect, it } from 'vitest';
import { memoryContext } from './helpers.js';
import { detectSupabaseRls, rlsReadingWarnings } from '../../src/project-map/detectRls.js';

const SQL_PACKAGE: [string, string] = ['package.json', '{"dependencies":{"@supabase/supabase-js":"2.0.0"}}'];
const OWN = 'USING (auth.uid() = user_id)';
const OPEN = 'USING (true)';

function rlsOf(files: [string, string][]) {
  return detectSupabaseRls(memoryContext([SQL_PACKAGE, ...files]).fileMap);
}
const names = (rls: ReturnType<typeof rlsOf>) =>
  rls.policies.map((policy) => `${policy.table}:${policy.filePath}:${policy.line}`);

describe('order and drops', () => {
  it('a literal ENABLE is read as before', () => {
    const rls = rlsOf([['supabase/migrations/001_a.sql', 'ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n']]);
    expect(rls.rlsEnabledTables).toEqual(['notes']);
    expect(rls.uncertainTables).toEqual([]);
    expect(rls.unreadRlsStatements).toEqual([]);
  });

  it('a FOREACH loop over a table list enables every table and goes through the same order', () => {
    const loop =
      "DO $$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY['a_tab','b_tab'] LOOP\n" +
      "  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);\n" +
      "  EXECUTE format('DROP POLICY IF EXISTS \"own_%s\" ON public.%I', t, t);\n" +
      `  EXECUTE format('CREATE POLICY "own_%s" ON public.%I FOR ALL ${OWN}', t, t);\n` +
      'END LOOP; END $$;\n';
    const rls = rlsOf([['supabase/migrations/001_loop.sql', loop]]);
    expect(rls.rlsEnabledTables).toEqual(['a_tab', 'b_tab']);
    expect(rls.policies.map((policy) => policy.table)).toEqual(['a_tab', 'b_tab']);
    expect(rls.unreadRlsStatements).toEqual([]);
  });

  it('a loop-rendered DROP removes a policy a literal CREATE made earlier', () => {
    const rls = rlsOf([
      ['supabase/migrations/001_open.sql', `CREATE POLICY "open" ON public.a_tab FOR SELECT ${OPEN};\n`],
      [
        'supabase/migrations/002_close.sql',
        "DO $$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY['a_tab'] LOOP\n" +
          "  EXECUTE format('DROP POLICY IF EXISTS \"open\" ON public.%I', t);\n" +
          'END LOOP; END $$;\n',
      ],
    ]);
    expect(rls.policies).toEqual([]);
  });

  it('CREATE, then DROP, then nothing: the policy is gone', () => {
    const rls = rlsOf([
      ['supabase/migrations/20240101000000_a.sql', `CREATE POLICY "open read" ON public.notes FOR SELECT ${OPEN};\n`],
      ['supabase/migrations/20240201000000_b.sql', 'DROP POLICY "open read" ON public.notes;\n'],
    ]);
    expect(rls.policies).toEqual([]);
    expect(rls.policyTables).toEqual([]);
    expect(rls.uncertainTables).toEqual([]);
  });

  it('CREATE, then DROP, then CREATE the same name: the second one is live', () => {
    const rls = rlsOf([
      ['supabase/migrations/001_a.sql', `CREATE POLICY "read" ON notes FOR SELECT ${OPEN};\n`],
      ['supabase/migrations/002_b.sql', `DROP POLICY IF EXISTS "read" ON notes;\nCREATE POLICY "read" ON notes FOR SELECT ${OWN};\n`],
    ]);
    expect(names(rls)).toEqual(['notes:supabase/migrations/002_b.sql:2']);
    expect(rls.policies[0]?.usingUnrestricted).toBe(false);
  });

  it('DROP POLICY IF EXISTS for a policy that never existed changes nothing', () => {
    const rls = rlsOf([
      ['supabase/migrations/001_a.sql', `CREATE POLICY "read" ON notes FOR SELECT ${OWN};\n`],
      ['supabase/migrations/002_b.sql', 'DROP POLICY IF EXISTS "never made" ON notes;\n'],
    ]);
    expect(names(rls)).toEqual(['notes:supabase/migrations/001_a.sql:1']);
    expect(rls.uncertainTables).toEqual([]);
  });

  it('a DROP of a same-named policy on a different table does not remove this one', () => {
    const rls = rlsOf([
      ['supabase/migrations/001_a.sql', `CREATE POLICY "own" ON notes FOR ALL ${OWN};\nCREATE POLICY "own" ON todos FOR ALL ${OWN};\n`],
      ['supabase/migrations/002_b.sql', 'DROP POLICY "own" ON todos;\n'],
    ]);
    expect(names(rls)).toEqual(['notes:supabase/migrations/001_a.sql:1']);
  });

  it('policy names compare as PostgreSQL compares them: bare names fold, quoted names do not', () => {
    const rls = rlsOf([
      ['supabase/migrations/001_a.sql', `CREATE POLICY Own_Rows ON notes FOR ALL ${OWN};\nCREATE POLICY "Mixed" ON todos FOR ALL ${OWN};\n`],
      ['supabase/migrations/002_b.sql', 'DROP POLICY "own_rows" ON notes;\nDROP POLICY mixed ON todos;\n'],
    ]);
    expect(rls.policies.map((policy) => policy.table)).toEqual(['todos']);
  });

  it('ENABLE, then DISABLE, then ENABLE across migration files: enabled, and never disabled', () => {
    const rls = rlsOf([
      ['supabase/migrations/001_a.sql', 'ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n'],
      ['supabase/migrations/002_b.sql', 'ALTER TABLE notes DISABLE ROW LEVEL SECURITY;\n'],
      ['supabase/migrations/003_c.sql', 'ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n'],
    ]);
    expect(rls.rlsEnabledTables).toEqual(['notes']);
    expect(rls.rlsDisabledTables).toEqual([]);
    expect(rls.uncertainTables).toEqual([]);
  });

  it('ENABLE then DISABLE: disabled at the end, and no longer also enabled', () => {
    const rls = rlsOf([
      ['supabase/migrations/001_a.sql', 'ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n'],
      ['supabase/migrations/002_b.sql', 'ALTER TABLE notes DISABLE ROW LEVEL SECURITY;\n'],
    ]);
    expect(rls.rlsEnabledTables).toEqual([]);
    expect(rls.rlsDisabledTables).toEqual(['notes']);
  });

  it('migrations are applied in filename order whatever order the file map lists them in', () => {
    const rls = rlsOf([
      ['supabase/migrations/20251201_drop.sql', 'DROP POLICY "read" ON notes;\n'],
      ['supabase/migrations/20251201000000_make.sql', `CREATE POLICY "read" ON notes FOR SELECT ${OPEN};\n`],
    ]);
    expect(rls.policies).toEqual([]);
  });

  it('a DROP in an unordered file leaves the policy in place and marks the table uncertain', () => {
    const rls = rlsOf([
      ['supabase/migrations/001_a.sql', `CREATE POLICY "open" ON notes FOR SELECT ${OPEN};\n`],
      ['schema.sql', 'DROP POLICY "open" ON notes;\n'],
    ]);
    expect(names(rls)).toEqual(['notes:supabase/migrations/001_a.sql:1']);
    expect(rls.uncertainTables).toEqual(['notes']);
    expect(rlsReadingWarnings(rls).join('\n')).toContain('could not be settled');
  });

  it('inside ONE unordered file the order is known, and a drop there does remove', () => {
    const rls = rlsOf([['schema.sql', `CREATE POLICY "open" ON notes FOR SELECT ${OPEN};\nDROP POLICY "open" ON notes;\n`]]);
    expect(rls.policies).toEqual([]);
    expect(rls.uncertainTables).toEqual([]);
  });

  it('a _down twin sharing its version with a forward migration is not applied, and is named', () => {
    const context = memoryContext([
      SQL_PACKAGE,
      ['supabase/migrations/079_orgs.sql', `ALTER TABLE orgs ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "org read" ON orgs FOR SELECT ${OWN};\n`],
      ['supabase/migrations/079_orgs_down.sql', 'DROP POLICY IF EXISTS "org read" ON orgs;\nDROP TABLE IF EXISTS public.orgs;\n'],
    ]);
    const rls = context.projectMap.supabaseRls;
    expect(rls.policies.map((policy) => policy.table)).toEqual(['orgs']);
    expect(rls.rlsEnabledTables).toEqual(['orgs']);
    expect(rls.uncertainTables).toEqual([]);
    expect(rls.rollbackFilesNotApplied).toEqual(['supabase/migrations/079_orgs_down.sql']);
    const warning = context.fileMap.warnings.find((text) => text.includes('rollback migration'));
    expect(warning).toContain('1 rollback migration was not treated as applied');
    expect(warning).toContain('supabase/migrations/079_orgs_down.sql');
  });

  it('the .down.sql spelling is a rollback twin too', () => {
    const rls = rlsOf([
      ['supabase/migrations/20240101000000_orgs.sql', `CREATE POLICY "org read" ON orgs FOR SELECT ${OWN};\n`],
      ['supabase/migrations/20240101000000_orgs.down.sql', 'DROP POLICY "org read" ON orgs;\n'],
    ]);
    expect(rls.policies).toHaveLength(1);
    expect(rls.rollbackFilesNotApplied).toEqual(['supabase/migrations/20240101000000_orgs.down.sql']);
  });

  it('a _down file with NO forward twin is an ordinary migration and keeps its place', () => {
    const rls = rlsOf([
      ['supabase/migrations/079_orgs.sql', `CREATE POLICY "org read" ON orgs FOR SELECT ${OPEN};\n`],
      ['supabase/migrations/080_open_read_down.sql', 'DROP POLICY "org read" ON orgs;\n'],
    ]);
    expect(rls.policies).toEqual([]);
    expect(rls.rollbackFilesNotApplied).toEqual([]);
  });

  it('a _down file OUTSIDE the ordered folder is not a twin: it stays unordered', () => {
    const rls = rlsOf([
      ['supabase/migrations/079_orgs.sql', `CREATE POLICY "org read" ON orgs FOR SELECT ${OWN};\n`],
      ['scripts/079_orgs_down.sql', 'DROP POLICY "org read" ON orgs;\n'],
    ]);
    expect(rls.policies).toHaveLength(1);
    expect(rls.uncertainTables).toEqual(['orgs']);
    expect(rls.rollbackFilesNotApplied).toEqual([]);
  });

  it('two FORWARD migrations sharing a version still have no order between them', () => {
    const rls = rlsOf([
      ['supabase/migrations/20251201_make.sql', `CREATE POLICY "read" ON hardware FOR SELECT ${OPEN};\n`],
      ['supabase/migrations/20251201_relax.sql', 'DROP POLICY "read" ON hardware;\n'],
    ]);
    expect(rls.policies).toHaveLength(1);
    expect(rls.uncertainTables).toEqual(['hardware']);
    expect(rls.rollbackFilesNotApplied).toEqual([]);
  });

  it('only the shallowest supabase/migrations folder is ordered; an editor history copy is not', () => {
    const rls = rlsOf([
      ['supabase/migrations/001_a.sql', `CREATE POLICY "read" ON notes FOR SELECT ${OWN};\n`],
      ['.history/supabase/migrations/002_b.sql', 'DROP POLICY "read" ON notes;\n'],
    ]);
    expect(rls.policies).toHaveLength(1);
    expect(rls.uncertainTables).toEqual(['notes']);
  });

  it('DROP TABLE removes the table\'s policies and its switch; ALTER PUBLICATION … DROP TABLE does not', () => {
    const rls = rlsOf([
      [
        'supabase/migrations/001_a.sql',
        `ALTER TABLE chat ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "own" ON chat FOR ALL ${OWN};\n` +
          `ALTER TABLE gone ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "own" ON gone FOR ALL ${OWN};\n`,
      ],
      ['supabase/migrations/002_b.sql', 'ALTER PUBLICATION supabase_realtime DROP TABLE IF EXISTS public.chat;\nDROP TABLE public.gone;\n'],
    ]);
    expect(rls.rlsEnabledTables).toEqual(['chat']);
    expect(rls.policies.map((policy) => policy.table)).toEqual(['chat']);
  });

  it('a DROP POLICY written inside a comment is not a statement', () => {
    const rls = rlsOf([
      ['supabase/migrations/001_a.sql', `CREATE POLICY "own" ON notes FOR ALL ${OWN};\n`],
      ['supabase/migrations/002_b.sql', '-- DROP POLICY "own" ON notes;\n/* DROP POLICY "own" ON notes; */\n'],
    ]);
    expect(rls.policies).toHaveLength(1);
  });

  it('a DROP POLICY inside a function body runs only when called: not applied, and uncertain', () => {
    const fn =
      'CREATE OR REPLACE FUNCTION public.reset_notes() RETURNS void LANGUAGE plpgsql AS $$\n' +
      'BEGIN\n  DROP POLICY "own" ON notes;\nEND;\n$$;\n';
    const rls = rlsOf([
      ['supabase/migrations/001_a.sql', `CREATE POLICY "own" ON notes FOR ALL ${OWN};\n`],
      ['supabase/migrations/002_b.sql', fn],
    ]);
    expect(rls.policies).toHaveLength(1);
    expect(rls.uncertainTables).toEqual(['notes']);
  });

  it('ALTER POLICY is not applied; the table is recorded as uncertain', () => {
    const rls = rlsOf([
      ['supabase/migrations/001_a.sql', `CREATE POLICY "own" ON notes FOR ALL ${OWN};\n`],
      ['supabase/migrations/002_b.sql', 'ALTER POLICY "own" ON notes USING (true);\n'],
    ]);
    expect(rls.policies[0]?.usingExpression).toBe('auth.uid() = user_id');
    expect(rls.uncertainTables).toEqual(['notes']);
  });

  it('ENABLE and DISABLE whose order is unknown: left where the order-free reading put it, and uncertain', () => {
    const rls = rlsOf([
      ['supabase/migrations/001_a.sql', 'ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n'],
      ['schema.sql', 'ALTER TABLE notes DISABLE ROW LEVEL SECURITY;\n'],
    ]);
    expect(rls.rlsEnabledTables).toEqual(['notes']);
    expect(rls.rlsDisabledTables).toEqual(['notes']);
    expect(rls.uncertainTables).toEqual(['notes']);
  });

  it('ENABLE in the migrations and ENABLE in an unordered file agree: settled, not uncertain', () => {
    const rls = rlsOf([
      ['supabase/migrations/001_a.sql', 'ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n'],
      ['schema.sql', 'ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n'],
    ]);
    expect(rls.rlsEnabledTables).toEqual(['notes']);
    expect(rls.uncertainTables).toEqual([]);
  });
});

describe('could not read', () => {
  it('a dynamic statement the expander cannot render is named, with its file and line', () => {
    const sql =
      'DO $$ DECLARE r record; BEGIN\n' +
      "  FOR r IN SELECT policyname, tablename FROM pg_policies WHERE schemaname = 'public' LOOP\n" +
      "    EXECUTE format('drop policy %I on public.%I', r.policyname, r.tablename);\n" +
      '  END LOOP;\nEND $$;\n' +
      "DO $$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY['x'] LOOP EXECUTE 'ALTER TABLE ' || t || ' ENABLE ROW LEVEL SECURITY'; END LOOP; END $$;\n";
    const context = memoryContext([SQL_PACKAGE, ['supabase/migrations/001_a.sql', sql]]);
    const rls = context.projectMap.supabaseRls;
    expect(rls.unreadRlsStatements).toEqual([
      { filePath: 'supabase/migrations/001_a.sql', line: 3 },
      { filePath: 'supabase/migrations/001_a.sql', line: 6 },
    ]);
    const warning = context.fileMap.warnings.find((text) => text.includes('could not be read'));
    expect(warning).toContain('2 row-level security statements');
    expect(warning).toContain('supabase/migrations/001_a.sql:3, supabase/migrations/001_a.sql:6');
  });

  it('a CREATE POLICY that does not parse is named too, and still counted as unparsed', () => {
    const rls = rlsOf([['supabase/migrations/001_a.sql', 'CREATE POLICY ON notes USING (true);\n']]);
    expect(rls.unparsedPolicyCount).toBe(1);
    expect(rls.unreadRlsStatements).toEqual([{ filePath: 'supabase/migrations/001_a.sql', line: 1 }]);
  });

  it('a RAISE message that mentions ALTER POLICY is not a statement', () => {
    const sql = "DO $$ BEGIN RAISE NOTICE 'ALTER POLICY created and dropped nothing'; END $$;\n";
    expect(rlsOf([['supabase/migrations/001_a.sql', sql]]).unreadRlsStatements).toEqual([]);
  });

  it('a project with nothing unread and nothing uncertain gets no warning at all', () => {
    const context = memoryContext([SQL_PACKAGE, ['supabase/migrations/001_a.sql', `ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "own" ON notes FOR ALL ${OWN};\n`]]);
    expect(rlsReadingWarnings(context.projectMap.supabaseRls)).toEqual([]);
    expect(context.fileMap.warnings.filter((text) => /row-level security/i.test(text))).toEqual([]);
  });

  it('the warning names at most five and says how many it left out, in the same sentence', () => {
    const files: [string, string][] = [['supabase/migrations/001_a.sql', '']];
    for (let index = 0; index < 7; index += 1) {
      files.push([`supabase/migrations/00${index + 2}_t.sql`, `CREATE POLICY "p" ON t${index} FOR ALL ${OWN};\n`]);
      files.push([`schema${index}.sql`, `DROP POLICY "p" ON t${index};\n`]);
    }
    const [warning] = rlsReadingWarnings(rlsOf(files));
    expect(warning).toContain('Row-level security for 7 tables');
    expect(warning).toContain('The first 5: t0, t1, t2, t3, t4 and 2 more.');
  });
});
