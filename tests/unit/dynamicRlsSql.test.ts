import { describe, expect, it } from 'vitest';
import { memoryContext } from './helpers.js';
import { detectSupabaseRls } from '../../src/project-map/detectRls.js';
import { expandDynamicRlsStatements, renderFormat } from '../../src/project-map/dynamicRlsSql.js';
import { supabaseRlsNotDetected } from '../../src/rules/contextual/supabaseRlsNotDetected.js';


const ASSETFLOW_LOOP =
  '-- sacco schema\n' +
  'CREATE TABLE IF NOT EXISTS public.sacco_loans (id uuid primary key, admin_id uuid, member_id uuid);\n' +
  'CREATE TABLE IF NOT EXISTS public.sacco_shares (id uuid primary key, admin_id uuid);\n' +
  'DO $$\n' +
  'DECLARE\n' +
  '  t text;\n' +
  '  sacco_tables text[] := ARRAY[\n' +
  "    'sacco_loans','sacco_shares'\n" +
  '  ];\n' +
  'BEGIN\n' +
  '  FOREACH t IN ARRAY sacco_tables LOOP\n' +
  "    EXECUTE format('ALTER TABLE public.%1$s ENABLE ROW LEVEL SECURITY;', t);\n" +
  '    EXECUTE format(\'DROP POLICY IF EXISTS "tenant_manage_%1$s" ON public.%1$s;\', t);\n' +
  '    EXECUTE format(\n' +
  '      \'CREATE POLICY "tenant_manage_%1$s" ON public.%1$s FOR ALL TO authenticated ' +
  'USING ((admin_id = public.current_admin_id() AND public.is_staff_member()) OR public.is_global_viewer()) ' +
  'WITH CHECK ((admin_id = public.current_admin_id() AND public.is_staff_member()) OR public.is_global_viewer());\',\n' +
  '      t);\n' +
  '  END LOOP;\n' +
  'END $$;\n';

const INLINE_ARRAY_LOOP =
  'do $$\n' +
  'declare t text;\n' +
  'begin\n' +
  "  foreach t in array array['sacco_asset_documents', 'sacco_asset_events'] loop\n" +
  "    execute format('alter table public.%I enable row level security', t);\n" +
  '    execute format(\'drop policy if exists "tenant_manage_%s" on public.%I\', t, t);\n' +
  '    execute format(\'create policy "tenant_manage_%s" on public.%I for all to authenticated ' +
  "using ((admin_id = public.current_admin_id() and public.is_staff_member()) or public.is_global_viewer())', t, t);\n" +
  "    execute format('grant select, insert, update, delete on public.%I to authenticated', t);\n" +
  '  end loop;\n' +
  'end;\n' +
  '$$;\n';

const SQL_PACKAGE: [string, string] = [
  'package.json',
  '{"devDependencies":{"@sveltejs/kit":"2.0.0"},"dependencies":{"@supabase/supabase-js":"2.0.0"}}',
];
const SVELTE_CONFIG: [string, string] = ['svelte.config.js', 'export default { kit: {} };'];
const SUPABASE_LIB: [string, string] = [
  'src/lib/supabase.ts',
  "import { createClient } from '@supabase/supabase-js';\n" +
    'export const supabase = createClient(import.meta.env.VITE_SUPABASE_URL, import.meta.env.VITE_SUPABASE_ANON_KEY);\n',
];
const LOANS_PAGE: [string, string] = [
  'src/routes/loans/+page.ts',
  "import { supabase } from '$lib/supabase';\n" +
    'export const load = async () => {\n' +
    "  const { data } = await supabase.from('sacco_loans').select('*');\n" +
    '  return { loans: data };\n' +
    '};\n',
];
const LOOP_PROJECT: [string, string][] = [
  SQL_PACKAGE,
  SVELTE_CONFIG,
  SUPABASE_LIB,
  LOANS_PAGE,
  ['supabase/migrations/0001_sacco.sql', ASSETFLOW_LOOP],
];

describe('RLS switched on inside a FOREACH … EXECUTE format loop', () => {
  it("Assetflow's shape: a declared array and %1$s — every table is enabled and its policy parsed", () => {
    const { fileMap } = memoryContext([SQL_PACKAGE, ['supabase/migrations/0001_sacco.sql', ASSETFLOW_LOOP]]);
    const rls = detectSupabaseRls(fileMap);
    expect(rls.rlsEnabledTables).toEqual(['sacco_loans', 'sacco_shares']);
    expect(rls.policyTables).toEqual(['sacco_loans', 'sacco_shares']);
    expect(rls.unparsedPolicyCount).toBe(0);
    const loans = rls.policies.find((policy) => policy.table === 'sacco_loans');
    expect(loans?.command).toBe('all');
    expect(loans?.roles).toEqual(['authenticated']);
    expect(loans?.usingExpression).toContain('admin_id = public.current_admin_id()');
    expect(loans?.usingUnrestricted).toBe(false);
    expect(loans?.line).toBe(14);
  });

  it('the inline-array, %I, no-semicolon variant is expanded too', () => {
    const { fileMap } = memoryContext([SQL_PACKAGE, ['supabase/migrations/0002_assets.sql', INLINE_ARRAY_LOOP]]);
    const rls = detectSupabaseRls(fileMap);
    expect(rls.rlsEnabledTables).toEqual(['sacco_asset_documents', 'sacco_asset_events']);
    expect(rls.policyTables).toEqual(['sacco_asset_documents', 'sacco_asset_events']);
    expect(rls.unparsedPolicyCount).toBe(0);
  });

  it('DISABLE in a loop is recorded as disabled, not enabled', () => {
    const sql =
      "DO $$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY['a_tab','b_tab'] LOOP " +
      "EXECUTE format('ALTER TABLE public.%I DISABLE ROW LEVEL SECURITY', t); END LOOP; END $$;";
    const rls = detectSupabaseRls(memoryContext([SQL_PACKAGE, ['m.sql', sql]]).fileMap);
    expect(rls.rlsDisabledTables).toEqual(['a_tab', 'b_tab']);
    expect(rls.rlsEnabledTables).toEqual([]);
  });

  it('shapes it cannot read are NOT expanded: concatenation, a foreign argument, a computed array', () => {
    const concatenation =
      "DO $$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY['x1'] LOOP " +
      "EXECUTE 'ALTER TABLE public.' || t || ' ENABLE ROW LEVEL SECURITY'; END LOOP; END $$;";
    const foreignArgument =
      "DO $$ DECLARE t text; s text := 'public'; BEGIN FOREACH t IN ARRAY ARRAY['x2'] LOOP " +
      "EXECUTE format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY', s, t); END LOOP; END $$;";
    const computedArray =
      'DO $$ DECLARE t text; tabs text[]; BEGIN SELECT array_agg(tablename) INTO tabs FROM pg_tables; ' +
      "FOREACH t IN ARRAY tabs LOOP EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t); END LOOP; END $$;";
    for (const sql of [concatenation, foreignArgument, computedArray]) {
      expect(expandDynamicRlsStatements(sql)).toEqual([]);
      expect(detectSupabaseRls(memoryContext([SQL_PACKAGE, ['m.sql', sql]]).fileMap).rlsEnabledTables).toEqual([]);
    }
  });

  it('format(): %s, %I, %L, positional and sequential arguments, %% — and nothing it does not know', () => {
    expect(renderFormat('%1$s/%1$I', 1, 'tab')).toBe('tab/tab');
    expect(renderFormat('%s', 1, 'tab')).toBe('tab');
    expect(renderFormat('%1$s/%s', 2, 'tab')).toBe('tab/tab');
    expect(renderFormat('%1$s/%s', 1, 'tab')).toBeUndefined();
    expect(renderFormat('%I', 1, 'Mixed')).toBe('"Mixed"');
    expect(renderFormat('%L', 1, "o'k")).toBe("'o''k'");
    expect(renderFormat('100%% %s', 1, 'x')).toBe('100% x');
    expect(renderFormat('%s %s', 2, 'x')).toBe('x x');
    expect(renderFormat('%s %s', 1, 'x')).toBeUndefined();
    expect(renderFormat('%d', 1, 'x')).toBeUndefined();
  });

  it('literal statements are read exactly as before', () => {
    const sql = 'ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "own" ON notes FOR ALL USING (auth.uid() = user_id);\n';
    const rls = detectSupabaseRls(memoryContext([SQL_PACKAGE, ['m.sql', sql]]).fileMap);
    expect(rls.rlsEnabledTables).toEqual(['notes']);
    expect(rls.policies).toHaveLength(1);
    expect(rls.policies[0]?.line).toBe(2);
  });

  it('the shipped rule supabase_rls_not_detected no longer fires on a loop-enabled table', () => {
    const context = memoryContext(LOOP_PROJECT);
    expect(context.projectMap.supabaseRls.rlsEnabledTables).toContain('sacco_loans');
    const findings = supabaseRlsNotDetected.run(context).filter((finding) => finding.evidence.includes('sacco_loans'));
    expect(findings).toEqual([]);
  });
});
