import { describe, expect, it } from 'vitest';
import { evaluatePredicate, stripSqlComments } from '../../src/project-map/rlsPredicate.js';
import {
  detectSupabaseRls,
  hasPolicyWithoutRlsEnabled,
  isCommandIdentityScoped,
  isUnrestrictedForCommand,
  policiesFor,
  policyExposure,
} from '../../src/project-map/detectRls.js';
import { supabaseReadableSensitiveData } from '../../src/rules/contextual/supabaseReadableSensitiveData.js';
import { memoryContext } from './helpers.js';
import type { FileMap } from '../../src/shared/types.js';

const PKG_SUPABASE: [string, string] = [
  'package.json',
  '{"name":"x","dependencies":{"@supabase/supabase-js":"2.0.0"}}',
];

function sqlMap(sql: string): FileMap {
  return {
    entries: [{ path: 'supabase/migrations/0001_init.sql', extension: '.sql', content: sql }],
  } as unknown as FileMap;
}

function firstSelectExposure(sql: string, table: string): string {
  const info = detectSupabaseRls(sqlMap(sql));
  const governing = policiesFor(info, table, 'select');
  expect(governing.length).toBeGreaterThan(0);
  return (
    governing.map((policy) => policyExposure(policy, 'select')).find((value) => value !== 'none') ??
    'none'
  );
}

describe('three-valued predicate evaluation', () => {
  it('evaluates a bare literal as permissive for every caller', () => {
    expect(evaluatePredicate('true', 'anonymous')).toEqual({ value: 'true', readable: true });
    expect(evaluatePredicate(' ( true ) ', 'authenticated')).toEqual({ value: 'true', readable: true });
    expect(evaluatePredicate('false', 'anonymous').value).toBe('false');
  });

  it('MUST FIRE: auth.uid() IS NULL OR … is TRUE for an anonymous caller (CVE-2025-48757 class)', () => {
    expect(evaluatePredicate("auth.uid() IS NULL OR org_id = 'acme'", 'anonymous').value).toBe('true');
    expect(evaluatePredicate("auth.uid() IS NULL OR org_id = 'acme'", 'authenticated').value).toBe(
      'unknown',
    );
  });

  it('MUST FIRE: role-only predicates are TRUE for any signed-in caller and FALSE for anonymous', () => {
    for (const expression of [
      "auth.role() = 'authenticated'",
      "'authenticated' = auth.role()",
      'auth.uid() IS NOT NULL',
      "auth.role() IN ('authenticated', 'service_role')",
      "(select auth.role()) = 'authenticated'",
    ]) {
      expect(evaluatePredicate(expression, 'authenticated').value).toBe('true');
      expect(evaluatePredicate(expression, 'anonymous').value).toBe('false');
    }
  });

  it('MUST STAY SILENT: an owner-scoped predicate is UNKNOWN for both callers', () => {
    for (const expression of [
      'auth.uid() = user_id',
      'auth.uid() = owner_id',
      '(select auth.uid()) = user_id',
      'user_id = (SELECT auth.uid())',
      "org_id = (select org_id from members where user_id = auth.uid())",
      "public.has_role(auth.uid(), 'admin')",
      "EXISTS (SELECT 1 FROM profiles p WHERE p.id = auth.uid() AND p.role = 'admin')",
      "(auth.jwt() -> 'user_metadata' ->> 'company_id') = company_id",
    ]) {
      expect(evaluatePredicate(expression, 'anonymous').value).toBe('unknown');
      expect(evaluatePredicate(expression, 'authenticated').value).toBe('unknown');
    }
  });

  it('MUST STAY SILENT: auth.role() = \'service_role\' is FALSE for both callers', () => {
    expect(evaluatePredicate("auth.role() = 'service_role'", 'anonymous').value).toBe('false');
    expect(evaluatePredicate("auth.role() = 'service_role'", 'authenticated').value).toBe('false');
  });

  it('applies SQL three-valued logic to AND and OR, not boolean logic', () => {
    expect(evaluatePredicate('auth.uid() IS NULL OR user_id = x', 'anonymous').value).toBe('true');
    expect(evaluatePredicate('auth.uid() IS NULL AND user_id = x', 'anonymous').value).toBe('unknown');
    expect(evaluatePredicate('auth.uid() IS NOT NULL AND user_id = x', 'anonymous').value).toBe('false');
    expect(evaluatePredicate('NOT (auth.uid() IS NOT NULL)', 'anonymous').value).toBe('true');
    expect(evaluatePredicate('NOT (user_id = x)', 'anonymous').value).toBe('unknown');
  });

  it('strips SQL comments before parsing, so a comment cannot supply an operator', () => {
    const withComment = '(created_by = auth.uid())\n-- OR if user is an admin member\nOR (EXISTS (SELECT 1))';
    expect(stripSqlComments(withComment)).not.toContain('admin member');
    expect(evaluatePredicate(withComment, 'anonymous').value).toBe('unknown');
    expect(evaluatePredicate('-- enforced at application level\ntrue', 'anonymous').value).toBe('true');
    expect(stripSqlComments("role = '-- not a comment'")).toBe("role = '-- not a comment'");
  });

  it('refuses to answer for an expression it cannot parse', () => {
    expect(evaluatePredicate('auth.uid() = (user_id', 'anonymous')).toEqual({
      value: 'unknown',
      readable: false,
    });
    expect(evaluatePredicate('', 'anonymous').readable).toBe(false);
    expect(evaluatePredicate(`true OR ${'x = y OR '.repeat(600)}z = w`, 'anonymous').readable).toBe(
      false,
    );
  });
});

describe('policyExposure — who a policy actually admits', () => {
  it('MUST FIRE: an INSERT policy with no WITH CHECK admits every new row (pgrls SEC006)', () => {
    const info = detectSupabaseRls(
      sqlMap(
        'CREATE TABLE public.signups (id uuid primary key, email text);\n' +
          'ALTER TABLE public.signups ENABLE ROW LEVEL SECURITY;\n' +
          'CREATE POLICY "anyone signs up" ON public.signups FOR INSERT;\n',
      ),
    );
    const [policy] = policiesFor(info, 'signups', 'insert');
    expect(policy?.missingCheckExpression).toBe(true);
    expect(policyExposure(policy!, 'insert')).toBe('anonymous');
    expect(isUnrestrictedForCommand(policy!, 'insert')).toBe(true);
  });

  it('MUST STAY SILENT: an UPDATE policy with USING and no WITH CHECK is NOT unconstrained', () => {
    const info = detectSupabaseRls(
      sqlMap(
        'CREATE TABLE public.notes (id uuid primary key, user_id uuid);\n' +
          'ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;\n' +
          'CREATE POLICY "own notes" ON public.notes FOR UPDATE USING (auth.uid() = user_id);\n',
      ),
    );
    const [policy] = policiesFor(info, 'notes', 'update');
    expect(policy?.missingCheckExpression).toBe(false);
    expect(policyExposure(policy!, 'update')).toBe('none');
  });

  it('MUST FIRE: a FOR ALL policy whose USING is permissive also governs the INSERT check', () => {
    const info = detectSupabaseRls(
      sqlMap(
        'CREATE TABLE public.rows (id uuid primary key);\n' +
          'ALTER TABLE public.rows ENABLE ROW LEVEL SECURITY;\n' +
          'CREATE POLICY "open" ON public.rows FOR ALL USING (true);\n',
      ),
    );
    const [policy] = policiesFor(info, 'rows', 'insert');
    expect(policyExposure(policy!, 'insert')).toBe('anonymous');
  });

  it('reads the TO clause: TO authenticated USING (true) is not an anonymous exposure', () => {
    const info = detectSupabaseRls(
      sqlMap(
        'CREATE TABLE public.provinces (id uuid primary key, name text);\n' +
          'ALTER TABLE public.provinces ENABLE ROW LEVEL SECURITY;\n' +
          'CREATE POLICY "read" ON public.provinces FOR SELECT TO authenticated USING (true);\n',
      ),
    );
    const [policy] = policiesFor(info, 'provinces', 'select');
    expect(policy?.roles).toEqual(['authenticated']);
    expect(policyExposure(policy!, 'select')).toBe('authenticated');
    expect(isUnrestrictedForCommand(policy!, 'select')).toBe(false);
  });

  it('does not read a role out of the policy NAME', () => {
    const info = detectSupabaseRls(
      sqlMap(
        'CREATE TABLE public.t (id uuid primary key);\n' +
          'CREATE POLICY "Admins can add members to their communities" ON public.t FOR SELECT USING (true);\n',
      ),
    );
    expect(policiesFor(info, 't', 'select')[0]?.roles).toEqual(['public']);
  });
});

describe('supabase_readable_sensitive_data — widened predicate', () => {
  const SENSITIVE_TABLE =
    'CREATE TABLE public.profiles (id uuid primary key, user_id uuid, phone_number text, latitude decimal);\n' +
    'ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;\n';

  function run(policy: string) {
    return supabaseReadableSensitiveData.run(
      memoryContext([PKG_SUPABASE, ['supabase/migrations/0001_init.sql', SENSITIVE_TABLE + policy]]),
    );
  }

  it('MUST FIRE: auth.uid() IS NULL OR … on a sensitive table, at CRITICAL', () => {
    const findings = run(
      `CREATE POLICY "public read" ON public.profiles FOR SELECT USING (auth.uid() IS NULL OR org_id = 'acme');\n`,
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('critical');
    expect(findings[0]?.evidence).toContain('auth.uid() IS NULL');
    expect(findings[0]?.userExplanation).toContain('not logged in');
  });

  it('MUST FIRE: a role-only policy, one tier lower because it costs an account', () => {
    const findings = run(
      `CREATE POLICY "any user" ON public.profiles FOR SELECT USING (auth.role() = 'authenticated');\n`,
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('high');
    expect(findings[0]?.userExplanation).toContain('Every signed-in user');
  });

  it('MUST FIRE: a literal SELECT true on a table WITH sensitive columns stays CRITICAL', () => {
    const findings = run('CREATE POLICY "open" ON public.profiles FOR SELECT USING (true);\n');
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('critical');
    expect(findings[0]?.evidence).toBe(
      'FOR SELECT USING (true) on "profiles" exposes latitude, phone_number',
    );
  });

  it('MUST STAY SILENT: an owner-scoped policy on the same sensitive table', () => {
    expect(
      run('CREATE POLICY "own row" ON public.profiles FOR SELECT USING (auth.uid() = user_id);\n'),
    ).toHaveLength(0);
    expect(
      run(
        'CREATE POLICY "own row" ON public.profiles FOR SELECT USING ((select auth.uid()) = user_id);\n',
      ),
    ).toHaveLength(0);
    expect(
      run(
        "CREATE POLICY \"tenant\" ON public.profiles FOR SELECT USING (org_id = (select org_id from members where user_id = auth.uid()));\n",
      ),
    ).toHaveLength(0);
  });

  it('MUST STAY SILENT: a permissive SELECT on a table with NO sensitive column (splinter split)', () => {
    const findings = supabaseReadableSensitiveData.run(
      memoryContext([
        PKG_SUPABASE,
        [
          'supabase/migrations/0001_init.sql',
          'CREATE TABLE public.posts (id uuid primary key, title text, body text);\n' +
            'ALTER TABLE public.posts ENABLE ROW LEVEL SECURITY;\n' +
            "CREATE POLICY \"any user\" ON public.posts FOR SELECT USING (auth.role() = 'authenticated');\n",
        ],
      ]),
    );
    expect(findings).toHaveLength(0);
  });

  it('prefers the literal `true` policy as the anchor when several are permissive', () => {
    const findings = run(
      `CREATE POLICY "role only" ON public.profiles FOR SELECT USING (auth.role() = 'authenticated');\n` +
        'CREATE POLICY "open" ON public.profiles FOR SELECT USING (true);\n',
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('critical');
    expect(findings[0]?.evidence).toContain('USING (true)');
  });
});

describe('policy written, RLS never enabled (splinter 0007)', () => {
  const sql =
    'CREATE TABLE public.orders (id uuid primary key, user_id uuid);\n' +
    'CREATE POLICY "own orders" ON public.orders FOR SELECT USING (auth.uid() = user_id);\n';

  it('MUST FIRE: the table has a committed policy and no ENABLE ROW LEVEL SECURITY', () => {
    const info = detectSupabaseRls(sqlMap(sql));
    expect(hasPolicyWithoutRlsEnabled(info, 'orders')).toBe(true);
  });

  it('MUST STAY SILENT once RLS is enabled, and for a table with no policy at all', () => {
    const enabled = detectSupabaseRls(
      sqlMap(sql + 'ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\n'),
    );
    expect(hasPolicyWithoutRlsEnabled(enabled, 'orders')).toBe(false);
    expect(hasPolicyWithoutRlsEnabled(enabled, 'nowhere')).toBe(false);
  });
});

describe('identity-scoping credit is withdrawn from a policy that binds nothing', () => {
  const table =
    'CREATE TABLE public.clientes (id uuid primary key, advisor_id uuid, nome text);\n' +
    'ALTER TABLE public.clientes ENABLE ROW LEVEL SECURITY;\n';

  it('MUST NOT credit a role-only policy as ownership-checked', () => {
    const info = detectSupabaseRls(
      sqlMap(
        table +
          `CREATE POLICY "clientes_authenticated_all" ON public.clientes FOR ALL USING (auth.role() = 'authenticated') WITH CHECK (auth.role() = 'authenticated');\n`,
      ),
    );
    expect(isCommandIdentityScoped(info, 'clientes', 'update')).toBe(false);
    expect(isCommandIdentityScoped(info, 'clientes', 'insert')).toBe(false);
    expect(isCommandIdentityScoped(info, 'clientes', 'delete')).toBe(false);
  });

  it('still credits a genuinely owner-scoped policy', () => {
    const info = detectSupabaseRls(
      sqlMap(
        table +
          'CREATE POLICY "own" ON public.clientes FOR ALL USING (auth.uid() = advisor_id) WITH CHECK (auth.uid() = advisor_id);\n',
      ),
    );
    expect(isCommandIdentityScoped(info, 'clientes', 'update')).toBe(true);
    expect(isCommandIdentityScoped(info, 'clientes', 'select')).toBe(true);
  });
});
