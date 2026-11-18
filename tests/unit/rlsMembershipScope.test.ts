import { describe, expect, it } from 'vitest';
import {
  detectSupabaseRls,
  isCommandCallerBound,
  isCommandIdentityScoped,
} from '../../src/project-map/detectRls.js';
import { bindsOnEveryBranch } from '../../src/project-map/rlsPredicate.js';
import { operationBypassesRls } from '../../src/shared/rlsBoundClient.js';
import { databaseDeleteWithoutOwnershipCheck } from '../../src/rules/contextual/databaseDeleteWithoutOwnershipCheck.js';
import { serverActionWithoutAuthorization } from '../../src/rules/contextual/serverActionWithoutAuthorization.js';
import { memoryContext } from './helpers.js';

const PACKAGE_JSON: [string, string] = [
  'package.json',
  '{"name":"x","dependencies":{"@supabase/supabase-js":"2.45.0"}}',
];

const DELETE_DOCUMENTS: [string, string] = [
  'components/DeleteDocument.tsx',
  "'use client';\nimport { createClient } from '@supabase/supabase-js';\n" +
    "const supabase = createClient('https://x.supabase.co', 'anon');\n" +
    "export function remove(id: string) { return supabase.from('documents').delete().eq('id', id); }\n",
];

const DELETE_DOCUMENTS_AS_ADMIN: [string, string] = [
  'app/actions/adminDelete.ts',
  "import { createClient } from '@supabase/supabase-js';\n" +
    "const supabaseAdmin = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n" +
    "export async function remove(id: string) { return supabaseAdmin.from('documents').delete().eq('id', id); }\n",
];

const migration = (sql: string): [string, string] => ['supabase/migrations/0001.sql', sql];

const ENABLE = 'ALTER TABLE documents ENABLE ROW LEVEL SECURITY;\n';

const IS_ORG_MEMBER_DEFINITION =
  'CREATE OR REPLACE FUNCTION public.is_org_member(_org_id uuid)\n' +
  'RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER AS $$\n' +
  '  SELECT EXISTS (\n' +
  '    SELECT 1 FROM public.organization_members m\n' +
  '     WHERE m.organization_id = _org_id AND m.user_id = auth.uid()\n' +
  '  );\n' +
  '$$;\n';

const deletes = (files: [string, string][]) =>
  databaseDeleteWithoutOwnershipCheck.run(memoryContext([PACKAGE_JSON, ...files]));

describe('committed SQL functions are read, not guessed at', () => {
  it('records a helper whose body references the caller identity', () => {
    const { fileMap } = memoryContext([PACKAGE_JSON, migration(IS_ORG_MEMBER_DEFINITION)]);
    const rls = detectSupabaseRls(fileMap);
    expect(rls.committedFunctions).toContain('is_org_member');
    expect(rls.identityBoundFunctions).toContain('is_org_member');
  });

  it('a committed helper whose body is only a login check is NOT identity-bound', () => {
    const { fileMap } = memoryContext([
      PACKAGE_JSON,
      migration(
        'CREATE FUNCTION public.has_access() RETURNS boolean LANGUAGE sql AS $$\n' +
          "  SELECT auth.role() = 'authenticated';\n$$;\n",
      ),
    ]);
    const rls = detectSupabaseRls(fileMap);
    expect(rls.committedFunctions).toContain('has_access');
    expect(rls.identityBoundFunctions).not.toContain('has_access');
  });

  it("the role claim spelled the long way is not the caller's identity either", () => {
    const { fileMap } = memoryContext([
      PACKAGE_JSON,
      migration(
        'CREATE FUNCTION public.is_team_member() RETURNS boolean LANGUAGE sql AS $$\n' +
          "  SELECT current_setting('request.jwt.claim.role') = 'authenticated';\n$$;\n",
      ),
    ]);
    expect(detectSupabaseRls(fileMap).identityBoundFunctions).not.toContain('is_team_member');
  });

  it('a dollar-quoted body ends at its OWN tag', () => {
    const { fileMap } = memoryContext([
      PACKAGE_JSON,
      migration(
        'CREATE FUNCTION public.is_org_admin(_org uuid) RETURNS boolean LANGUAGE sql AS $fn$\n' +
          '  SELECT false;\n$fn$;\n' +
          'CREATE FUNCTION public.unrelated() RETURNS uuid LANGUAGE sql AS $$ SELECT auth.uid(); $$;\n',
      ),
    ]);
    const rls = detectSupabaseRls(fileMap);
    expect(rls.committedFunctions).toEqual(['is_org_admin', 'unrelated']);
    expect(rls.identityBoundFunctions).toEqual(['unrelated']);
  });
});

describe('bindsOnEveryBranch follows the boolean structure, not the text', () => {
  const bound = (leaf: string) => /BOUND/.test(leaf);

  it('every OR branch must bind — one unbound branch admits rows on its own', () => {
    expect(bindsOnEveryBranch('BOUND(a) OR BOUND(b)', bound)).toBe(true);
    expect(bindsOnEveryBranch('BOUND(a) OR is_public', bound)).toBe(false);
  });

  it('one binding conjunct is enough — AND only narrows', () => {
    expect(bindsOnEveryBranch('deleted_at IS NULL AND BOUND(a)', bound)).toBe(true);
  });

  it('an OR nested inside an AND is still checked', () => {
    expect(bindsOnEveryBranch('org_id = x AND (BOUND(a) OR true)', bound)).toBe(false);
  });

  it('a negated predicate never binds', () => {
    expect(bindsOnEveryBranch('NOT BOUND(a)', bound)).toBe(false);
  });

  it('an unreadable expression binds nothing', () => {
    expect(bindsOnEveryBranch('BOUND(a', bound)).toBe(false);
    expect(bindsOnEveryBranch('   ', bound)).toBe(false);
  });

  it('a comment cannot supply the binding, and cannot hide an OR', () => {
    expect(bindsOnEveryBranch('-- BOUND\n is_public', bound)).toBe(false);
    expect(bindsOnEveryBranch('BOUND(a)\n-- OR\n', bound)).toBe(true);
  });
});

describe('isCommandCallerBound — the widened credit', () => {
  const rlsFor = (sql: string) => detectSupabaseRls(memoryContext([PACKAGE_JSON, migration(sql)]).fileMap);

  it('credits an org-scoped policy the identity test cannot see', () => {
    const rls = rlsFor(
      ENABLE + IS_ORG_MEMBER_DEFINITION +
        'CREATE POLICY "org members manage documents" ON public.documents FOR DELETE\n' +
        '  USING (public.is_org_member(organization_id));\n',
    );
    expect(isCommandIdentityScoped(rls, 'documents', 'delete')).toBe(false);
    expect(isCommandCallerBound(rls, 'documents', 'delete')).toBe(true);
  });

  it('credits an EXISTS over a membership table', () => {
    const rls = rlsFor(
      ENABLE +
        'CREATE POLICY p ON documents FOR DELETE USING (\n' +
        '  EXISTS (SELECT 1 FROM members m WHERE m.org_id = documents.org_id AND m.user_id = auth.uid())\n' +
        ');\n',
    );
    expect(isCommandCallerBound(rls, 'documents', 'delete')).toBe(true);
  });

  it("credits a tenant column compared to the caller's JWT org claim", () => {
    const rls = rlsFor(
      ENABLE +
        "CREATE POLICY p ON documents FOR DELETE USING (organization_id::text = (auth.jwt() ->> 'org_id'));\n",
    );
    expect(isCommandCallerBound(rls, 'documents', 'delete')).toBe(true);
  });

  it('still credits the owner-scoped policy it always credited', () => {
    const rls = rlsFor(ENABLE + 'CREATE POLICY p ON documents FOR DELETE USING (auth.uid() = user_id);\n');
    expect(isCommandCallerBound(rls, 'documents', 'delete')).toBe(true);
  });

  it('REFUSES a role-only policy — every account satisfies it', () => {
    const rls = rlsFor(
      ENABLE + "CREATE POLICY p ON documents FOR DELETE USING (auth.role() = 'authenticated');\n",
    );
    expect(isCommandCallerBound(rls, 'documents', 'delete')).toBe(false);
  });

  it('REFUSES `auth.uid() IS NOT NULL` — it names the caller and binds no row', () => {
    const rls = rlsFor(ENABLE + 'CREATE POLICY p ON documents FOR DELETE USING (auth.uid() IS NOT NULL);\n');
    expect(isCommandCallerBound(rls, 'documents', 'delete')).toBe(false);
  });

  it('REFUSES the inverted-auth shape even when the other branch is a real membership check', () => {
    const rls = rlsFor(
      ENABLE + IS_ORG_MEMBER_DEFINITION +
        'CREATE POLICY p ON documents FOR DELETE\n' +
        '  USING (auth.uid() IS NULL OR public.is_org_member(org_id));\n',
    );
    expect(isCommandCallerBound(rls, 'documents', 'delete')).toBe(false);
  });

  it('REFUSES a literal true', () => {
    const rls = rlsFor(ENABLE + 'CREATE POLICY p ON documents FOR DELETE USING (true);\n');
    expect(isCommandCallerBound(rls, 'documents', 'delete')).toBe(false);
  });

  it('REFUSES a permissive sibling — policies are OR-ed', () => {
    const rls = rlsFor(
      ENABLE + IS_ORG_MEMBER_DEFINITION +
        'CREATE POLICY p1 ON documents FOR DELETE USING (public.is_org_member(organization_id));\n' +
        'CREATE POLICY p2 ON documents FOR ALL USING (true);\n',
    );
    expect(isCommandCallerBound(rls, 'documents', 'delete')).toBe(false);
  });

  it('REFUSES a policy with one unbound OR branch', () => {
    const rls = rlsFor(
      ENABLE + IS_ORG_MEMBER_DEFINITION +
        'CREATE POLICY p ON documents FOR DELETE USING (public.is_org_member(org_id) OR is_public);\n',
    );
    expect(isCommandCallerBound(rls, 'documents', 'delete')).toBe(false);
  });

  it('REFUSES a helper the migrations define as a login check, whatever its name says', () => {
    const rls = rlsFor(
      ENABLE +
        'CREATE FUNCTION public.has_access() RETURNS boolean LANGUAGE sql AS $$\n' +
        "  SELECT auth.role() = 'authenticated';\n$$;\n" +
        'CREATE POLICY p ON documents FOR DELETE USING (public.has_access());\n',
    );
    expect(isCommandCallerBound(rls, 'documents', 'delete')).toBe(false);
  });

  it('REFUSES a plain row predicate that mentions nobody', () => {
    const rls = rlsFor(ENABLE + 'CREATE POLICY p ON documents FOR DELETE USING (deleted_at IS NULL);\n');
    expect(isCommandCallerBound(rls, 'documents', 'delete')).toBe(false);
  });

  it('REFUSES when RLS was never enabled, and when it was later disabled', () => {
    const policy = IS_ORG_MEMBER_DEFINITION +
      'CREATE POLICY p ON documents FOR DELETE USING (public.is_org_member(org_id));\n';
    expect(isCommandCallerBound(rlsFor(policy), 'documents', 'delete')).toBe(false);
    expect(
      isCommandCallerBound(
        rlsFor(ENABLE + policy + 'ALTER TABLE documents DISABLE ROW LEVEL SECURITY;\n'),
        'documents',
        'delete',
      ),
    ).toBe(false);
  });

  it('REFUSES while any policy in the project failed to parse', () => {
    const rls = rlsFor(
      ENABLE + IS_ORG_MEMBER_DEFINITION +
        'CREATE POLICY p ON documents FOR DELETE USING (public.is_org_member(org_id));\n' +
        'CREATE POLICY 9bad ON other FOR SELECT USING (true);\n',
    );
    expect(rls.unparsedPolicyCount).toBeGreaterThan(0);
    expect(isCommandCallerBound(rls, 'documents', 'delete')).toBe(false);
  });

  it('an uncommitted helper is credited on its NAME, and only a membership name', () => {
    const membership = rlsFor(
      ENABLE + 'CREATE POLICY p ON documents FOR DELETE USING (is_workspace_member(workspace_id));\n',
    );
    expect(isCommandCallerBound(membership, 'documents', 'delete')).toBe(true);
    const notMembership = rlsFor(
      ENABLE + 'CREATE POLICY p ON documents FOR DELETE USING (is_deleted(id));\n',
    );
    expect(isCommandCallerBound(notMembership, 'documents', 'delete')).toBe(false);
    const loginShaped = rlsFor(
      ENABLE + 'CREATE POLICY p ON documents FOR DELETE USING (is_authenticated_user());\n',
    );
    expect(isCommandCallerBound(loginShaped, 'documents', 'delete')).toBe(false);
  });

  it('an UPDATE policy must bind on BOTH the row it picks and the row it writes', () => {
    const rls = rlsFor(
      ENABLE + IS_ORG_MEMBER_DEFINITION +
        'CREATE POLICY p ON documents FOR UPDATE\n' +
        '  USING (public.is_org_member(org_id)) WITH CHECK (true);\n',
    );
    expect(isCommandCallerBound(rls, 'documents', 'update')).toBe(false);
  });
});

describe('operationBypassesRls fails closed', () => {
  it('a module naming the service-role key is privileged throughout', () => {
    expect(operationBypassesRls('const k = process.env.SUPABASE_SERVICE_ROLE_KEY;\nx.from("t")', 40)).toBe(true);
  });

  it('an admin client under a conventional name counts', () => {
    expect(operationBypassesRls("import { supabaseAdmin } from '@/lib/admin';\n", 20)).toBe(true);
  });

  it('THE STATION REGRESSION: a factory whose name spells the family differently', () => {
    expect(
      operationBypassesRls("import { createSupabaseServiceClient } from '@/lib/supabase/server';\n", 20),
    ).toBe(true);
    expect(operationBypassesRls('const c = getServiceRoleClient();\n', 10)).toBe(true);
    expect(operationBypassesRls('const c = create_admin_client();\n', 10)).toBe(true);
  });

  it('a COMMENT about the service-role key is not a service-role client', () => {
    const file =
      '/**\n * The client here is the ordinary session-scoped one. The service-role key\n' +
      ' * is never involved.\n */\n' +
      "const supabase = createClient();\nawait supabase.from('profiles').update({ name });\n";
    expect(operationBypassesRls(file, file.length - 10)).toBe(false);
  });

  it('an ordinary anon client does not', () => {
    expect(
      operationBypassesRls("const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);\n", 30),
    ).toBe(false);
  });
});

describe('database_delete_without_ownership_check — the membership credit', () => {
  it('SILENT: an org-scoped DELETE policy the identity test could not see', () => {
    expect(
      deletes([
        DELETE_DOCUMENTS,
        migration(
          ENABLE + IS_ORG_MEMBER_DEFINITION +
            'CREATE POLICY "org members" ON public.documents FOR DELETE\n' +
            '  USING (public.is_org_member(organization_id));\n',
        ),
      ]),
    ).toHaveLength(0);
  });

  it('SILENT: an EXISTS-membership DELETE policy', () => {
    expect(
      deletes([
        DELETE_DOCUMENTS,
        migration(
          ENABLE +
            'CREATE POLICY p ON documents FOR DELETE USING (\n' +
            '  EXISTS (SELECT 1 FROM org_members m\n' +
            '           WHERE m.org_id = documents.org_id AND m.user_id = auth.uid())\n' +
            ');\n',
        ),
      ]),
    ).toHaveLength(0);
  });

  it('SILENT (unchanged): an owner-scoped DELETE policy', () => {
    expect(
      deletes([
        DELETE_DOCUMENTS,
        migration(ENABLE + 'CREATE POLICY p ON documents FOR DELETE USING (auth.uid() = user_id);\n'),
      ]),
    ).toHaveLength(0);
  });

  it('FIRES: a role-only DELETE policy — any signed-in account passes it', () => {
    expect(
      deletes([
        DELETE_DOCUMENTS,
        migration(ENABLE + "CREATE POLICY p ON documents FOR DELETE USING (auth.role() = 'authenticated');\n"),
      ]),
    ).toHaveLength(1);
  });

  it('FIRES: a permissive USING (true) DELETE policy', () => {
    expect(
      deletes([DELETE_DOCUMENTS, migration(ENABLE + 'CREATE POLICY p ON documents FOR DELETE USING (true);\n')]),
    ).toHaveLength(1);
  });

  it('FIRES: no committed policy names the table at all', () => {
    expect(
      deletes([
        DELETE_DOCUMENTS,
        migration('CREATE TABLE documents (id uuid, organization_id uuid, user_id uuid);\n'),
      ]),
    ).toHaveLength(1);
  });

  it('FIRES: the service-role client bypasses RLS, however well the table is scoped', () => {
    const findings = deletes([
      DELETE_DOCUMENTS_AS_ADMIN,
      migration(
        ENABLE + IS_ORG_MEMBER_DEFINITION +
          'CREATE POLICY p ON public.documents FOR DELETE USING (public.is_org_member(organization_id));\n',
      ),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.filePath).toBe('app/actions/adminDelete.ts');
  });
});

describe('server_action_without_authorization — the membership credit', () => {
  const ACTION_HEADER = "'use server';\nimport { createClient } from '@/lib/supabase/server';\n";

  const action = (body: string): [string, string] => [
    'app/actions/documents.ts',
    ACTION_HEADER +
      'export async function renameDocument(id: string, title: string) {\n' +
      `${body}\n` +
      '}\n',
  ];

  const adminAction = (body: string): [string, string] => [
    'app/actions/documents.ts',
    "'use server';\nimport { createClient } from '@supabase/supabase-js';\n" +
      'const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n' +
      'export async function renameDocument(id: string, title: string) {\n' +
      `${body}\n` +
      '}\n',
  ];

  const UPDATE_DOCUMENTS =
    '  const supabase = createClient();\n' +
    "  await supabase.from('documents').update({ title }).eq('id', id);";

  const actions = (files: [string, string][]) =>
    serverActionWithoutAuthorization.run(memoryContext([PACKAGE_JSON, ...files]));

  const ORG_UPDATE_POLICY =
    'ALTER TABLE documents ENABLE ROW LEVEL SECURITY;\n' + IS_ORG_MEMBER_DEFINITION +
    'CREATE POLICY "org members write documents" ON public.documents FOR UPDATE\n' +
    '  USING (public.is_org_member(organization_id))\n' +
    '  WITH CHECK (public.is_org_member(organization_id));\n';

  it('control: the action fires with no committed policy at all', () => {
    expect(
      actions([action(UPDATE_DOCUMENTS), migration('CREATE TABLE documents (id uuid, organization_id uuid);\n')]),
    ).toHaveLength(1);
  });

  it('SILENT: an org-scoped UPDATE policy governs the table', () => {
    expect(actions([action(UPDATE_DOCUMENTS), migration(ORG_UPDATE_POLICY)])).toHaveLength(0);
  });

  it('SILENT: an owner-scoped UPDATE policy', () => {
    expect(
      actions([
        action(UPDATE_DOCUMENTS),
        migration(
          'ALTER TABLE documents ENABLE ROW LEVEL SECURITY;\n' +
            'CREATE POLICY p ON documents FOR UPDATE USING (auth.uid() = user_id)\n' +
            '  WITH CHECK (auth.uid() = user_id);\n',
        ),
      ]),
    ).toHaveLength(0);
  });

  it('SILENT: an EXISTS-membership INSERT policy on an insert action', () => {
    expect(
      actions([
        action(
          '  const supabase = createClient();\n' +
            "  await supabase.from('documents').insert({ title });",
        ),
        migration(
          'ALTER TABLE documents ENABLE ROW LEVEL SECURITY;\n' +
            'CREATE POLICY p ON documents FOR INSERT WITH CHECK (\n' +
            '  EXISTS (SELECT 1 FROM members m\n' +
            '           WHERE m.org_id = documents.org_id AND m.user_id = auth.uid())\n' +
            ');\n',
        ),
      ]),
    ).toHaveLength(0);
  });

  it('FIRES: a role-only UPDATE policy', () => {
    expect(
      actions([
        action(UPDATE_DOCUMENTS),
        migration(
          'ALTER TABLE documents ENABLE ROW LEVEL SECURITY;\n' +
            "CREATE POLICY p ON documents FOR UPDATE USING (auth.role() = 'authenticated');\n",
        ),
      ]),
    ).toHaveLength(1);
  });

  it('FIRES: a permissive WITH CHECK (true)', () => {
    expect(
      actions([
        action(UPDATE_DOCUMENTS),
        migration(
          'ALTER TABLE documents ENABLE ROW LEVEL SECURITY;\n' + IS_ORG_MEMBER_DEFINITION +
            'CREATE POLICY p ON documents FOR UPDATE USING (public.is_org_member(org_id))\n' +
            '  WITH CHECK (true);\n',
        ),
      ]),
    ).toHaveLength(1);
  });

  it('FIRES: the service-role client bypasses the policy entirely', () => {
    expect(actions([adminAction(UPDATE_DOCUMENTS), migration(ORG_UPDATE_POLICY)])).toHaveLength(1);
  });

  it('FIRES: a SECOND mutation in the same action is unconstrained', () => {
    expect(
      actions([
        action(
          '  const supabase = createClient();\n' +
            "  await supabase.from('documents').update({ title }).eq('id', id);\n" +
            "  await supabase.from('audit_log').insert({ id, title });",
        ),
        migration(ORG_UPDATE_POLICY),
      ]),
    ).toHaveLength(1);
  });

  it('FIRES: a Prisma mutation is never credited by a Supabase policy', () => {
    expect(
      actions([
        [
          'app/actions/documents.ts',
          ACTION_HEADER +
            'export async function renameDocument(id: string, title: string) {\n' +
            '  await prisma.documents.update({ where: { id }, data: { title } });\n}\n',
        ],
        migration(ORG_UPDATE_POLICY),
      ]),
    ).toHaveLength(1);
  });

  it('FIRES: a .from() belonging to an EARLIER statement cannot name this write', () => {
    expect(
      actions([
        action(
          '  const supabase = createClient();\n' +
            "  const existing = await supabase.from('documents').select('*').eq('id', id);\n" +
            '  await auditTable.update({ title });',
        ),
        migration(ORG_UPDATE_POLICY),
      ]),
    ).toHaveLength(1);
  });
});
