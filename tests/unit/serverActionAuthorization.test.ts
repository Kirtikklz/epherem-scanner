import { describe, expect, it } from 'vitest';
import { serverActionWithoutAuthorization } from '../../src/rules/contextual/serverActionWithoutAuthorization.js';
import { envUsageWithoutServerBoundary } from '../../src/rules/contextual/envUsageWithoutServerBoundary.js';
import { supabaseServiceRoleExposed } from '../../src/rules/basic/supabaseServiceRoleExposed.js';
import { memoryContext } from './helpers.js';

const NEXT: [string, string] = ['package.json', '{"name":"x","dependencies":{"next":"14.0.0","@prisma/client":"5.0.0","@supabase/supabase-js":"^2.0.0"}}'];
const APP_MARKER: [string, string] = ['app/page.tsx', 'export default function Page(){ return null; }\n'];

const sa = (path: string, code: string) =>
  serverActionWithoutAuthorization.run(memoryContext([NEXT, APP_MARKER, [path, code]]));

describe('server_action_without_authorization', () => {
  it('unprotected server action (file-level use server) flags', () => {
    const f = sa('app/actions/a.ts', "'use server';\nexport async function rename(id, name){\n  await prisma.project.update({ where: { id }, data: { name } });\n}\n");
    expect(f).toHaveLength(1);
    expect(f[0]?.category).toBe('authorization');
  });

  it('unprotected create flags', () => {
    expect(sa('app/actions/b.ts', "'use server';\nexport async function make(data){\n  await prisma.project.create({ data });\n}\n")).toHaveLength(1);
  });

  it('inline "use server" action, unprotected, flags', () => {
    expect(
      sa('app/x/page.tsx', "export default function P(){\n  async function save(fd){\n    'use server';\n    await prisma.note.create({ data: { text: 'x' } });\n  }\n  return null;\n}\n"),
    ).toHaveLength(1);
  });

  it('authenticated (session check) but caller-controlled id, no ownership → STILL flags', () => {
    const f = sa('app/actions/c.ts', "'use server';\nimport { auth } from '@/auth';\nexport async function updateProject(projectId, name){\n  const session = await auth();\n  if (!session?.user) { throw new Error('Unauthorized'); }\n  return prisma.project.update({ where: { id: projectId }, data: { name } });\n}\n");
    expect(f).toHaveLength(1);
    expect(f[0]?.category).toBe('authorization');
  });

  it('authenticated upsert by caller-controlled id, no ownership → STILL flags', () => {
    expect(sa('app/actions/c2.ts', "'use server';\nimport { auth } from '@/auth';\nexport async function up(id, data){\n  const session = await auth();\n  if (!session) throw new Error('401');\n  return prisma.project.upsert({ where: { id }, create: data, update: data });\n}\n")).toHaveLength(1);
  });

  it('authentication-only helper (requireSession) + caller-controlled id → STILL flags', () => {
    expect(sa('app/actions/f.ts', "'use server';\nexport async function rename(id, name){\n  await requireSession();\n  await prisma.project.update({ where: { id }, data: { name } });\n}\n")).toHaveLength(1);
  });

  it('authentication-only wrapper (withAuth) + caller-controlled id → STILL flags', () => {
    expect(sa('app/actions/e.ts', "'use server';\nexport const rename = withAuth(async (id, name) => {\n  await prisma.project.update({ where: { id }, data: { name } });\n});\n")).toHaveLength(1);
  });

  it('owner-scoped update binds the row to the authenticated identity → clears', () => {
    expect(sa('app/actions/d.ts', "'use server';\nimport { auth } from '@/auth';\nexport async function updateProject(projectId, name){\n  const session = await auth();\n  if (!session?.user) { throw new Error('Unauthorized'); }\n  return prisma.project.update({ where: { id: projectId, userId: session.user.id }, data: { name } });\n}\n")).toHaveLength(0);
  });

  it('inherently self-scoped mutation (where id = session.user.id) → clears', () => {
    expect(sa('app/actions/d2.ts', "'use server';\nimport { auth } from '@/auth';\nexport async function updateMe(data){\n  const session = await auth();\n  return prisma.user.update({ where: { id: session.user.id }, data });\n}\n")).toHaveLength(0);
  });

  it('role guard (session.user.role !== admin) → clears', () => {
    expect(sa('app/actions/r.ts', "'use server';\nimport { auth } from '@/auth';\nexport async function up(id, name){\n  const session = await auth();\n  if (session.user.role !== 'admin') throw new Error('403');\n  return prisma.project.update({ where: { id }, data: { name } });\n}\n")).toHaveLength(0);
  });

  it('explicit ownership comparison (row.userId !== session.user.id) → clears', () => {
    expect(sa('app/actions/o.ts', "'use server';\nimport { auth } from '@/auth';\nexport async function up(id, name){\n  const session = await auth();\n  const row = await prisma.project.findUnique({ where: { id } });\n  if (row.userId !== session.user.id) throw new Error('403');\n  return prisma.project.update({ where: { id }, data: { name } });\n}\n")).toHaveLength(0);
  });

  it('authorization helper (requireRole) → clears', () => {
    expect(sa('app/actions/f2.ts', "'use server';\nexport async function rename(id, name){\n  await requireRole('editor');\n  await prisma.project.update({ where: { id }, data: { name } });\n}\n")).toHaveLength(0);
  });

  it('authorization wrapper (adminAction) → clears', () => {
    expect(sa('app/actions/e2.ts', "'use server';\nexport const rename = adminAction(async (id, name) => {\n  await prisma.project.update({ where: { id }, data: { name } });\n});\n")).toHaveLength(0);
  });

  it('Supabase .eq owner constraint on the authenticated user → clears', () => {
    expect(sa('app/actions/sb.ts', "'use server';\nexport async function up(id){\n  const { data: { user } } = await supabase.auth.getUser();\n  return supabase.from('projects').update({ n: 1 }).eq('id', id).eq('user_id', user.id);\n}\n")).toHaveLength(0);
  });

  it('a plain server module with no "use server" is NOT a server action', () => {
    expect(sa('app/lib/g.ts', "export async function rename(id, name){\n  await prisma.project.update({ where: { id }, data: { name } });\n}\n")).toHaveLength(0);
  });

  it('a read-only server action does not flag (no mutation)', () => {
    expect(sa('app/actions/h.ts', "'use server';\nexport async function listProjects(){\n  return prisma.project.findMany();\n}\n")).toHaveLength(0);
  });

  it("'use server' quoted in a comment does not create a phantom action", () => {
    expect(sa('app/actions/i.ts', "// this file will eventually be 'use server'\nexport async function rename(id, name){\n  await prisma.project.update({ where: { id }, data: { name } });\n}\n")).toHaveLength(0);
  });

  it('a delete is left to database_delete_without_ownership_check (no duplicate)', () => {
    expect(sa('app/actions/j.ts', "'use server';\nexport async function del(id){\n  await prisma.project.delete({ where: { id } });\n}\n")).toHaveLength(0);
  });
});

describe('Next.js boundary fixtures (definition of done)', () => {
  const ctx = (path: string, code: string, extra: [string, string][] = []) =>
    memoryContext([NEXT, APP_MARKER, [path, code], ...extra]);

  it('protected server action → no server-action finding', () => {
    expect(serverActionWithoutAuthorization.run(ctx('app/actions/ok.ts', "'use server';\nimport { auth } from '@/auth';\nexport async function upd(id){\n  const s = await auth();\n  if (!s) throw new Error('401');\n  await prisma.p.update({ where: { id, userId: s.user.id }, data: {} });\n}\n"))).toHaveLength(0);
  });

  it('unprotected server action → server-action finding', () => {
    expect(serverActionWithoutAuthorization.run(ctx('app/actions/bad.ts', "'use server';\nexport async function upd(id){\n  await prisma.p.update({ where: { id }, data: {} });\n}\n"))).toHaveLength(1);
  });

  it('client import of server-only privileged code (no server-only guard) → secret exposed', () => {
    const c = ctx(
      'app/ui/Btn.tsx',
      "'use client';\nimport { admin } from '../lib/admin';\nexport function Btn(){ admin.from('x').delete(); return null; }\n",
      [['app/lib/admin.ts', "import { createClient } from '@supabase/supabase-js';\nexport const admin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);\n"]],
    );
    expect(supabaseServiceRoleExposed.run(c).length).toBeGreaterThan(0);
  });

  it('harmless server component → nothing', () => {
    const c = ctx('app/roster/page.tsx', "export default async function Roster(){\n  const rows = await prisma.member.findMany();\n  return null;\n}\n");
    expect(serverActionWithoutAuthorization.run(c)).toHaveLength(0);
    expect(envUsageWithoutServerBoundary.run(c)).toHaveLength(0);
    expect(supabaseServiceRoleExposed.run(c)).toHaveLength(0);
  });

  it('valid NEXT_PUBLIC usage in a client component → no boundary finding', () => {
    const c = ctx('app/ui/Env.tsx', "'use client';\nexport function E(){ const u = process.env.NEXT_PUBLIC_API_URL; return u; }\n");
    expect(envUsageWithoutServerBoundary.run(c)).toHaveLength(0);
  });

  it('a non-public secret read in a Next.js client component is stripped, not leaked', () => {
    const c = ctx('app/ui/Leak.tsx', "'use client';\nexport function L(){ const k = process.env.STRIPE_SECRET_KEY; return k; }\n");
    expect(envUsageWithoutServerBoundary.run(c)).toHaveLength(0);
  });

  it('leaked server secret under NEXT_PUBLIC_ in a client component → env boundary finding', () => {
    const c = ctx('app/ui/Leak.tsx', "'use client';\nexport function L(){ const k = process.env.NEXT_PUBLIC_STRIPE_SECRET; return k; }\n");
    expect(envUsageWithoutServerBoundary.run(c)).toHaveLength(1);
  });
});
