import { describe, expect, it } from 'vitest';
import { brokenAccessControl } from '../../src/rules/contextual/brokenAccessControl.js';
import { databaseDeleteWithoutOwnershipCheck } from '../../src/rules/contextual/databaseDeleteWithoutOwnershipCheck.js';
import { memoryContext } from './helpers.js';

const PKG: [string, string] = ['package.json', '{"name":"x","dependencies":{"next":"14.0.0"}}'];
const bac = (code: string) => brokenAccessControl.run(memoryContext([PKG, ['pages/api/r.ts', code]]));
const del = (code: string) => databaseDeleteWithoutOwnershipCheck.run(memoryContext([PKG, ['pages/api/d.ts', code]]));

describe('broken_access_control (trusted vs request identity)', () => {
  it('CONFIRMED BYPASS: ownership field taken from the request is not protection', () => {
    expect(
      bac('export default async function h(req,res){ const o = await prisma.order.findUnique({ where: { id: req.query.id, userId: req.query.userId } }); res.json(o); }\n'),
    ).toHaveLength(1);
  });
  it('READ scoped by session identity is safe', () => {
    expect(
      bac('export default async function h(req,res){ const s = await getServerSession(); const o = await prisma.order.findFirst({ where: { id: req.query.id, userId: s.user.id } }); res.json(o); }\n'),
    ).toHaveLength(0);
  });
  it('UPDATE by request id with no trusted owner is flagged', () => {
    expect(
      bac('export default async function h(req,res){ await prisma.order.update({ where: { id: req.query.id }, data: req.body }); res.json({ok:true}); }\n'),
    ).toHaveLength(1);
  });
  it('trusted alias (const userId = session.user.id) is safe; request alias is flagged', () => {
    expect(
      bac('export default async function h(req,res){ const userId = session.user.id; const o = await prisma.order.findFirst({ where: { id: req.query.id, userId } }); res.json(o); }\n'),
    ).toHaveLength(0);
    expect(
      bac('export default async function h(req,res){ const userId = req.query.userId; const o = await prisma.order.findFirst({ where: { id: req.query.id, userId } }); res.json(o); }\n'),
    ).toHaveLength(1);
  });
  it('listing my own rows (no request id) is not flagged', () => {
    expect(
      bac('export default async function h(req,res){ const s = await getServerSession(); const o = await prisma.order.findMany({ where: { userId: s.user.id } }); res.json(o); }\n'),
    ).toHaveLength(0);
  });
});

describe('database_delete_without_ownership_check (trusted identity)', () => {
  it('DELETE with request-controlled owner field is flagged', () => {
    expect(
      del('export default async function h(req,res){ await prisma.item.delete({ where: { id: req.query.id, userId: req.query.userId } }); res.json({ok:true}); }\n'),
    ).toHaveLength(1);
  });
  it('DELETE scoped by session identity is safe', () => {
    expect(
      del('export default async function h(req,res){ const s = await getServerSession(); await prisma.item.delete({ where: { id: req.query.id, userId: s.user.id } }); res.json({ok:true}); }\n'),
    ).toHaveLength(0);
  });

  const supa = (code: string, sql?: string) =>
    databaseDeleteWithoutOwnershipCheck.run(
      memoryContext(
        sql === undefined
          ? [PKG, ['src/pages/D.tsx', code]]
          : [PKG, ['src/pages/D.tsx', code], ['supabase/migrations/0001.sql', sql]],
      ),
    );

  it('FP regression: identity from a React auth hook counts as trusted', () => {
    expect(
      supa(
        'import { useAuth } from "@/contexts/AuthContext";\n' +
          'export function D(){ const { user } = useAuth();\n' +
          '  const go = async () => { await supabase.from("notes").delete().eq("user_id", user.id); };\n' +
          '  return go; }\n',
      ),
    ).toHaveLength(0);
  });

  it('FP regression: owner column named host_id/created_by still counts', () => {
    expect(
      supa(
        'import { useAuth } from "@/contexts/AuthContext";\n' +
          'export function D(){ const { user } = useAuth();\n' +
          '  const go = async () => { await supabase.from("games").delete().eq("id", gameId).eq("host_id", user?.id); };\n' +
          '  return go; }\n',
      ),
    ).toHaveLength(0);
  });

  it('FP regression: nested destructuring of supabase.auth.getUser() is trusted', () => {
    expect(
      supa(
        'export async function d(){\n' +
          '  const { data: { user }, error } = await supabaseClient.auth.getUser();\n' +
          '  await supabaseClient.from("profiles").delete().eq("id", user.id);\n' +
          '}\n',
      ),
    ).toHaveLength(0);
  });

  it('FP regression: an RLS DELETE policy scoped to auth.uid() is ownership enforcement', () => {
    expect(
      supa(
        'export async function d(id: string){ await supabase.from("notes").delete().eq("id", id); }\n',
        'ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n' +
          'CREATE POLICY p ON notes FOR DELETE USING (auth.uid() = user_id);\n',
      ),
    ).toHaveLength(0);
  });

  it('FP regression: RLS on with NO delete policy is default-deny, not an exposure', () => {
    expect(
      supa(
        'export async function d(id: string){ await supabase.from("notes").delete().eq("id", id); }\n',
        'ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n' +
          'CREATE POLICY p ON notes FOR SELECT USING (auth.uid() = user_id);\n',
      ),
    ).toHaveLength(0);
  });

  it('FP regression: a policy NAME containing "on <word>" no longer hides the real policy', () => {
    expect(
      supa(
        'export async function d(id: string){ await supabase.from("reviews").delete().eq("id", id); }\n',
        'ALTER TABLE reviews ENABLE ROW LEVEL SECURITY;\n' +
          'CREATE POLICY "Raters can delete their review on a completed transaction"\n' +
          '  ON public.reviews FOR DELETE USING (auth.uid() = rater_id);\n',
      ),
    ).toHaveLength(0);
  });

  it('TP retention: no ownership filter and no RLS still fires', () => {
    expect(
      supa('export async function d(id: string){ await supabase.from("notes").delete().eq("id", id); }\n'),
    ).toHaveLength(1);
  });

  it('TP retention: a USING (true) delete policy is not enforcement', () => {
    expect(
      supa(
        'export async function d(id: string){ await supabase.from("notes").delete().eq("id", id); }\n',
        'ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\nCREATE POLICY p ON notes FOR DELETE USING (true);\n',
      ),
    ).toHaveLength(1);
  });

  it('TP retention: RLS later disabled is not enforcement', () => {
    expect(
      supa(
        'export async function d(id: string){ await supabase.from("notes").delete().eq("id", id); }\n',
        'ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n' +
          'CREATE POLICY p ON notes FOR DELETE USING (auth.uid() = user_id);\n' +
          'ALTER TABLE notes DISABLE ROW LEVEL SECURITY;\n',
      ),
    ).toHaveLength(1);
  });

  it('TP retention: a request-controlled owner value is still not protection', () => {
    expect(
      supa(
        'export async function d(req){ const userId = req.query.userId;\n' +
          '  await supabase.from("notes").delete().eq("user_id", userId); }\n',
      ),
    ).toHaveLength(1);
  });

  it('TP retention: an RLS policy for a DIFFERENT table does not clear this one', () => {
    expect(
      supa(
        'export async function d(id: string){ await supabase.from("secrets").delete().eq("id", id); }\n',
        'ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n' +
          'CREATE POLICY p ON notes FOR DELETE USING (auth.uid() = user_id);\n',
      ),
    ).toHaveLength(1);
  });
});

describe('broken_access_control admin route middleware', () => {
  it('does not require ownership on routes with proven admin middleware', () => {
    const ctx = memoryContext([['package.json', '{"dependencies":{"express":"^4.0.0","prisma":"^5.0.0"}}'], ['server.js',
      'function require_admin(req, res, next){ if(req.user.role !== "admin") return res.status(403).end(); next(); }\n' +
      'router.get("/user-packages/:user_id", get_current_user, require_admin, async (req, res) => {\n' +
      '  const rows = await prisma.package.findMany({ where: { userId: req.params.user_id } });\n' +
      '  res.json(rows);\n' +
      '});\n']]);
    expect(brokenAccessControl.run(ctx)).toHaveLength(0);
  });

  it('still flags ordinary authenticated routes without ownership', () => {
    const ctx = memoryContext([['package.json', '{"dependencies":{"express":"^4.0.0","prisma":"^5.0.0"}}'], ['server.js',
      'router.get("/clips/:project_id", get_current_user, validateProjectId, async (req, res) => {\n' +
      '  const clip = await prisma.clip.findFirst({ where: { projectId: req.params.project_id } });\n' +
      '  res.json(clip);\n' +
      '});\n']]);
    expect(brokenAccessControl.run(ctx).length).toBeGreaterThan(0);
  });
});
describe('admin middleware proof', () => {
  it('accepts real admin middleware as authorization for admin IDOR access', () => {
    const ctx = memoryContext([PKG, ['server/admin.js',
      'function requireAdmin(req,res,next){ if(req.user.role !== "admin") return res.status(403).end(); next(); }\n' +
      'router.get("/admin/users/:id", requireAdmin, (req,res)=> prisma.user.findUnique({ where: { id: req.params.id } }));\n']]);
    expect(brokenAccessControl.run(ctx)).toHaveLength(0);
  });

  it('does not trust a no-op function named requireAdmin', () => {
    const ctx = memoryContext([PKG, ['server/admin.js',
      'function requireAdmin(req,res,next){ next(); }\n' +
      'router.get("/admin/users/:id", requireAdmin, (req,res)=> prisma.user.findUnique({ where: { id: req.params.id } }));\n']]);
    expect(brokenAccessControl.run(ctx).length).toBeGreaterThan(0);
  });
});


describe('database_delete_without_ownership_check — Prisma/tRPC/capability/seed', () => {
  const PK: [string, string] = ['package.json', '{"name":"x","dependencies":{"@prisma/client":"5.0.0"}}'];
  const del = (path: string, code: string, extra: [string, string][] = []) =>
    databaseDeleteWithoutOwnershipCheck.run(memoryContext([PK, [path, code], ...extra]));

  it('FP regression: fetch-with-ownership then delete-by-id (buildTeamWhereQuery)', () => {
    const code =
      'export const deleteFolder = async ({ userId, teamId, folderId }) => {\n' +
      '  const folder = await prisma.folder.findFirst({ where: { id: folderId, team: buildTeamWhereQuery({ teamId, userId }) } });\n' +
      "  if (!folder) throw new Error('not found');\n" +
      '  return await prisma.folder.delete({ where: { id: folder.id } });\n' +
      '};\n';
    expect(del('packages/lib/server-only/folder/delete-folder.ts', code)).toHaveLength(0);
  });

  it('FP regression: delete scoped by a trusted param ownership column (shorthand)', () => {
    const code =
      'export const deletePasskeyChallenge = async ({ userId }) => {\n' +
      "  await prisma.verificationToken.deleteMany({ where: { userId, identifier: 'PASSKEY_CHALLENGE' } });\n" +
      '};\n';
    expect(del('packages/lib/server-only/auth/x.ts', code)).toHaveLength(0);
  });

  it('FP regression: admin tRPC procedure deleting a global record', () => {
    const code =
      'export const deleteEmailTransportRoute = adminProcedure\n' +
      '  .input(Z)\n' +
      '  .mutation(async ({ input, ctx }) => {\n' +
      '    await prisma.emailTransport.delete({ where: { id: input.id } });\n' +
      '  });\n';
    expect(del('packages/trpc/server/admin-router/delete-email-transport.ts', code)).toHaveLength(0);
  });

  it('FP regression: capability-token delete keyed by the token itself', () => {
    const code =
      'export const declineLink = procedure.mutation(async ({ input }) => {\n' +
      '  const { token } = input;\n' +
      "  await prisma.verificationToken.delete({ where: { token, identifier: 'LINK' } });\n" +
      '});\n';
    expect(del('packages/trpc/server/enterprise-router/decline.ts', code)).toHaveLength(0);
  });

  it('FP regression: deleting the caller’s own expired session', () => {
    const code =
      'export const validateSession = async (sessionToken) => {\n' +
      '  const sessionId = hashToken(sessionToken);\n' +
      '  const result = await prisma.session.findFirst({ where: { id: sessionId } });\n' +
      '  if (!result) return null;\n' +
      '  if (Date.now() >= result.expiresAt.getTime()) {\n' +
      '    await prisma.session.delete({ where: { id: sessionId } });\n' +
      '    return null;\n' +
      '  }\n' +
      '};\n';
    expect(del('packages/auth/server/lib/session/session.ts', code)).toHaveLength(0);
  });

  it('FP regression: a seed script is not application delete logic', () => {
    const code = 'await prisma.user.delete({ where: { id: someId } });\n';
    expect(del('packages/prisma/seed/users.ts', code)).toHaveLength(0);
  });

  it('FP regression: a database migration is excluded', () => {
    const code = 'await prisma.user.delete({ where: { id: someId } });\n';
    expect(del('db/migrations/20230101-init.ts', code)).toHaveLength(0);
  });

  it('TP retention: a helper deleting by id with NO ownership context still fires', () => {
    const code =
      'export const deleteEmailDomain = async ({ emailDomainId }) => {\n' +
      '  await prisma.emailDomain.delete({ where: { id: emailDomainId } });\n' +
      '};\n';
    expect(del('packages/lib/server-only/x/delete-email-domain.ts', code)).toHaveLength(1);
  });

  it('TP retention: authenticatedProcedure alone (login, not authority) still fires', () => {
    const code =
      'export const deleteThing = authenticatedProcedure.mutation(async ({ input }) => {\n' +
      '  await prisma.thing.delete({ where: { id: input.id } });\n' +
      '});\n';
    expect(del('packages/trpc/server/thing-router/delete-thing.ts', code)).toHaveLength(1);
  });

  it('TP retention: request-controlled owner column is still not ownership', () => {
    const code =
      'export default async function handler(req, res) {\n' +
      '  await prisma.item.delete({ where: { id: req.query.id, userId: req.query.userId } });\n' +
      '  res.json({ ok: true });\n' +
      '}\n';
    expect(del('pages/api/item.ts', code)).toHaveLength(1);
  });
});
