import { describe, expect, it } from 'vitest';
import { brokenAccessControl } from '../../src/rules/contextual/brokenAccessControl.js';
import { databaseDeleteWithoutOwnershipCheck } from '../../src/rules/contextual/databaseDeleteWithoutOwnershipCheck.js';
import { apiMutationWithoutAuth } from '../../src/rules/contextual/apiMutationWithoutAuth.js';
import { memoryContext } from './helpers.js';

const PKG: [string, string] = [
  'package.json',
  '{"name":"x","dependencies":{"next":"14.0.0","@prisma/client":"5.0.0","drizzle-orm":"^0.30.0","@supabase/supabase-js":"^2.0.0"}}',
];
const ROUTE = 'app/api/x/route.ts';

const authed = (body: string) =>
  "import { auth } from '@/auth';\n" +
  'export async function POST(req){\n' +
  '  const session = await auth();\n' +
  "  if (!session) return new Response('no', { status: 401 });\n" +
  `${body}\n}\n`;

const bac = (code: string) => brokenAccessControl.run(memoryContext([PKG, [ROUTE, code]]));
const del = (code: string) => databaseDeleteWithoutOwnershipCheck.run(memoryContext([PKG, [ROUTE, code]]));

describe('ownership precision — supported patterns clear', () => {
  it('Prisma: where { id, userId: session.user.id }', () => {
    expect(bac(authed("  const { id } = await req.json();\n  await prisma.project.update({ where: { id, userId: session.user.id }, data: { name: 'x' } });"))).toHaveLength(0);
  });

  it('Prisma: deleteMany with an owner constraint', () => {
    expect(del(authed('  const { id } = await req.json();\n  await prisma.project.deleteMany({ where: { id, userId: session.user.id } });'))).toHaveLength(0);
  });

  it("Supabase: .eq('user_id', user.id)", () => {
    expect(bac(authed("  const { id } = await req.json();\n  await supabase.from('projects').update({ name: 'x' }).eq('id', id).eq('user_id', session.user.id);"))).toHaveLength(0);
  });

  it('Drizzle: and(eq(id), eq(userId, session.user.id))', () => {
    expect(bac(authed('  const { id } = await req.json();\n  await db.update(projects).set({ name: 1 }).where(and(eq(projects.id, id), eq(projects.userId, session.user.id)));'))).toHaveLength(0);
  });

  it('Explicit guard: load, compare resource.userId to identity, reject', () => {
    expect(bac(authed("  const { id } = await req.json();\n  const row = await prisma.project.findUnique({ where: { id } });\n  if (row.userId !== session.user.id) return new Response('no', { status: 403 });\n  await prisma.project.update({ where: { id }, data: { name: 'x' } });"))).toHaveLength(0);
  });

  it('Clerk: findOne scoped by the getAuth(req) userId', () => {
    const code =
      "import { getAuth } from '@clerk/nextjs/server';\n" +
      'export async function PUT(req, { params }){\n' +
      '  const { userId } = getAuth(req);\n' +
      '  const cardId = params.card;\n' +
      '  const reminder = await Reminder.findOne({ cardId: cardId, userId: userId });\n' +
      "  if (!reminder) return new Response('no', { status: 401 });\n" +
      '}\n';
    expect(bac(code)).toHaveLength(0);
  });

  it('Clerk: the aliased owner id, const { userId: ownerId } = getAuth(req)', () => {
    const code =
      "import { getAuth } from '@clerk/nextjs/server';\n" +
      'export async function POST(req, { params }){\n' +
      '  const { userId: ownerId } = getAuth(req);\n' +
      '  const courseId = params.course;\n' +
      '  const course = await Course.findOne({ _id: courseId, ownerId: ownerId });\n' +
      "  if (!course) return new Response('no', { status: 401 });\n" +
      '}\n';
    expect(bac(code)).toHaveLength(0);
  });

  it('Role guard: admin authorization (not merely isAuthenticated)', () => {
    expect(bac(authed("  if (session.user.role !== 'admin') return new Response('no', { status: 403 });\n  const { id } = await req.json();\n  await prisma.project.update({ where: { id }, data: { name: 'x' } });"))).toHaveLength(0);
  });
});

describe('ownership precision — traps still flag', () => {
  it('DIFFERENTIATOR: authenticated mutation, no ownership at all (App Router body)', () => {
    expect(del(authed('  const { id } = await req.json();\n  await prisma.project.deleteMany({ where: { id } });'))).toHaveLength(1);
  });

  it('TRAP: userId taken from req.body is not ownership', () => {
    expect(bac(authed("  const { id, userId } = await req.json();\n  await prisma.project.update({ where: { id, userId }, data: { name: 'x' } });"))).toHaveLength(1);
  });

  it('TRAP: userId taken from req.query is not ownership', () => {
    expect(
      bac("import { auth } from '@/auth';\nexport async function GET(req){\n  await auth();\n  await prisma.project.update({ where: { id: req.query.id, userId: req.query.userId }, data: {} });\n}\n"),
    ).toHaveLength(1);
  });

  it('TRAP: a Clerk-shaped userId read from the BODY is not the session', () => {
    const code =
      "import { getAuth } from '@clerk/nextjs/server';\n" +
      'export async function PUT(req, { params }){\n' +
      '  const { userId } = await req.json();\n' +
      '  const cardId = params.card;\n' +
      '  const reminder = await Reminder.findOne({ cardId: cardId, userId: userId });\n' +
      '}\n';
    expect(bac(code)).toHaveLength(1);
  });

  it('TRAP: an unscoped read in a handler that DID call getAuth still flags', () => {
    const code =
      "import { getAuth } from '@clerk/nextjs/server';\n" +
      'export async function GET(req, { params }){\n' +
      '  const { userId } = getAuth(req);\n' +
      '  const courseId = params.course;\n' +
      '  const invitations = await Invitation.find({ courseId: courseId });\n' +
      '  return Response.json(invitations);\n' +
      '}\n';
    expect(bac(code)).toHaveLength(1);
  });

  it('TRAP: owner taken from params is not ownership', () => {
    expect(
      bac("import { auth } from '@/auth';\nexport async function POST(req, { params }){\n  const { userId } = await auth();\n  if (!userId) return new Response('Unauthorized', { status: 401 });\n  await prisma.project.update({ where: { id: params.id, owner: params.owner }, data: {} });\n}\n"),
    ).toHaveLength(1);
  });
});

describe('authentication/authorization confusion', () => {
  it('router.get(...) route registration is NOT a record access', () => {
    const ctx = memoryContext([
      ['package.json', '{"name":"x","dependencies":{"koa-router":"^12.0.0"}}'],
      ['server/routes.js', 'router.get("/opensearch.xml", (ctx) => { ctx.body = build(ctx.request.URL.origin); });\n'],
    ]);
    expect(brokenAccessControl.run(ctx).filter((f) => f.filePath === 'server/routes.js')).toHaveLength(0);
  });

  it('a read-only SELECT (health check) is not a mutation-without-auth', () => {
    const ctx = memoryContext([
      ['package.json', '{"name":"x","dependencies":{"koa":"^2.0.0","sequelize":"^6.0.0"}}'],
      ['pages/api/health.ts', 'export default async function handler(req, res){ await sequelize.query("SELECT 1"); res.json({ ok: true }); }\n'],
    ]);
    expect(apiMutationWithoutAuth.run(ctx)).toHaveLength(0);
  });

  it("auth() invoked inside Promise.all, checked a few lines later, IS recognized", () => {
    const code =
      "import { auth } from '@/auth';\n" +
      'export async function POST(req){\n' +
      '  const body = await req.json();\n' +
      '  const [bot, session] = await Promise.all([checkBot().catch(() => null), auth()]);\n' +
      '  if (bot?.isBot) { return new Response("no", { status: 403 }); }\n' +
      '  if (!session?.user) { return new Response("no", { status: 401 }); }\n' +
      '  await prisma.message.create({ data: { text: body.text, userId: session.user.id } });\n' +
      '}\n';
    expect(apiMutationWithoutAuth.run(memoryContext([PKG, [ROUTE, code]]))).toHaveLength(0);
  });

  it('an imported-but-not-invoked requireAuth does not count as active protection', () => {
    const ctx = memoryContext([
      PKG,
      ['lib/auth.ts', 'export function requireAuth(req){ if(!req.session) throw new Error("401"); }\n'],
      ['app/api/y/route.ts', "import { requireAuth } from '@/lib/auth';\nexport async function POST(req){\n  const body = await req.json();\n  await prisma.project.create({ data: body });\n}\n"],
    ]);
    expect(apiMutationWithoutAuth.run(ctx).length).toBeGreaterThan(0);
  });
});

describe('load-then-truthiness ownership guard', () => {
  const clerk = (body: string) =>
    "import { getAuth } from '@clerk/nextjs/server';\n" +
    'export async function PUT(req, { params }) {\n' +
    '  const { userId } = getAuth(req);\n' +
    '  const courseId = params.course;\n' +
    `${body}\n}\n`;

  it('clears sinks in a handler that loads an owner-bound row and returns on falsy', () => {
    const code = clerk(
      '  const owned = await Course.findOne({ _id: courseId, ownerId: userId }).lean();\n' +
      '  if (!owned) return NextResponse.json({ error: "Unauthorized access" });\n' +
      '  await Course.findOneAndUpdate({ _id: courseId }, { courseName: "x" });',
    );
    expect(bac(code)).toHaveLength(0);
  });

  it('accepts the braced form and a compound condition', () => {
    const code = clerk(
      '  const owned = await Course.findOne({ _id: courseId, ownerId: userId }).lean();\n' +
      '  const student = await Course.findOne({ _id: courseId, userId: userId }).lean();\n' +
      '  if (!owned && !student) {\n' +
      '    return NextResponse.json({ error: "Unauthorized access" });\n' +
      '  }\n' +
      '  await Course.findOneAndUpdate({ _id: courseId }, { courseName: "x" });',
    );
    expect(bac(code)).toHaveLength(0);
  });

  it('does NOT credit a guard whose owner field is bound to a REQUEST value', () => {
    const code = clerk(
      '  const body = await req.json();\n' +
      '  const owned = await Course.findOne({ _id: courseId, ownerId: body.ownerId }).lean();\n' +
      '  if (!owned) return NextResponse.json({ error: "Unauthorized access" });\n' +
      '  await Course.findOneAndUpdate({ _id: courseId }, { courseName: "x" });',
    );
    expect(bac(code).length).toBeGreaterThan(0);
  });

  it('does NOT credit an owner-bound load with no early return', () => {
    const code = clerk(
      '  const owned = await Course.findOne({ _id: courseId, ownerId: userId }).lean();\n' +
      '  console.log(owned);\n' +
      '  await Course.findOneAndUpdate({ _id: courseId }, { courseName: "x" });',
    );
    expect(bac(code).length).toBeGreaterThan(0);
  });

  it('a handler with no guard at all still fires', () => {
    const code = clerk('  await Course.findOneAndUpdate({ _id: courseId }, { courseName: "x" });');
    expect(bac(code).length).toBeGreaterThan(0);
  });

  it('still reports a same-model sink keyed non-uniquely — the guard\'s scope was dropped', () => {
    const code = clerk(
      '  const cardId = params.card;\n' +
      '  const reminder = await Reminder.findOne({ cardId: cardId, userId: userId }).lean();\n' +
      '  if (!reminder) {\n' +
      '    return NextResponse.json({ error: "Unauthorized access" });\n' +
      '  }\n' +
      '  await Reminder.findOneAndUpdate({ cardId: cardId }, { phase: 1 }, { new: true });',
    );
    const onWrite = bac(code).filter((f) => /findOneAndUpdate/.test(f.evidence ?? ''));
    expect(onWrite.length).toBeGreaterThan(0);
  });

  it('clears a same-model sink keyed by the unique id the guard validated', () => {
    const code = clerk(
      '  const owned = await Course.findOne({ _id: courseId, ownerId: userId }).lean();\n' +
      '  if (!owned) return NextResponse.json({ error: "Unauthorized access" });\n' +
      '  await Course.findOneAndUpdate({ _id: courseId }, { $pull: { studentIds: "x" } });',
    );
    expect(bac(code)).toHaveLength(0);
  });

  it('does not lend the guard to a sibling handler', () => {
    const code =
      "import { getAuth } from '@clerk/nextjs/server';\n" +
      'export async function PUT(req, { params }) {\n' +
      '  const { userId } = getAuth(req);\n' +
      '  const courseId = params.course;\n' +
      '  const owned = await Course.findOne({ _id: courseId, ownerId: userId }).lean();\n' +
      '  if (!owned) return NextResponse.json({ error: "Unauthorized access" });\n' +
      '  await Course.findOneAndUpdate({ _id: courseId }, { courseName: "x" });\n' +
      '}\n' +
      'export async function GET(req, { params }) {\n' +
      '  const otherId = params.course;\n' +
      '  const course = await Course.findOne({ _id: otherId }).lean();\n' +
      '  return NextResponse.json(course);\n' +
      '}\n';
    const inGet = bac(code).filter((f) => f.lineStart >= 9);
    expect(inGet.length).toBeGreaterThan(0);
  });
});

describe('function-scoped taint at the ownership rules', () => {
  const courseCard = (getBody: string) =>
    "import { getAuth } from '@clerk/nextjs/server';\n" +
    'export async function PUT(req, { params }) {\n' +
    '  const { userId } = getAuth(req);\n' +
    '  const data = await req.json();\n' +
    '  const courseId = params.course;\n' +
    '  let studentId = data.studentId || userId;\n' +
    '  await Course.findOneAndUpdate({ _id: courseId }, { $pull: { studentIds: studentId } });\n' +
    '}\n' +
    'export async function GET(req, { params }) {\n' +
    '  const { userId } = getAuth(req);\n' +
    '  const course = await Course.findOne({ _id: params.course, ownerId: userId }).lean();\n' +
    `${getBody}\n}\n`;

  it('a sibling handler\'s local does not make a lookup request-controlled', () => {
    const code = courseCard(
      '  const students = await Promise.all(course.studentIds.map(async (studentId) => {\n' +
      '    const user = await User.findOne({ clerkId: studentId }).lean();\n' +
      '    return { studentId, email: user.email };\n' +
      '  }));',
    );
    const onMapLookup = bac(code).filter((finding) => /clerkId/.test(finding.evidence ?? ''));
    expect(onMapLookup).toHaveLength(0);
  });

  it('the SAME handler reading the request into that name still reports', () => {
    const code = courseCard(
      '  const body = await req.json();\n' +
      '  const studentId = body.studentId;\n' +
      '  const user = await User.findOne({ clerkId: studentId }).lean();',
    );
    const onLookup = bac(code).filter((finding) => /clerkId/.test(finding.evidence ?? ''));
    expect(onLookup.length).toBeGreaterThan(0);
  });
});
