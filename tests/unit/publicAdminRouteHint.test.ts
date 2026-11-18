import { describe, expect, it } from 'vitest';
import { publicAdminRouteHint } from '../../src/rules/basic/publicAdminRouteHint.js';
import { brokenAccessControl } from '../../src/rules/contextual/brokenAccessControl.js';
import { memoryContext } from './helpers.js';

const NEXT_PACKAGE = ['package.json', '{"dependencies":{"next":"14.0.0"}}'] as [string, string];

describe('public_admin_route_hint on file-routed frameworks', () => {
  it('goes quiet on a Next.js admin route whose handler checks an Administrator role', () => {
    const context = memoryContext([NEXT_PACKAGE, ['app/api/admin/teachers/route.ts',
      "import { getServerSession } from 'next-auth';\n" +
      'export async function GET(request: Request) {\n' +
      '  const session = await getServerSession(authOptions);\n' +
      "  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });\n" +
      '  const roles = (session.user as any)?.roles as string[] | undefined;\n' +
      "  if (!roles?.includes('Administrator')) {\n" +
      "    return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });\n" +
      '  }\n' +
      '  return NextResponse.json(await listTeachers());\n' +
      '}\n']]);
    expect(publicAdminRouteHint.run(context)).toHaveLength(0);
  });

  it('goes quiet when the role is compared against a string literal that is not the word admin', () => {
    const context = memoryContext([NEXT_PACKAGE, ['app/api/admin/payouts/route.ts',
      'export async function POST(request: Request) {\n' +
      '  const user = await getAppUser(request);\n' +
      '  if (user?.role !== "superadmin") return Response.json({ error: "forbidden" }, { status: 403 });\n' +
      '  return Response.json(await payout());\n' +
      '}\n']]);
    expect(publicAdminRouteHint.run(context)).toHaveLength(0);
  });

  it('still fires on an admin route with no rejection anywhere on the admin path', () => {
    const context = memoryContext([NEXT_PACKAGE, ['app/api/admin/orders/route.js',
      'export async function GET() {\n' +
      '  const orders = await Order.find({});\n' +
      '  return Response.json({ orders });\n' +
      '}\n']]);
    const findings = publicAdminRouteHint.run(context);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('high');
    expect(findings[0]?.evidence).toContain('/api/admin/orders');
  });

  it('judges per method: a guarded POST does not vouch for an unguarded GET below it', () => {
    const context = memoryContext([NEXT_PACKAGE, ['app/api/admin/positions/route.ts',
      'export async function POST(request: Request) {\n' +
      '  const session = await getServerSession(authOptions);\n' +
      "  if (session?.user?.role !== 'admin') return NextResponse.json({}, { status: 403 });\n" +
      '  return NextResponse.json(await recalculate());\n' +
      '}\n' +
      'export async function GET(request: Request) {\n' +
      '  return NextResponse.json(await prisma.termResult.findMany({ include: { student: true } }));\n' +
      '}\n']]);
    const findings = publicAdminRouteHint.run(context);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.lineStart).toBe(6);
  });

  it('judges per method in the other direction too: an unguarded GET above a guarded POST', () => {
    const context = memoryContext([NEXT_PACKAGE, ['app/api/admin/exports/route.ts',
      'export async function GET(request: Request) {\n' +
      '  return NextResponse.json(await everything());\n' +
      '}\n' +
      'export async function POST(request: Request) {\n' +
      '  const session = await getServerSession(authOptions);\n' +
      "  if (session?.user?.role !== 'admin') return NextResponse.json({}, { status: 403 });\n" +
      '  return NextResponse.json(await write());\n' +
      '}\n']]);
    const findings = publicAdminRouteHint.run(context);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.lineStart).toBe(1);
  });

  it('says something sharper when the caller is authenticated but no role is checked', () => {
    const context = memoryContext([NEXT_PACKAGE, ['app/api/admin/reindex/route.ts',
      "import { getServerSession } from 'next-auth';\n" +
      'export async function POST(request: Request) {\n' +
      '  const session = await getServerSession(authOptions);\n' +
      "  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });\n" +
      '  return NextResponse.json(await reindexEverything());\n' +
      '}\n']]);
    const findings = publicAdminRouteHint.run(context);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain('authenticates the caller but has no visible admin role check');
    expect(findings[0]?.severity).toBe('medium');
  });

  it('does not treat a non-admin word that merely contains admin as an admin route', () => {
    const context = memoryContext([NEXT_PACKAGE, ['app/api/badminton/route.ts',
      'export async function GET() {\n  return Response.json(await courts());\n}\n']]);
    expect(publicAdminRouteHint.run(context)).toHaveLength(0);
  });

  it('reads the route path, not the file path: a non-admin route filed under an admin directory is not an admin route', () => {
    const context = memoryContext([NEXT_PACKAGE, ['src/admin-tools/pages/api/health.ts',
      'export default async function handler(req, res) {\n  res.json({ ok: true });\n}\n']]);
    expect(publicAdminRouteHint.run(context)).toHaveLength(0);
  });
});

describe('the widened role vocabulary as broken_access_control sees it', () => {
  it('broken_access_control still fires on an id read straight from the request with no ownership check', () => {
    const context = memoryContext([NEXT_PACKAGE, ['app/api/sessions/[sessionId]/feedback/route.ts',
      'export async function GET(request: Request, { params }: { params: { sessionId: string } }) {\n' +
      '  const feedback = await prisma.feedback.findMany({ where: { sessionId: params.sessionId } });\n' +
      '  return Response.json({ feedback });\n' +
      '}\n']]);
    expect(brokenAccessControl.run(context).length).toBeGreaterThan(0);
  });
});
