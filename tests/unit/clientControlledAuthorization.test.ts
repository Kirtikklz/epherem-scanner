import { describe, expect, it } from 'vitest';
import { clientControlledAuthorization } from '../../src/rules/contextual/clientControlledAuthorization.js';
import { memoryContext } from './helpers.js';

const PKG_NEXT: [string, string] = ['package.json', '{"name":"x","dependencies":{"next":"14.0.0"}}'];

const HEADER_ROUTE =
  'import { prisma } from "@/lib/prisma";\n' +
  'import { hasPermission } from "@/lib/permissions";\n' +
  'export async function GET(request) {\n' +
  '  const userId = request.headers.get("x-user-id");\n' +
  '  const user = await prisma.user.findUnique({ where: { id: userId }, select: { id: true, role: true, permissions: true } });\n' +
  '  if (!user || !hasPermission(user, "orders.view")) {\n' +
  '    return Response.json({ error: "Unauthorized" }, { status: 403 });\n' +
  '  }\n' +
  '  return Response.json(await prisma.order.findMany());\n' +
  '}\n';

describe('client_controlled_authorization — spoofable identity header', () => {
  it('flags a route that trusts x-user-id as the caller (unsafe)', () => {
    const ctx = memoryContext([PKG_NEXT, ['app/api/orders/route.js', HEADER_ROUTE]]);
    const findings = clientControlledAuthorization.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('high');
    expect(findings[0]?.confidence).toBe('high');
    expect(findings[0]?.category).toBe('authentication');
    expect(findings[0]?.evidence).toContain('x-user-id');
  });

  it('is silent on the same route guarded by a real session check (safe)', () => {
    const guarded = HEADER_ROUTE.replace(
      '  const userId = request.headers.get("x-user-id");\n',
      '  const { data: { user: sessionUser } } = await supabase.auth.getUser();\n' +
        '  if (!sessionUser) return Response.json({ error: "Unauthorized" }, { status: 401 });\n' +
        '  const userId = sessionUser.id;\n',
    );
    const ctx = memoryContext([PKG_NEXT, ['app/api/orders/route.js', guarded]]);
    expect(clientControlledAuthorization.run(ctx)).toHaveLength(0);
  });

  it('is silent on an API-KEY header, which carries a secret rather than an identity (safe)', () => {
    const ctx = memoryContext([PKG_NEXT, ['app/api/device/route.ts',
      'export async function GET(request: Request) {\n' +
      '  const key = request.headers.get("x-api-key");\n' +
      '  const record = await prisma.user.findFirst({ where: { apiKey: key }, select: { id: true, role: true } });\n' +
      '  if (!record) return Response.json({ error: "Unauthorized" }, { status: 401 });\n' +
      '  return Response.json({ ok: true });\n' +
      '}\n']]);
    expect(clientControlledAuthorization.run(ctx)).toHaveLength(0);
  });

  it('is silent on a non-identity tracing header (safe)', () => {
    const ctx = memoryContext([PKG_NEXT, ['app/api/orders/route.js',
      HEADER_ROUTE.replace('"x-user-id"', '"x-request-id"')]]);
    expect(clientControlledAuthorization.run(ctx)).toHaveLength(0);
  });
});

describe('client_controlled_authorization — request field as the caller', () => {
  it('flags a body userId consumed as the authenticated caller (unsafe)', () => {
    const ctx = memoryContext([PKG_NEXT, ['app/api/auth/me/route.js',
      'import { prisma } from "@/lib/prisma";\n' +
      'export async function POST(request) {\n' +
      '  const { userId } = await request.json();\n' +
      '  const user = await prisma.user.findUnique({ where: { id: userId }, select: { id: true, role: true, status: true, permissions: true } });\n' +
      '  if (!user) return Response.json({ error: "not found" }, { status: 404 });\n' +
      '  if (user.status !== "ACTIVE") return Response.json({ error: "inactive" }, { status: 403 });\n' +
      '  return Response.json({ user });\n' +
      '}\n']]);
    const findings = clientControlledAuthorization.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('high');
    expect(findings[0]?.evidence).toContain('userId');
  });

  it('flags the two-step destructuring shape (const data = await req.json(); const { userId } = data)', () => {
    const ctx = memoryContext([PKG_NEXT, ['app/api/scan/route.js',
      'import { prisma } from "@/lib/prisma";\n' +
      'import { hasPermission } from "@/lib/permissions";\n' +
      'export async function POST(request) {\n' +
      '  const data = await request.json();\n' +
      '  const { trackingNumber, userId } = data;\n' +
      '  const user = await prisma.user.findUnique({ where: { id: userId }, select: { id: true, role: true, permissions: true } });\n' +
      '  if (!user || !hasPermission(user, "scan")) return Response.json({ error: "Unauthorized" }, { status: 403 });\n' +
      '  return Response.json({ ok: trackingNumber });\n' +
      '}\n']]);
    expect(clientControlledAuthorization.run(ctx)).toHaveLength(1);
  });

  it('is silent when the body userId is attribution data, not identity (safe)', () => {
    const ctx = memoryContext([PKG_NEXT, ['app/api/ship/route.js',
      'import { prisma } from "@/lib/prisma";\n' +
      'export async function POST(request) {\n' +
      '  const { items, userId } = await request.json();\n' +
      '  if (!items?.length) return Response.json({ error: "bad" }, { status: 400 });\n' +
      '  const order = await prisma.salesOrder.findUnique({ where: { id: items[0].orderId } });\n' +
      '  if (!order) return Response.json({ error: "Unauthorized" }, { status: 403 });\n' +
      '  await prisma.shipment.create({ data: { orderId: order.id, userId } });\n' +
      '  return Response.json({ ok: true });\n' +
      '}\n']]);
    expect(clientControlledAuthorization.run(ctx)).toHaveLength(0);
  });

  it('is silent on a login route, where the credential is the proof (safe)', () => {
    const ctx = memoryContext([PKG_NEXT, ['app/api/auth/login/route.js',
      'import { prisma } from "@/lib/prisma";\n' +
      'export async function POST(request) {\n' +
      '  const { userId, password } = await request.json();\n' +
      '  const user = await prisma.user.findUnique({ where: { id: userId }, select: { id: true, role: true, password: true, permissions: true } });\n' +
      '  if (!user || password !== user.password) return Response.json({ error: "Unauthorized" }, { status: 401 });\n' +
      '  return Response.json({ user });\n' +
      '}\n']]);
    expect(clientControlledAuthorization.run(ctx)).toHaveLength(0);
  });

  it('is silent when the lookup has no privilege attribute and no permission predicate (safe)', () => {
    const ctx = memoryContext([PKG_NEXT, ['app/api/checkout/route.ts',
      'export async function POST(request: Request) {\n' +
      '  const { userId, planId } = await request.json();\n' +
      '  const { data: profile } = await supabase.from("profiles").select("stripe_customer_id").eq("id", userId).single();\n' +
      '  if (!profile) return Response.json({ message: "User not found" }, { status: 404 });\n' +
      '  return Response.json({ ok: planId });\n' +
      '}\n']]);
    expect(clientControlledAuthorization.run(ctx)).toHaveLength(0);
  });
});

describe('client_controlled_authorization — client storage and UI state', () => {
  it('is silent on a localStorage read used for a theme preference (safe)', () => {
    const ctx = memoryContext([PKG_NEXT, ['app/api/prefs/route.ts',
      'export async function GET(request: Request) {\n' +
      '  const theme = globalThis.localStorage?.getItem("theme") ?? "light";\n' +
      '  const cart = globalThis.localStorage?.getItem("cart");\n' +
      '  return Response.json({ theme, cart });\n' +
      '}\n'],
      ['components/ThemeToggle.tsx',
      '"use client";\n' +
      'export function ThemeToggle() {\n' +
      '  const theme = localStorage.getItem("theme");\n' +
      '  const role = localStorage.getItem("role");\n' +
      '  return <div>{role === "admin" ? "admin" : theme}</div>;\n' +
      '}\n']]);
    expect(clientControlledAuthorization.run(ctx)).toHaveLength(0);
  });
});

describe('client_controlled_authorization — user-writable role column', () => {
  const WRITABLE_AND_TRUSTED =
    'CREATE TABLE public.profiles (\n' +
    '  id uuid PRIMARY KEY,\n' +
    '  full_name text\n' +
    ');\n' +
    'ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;\n' +
    'ALTER TABLE profiles ADD COLUMN is_admin boolean DEFAULT false;\n' +
    'CREATE POLICY "Users can update their own profile"\n' +
    'ON public.profiles FOR UPDATE\n' +
    'USING (auth.uid() = id);\n' +
    'CREATE POLICY "Only admins can modify subscription plans"\n' +
    'ON public.subscription_plans FOR ALL\n' +
    'USING (auth.uid() IN (SELECT id FROM public.profiles WHERE is_admin = true));\n';

  it('flags a user-writable is_admin that a privilege policy trusts (unsafe)', () => {
    const ctx = memoryContext([PKG_NEXT, ['supabase/migrations/001_init.sql', WRITABLE_AND_TRUSTED]]);
    const findings = clientControlledAuthorization.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('high');
    expect(findings[0]?.category).toBe('authorization');
    expect(findings[0]?.evidence).toContain('is_admin');
  });

  it('is silent when the role column is never consulted for a privilege decision (safe)', () => {
    const ctx = memoryContext([PKG_NEXT, ['supabase/migrations/001_init.sql',
      WRITABLE_AND_TRUSTED.replace(
        'USING (auth.uid() IN (SELECT id FROM public.profiles WHERE is_admin = true));',
        'USING (is_active = true);')]]);
    expect(clientControlledAuthorization.run(ctx)).toHaveLength(0);
  });

  it('is silent when a column-scoped GRANT withholds write on the role column (safe)', () => {
    const ctx = memoryContext([PKG_NEXT, ['supabase/migrations/001_init.sql',
      WRITABLE_AND_TRUSTED.replace(
        'ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;',
        'GRANT SELECT, UPDATE (full_name) ON public.profiles TO authenticated;\n' +
        'ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;')]]);
    expect(clientControlledAuthorization.run(ctx)).toHaveLength(0);
  });

  it('is silent when a later migration drops the role column (safe)', () => {
    const ctx = memoryContext([PKG_NEXT, ['supabase/migrations/001_init.sql',
      `${WRITABLE_AND_TRUSTED}ALTER TABLE public.profiles DROP COLUMN IF EXISTS is_admin;\n`]]);
    expect(clientControlledAuthorization.run(ctx)).toHaveLength(0);
  });
});
