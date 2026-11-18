import { describe, expect, it } from 'vitest';
import { clientSideOnlyAuthorization } from '../../src/rules/contextual/clientSideOnlyAuthorization.js';
import { memoryContext } from './helpers.js';

const PKG_NEXT: [string, string] = ['package.json', '{"name":"x","dependencies":{"next":"14.0.0"}}'];

const STORAGE_AUTH_CONTEXT =
  '"use client"\n' +
  'import { createContext, useContext, useState, useEffect } from "react";\n' +
  'const AuthContext = createContext();\n' +
  'export function AuthProvider({ children }) {\n' +
  '  const [user, setUser] = useState(null);\n' +
  '  useEffect(() => {\n' +
  '    const stored = localStorage.getItem("ims_user");\n' +
  '    if (stored) {\n' +
  '      const parsed = JSON.parse(stored);\n' +
  '      setUser(parsed);\n' +
  '    }\n' +
  '  }, []);\n' +
  '  return <AuthContext.Provider value={{ user, setUser }}>{children}</AuthContext.Provider>;\n' +
  '}\n' +
  'export const useAuth = () => useContext(AuthContext);\n';

const GATE_LAYOUT =
  '"use client"\n' +
  'import { useAuth } from "@/lib/auth";\n' +
  'import LoginForm from "@/components/login-form";\n' +
  'import DashboardNav from "@/components/dashboard-nav";\n' +
  'export default function DashboardLayout({ children }) {\n' +
  '  const { user, loading } = useAuth();\n' +
  '  if (loading) {\n' +
  '    return <div className="spinner" />;\n' +
  '  }\n' +
  '  if (!user) {\n' +
  '    return <LoginForm />;\n' +
  '  }\n' +
  '  return <div><DashboardNav />{children}</div>;\n' +
  '}\n';

const OPEN_API_ROUTE =
  'import { prisma } from "@/lib/prisma";\n' +
  'export async function GET() {\n' +
  '  return Response.json(await prisma.order.findMany());\n' +
  '}\n';

const IMS_LIKE: [string, string][] = [
  PKG_NEXT,
  ['lib/auth.js', STORAGE_AUTH_CONTEXT],
  ['app/(dashboard)/layout.jsx', GATE_LAYOUT],
  ['app/api/orders/route.js', OPEN_API_ROUTE],
];

describe('client_side_only_authorization — the browser is the only lock', () => {
  it('flags a client gate whose identity comes from localStorage, with no server auth (unsafe)', () => {
    const findings = clientSideOnlyAuthorization.run(memoryContext(IMS_LIKE));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.filePath).toBe('app/(dashboard)/layout.jsx');
    expect(findings[0]?.severity).toBe('high');
    expect(findings[0]?.confidence).toBe('high');
    expect(findings[0]?.category).toBe('authentication');
    expect(findings[0]?.evidence).toContain('ims_user');
    expect(findings[0]?.evidence).toContain('lib/auth.js');
  });

  it('flags the same defect written entirely inside one component', () => {
    const findings = clientSideOnlyAuthorization.run(
      memoryContext([
        PKG_NEXT,
        [
          'app/admin/page.jsx',
          '"use client"\n' +
            'import { useState, useEffect } from "react";\n' +
            'import LoginPage from "@/components/login-page";\n' +
            'export default function Admin() {\n' +
            '  const [session, setSession] = useState(null);\n' +
            '  useEffect(() => {\n' +
            '    const raw = sessionStorage.getItem("currentUser");\n' +
            '    setSession(JSON.parse(raw));\n' +
            '  }, []);\n' +
            '  if (!session) {\n' +
            '    return <LoginPage />;\n' +
            '  }\n' +
            '  return <div>secret</div>;\n' +
            '}\n',
        ],
        ['app/api/orders/route.js', OPEN_API_ROUTE],
      ]),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain('currentUser');
  });
});

describe('client_side_only_authorization — discriminator 1: where the identity came from', () => {
  it('is silent when the gate reads a next-auth useSession() (safe)', () => {
    const ctx = memoryContext([
      PKG_NEXT,
      [
        'lib/auth.js',
        '"use client"\n' +
          'import { useSession } from "next-auth/react";\n' +
          'export const useAuth = () => {\n' +
          '  const { data } = useSession();\n' +
          '  return { user: data?.user, loading: false };\n' +
          '};\n',
      ],
      ['app/(dashboard)/layout.jsx', GATE_LAYOUT],
      ['app/api/orders/route.js', OPEN_API_ROUTE],
    ]);
    expect(clientSideOnlyAuthorization.run(ctx)).toHaveLength(0);
  });

  it("is silent when the gate reads Clerk's useUser(), even beside a localStorage cache (safe)", () => {
    const ctx = memoryContext([
      PKG_NEXT,
      [
        'lib/auth.js',
        '"use client"\n' +
          'import { useUser } from "@clerk/nextjs";\n' +
          'export const useAuth = () => {\n' +
          '  const { user, isLoaded } = useUser();\n' +
          '  const stored = localStorage.getItem("cached_user");\n' +
          '  if (stored) setUser(JSON.parse(stored));\n' +
          '  return { user, loading: !isLoaded };\n' +
          '};\n',
      ],
      ['app/(dashboard)/layout.jsx', GATE_LAYOUT],
      ['app/api/orders/route.js', OPEN_API_ROUTE],
    ]);
    expect(clientSideOnlyAuthorization.run(ctx)).toHaveLength(0);
  });

  it('is silent when the identity comes from a Supabase session — the notifai/rodket shape (safe)', () => {
    const ctx = memoryContext([
      PKG_NEXT,
      [
        'lib/auth.js',
        '"use client"\n' +
          'import { useState, useEffect } from "react";\n' +
          'import { supabase } from "@/lib/supabase";\n' +
          'export function AuthProvider({ children }) {\n' +
          '  const [user, setUser] = useState(null);\n' +
          '  useEffect(() => {\n' +
          '    supabase.auth.getSession().then(({ data }) => setUser(data.session?.user ?? null));\n' +
          '  }, []);\n' +
          '  return children;\n' +
          '}\n' +
          'export const useAuth = () => ({ user: null, loading: false });\n',
      ],
      ['app/(dashboard)/layout.jsx', GATE_LAYOUT],
      ['app/api/orders/route.js', OPEN_API_ROUTE],
    ]);
    expect(clientSideOnlyAuthorization.run(ctx)).toHaveLength(0);
  });

  it('is silent on a localStorage read used for a UI preference (safe)', () => {
    const ctx = memoryContext([
      PKG_NEXT,
      [
        'lib/auth.js',
        '"use client"\n' +
          'import { useState, useEffect } from "react";\n' +
          'export function ThemeProvider({ children }) {\n' +
          '  const [theme, setTheme] = useState("light");\n' +
          '  useEffect(() => {\n' +
          '    const stored = localStorage.getItem("theme");\n' +
          '    if (stored) setTheme(stored);\n' +
          '  }, []);\n' +
          '  return children;\n' +
          '}\n' +
          'export const useAuth = () => ({ user: null, loading: false });\n',
      ],
      ['app/(dashboard)/layout.jsx', GATE_LAYOUT],
      ['app/api/orders/route.js', OPEN_API_ROUTE],
    ]);
    expect(clientSideOnlyAuthorization.run(ctx)).toHaveLength(0);
  });

  it('is silent when an identity-named key never reaches identity state (the authReturnUrl shape)', () => {
    const ctx = memoryContext([
      PKG_NEXT,
      [
        'lib/auth.js',
        '"use client"\n' +
          'import { useState } from "react";\n' +
          'export function useReturn() {\n' +
          '  const returnUrl = sessionStorage.getItem("authReturnUrl");\n' +
          '  if (returnUrl) sessionStorage.removeItem("authReturnUrl");\n' +
          '  return returnUrl;\n' +
          '}\n' +
          'export const useAuth = () => ({ user: null, loading: false });\n',
      ],
      ['app/(dashboard)/layout.jsx', GATE_LAYOUT],
      ['app/api/orders/route.js', OPEN_API_ROUTE],
    ]);
    expect(clientSideOnlyAuthorization.run(ctx)).toHaveLength(0);
  });
});

describe('client_side_only_authorization — discriminator 2: what is behind the gate', () => {
  it('is silent when middleware enforces authentication server-side (safe)', () => {
    const ctx = memoryContext([
      ...IMS_LIKE,
      [
        'middleware.ts',
        'import { NextResponse } from "next/server";\n' +
          'export async function middleware(req) {\n' +
          '  const session = await getSession(req);\n' +
          '  if (!session) {\n' +
          '    return NextResponse.redirect(new URL("/login", req.url));\n' +
          '  }\n' +
          '  return NextResponse.next();\n' +
          '}\n',
      ],
    ]);
    expect(clientSideOnlyAuthorization.run(ctx)).toHaveLength(0);
  });

  it('is silent when the API routes carry a checked session guard (safe)', () => {
    const guardedRoute =
      'import { getServerSession } from "next-auth";\n' +
      'export async function GET() {\n' +
      '  const session = await getServerSession();\n' +
      '  if (!session) return Response.json({ error: "Unauthorized" }, { status: 401 });\n' +
      '  return Response.json([]);\n' +
      '}\n';
    const ctx = memoryContext([
      PKG_NEXT,
      ['lib/auth.js', STORAGE_AUTH_CONTEXT],
      ['app/(dashboard)/layout.jsx', GATE_LAYOUT],
      ['app/api/orders/route.js', guardedRoute],
    ]);
    expect(clientSideOnlyAuthorization.run(ctx)).toHaveLength(0);
  });

  it('is silent when Supabase RLS policies enforce access in the database (safe)', () => {
    const ctx = memoryContext([
      ...IMS_LIKE,
      [
        'supabase/migrations/0001_rls.sql',
        'ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\n' +
          'CREATE POLICY "own orders" ON public.orders FOR SELECT USING (auth.uid() = user_id);\n',
      ],
    ]);
    expect(clientSideOnlyAuthorization.run(ctx)).toHaveLength(0);
  });
});

describe('client_side_only_authorization — the gate must actually deny somebody', () => {
  it('is silent on a bare `if (!user) return` data-fetch bail-out (safe)', () => {
    const ctx = memoryContext([
      PKG_NEXT,
      ['lib/auth.js', STORAGE_AUTH_CONTEXT],
      [
        'components/returns.jsx',
        '"use client"\n' +
          'import { useAuth } from "@/lib/auth";\n' +
          'export default function Returns() {\n' +
          '  const { user } = useAuth();\n' +
          '  const fetchQueue = async () => {\n' +
          '    if (!user) return;\n' +
          '    await fetch("/api/scanned-parcels");\n' +
          '  };\n' +
          '  return <button onClick={fetchQueue}>refresh</button>;\n' +
          '}\n',
      ],
      ['app/api/orders/route.js', OPEN_API_ROUTE],
    ]);
    expect(clientSideOnlyAuthorization.run(ctx)).toHaveLength(0);
  });

  it('is silent on role-conditional rendering, which is deliberately out of scope (safe)', () => {
    const ctx = memoryContext([
      PKG_NEXT,
      ['lib/auth.js', STORAGE_AUTH_CONTEXT],
      [
        'components/settings.jsx',
        '"use client"\n' +
          'import { useAuth } from "@/lib/auth";\n' +
          'export default function Settings() {\n' +
          '  const { user } = useAuth();\n' +
          '  return <div>{user.role === "ADMIN" && <button>delete everything</button>}</div>;\n' +
          '}\n',
      ],
      ['app/api/orders/route.js', OPEN_API_ROUTE],
    ]);
    expect(clientSideOnlyAuthorization.run(ctx)).toHaveLength(0);
  });
});
