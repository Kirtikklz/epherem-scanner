import { describe, expect, it } from 'vitest';
import { publicAdminRouteHint } from '../../src/rules/basic/publicAdminRouteHint.js';
import { apiMutationWithoutAuth } from '../../src/rules/contextual/apiMutationWithoutAuth.js';
import { missingRateLimit } from '../../src/rules/contextual/missingRateLimit.js';
import { brokenAccessControl } from '../../src/rules/contextual/brokenAccessControl.js';
import { cascadingControlProven, cascadingGuardsForFile } from '../../src/shared/cascadingGuard.js';
import { memoryContext } from './helpers.js';

const SVELTE_PACKAGE: [string, string] =
  ['package.json', '{"devDependencies":{"@sveltejs/kit":"2.0.0"}}'];
const SVELTE_CONFIG: [string, string] = ['svelte.config.js', 'export default { kit: {} };'];

const ADMIN_GUARD: [string, string] = ['src/lib/server/guards.ts',
  "import { redirect } from '@sveltejs/kit';\n" +
  'export function requireAdmin(user) {\n' +
  "  if (!user || user.role !== 'admin') redirect(303, '/');\n" +
  '  return user;\n' +
  '}\n'];

const GUARDED_LAYOUT: [string, string] = ['src/routes/(admin)/admin/+layout.server.ts',
  "import { requireAdmin } from '$lib/server/guards';\n" +
  'export const load = async ({ locals }) => {\n' +
  '  requireAdmin(locals.user);\n' +
  '  return { ok: true };\n' +
  '};\n'];

const OPEN_LAYOUT: [string, string] = ['src/routes/(admin)/admin/+layout.server.ts',
  'export const load = async ({ locals }) => ({ signedIn: Boolean(locals.user) });\n'];

const CHILD_LOAD: [string, string] = ['src/routes/(admin)/admin/users/+page.server.ts',
  "import { db } from '$lib/server/db';\n" +
  'export const load = async () => ({ users: await db.user.findMany() });\n'];

const CHILD_ACTION: [string, string] = ['src/routes/(admin)/admin/users/+page.server.ts',
  "import { db } from '$lib/server/db';\n" +
  'export const actions = {\n' +
  '  remove: async ({ request }) => {\n' +
  '    const form = await request.formData();\n' +
  "    await db.user.delete({ where: { id: form.get('id') } });\n" +
  '    return { ok: true };\n' +
  '  },\n' +
  '};\n'];

const CHILD_ENDPOINT: [string, string] = ['src/routes/(admin)/admin/purge/+server.ts',
  "import { db } from '$lib/server/db';\n" +
  'export const POST = async () => {\n' +
  '  await db.user.deleteMany();\n' +
  "  return new Response('ok');\n" +
  '};\n'];

function firedOn(findings: { filePath: string }[], fragment: string): number {
  return findings.filter((finding) => finding.filePath.includes(fragment)).length;
}

describe('SvelteKit: a parent +layout.server.ts guard', () => {
  it('protects a child page LOAD — the rule goes quiet', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, ADMIN_GUARD, GUARDED_LAYOUT, CHILD_LOAD]);
    expect(firedOn(publicAdminRouteHint.run(context), 'users')).toBe(0);
  });

  it('does NOT protect a form ACTION in the same subtree', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, ADMIN_GUARD, GUARDED_LAYOUT, CHILD_ACTION]);
    expect(firedOn(publicAdminRouteHint.run(context), 'users')).toBeGreaterThan(0);
  });

  it('does NOT protect a +server.ts endpoint in the same subtree', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, ADMIN_GUARD, GUARDED_LAYOUT, CHILD_ENDPOINT]);
    expect(firedOn(publicAdminRouteHint.run(context), 'purge')).toBeGreaterThan(0);
  });

  it('is not credited when the layout has no guard at all', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, ADMIN_GUARD, OPEN_LAYOUT, CHILD_LOAD]);
    expect(firedOn(publicAdminRouteHint.run(context), 'users')).toBeGreaterThan(0);
  });

  it('is not credited from a directory that is not an ancestor', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, ADMIN_GUARD,
      ['src/routes/(admin)/admin/reports/+layout.server.ts', GUARDED_LAYOUT[1]],
      CHILD_LOAD,
    ]);
    expect(firedOn(publicAdminRouteHint.run(context), 'users')).toBeGreaterThan(0);
  });

  it('does not report the guarded layout itself', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, ADMIN_GUARD, GUARDED_LAYOUT, CHILD_LOAD]);
    expect(firedOn(publicAdminRouteHint.run(context), '+layout.server.ts')).toBe(0);
  });
});

describe('SvelteKit: a hooks.server.ts handle guard', () => {
  const GUARDING_HOOK: [string, string] = ['src/hooks.server.ts',
    "import { redirect, type Handle } from '@sveltejs/kit';\n" +
    'const authGuard: Handle = async ({ event, resolve }) => {\n' +
    '  const session = await event.locals.getSession();\n' +
    "  if (!session) throw redirect(303, '/login');\n" +
    '  return resolve(event);\n' +
    '};\n' +
    'export const handle: Handle = authGuard;\n'];

  const MUTATING_ENDPOINT: [string, string] = ['src/routes/api/notes/+server.ts',
    "import { prisma } from '$lib/server/db';\n" +
    'export const POST = async ({ request }) => {\n' +
    '  const body = await request.json();\n' +
    '  await prisma.note.create({ data: body });\n' +
    "  return new Response('ok');\n" +
    '};\n'];

  it('protects a +server.ts endpoint — a hook runs for every request', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, GUARDING_HOOK, MUTATING_ENDPOINT]);
    expect(firedOn(apiMutationWithoutAuth.run(context), 'notes')).toBe(0);
  });

  it('is not credited when the hook establishes a session but refuses nothing', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, MUTATING_ENDPOINT,
      ['src/hooks.server.ts',
        "import type { Handle } from '@sveltejs/kit';\n" +
        'export const handle: Handle = async ({ event, resolve }) => {\n' +
        "  event.locals.session = await verify(event.cookies.get('sid'));\n" +
        '  return resolve(event);\n' +
        '};\n'],
    ]);
    expect(firedOn(apiMutationWithoutAuth.run(context), 'notes')).toBeGreaterThan(0);
  });

  it('is scoped to the path its guarding condition names', () => {
    const scoped: [string, string] = ['src/hooks.server.ts',
      "import { redirect, type Handle } from '@sveltejs/kit';\n" +
      'export const handle: Handle = async ({ event, resolve }) => {\n' +
      "  if (event.url.pathname.startsWith('/admin') && !event.locals.user) {\n" +
      "    throw redirect(303, '/login');\n" +
      '  }\n' +
      '  return resolve(event);\n' +
      '};\n'];
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, scoped, MUTATING_ENDPOINT]);
    expect(firedOn(apiMutationWithoutAuth.run(context), 'notes')).toBeGreaterThan(0);
    expect(cascadingControlProven(context,
      { filePath: 'x', routePath: '/admin/users', line: 1, framework: 'sveltekit' }, 'auth')).toBe(true);
    expect(cascadingControlProven(context,
      { filePath: 'x', routePath: '/api/notes', line: 1, framework: 'sveltekit' }, 'auth')).toBe(false);
  });

  it('does not cover a path the hook declares public', () => {
    const exempting: [string, string] = ['src/hooks.server.ts',
      "import { redirect, type Handle } from '@sveltejs/kit';\n" +
      "const PUBLIC_PATHS = ['/login', '/api/cron'];\n" +
      'export const handle: Handle = async ({ event, resolve }) => {\n' +
      '  const session = await event.locals.getSession();\n' +
      '  const isPublic = PUBLIC_PATHS.some((p) => event.url.pathname.startsWith(p));\n' +
      "  if (!session && !isPublic) throw redirect(303, '/login');\n" +
      '  return resolve(event);\n' +
      '};\n'];
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, exempting, MUTATING_ENDPOINT]);
    expect(cascadingControlProven(context,
      { filePath: 'x', routePath: '/api/notes', line: 1, framework: 'sveltekit' }, 'auth')).toBe(true);
    expect(cascadingControlProven(context,
      { filePath: 'x', routePath: '/api/cron/sync', line: 1, framework: 'sveltekit' }, 'auth')).toBe(false);
  });

  it('is not credited from a function the handle export never reaches', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, MUTATING_ENDPOINT,
      ['src/hooks.server.ts',
        "import { redirect, type Handle } from '@sveltejs/kit';\n" +
        'export function requireUser(event) {\n' +
        "  if (!event.locals.user) throw redirect(303, '/login');\n" +
        '}\n' +
        'export const handle: Handle = async ({ event, resolve }) => resolve(event);\n'],
    ]);
    expect(firedOn(apiMutationWithoutAuth.run(context), 'notes')).toBeGreaterThan(0);
  });

  it('follows one composition hop through sequence(...)', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, MUTATING_ENDPOINT,
      ['src/hooks.server.ts',
        "import { redirect, type Handle } from '@sveltejs/kit';\n" +
        "import { sequence } from '@sveltejs/kit/hooks';\n" +
        'const supabase: Handle = async ({ event, resolve }) => resolve(event);\n' +
        'const authGuard: Handle = async ({ event, resolve }) => {\n' +
        '  const { session } = await event.locals.safeGetSession();\n' +
        "  if (!session) throw redirect(303, '/login');\n" +
        '  return resolve(event);\n' +
        '};\n' +
        'export const handle: Handle = sequence(supabase, authGuard);\n'],
    ]);
    expect(firedOn(apiMutationWithoutAuth.run(context), 'notes')).toBe(0);
  });
});

describe('SvelteKit: a rate limiter that cascades', () => {
  const LOGIN_ENDPOINT: [string, string] = ['src/routes/api/session/+server.ts',
    'export const POST = async ({ request }) => {\n' +
    '  const { email, password } = await request.json();\n' +
    '  return new Response(await signIn(email, password));\n' +
    '};\n'];

  it('credits a limiter enforced in the hook', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, LOGIN_ENDPOINT,
      ['src/hooks.server.ts',
        "import { error, type Handle } from '@sveltejs/kit';\n" +
        'const hits = new Map();\n' +
        'const limit = 20;\n' +
        'export const handle: Handle = async ({ event, resolve }) => {\n' +
        "  const bucket = hits.get(event.getClientAddress()) ?? { count: 0, resetAt: Date.now() + 60000 };\n" +
        '  bucket.count += 1;\n' +
        '  if (bucket.count > limit) {\n' +
        "    throw error(429, 'too many requests');\n" +
        '  }\n' +
        '  return resolve(event);\n' +
        '};\n'],
    ]);
    expect(firedOn(missingRateLimit.run(context), 'session')).toBe(0);
  });

  it('still fires when the hook counts nothing', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, LOGIN_ENDPOINT,
      ['src/hooks.server.ts',
        "import type { Handle } from '@sveltejs/kit';\n" +
        'export const handle: Handle = async ({ event, resolve }) => resolve(event);\n'],
    ]);
    expect(firedOn(missingRateLimit.run(context), 'session')).toBeGreaterThan(0);
  });

  it('skips a page load and reports the action that actually exchanges credentials', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG,
      ['src/routes/login/+page.server.ts',
        'export const load = async () => ({ providers: await listProviders() });\n' +
        'export const actions = {\n' +
        '  default: async ({ request }) => {\n' +
        '    const form = await request.formData();\n' +
        "    return signIn(form.get('email'), form.get('password'));\n" +
        '  },\n' +
        '};\n'],
    ]);
    const findings = missingRateLimit.run(context);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain('POST');
  });

  it('reports a load-only sensitive page not at all', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG,
      ['src/routes/login/+page.server.ts',
        'export const load = async () => ({ providers: await listProviders() });\n'],
    ]);
    expect(missingRateLimit.run(context)).toHaveLength(0);
  });
});

describe('Next.js: what a layout may and may not vouch for', () => {
  const NEXT_PACKAGE: [string, string] = ['package.json', '{"dependencies":{"next":"14.0.0"}}'];
  const GUARDED_APP_LAYOUT: [string, string] = ['app/(admin)/admin/layout.tsx',
    "import { redirect } from 'next/navigation';\n" +
    'export default async function AdminLayout({ children }) {\n' +
    '  const session = await auth();\n' +
    "  if (session?.user?.role !== 'admin') redirect('/');\n" +
    '  return <>{children}</>;\n' +
    '}\n'];

  it('credits a page.tsx under a role-guarded layout', () => {
    const context = memoryContext([NEXT_PACKAGE, GUARDED_APP_LAYOUT,
      ['app/(admin)/admin/invoices/page.tsx',
        'export default async function Page({ searchParams }) {\n' +
        '  const invoice = await prisma.invoice.findUnique({ where: { id: searchParams.id } });\n' +
        '  return <pre>{JSON.stringify(invoice)}</pre>;\n' +
        '}\n'],
    ]);
    expect(cascadingGuardsForFile(context, 'app/(admin)/admin/invoices/page.tsx')
      .some((guard) => guard.control === 'admin')).toBe(true);
    expect(firedOn(brokenAccessControl.run(context), 'invoices/page.tsx')).toBe(0);
  });

  it('does NOT credit a route.ts under the same layout', () => {
    const context = memoryContext([NEXT_PACKAGE, GUARDED_APP_LAYOUT,
      ['app/(admin)/admin/users/route.ts',
        'export async function GET() {\n' +
        '  return Response.json(await prisma.user.findMany());\n' +
        '}\n'],
    ]);
    expect(cascadingGuardsForFile(context, 'app/(admin)/admin/users/route.ts')).toHaveLength(0);
    expect(firedOn(publicAdminRouteHint.run(context), 'users/route.ts')).toBeGreaterThan(0);
  });

  it("does NOT credit a file whose every export is a server action", () => {
    const context = memoryContext([NEXT_PACKAGE, GUARDED_APP_LAYOUT,
      ['app/(admin)/admin/settings/page.tsx',
        "'use server';\n" +
        'export async function deleteUser(id: string) {\n' +
        '  await prisma.user.delete({ where: { id } });\n' +
        '}\n' +
        'export default async function Page() {\n' +
        '  return <form action={deleteUser} />;\n' +
        '}\n'],
    ]);
    expect(cascadingGuardsForFile(context, 'app/(admin)/admin/settings/page.tsx')).toHaveLength(0);
  });

  it('does NOT credit an actions module under the same layout', () => {
    const context = memoryContext([NEXT_PACKAGE, GUARDED_APP_LAYOUT,
      ['app/(admin)/admin/actions.ts',
        "'use server';\n" +
        'export async function deleteUser(id: string) {\n' +
        '  await prisma.user.delete({ where: { id } });\n' +
        '}\n'],
    ]);
    expect(cascadingGuardsForFile(context, 'app/(admin)/admin/actions.ts')).toHaveLength(0);
  });
});

describe('Express: a use() applied before the routes it covers', () => {
  const EXPRESS_PACKAGE: [string, string] = ['package.json', '{"dependencies":{"express":"4.18.0"}}'];
  const AUTH_MIDDLEWARE: [string, string] = ['src/middleware/auth.js',
    'function requireAuth(req, res, next) {\n' +
    "  const token = req.headers['authorization'];\n" +
    "  if (!token) return res.status(401).json({ error: 'unauthorized' });\n" +
    '  req.user = verify(token);\n' +
    '  next();\n' +
    '}\n' +
    'module.exports = { requireAuth };\n'];

  const ordered = (usesFirst: boolean): [string, string] => ['src/server.js',
    "const express = require('express');\n" +
    "const { requireAuth } = require('./middleware/auth');\n" +
    'const app = express();\n' +
    (usesFirst ? 'app.use(requireAuth);\n' : '') +
    "app.post('/admin/reset', async (req, res) => {\n" +
    '  await db.users.deleteMany({});\n' +
    '  res.json({ ok: true });\n' +
    '});\n' +
    (usesFirst ? '' : 'app.use(requireAuth);\n')];

  it('credits app.use(guard) registered above the route', () => {
    const context = memoryContext([EXPRESS_PACKAGE, AUTH_MIDDLEWARE, ordered(true)]);
    expect(cascadingControlProven(context,
      { filePath: 'src/server.js', routePath: '/admin/reset', line: 5, framework: 'express' }, 'auth')).toBe(true);
  });

  it('does NOT credit the same app.use(guard) registered below the route', () => {
    const context = memoryContext([EXPRESS_PACKAGE, AUTH_MIDDLEWARE, ordered(false)]);
    expect(cascadingControlProven(context,
      { filePath: 'src/server.js', routePath: '/admin/reset', line: 4, framework: 'express' }, 'auth')).toBe(false);
  });

  it('scopes app.use("/prefix", guard) to that prefix', () => {
    const context = memoryContext([EXPRESS_PACKAGE, AUTH_MIDDLEWARE,
      ['src/server.js',
        "const express = require('express');\n" +
        "const { requireAuth } = require('./middleware/auth');\n" +
        'const app = express();\n' +
        "app.use('/admin', requireAuth);\n" +
        "app.post('/admin/reset', (req, res) => res.json({}));\n" +
        "app.post('/public/subscribe', (req, res) => res.json({}));\n"],
    ]);
    expect(cascadingControlProven(context,
      { filePath: 'src/server.js', routePath: '/admin/reset', line: 5, framework: 'express' }, 'auth')).toBe(true);
    expect(cascadingControlProven(context,
      { filePath: 'src/server.js', routePath: '/public/subscribe', line: 6, framework: 'express' }, 'auth')).toBe(false);
  });

  it('leaves router.use(guard) to the routing tree, which still suppresses', () => {
    const context = memoryContext([EXPRESS_PACKAGE, AUTH_MIDDLEWARE,
      ['src/routes/admin.js',
        "const express = require('express');\n" +
        "const { requireAuth } = require('../middleware/auth');\n" +
        'const router = express.Router();\n' +
        'router.use(requireAuth);\n' +
        "router.post('/admin/reset', async (req, res) => {\n" +
        '  await db.users.deleteMany({});\n' +
        '  res.json({ ok: true });\n' +
        '});\n' +
        'module.exports = router;\n'],
      ['src/server.js',
        "const express = require('express');\n" +
        'const app = express();\n' +
        "app.use('/api', require('./routes/admin'));\n"],
    ]);
    expect(firedOn(apiMutationWithoutAuth.run(context), 'routes/admin.js')).toBe(0);
  });
});
