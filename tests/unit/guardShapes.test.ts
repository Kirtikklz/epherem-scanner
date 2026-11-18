import { describe, expect, it } from 'vitest';
import { brokenAccessControl } from '../../src/rules/contextual/brokenAccessControl.js';
import { cascadingControlProven } from '../../src/shared/cascadingGuard.js';
import { apiMutationWithoutAuth } from '../../src/rules/contextual/apiMutationWithoutAuth.js';
import {
  classifyGuardBody,
  guardOnlyModules,
  resolvesToRejection,
} from '../../src/shared/handlerGuardCall.js';
import { svelteKitRouteId } from '../../src/shared/frameworkModel.js';
import { memoryContext } from './helpers.js';

const SVELTE_PACKAGE: [string, string] =
  ['package.json', '{"devDependencies":{"@sveltejs/kit":"2.0.0"}}'];
const SVELTE_CONFIG: [string, string] = ['svelte.config.js', 'export default { kit: {} };'];

describe('a hook body is read past the prose in its comments', () => {
  const COMMENTED_HOOK: [string, string] = ['src/hooks.server.ts',
    "import { redirect } from '@sveltejs/kit';\n" +
    'export const handle = async ({ event, resolve }) => {\n' +
    '  /**\n' +
    "   * Note: the path is set here due to sveltekit's cookie API\n" +
    '   * requiring it, which replicates standard behaviour.\n' +
    '   */\n' +
    '  const session = await event.locals.getSession();\n' +
    "  if (!session) redirect(303, '/login');\n" +
    '  return resolve(event);\n' +
    '};\n'];

  const ENDPOINT: [string, string] = ['src/routes/api/profile/+server.ts',
    "import { json } from '@sveltejs/kit';\n" +
    'export async function PATCH({ request, locals }) {\n' +
    '  const body = await request.json();\n' +
    "  await locals.supabase.from('profiles').update(body);\n" +
    '  return json({ ok: true });\n' +
    '}\n'];

  const query = {
    filePath: 'src/routes/api/profile/+server.ts',
    routePath: '/api/profile',
    line: 2,
    framework: 'sveltekit' as const,
    method: 'PATCH',
  };

  it('reads an enforcing hook whose comment contains an apostrophe', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, COMMENTED_HOOK, ENDPOINT]);
    expect(cascadingControlProven(context, query, 'auth')).toBe(true);
  });

  it('STILL FIRES: the same comment above a hook that only populates', () => {
    const populating: [string, string] = ['src/hooks.server.ts',
      'export const handle = async ({ event, resolve }) => {\n' +
      '  /**\n' +
      "   * Note: the path is set here due to sveltekit's cookie API\n" +
      '   */\n' +
      '  const session = await event.locals.getSession();\n' +
      '  event.locals.user = session ? session.user : null;\n' +
      '  return resolve(event);\n' +
      '};\n'];
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, populating, ENDPOINT]);
    expect(cascadingControlProven(context, query, 'auth')).toBe(false);
  });
});

describe('a hook scoped on event.route.id', () => {
  const GROUP_HOOK: [string, string] = ['src/hooks.server.ts',
    "import { redirect } from '@sveltejs/kit';\n" +
    'const isProtectedRoute = (routeId) =>\n' +
    "  typeof routeId === 'string' && routeId.startsWith('/(app)');\n" +
    'export const handle = async ({ event, resolve }) => {\n' +
    '  if (isProtectedRoute(event.route.id)) {\n' +
    '    const { data: { user }, error } = await event.locals.supabase.auth.getUser();\n' +
    "    if (error || !user) { throw redirect(303, '/login'); }\n" +
    '  }\n' +
    '  return resolve(event);\n' +
    '};\n'];

  const inside = {
    filePath: 'src/routes/(app)/admin/prompts/+page.server.ts',
    routePath: '/admin/prompts',
    line: 2,
    framework: 'sveltekit' as const,
    method: 'POST',
  };
  const outside = {
    filePath: 'src/routes/api/leads/intake/+server.ts',
    routePath: '/api/leads/intake',
    line: 2,
    framework: 'sveltekit' as const,
    method: 'POST',
  };

  const PAGE: [string, string] = ['src/routes/(app)/admin/prompts/+page.server.ts',
    'export const actions = {\n' +
    '  toggle: async ({ request, locals }) => {\n' +
    '    const form = await request.formData();\n' +
    "    await locals.supabase.from('prompts').update({ active: form.get('a') });\n" +
    '    return { success: true };\n' +
    '  }\n' +
    '};\n'];
  const OPEN_API: [string, string] = ['src/routes/api/leads/intake/+server.ts',
    "import { json } from '@sveltejs/kit';\n" +
    'export async function POST({ request, locals }) {\n' +
    '  const body = await request.json();\n' +
    "  await locals.supabase.from('leads').insert(body);\n" +
    '  return json({ ok: true });\n' +
    '}\n'];

  const files = [SVELTE_PACKAGE, SVELTE_CONFIG, GROUP_HOOK, PAGE, OPEN_API];

  it('derives the route id with its layout groups intact', () => {
    expect(svelteKitRouteId('src/routes/(app)/admin/prompts/+page.server.ts'))
      .toBe('/(app)/admin/prompts');
    expect(svelteKitRouteId('src/routes/api/leads/intake/+server.ts'))
      .toBe('/api/leads/intake');
  });

  it('protects a route inside the group', () => {
    expect(cascadingControlProven(memoryContext(files), inside, 'auth')).toBe(true);
  });

  it('STILL FIRES on a route outside the group', () => {
    expect(cascadingControlProven(memoryContext(files), outside, 'auth')).toBe(false);
  });

  it('STILL FIRES when the block inside the group only populates', () => {
    const populating: [string, string] = ['src/hooks.server.ts',
      "const isProtectedRoute = (routeId) => routeId.startsWith('/(app)');\n" +
      'export const handle = async ({ event, resolve }) => {\n' +
      '  if (isProtectedRoute(event.route.id)) {\n' +
      '    const { data: { user } } = await event.locals.supabase.auth.getUser();\n' +
      '    event.locals.user = user;\n' +
      '  }\n' +
      '  return resolve(event);\n' +
      '};\n'];
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, populating, PAGE, OPEN_API]);
    expect(cascadingControlProven(context, inside, 'auth')).toBe(false);
  });

  it('STILL FIRES when the block fetches the identity and ignores the answer', () => {
    const ignoring: [string, string] = ['src/hooks.server.ts',
      "const isProtectedRoute = (routeId) => routeId.startsWith('/(app)');\n" +
      'export const handle = async ({ event, resolve }) => {\n' +
      '  if (isProtectedRoute(event.route.id)) {\n' +
      '    await event.locals.supabase.auth.getUser();\n' +
      '  }\n' +
      '  return resolve(event);\n' +
      '};\n'];
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, ignoring, PAGE, OPEN_API]);
    expect(cascadingControlProven(context, inside, 'auth')).toBe(false);
  });

  it('STILL FIRES when the enclosing condition is not a path test at all', () => {
    const methodGated: [string, string] = ['src/hooks.server.ts',
      "import { redirect } from '@sveltejs/kit';\n" +
      'export const handle = async ({ event, resolve }) => {\n' +
      "  if (event.request.method === 'POST') {\n" +
      '    const { data: { user } } = await event.locals.supabase.auth.getUser();\n' +
      "    if (!user) { throw redirect(303, '/login'); }\n" +
      '  }\n' +
      '  return resolve(event);\n' +
      '};\n'];
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, methodGated, PAGE, OPEN_API]);
    expect(cascadingControlProven(context, inside, 'auth')).toBe(false);
  });

  it('a call NOT handed the route id leaves a global hook global', () => {
    const globalHook: [string, string] = ['src/hooks.server.ts',
      "import { redirect } from '@sveltejs/kit';\n" +
      'const isValidSession = (session) => Boolean(session && session.user);\n' +
      'export const handle = async ({ event, resolve }) => {\n' +
      '  const session = await event.locals.getSession();\n' +
      "  if (!isValidSession(session)) { throw redirect(303, '/login'); }\n" +
      '  return resolve(event);\n' +
      '};\n'];
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, globalHook, PAGE, OPEN_API]);
    expect(cascadingControlProven(context, inside, 'auth')).toBe(true);
    expect(cascadingControlProven(context, outside, 'auth')).toBe(true);
  });

  it('STILL FIRES when a readable gate encloses an unreadable one', () => {
    const twoGates: [string, string] = ['src/hooks.server.ts',
      "import { redirect } from '@sveltejs/kit';\n" +
      "const isProtectedRoute = (routeId) => routeId.startsWith('/(app)');\n" +
      'export const handle = async ({ event, resolve }) => {\n' +
      '  if (isProtectedRoute(event.route.id)) {\n' +
      "    if (event.request.method === 'POST') {\n" +
      '      const { data: { user } } = await event.locals.supabase.auth.getUser();\n' +
      "      if (!user) { throw redirect(303, '/login'); }\n" +
      '    }\n' +
      '  }\n' +
      '  return resolve(event);\n' +
      '};\n'];
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, twoGates, PAGE, OPEN_API]);
    expect(cascadingControlProven(context, inside, 'auth')).toBe(false);
  });

  it('STILL FIRES on a route that satisfies the inner gate but not the outer', () => {
    const nested: [string, string] = ['src/hooks.server.ts',
      "import { redirect } from '@sveltejs/kit';\n" +
      "const isProtectedRoute = (routeId) => routeId.startsWith('/(app)');\n" +
      'export const handle = async ({ event, resolve }) => {\n' +
      '  if (isProtectedRoute(event.route.id)) {\n' +
      "    if (event.url.pathname.startsWith('/admin')) {\n" +
      '      const { data: { user } } = await event.locals.supabase.auth.getUser();\n' +
      "      if (!user) { throw redirect(303, '/login'); }\n" +
      '    }\n' +
      '  }\n' +
      '  return resolve(event);\n' +
      '};\n'];
    const ungrouped: [string, string] = ['src/routes/admin/x/+page.server.ts',
      'export const actions = {\n' +
      '  save: async ({ request, locals }) => {\n' +
      '    const form = await request.formData();\n' +
      "    await locals.supabase.from('things').update({ n: form.get('n') });\n" +
      '    return { success: true };\n' +
      '  }\n' +
      '};\n'];
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, nested, ungrouped]);
    expect(cascadingControlProven(context, {
      filePath: 'src/routes/admin/x/+page.server.ts',
      routePath: '/admin/x',
      line: 2,
      framework: 'sveltekit' as const,
      method: 'POST',
    }, 'auth')).toBe(false);
  });

  it('protects a route that satisfies every gate in the chain', () => {
    const nested: [string, string] = ['src/hooks.server.ts',
      "import { redirect } from '@sveltejs/kit';\n" +
      "const isProtectedRoute = (routeId) => routeId.startsWith('/(app)');\n" +
      'export const handle = async ({ event, resolve }) => {\n' +
      '  if (isProtectedRoute(event.route.id)) {\n' +
      "    if (event.url.pathname.startsWith('/admin')) {\n" +
      '      const { data: { user } } = await event.locals.supabase.auth.getUser();\n' +
      "      if (!user) { throw redirect(303, '/login'); }\n" +
      '    }\n' +
      '  }\n' +
      '  return resolve(event);\n' +
      '};\n'];
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, nested, PAGE, OPEN_API]);
    expect(cascadingControlProven(context, inside, 'auth')).toBe(true);
  });

  it('STILL FIRES when the route-id predicate yields no readable literal', () => {
    const unreadable: [string, string] = ['src/hooks.server.ts',
      "import { redirect } from '@sveltejs/kit';\n" +
      'const PROTECTED = [/^..app./];\n' +
      'const isProtectedRoute = (routeId) => PROTECTED.some((re) => re.test(routeId));\n' +
      'export const handle = async ({ event, resolve }) => {\n' +
      '  if (isProtectedRoute(event.route.id)) {\n' +
      '    const { data: { user } } = await event.locals.supabase.auth.getUser();\n' +
      "    if (!user) { throw redirect(303, '/login'); }\n" +
      '  }\n' +
      '  return resolve(event);\n' +
      '};\n'];
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, unreadable, PAGE, OPEN_API]);
    expect(cascadingControlProven(context, inside, 'auth')).toBe(false);
  });
});

describe('a helper that returns an identity or null', () => {
  const GET_AUTH_USER =
    "  const token = request.headers.get('authorization')?.replace('Bearer ', '');\n" +
    '  if (!token) return null;\n' +
    '  const { data: { user }, error } = await supabaseAdmin.auth.getUser(token);\n' +
    '  return error ? null : user;\n';

  it('decides identity: it fetched one, and it can hand back nothing', () => {
    expect(classifyGuardBody(GET_AUTH_USER).decides.identity).toBe(true);
  });

  it('does not BLOCK — a null return stops nothing by itself', () => {
    expect(classifyGuardBody(GET_AUTH_USER).blocks.identity).toBe(false);
  });

  it('STILL FIRES: a record lookup that returns null fetches no identity', () => {
    const lookup =
      '  const row = await db.record.findUnique({ where: { id } });\n' +
      '  if (!row) return null;\n' +
      '  return row.user;\n';
    expect(classifyGuardBody(lookup).decides.identity).toBe(false);
  });

  it('STILL FIRES: a helper that hands the identity back unconditionally', () => {
    const noRefusal =
      '  const { data: { user } } = await supabase.auth.getUser(token);\n' +
      '  return user;\n';
    expect(classifyGuardBody(noRefusal).decides.identity).toBe(false);
  });

  it('STILL FIRES: a helper whose every return is null decides nothing', () => {
    const alwaysNull =
      '  const { data: { user } } = await supabase.auth.getUser(token);\n' +
      '  if (!user) return null;\n' +
      '  return null;\n';
    expect(classifyGuardBody(alwaysNull).decides.identity).toBe(false);
  });

  const ROUTE_PATH = 'src/routes/api/access/roles/+server.js';
  const HANDLER = (guardLine: string): string =>
    'export async function POST({ request }) {\n' +
    '  const user = await getAuthUser(request);\n' +
    guardLine +
    '  const body = await request.json();\n' +
    "  await supabaseAdmin.from('roles').insert(body);\n" +
    '  return json({ ok: true });\n' +
    '}\n';

  const FILE = (guardLine: string): [string, string] =>
    [ROUTE_PATH,
      "import { json } from '@sveltejs/kit';\n" +
      "import { supabaseAdmin } from '$lib/server/supabaseAdmin';\n" +
      'async function getAuthUser(request) {\n' + GET_AUTH_USER + '}\n' +
      HANDLER(guardLine)];

  const credited = (guardLine: string): boolean => {
    const files: [string, string][] = [SVELTE_PACKAGE, SVELTE_CONFIG, FILE(guardLine)];
    return resolvesToRejection(memoryContext(files), ROUTE_PATH, HANDLER(guardLine));
  };

  it('is credited when the caller blocks on the falsy result', () => {
    expect(credited("  if (!user) return json({ error: 'no' }, { status: 401 });\n")).toBe(true);
  });

  it('STILL FIRES when the caller ignores the null', () => {
    expect(credited('  const actor = user ? user.id : null;\n')).toBe(false);
  });

  it('the rule goes quiet on the blocking caller and fires on the ignoring one', () => {
    const fired = (guardLine: string): number =>
      apiMutationWithoutAuth.run(memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, FILE(guardLine)]))
        .filter((item) => item.filePath === ROUTE_PATH).length;
    expect(fired("  if (!user) return json({ error: 'no' }, { status: 401 });\n")).toBe(0);
    expect(fired('  const actor = user ? user.id : null;\n')).toBeGreaterThan(0);
  });
});

describe('guardOnlyModules', () => {
  const AUTH_MODULE: [string, string] = ['src/lib/server/auth.ts',
    "import { error } from '@sveltejs/kit';\n" +
    'export async function requireAuth(event) {\n' +
    '  const { session, user } = await event.locals.safeGetSession();\n' +
    "  if (!session || !user) { throw error(401, 'Unauthorized'); }\n" +
    '  return { session, user };\n' +
    '}\n' +
    'export async function getUserProfile(event, userId) {\n' +
    "  const { data } = await event.locals.supabase.from('user_profiles')\n" +
    "    .select('id, modules').eq('id', userId).single();\n" +
    '  return data;\n' +
    '}\n' +
    'export async function requireCourseAdmin(event, courseSlug) {\n' +
    '  const { user } = await requireAuth(event);\n' +
    '  const profile = await getUserProfile(event, user.id);\n' +
    "  if (hasModuleLevel(profile, 'courses.admin')) { return { user, profile }; }\n" +
    "  const { data: course } = await event.locals.supabase.from('courses')\n" +
    "    .select('id').eq('slug', courseSlug).single();\n" +
    '  if (course && profile) { return { user, profile }; }\n' +
    "  throw error(403, 'Requires course admin access');\n" +
    '}\n'];

  const GUARDED_PATH = 'src/routes/admin/courses/[slug]/settings/api/+server.ts';
  const GUARDED_ROUTE: [string, string] = [GUARDED_PATH,
    "import { json } from '@sveltejs/kit';\n" +
    "import { requireCourseAdmin } from '$lib/server/auth';\n" +
    "import { supabaseAdmin } from '$lib/server/supabase';\n" +
    'export const GET = async (event) => {\n' +
    '  const courseSlug = event.params.slug;\n' +
    '  await requireCourseAdmin(event, courseSlug);\n' +
    "  const { data } = await supabaseAdmin.from('courses').select('*').eq('slug', courseSlug);\n" +
    '  return json({ data });\n' +
    '};\n'];

  const modulesFor = (files: [string, string][], path: string): string[] => {
    const context = memoryContext(files);
    const entry = context.fileMap.entries.find((item) => item.path === path);
    return guardOnlyModules(context, path, entry?.content ?? '');
  };

  it('names the module a route calls only as a guard, and takes only an identity from', () => {
    expect(modulesFor([SVELTE_PACKAGE, SVELTE_CONFIG, AUTH_MODULE, GUARDED_ROUTE], GUARDED_PATH))
      .toContain('src/lib/server/auth.ts');
  });

  it('REFUSES a module whose guard hands a record back', () => {
    const leaky: [string, string] = ['src/lib/server/docs.ts',
      "import { error } from '@sveltejs/kit';\n" +
      'export async function requireOwnedDoc(event, docId) {\n' +
      '  const { user } = await event.locals.safeGetSession();\n' +
      "  if (!user) { throw error(401, 'Unauthorized'); }\n" +
      "  const { data } = await event.locals.supabase.from('docs').select('*').eq('id', docId);\n" +
      '  return data;\n' +
      '}\n'];
    const route: [string, string] = ['src/routes/api/docs/+server.ts',
      "import { json } from '@sveltejs/kit';\n" +
      "import { requireOwnedDoc } from '$lib/server/docs';\n" +
      'export const GET = async (event) => {\n' +
      "  const doc = await requireOwnedDoc(event, event.url.searchParams.get('id'));\n" +
      '  return json({ doc });\n' +
      '};\n'];
    expect(modulesFor([SVELTE_PACKAGE, SVELTE_CONFIG, leaky, route], 'src/routes/api/docs/+server.ts'))
      .not.toContain('src/lib/server/docs.ts');
  });

  it('REFUSES a module whose call is discarded but proves no control', () => {
    const audit: [string, string] = ['src/lib/server/audit.ts',
      'export async function logAccess(event) {\n' +
      "  const { data } = await event.locals.supabase.from('audit_log')\n" +
      "    .select('id').eq('path', event.url.pathname);\n" +
      '  return data;\n' +
      '}\n'];
    const path = 'src/routes/api/audited/+server.ts';
    const route: [string, string] = [path,
      "import { json } from '@sveltejs/kit';\n" +
      "import { logAccess } from '$lib/server/audit';\n" +
      'export const GET = async (event) => {\n' +
      '  await logAccess(event);\n' +
      '  return json({ ok: true });\n' +
      '};\n'];
    expect(modulesFor([SVELTE_PACKAGE, SVELTE_CONFIG, audit, route], path))
      .not.toContain('src/lib/server/audit.ts');
  });

  it('REFUSES a module that is not called as a guard at all', () => {
    const service: [string, string] = ['src/lib/server/reports.ts',
      'export async function loadReport(event, id) {\n' +
      "  const { data } = await event.locals.supabase.from('reports').select('*').eq('id', id);\n" +
      '  return data;\n' +
      '}\n'];
    const route: [string, string] = ['src/routes/api/reports/+server.ts',
      "import { json } from '@sveltejs/kit';\n" +
      "import { loadReport } from '$lib/server/reports';\n" +
      'export const GET = async (event) => {\n' +
      "  const report = await loadReport(event, event.url.searchParams.get('id'));\n" +
      '  return json({ report });\n' +
      '};\n'];
    expect(modulesFor([SVELTE_PACKAGE, SVELTE_CONFIG, service, route], 'src/routes/api/reports/+server.ts'))
      .not.toContain('src/lib/server/reports.ts');
  });

  it('the route whose only imported access is its guard goes quiet', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, AUTH_MODULE, GUARDED_ROUTE]);
    expect(brokenAccessControl.run(context)
      .filter((item) => item.filePath === GUARDED_PATH && item.confidence === 'high'))
      .toHaveLength(0);
  });

  it('STILL COUNTS record access in a module that is not the guard', () => {
    const service: [string, string] = ['src/lib/server/enrollment.ts',
      'export async function listEnrolments(event, cohortId) {\n' +
      "  const { data } = await event.locals.supabase.from('enrolments')\n" +
      "    .select('*').eq('cohort_id', cohortId);\n" +
      '  return data;\n' +
      '}\n'];
    const path = 'src/routes/admin/courses/[slug]/enrol/api/+server.ts';
    const route: [string, string] = [path,
      "import { json } from '@sveltejs/kit';\n" +
      "import { requireCourseAdmin } from '$lib/server/auth';\n" +
      "import { listEnrolments } from '$lib/server/enrollment';\n" +
      'export const GET = async (event) => {\n' +
      '  await requireCourseAdmin(event, event.params.slug);\n' +
      "  const rows = await listEnrolments(event, event.url.searchParams.get('cohortId'));\n" +
      '  return json({ rows });\n' +
      '};\n'];
    expect(modulesFor([SVELTE_PACKAGE, SVELTE_CONFIG, AUTH_MODULE, service, route], path))
      .not.toContain('src/lib/server/enrollment.ts');
  });
});
