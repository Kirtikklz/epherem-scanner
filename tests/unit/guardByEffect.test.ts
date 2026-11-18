import { describe, expect, it } from 'vitest';
import { apiMutationWithoutAuth } from '../../src/rules/contextual/apiMutationWithoutAuth.js';
import { cascadingControlProven } from '../../src/shared/cascadingGuard.js';
import { classifyGuardBody } from '../../src/shared/handlerGuardCall.js';
import { effectiveGuards } from '../../src/project-map/detectAuthSignals.js';
import { memoryContext } from './helpers.js';

const SVELTE_PACKAGE: [string, string] =
  ['package.json', '{"devDependencies":{"@sveltejs/kit":"2.0.0"}}'];
const SVELTE_CONFIG: [string, string] = ['svelte.config.js', 'export default { kit: {} };'];

const ENFORCING_HOOK: [string, string] = ['src/hooks.server.ts',
  "import { redirect } from '@sveltejs/kit';\n" +
  'export const handle = async ({ event, resolve }) => {\n' +
  '  const session = await event.locals.getSession();\n' +
  "  if (!session) redirect(303, '/login');\n" +
  '  event.locals.user = session.user;\n' +
  '  return resolve(event);\n' +
  '};\n'];

const POPULATING_HOOK: [string, string] = ['src/hooks.server.ts',
  'export const handle = async ({ event, resolve }) => {\n' +
  '  const session = await event.locals.getSession();\n' +
  '  event.locals.user = session ? session.user : null;\n' +
  '  return resolve(event);\n' +
  '};\n'];

const ENFORCING_HELPER: [string, string] = ['src/lib/server/auth.ts',
  "import { error } from '@sveltejs/kit';\n" +
  'export async function ensureCaller(locals) {\n' +
  '  const user = locals.user;\n' +
  '  if (!user) {\n' +
  "    throw error(401, 'Unauthorized');\n" +
  '  }\n' +
  '  return user;\n' +
  '}\n'];

const POPULATING_HELPER: [string, string] = ['src/lib/server/auth.ts',
  'export async function ensureCaller(locals) {\n' +
  '  const user = locals.user;\n' +
  '  return user ? user : null;\n' +
  '}\n'];

const MUTATING_ENDPOINT = (body: string): [string, string] =>
  ['src/routes/api/profile/+server.ts',
    "import { error, json } from '@sveltejs/kit';\n" +
    "import { ensureCaller } from '$lib/server/auth';\n" +
    "import { prisma } from '$lib/server/db';\n" +
    'export const PATCH = async ({ request, locals }) => {\n' +
    body +
    '  await prisma.profile.update({ where: { id: 1 }, data: { name: 1 } });\n' +
    '  return json({ ok: true });\n' +
    '};\n'];

function firedOn(findings: { filePath: string }[], fragment: string): number {
  return findings.filter((finding) => finding.filePath.includes(fragment)).length;
}

describe('a guard that enforces is recognised by effect', () => {
  it('an enforcing hook protects the endpoints beneath it', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, ENFORCING_HOOK,
      MUTATING_ENDPOINT('')]);
    expect(firedOn(apiMutationWithoutAuth.run(context), 'profile')).toBe(0);
  });

  it('a project-defined helper that throws is credited without knowing its name', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, ENFORCING_HELPER,
      MUTATING_ENDPOINT('  await ensureCaller(locals);\n')]);
    expect(firedOn(apiMutationWithoutAuth.run(context), 'profile')).toBe(0);
  });
});

describe('the inline handler guard, which is a property read', () => {
  it('is not flagged: `if (!locals.user) throw error(401)`', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG,
      MUTATING_ENDPOINT("  if (!locals.user) {\n    throw error(401, 'Unauthorized');\n  }\n")]);
    expect(firedOn(apiMutationWithoutAuth.run(context), 'profile')).toBe(0);
  });

  it('is not flagged when the identity is destructured out of the event', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG,
      ['src/routes/api/profile/+server.ts',
        "import { error, json } from '@sveltejs/kit';\n" +
        "import { prisma } from '$lib/server/db';\n" +
        'export const PATCH = async ({ request, locals: { user } }) => {\n' +
        "  if (!user) throw error(401, 'Unauthorized');\n" +
        '  await prisma.profile.update({ where: { id: 1 }, data: { name: 1 } });\n' +
        '  return json({ ok: true });\n' +
        '};\n']]);
    expect(firedOn(apiMutationWithoutAuth.run(context), 'profile')).toBe(0);
  });

  it('is not flagged when the guard uses safeGetSession() and returns fail(401)', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG,
      ['src/routes/api/profile/+server.ts',
        "import { fail, json } from '@sveltejs/kit';\n" +
        "import { prisma } from '$lib/server/db';\n" +
        'export const PATCH = async ({ request, locals: { safeGetSession } }) => {\n' +
        '  const { user } = await safeGetSession();\n' +
        "  if (!user) return fail(401, { message: 'not authenticated' });\n" +
        '  await prisma.profile.update({ where: { id: 1 }, data: { name: 1 } });\n' +
        '  return json({ ok: true });\n' +
        '};\n']]);
    expect(firedOn(apiMutationWithoutAuth.run(context), 'profile')).toBe(0);
  });

  it('STILL FIRES when safeGetSession() is called and its answer ignored', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG,
      ['src/routes/api/profile/+server.ts',
        "import { json } from '@sveltejs/kit';\n" +
        "import { prisma } from '$lib/server/db';\n" +
        'export const PATCH = async ({ request, locals: { safeGetSession } }) => {\n' +
        '  const { user } = await safeGetSession();\n' +
        '  await prisma.profile.update({ where: { id: 1 }, data: { name: user } });\n' +
        '  return json({ ok: true });\n' +
        '};\n']]);
    expect(firedOn(apiMutationWithoutAuth.run(context), 'profile')).toBeGreaterThan(0);
  });

  it('STILL FIRES when locals.user is merely read, never tested', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG,
      ['src/routes/api/profile/+server.ts',
        "import { json } from '@sveltejs/kit';\n" +
        "import { prisma } from '$lib/server/db';\n" +
        'export const PATCH = async ({ request, locals }) => {\n' +
        '  await prisma.profile.update({ where: { id: locals.user.id }, data: { name: 1 } });\n' +
        '  return json({ ok: true });\n' +
        '};\n']]);
    expect(firedOn(apiMutationWithoutAuth.run(context), 'profile')).toBeGreaterThan(0);
  });
});

describe('the enforce-vs-populate line', () => {
  it('STILL FIRES under a hook that only populates locals', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, POPULATING_HOOK,
      MUTATING_ENDPOINT('')]);
    expect(firedOn(apiMutationWithoutAuth.run(context), 'profile')).toBeGreaterThan(0);
  });

  it('STILL FIRES when the helper it calls only hands the identity back', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, POPULATING_HELPER,
      MUTATING_ENDPOINT('  const caller = await ensureCaller(locals);\n')]);
    expect(firedOn(apiMutationWithoutAuth.run(context), 'profile')).toBeGreaterThan(0);
  });

  it('STILL FIRES when an assignment sits beside an unrelated validation check', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG,
      ['src/routes/api/profile/+server.ts',
        "import { error, json } from '@sveltejs/kit';\n" +
        "import { prisma } from '$lib/server/db';\n" +
        'export const PATCH = async ({ request, locals }) => {\n' +
        '  const body = await request.json();\n' +
        "  if (!body.name) throw error(400, 'name required');\n" +
        '  locals.user = body.actor;\n' +
        '  await prisma.profile.update({ where: { id: 1 }, data: { name: 1 } });\n' +
        '  return json({ ok: true });\n' +
        '};\n']]);
    expect(firedOn(apiMutationWithoutAuth.run(context), 'profile')).toBeGreaterThan(0);
  });

  it('an assignment to locals.user yields no checked auth signal', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, POPULATING_HOOK]);
    const signals = context.projectMap.authSignals
      .filter((signal) => signal.filePath === 'src/hooks.server.ts' && signal.snippet.includes('='));
    expect(effectiveGuards(signals).filter((s) => s.snippet.includes('locals.user =')))
      .toHaveLength(0);
  });
});

describe('a route with no guard anywhere', () => {
  it('STILL FIRES with no hook, no helper and no inline check', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, MUTATING_ENDPOINT('')]);
    expect(firedOn(apiMutationWithoutAuth.run(context), 'profile')).toBeGreaterThan(0);
  });
});

describe('a form action nested in an `actions` object', () => {
  const TWO_ACTIONS = (first: string, second: string): [string, string] =>
    ['src/routes/settings/+page.server.ts',
      "import { error } from '@sveltejs/kit';\n" +
      "import { prisma } from '$lib/server/db';\n" +
      'export const actions = {\n' +
      '  rename: async ({ request, locals }) => {\n' +
      first +
      '    await prisma.profile.update({ where: { id: 1 }, data: { name: 1 } });\n' +
      '    return { ok: true };\n' +
      '  },\n' +
      '  purge: async ({ request, locals }) => {\n' +
      second +
      '    await prisma.profile.update({ where: { id: 2 }, data: { name: 2 } });\n' +
      '    return { ok: true };\n' +
      '  },\n' +
      '};\n'];
  const GUARD = "    if (!locals.user) throw error(401, 'Unauthorized');\n";

  it('is protected by an enforcing hook — both actions, not just the first', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, ENFORCING_HOOK,
      TWO_ACTIONS('', '')]);
    expect(firedOn(apiMutationWithoutAuth.run(context), 'settings')).toBe(0);
  });

  it('does NOT let a guarded action vouch for its unguarded sibling', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, POPULATING_HOOK,
      TWO_ACTIONS(GUARD, '')]);
    expect(firedOn(apiMutationWithoutAuth.run(context), 'settings')).toBe(1);
  });
});

describe('a hook whose path test is written through a const', () => {
  const SCOPED_HOOK: [string, string] = ['src/hooks.server.ts',
    "import { redirect } from '@sveltejs/kit';\n" +
    'export const handle = async ({ event, resolve }) => {\n' +
    '  const session = await event.locals.getSession();\n' +
    "  const isPrivate = event.url.pathname.startsWith('/api/profile');\n" +
    "  if (isPrivate && !session) redirect(303, '/login');\n" +
    '  return resolve(event);\n' +
    '};\n'];

  it('covers a route inside the prefixes that const names', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, SCOPED_HOOK,
      MUTATING_ENDPOINT('')]);
    expect(firedOn(apiMutationWithoutAuth.run(context), 'profile')).toBe(0);
  });

  it('does NOT cover a route outside them', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, SCOPED_HOOK,
      ['src/routes/api/billing/+server.ts',
        "import { json } from '@sveltejs/kit';\n" +
        "import { prisma } from '$lib/server/db';\n" +
        'export const POST = async ({ request }) => {\n' +
        '  await prisma.invoice.update({ where: { id: 1 }, data: { paid: true } });\n' +
        '  return json({ ok: true });\n' +
        '};\n']]);
    expect(firedOn(apiMutationWithoutAuth.run(context), 'billing')).toBeGreaterThan(0);
  });
});

describe('a helper whose success paths return and whose fall-through refuses', () => {
  const INVERTED = '  const user = await getUser(event);\n' +
    '  const profile = await getProfile(user.id);\n' +
    "  if (hasModuleLevel(profile.modules, 'courses.admin')) return { user, profile };\n" +
    '  if (isAssigned(profile, slug)) return { user, profile };\n' +
    "  if (event.mode === 'redirect') throw redirect(303, '/');\n" +
    "  throw error(403, 'Not authorized');\n";

  it('is read as blocking on identity', () => {
    expect(classifyGuardBody(INVERTED).blocks.identity).toBe(true);
  });

  it('is NOT credited when the fall-through throws a 404', () => {
    const loader = '  const row = await db.course.find(slug, user.id);\n' +
      '  if (row) return row;\n' +
      "  throw error(404, 'No such course');\n";
    expect(classifyGuardBody(loader).blocks.identity).toBe(false);
  });

  it('is NOT credited when there is no way to pass', () => {
    const thrower = '  const caller = user;\n' +
      "  throw error(403, 'Not authorized');\n";
    expect(classifyGuardBody(thrower).blocks.identity).toBe(false);
  });

  it('is NOT credited when the only refusal is inside a conditional', () => {
    const conditional = '  const thing = await db.thing.find(id, user.id);\n' +
      "  if (thing.locked) { throw error(403, 'locked'); }\n" +
      '  return thing;\n';
    expect(classifyGuardBody(conditional).blocks.identity).toBe(false);
  });
});

describe('cascadingControlProven under the two hooks', () => {
  const query = {
    filePath: 'src/routes/api/profile/+server.ts',
    routePath: '/api/profile',
    line: 4,
    framework: 'sveltekit' as const,
    method: 'PATCH',
  };

  it('proves auth under the enforcing hook', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, ENFORCING_HOOK,
      MUTATING_ENDPOINT('')]);
    expect(cascadingControlProven(context, query, 'auth')).toBe(true);
  });

  it('proves NOTHING under the populating hook', () => {
    const context = memoryContext([SVELTE_PACKAGE, SVELTE_CONFIG, POPULATING_HOOK,
      MUTATING_ENDPOINT('')]);
    expect(cascadingControlProven(context, query, 'auth')).toBe(false);
  });
});
