import { describe, expect, it } from 'vitest';
import { extractApiRoutes } from '../../src/project-map/extractApiRoutes.js';
import { buildPathAliases, resolveLocalImport } from '../../src/project-map/resolveImports.js';
import { fileRoutedHandlers, svelteKitRouteKind, SVELTEKIT_IDENTITY } from '../../src/shared/frameworkModel.js';
import { supabaseServiceRoleExposed } from '../../src/rules/basic/supabaseServiceRoleExposed.js';
import { failOpenAuthentication } from '../../src/rules/contextual/failOpenAuthentication.js';
import { memoryContext, memoryFile } from './helpers.js';
import { buildFileMap } from '../../src/file-map/buildFileMap.js';
import type { PreparedInput } from '../../src/shared/types.js';

const SVELTE_CONFIG = ['svelte.config.js', 'export default { kit: {} };\n'] as [string, string];
const PACKAGE_JSON = [
  'package.json',
  '{"dependencies":{"@sveltejs/kit":"2.0.0","svelte":"4.0.0"}}',
] as [string, string];

const AUTH_HELPER = [
  'src/lib/server/auth.ts',
  "import { error } from '@sveltejs/kit';\n" +
    "import type { RequestEvent } from '@sveltejs/kit';\n" +
    'export function requireSession(event: RequestEvent) {\n' +
    '  const session = event.locals.session;\n' +
    "  if (!session) throw error(401, 'sign in');\n" +
    '  return session;\n' +
    '}\n',
] as [string, string];

describe('the shared framework model: SvelteKit route recognition', () => {
  it('recognises every method export in a +server.ts, with its method and route path', () => {
    const entry = memoryFile(
      'src/routes/api/invoices/[id]/+server.ts',
      "import { json } from '@sveltejs/kit';\n" +
        'export const GET: RequestHandler = async (event) => json({});\n' +
        'export const PATCH: RequestHandler = async (event) => json({});\n' +
        'export async function DELETE(event) { return new Response(null); }\n',
    );
    const routes = extractApiRoutes({ ...entry, isLikelyApiRoute: true } as never);
    expect(routes.map((route) => route.methods[0]).sort()).toEqual(['DELETE', 'GET', 'PATCH']);
    for (const route of routes) {
      expect(route.framework).toBe('sveltekit');
      expect(route.routePath).toBe('/api/invoices/[id]');
    }
  });

  it('reads +page.server.ts load as a GET and its actions as a POST', () => {
    const entry = memoryFile(
      'src/routes/settings/+page.server.ts',
      'export const load = async ({ locals }) => ({ ok: true });\n' +
        'export const actions = { default: async (event) => ({}) };\n',
    );
    const routes = extractApiRoutes({ ...entry, isLikelyApiRoute: true } as never);
    expect(routes.map((route) => route.methods[0]).sort()).toEqual(['GET', 'POST']);
    expect(routes.every((route) => route.routePath === '/settings')).toBe(true);
  });

  it('produces NO route for a +page.server.ts that exports neither load nor actions', () => {
    const entry = memoryFile('src/routes/x/+page.server.ts', 'export type Data = { a: string };\n');
    expect(extractApiRoutes({ ...entry, isLikelyApiRoute: true } as never)).toEqual([]);
  });

  it('strips (group) segments from the route path, as the App Router does', () => {
    expect(svelteKitRouteKind('src/routes/(app)/billing/+server.ts')?.routePath).toBe('/billing');
  });

  it('does not mistake an ordinary server.ts for a SvelteKit route', () => {
    expect(svelteKitRouteKind('src/routes/server.ts')).toBeUndefined();
    expect(svelteKitRouteKind('src/lib/server.ts')).toBeUndefined();
  });
});

describe('the shared framework model: App Router parity', () => {
  it('still resolves an app-router route.ts to nextjs_app, per method', () => {
    const entry = memoryFile(
      'app/api/notes/[id]/route.ts',
      'export async function GET(request: Request) { return Response.json({}); }\n' +
        'export const POST = async (request: Request) => Response.json({});\n',
    );
    const routes = extractApiRoutes({ ...entry, isLikelyApiRoute: true } as never);
    expect(routes.map((route) => `${route.framework}:${route.methods[0]}`).sort()).toEqual([
      'nextjs_app:GET',
      'nextjs_app:POST',
    ]);
    expect(routes[0]?.routePath).toBe('/api/notes/[id]');
  });

  it('still gives an app-router route.ts with no method export the ANY fallback', () => {
    const entry = memoryFile('app/api/x/route.ts', 'const handler = 1;\n');
    const routes = extractApiRoutes({ ...entry, isLikelyApiRoute: true } as never);
    expect(routes).toHaveLength(1);
    expect(routes[0]?.methods).toEqual(['ANY']);
  });

  it('still resolves a pages/api file to nextjs_pages with ANY', () => {
    const entry = memoryFile('pages/api/users/index.ts', 'export default function handler() {}\n');
    const routes = extractApiRoutes({ ...entry, isLikelyApiRoute: true } as never);
    expect(routes[0]?.framework).toBe('nextjs_pages');
    expect(routes[0]?.routePath).toBe('/api/users');
  });

  it('leaves an express file to the content-driven arm', () => {
    const entry = memoryFile('src/server.ts', "app.post('/api/x', handler);\n");
    expect(extractApiRoutes({ ...entry, isLikelyApiRoute: true } as never)[0]?.framework).toBe('express');
  });

  it('returns undefined — not an empty array — for a file no file-routed dialect owns', () => {
    const entry = memoryFile('src/server.ts', "app.post('/api/x', handler);\n");
    expect(fileRoutedHandlers({ ...entry, isLikelyApiRoute: true } as never)).toBeUndefined();
  });
});

describe('the shared framework model: $lib resolution and the auth credit', () => {
  function aliasesFor(files: [string, string][]) {
    const prepared: PreparedInput = {
      rootPath: '/virtual',
      files: files.map(([filePath, content]) => memoryFile(filePath, content)),
      skipped: [],
      skippedCount: 0,
      warnings: [],
    } as unknown as PreparedInput;
    return buildPathAliases(buildFileMap(prepared));
  }

  it('resolves $lib against the directory holding svelte.config.js', () => {
    const files: [string, string][] = [SVELTE_CONFIG, PACKAGE_JSON, AUTH_HELPER];
    const aliases = aliasesFor(files);
    const paths = new Set(files.map(([filePath]) => filePath));
    expect(
      resolveLocalImport('src/routes/api/x/+server.ts', '$lib/server/auth', paths, aliases),
    ).toBe('src/lib/server/auth.ts');
  });

  it('scopes $lib to its own app in a monorepo', () => {
    const files: [string, string][] = [
      ['apps/portal/svelte.config.js', 'export default {};\n'],
      ['apps/portal/src/lib/server/auth.ts', 'export const requireSession = () => {};\n'],
      ['apps/other/src/lib/server/auth.ts', 'export const requireSession = () => {};\n'],
    ];
    const aliases = aliasesFor(files);
    const paths = new Set(files.map(([filePath]) => filePath));
    expect(
      resolveLocalImport('apps/portal/src/routes/+server.ts', '$lib/server/auth', paths, aliases),
    ).toBe('apps/portal/src/lib/server/auth.ts');
    expect(
      resolveLocalImport('apps/other/src/routes/+server.ts', '$lib/server/auth', paths, aliases),
    ).toBeUndefined();
  });

  it('reads a package tsconfig, not only the project root — the monorepo case', () => {
    const files: [string, string][] = [
      ['apps/web/tsconfig.json', '{"compilerOptions":{"paths":{"@/*":["./src/*"]}}}'],
      ['apps/web/src/lib/auth.ts', 'export const auth = () => {};\n'],
    ];
    const aliases = aliasesFor(files);
    const paths = new Set(files.map(([filePath]) => filePath));
    expect(resolveLocalImport('apps/web/src/app/api/x/route.ts', '@/lib/auth', paths, aliases)).toBe(
      'apps/web/src/lib/auth.ts',
    );
  });

  it('does not let one package’s alias resolve another package’s import', () => {
    const files: [string, string][] = [
      ['apps/web/tsconfig.json', '{"compilerOptions":{"paths":{"@/*":["./src/*"]}}}'],
      ['apps/web/src/lib/auth.ts', 'export const auth = () => {};\n'],
      ['apps/admin/src/lib/auth.ts', 'export const auth = () => {};\n'],
    ];
    const aliases = aliasesFor(files);
    const paths = new Set(files.map(([filePath]) => filePath));
    expect(
      resolveLocalImport('apps/admin/src/app/api/x/route.ts', '@/lib/auth', paths, aliases),
    ).not.toBe('apps/web/src/lib/auth.ts');
  });

  it('credits authentication on a SvelteKit route that calls a $lib guard', () => {
    const context = memoryContext([
      SVELTE_CONFIG,
      PACKAGE_JSON,
      AUTH_HELPER,
      [
        'src/routes/api/invoices/+server.ts',
        "import { requireSession } from '$lib/server/auth';\n" +
          "import { pool } from '$lib/server/db';\n" +
          'export const DELETE = async (event) => {\n' +
          '  requireSession(event);\n' +
          "  await pool.query('delete from invoices where id = $1', [event.params.id]);\n" +
          '  return new Response(null, { status: 204 });\n' +
          '};\n',
      ],
      ['src/lib/server/db.ts', 'export const pool = { query: async (_sql: string, _p: unknown[]) => [] };\n'],
    ]);
    const profile = (context.projectMap.routeSecurityProfiles ?? []).find(
      (candidate) => candidate.method === 'DELETE',
    );
    expect(profile).toBeDefined();
    expect(profile?.framework).toBe('sveltekit');
    expect(profile?.authentication.status).toBe('present');
  });

  it('sees the request body entering a SvelteKit handler', () => {
    const context = memoryContext([
      SVELTE_CONFIG,
      PACKAGE_JSON,
      [
        'src/routes/api/messages/+server.ts',
        "import { json } from '@sveltejs/kit';\n" +
          'export const POST = async ({ request }) => {\n' +
          '  const { body } = await request.json();\n' +
          '  return json({ body });\n' +
          '};\n',
      ],
    ]);
    const profile = (context.projectMap.routeSecurityProfiles ?? []).find(
      (candidate) => candidate.method === 'POST',
    );
    expect(profile).toBeDefined();
    expect(profile?.inputValidation.status).not.toBe('present');
  });
});

describe('the shared framework model: values that cross a boundary the module does not', () => {
  const PRIVATE_ENV = "import { SUPABASE_SERVICE_ROLE_KEY } from '$env/static/private';\n";

  it('reports a private-env secret returned from a server load', () => {
    const findings = supabaseServiceRoleExposed.run(
      memoryContext([
        SVELTE_CONFIG,
        PACKAGE_JSON,
        [
          'src/routes/+layout.server.ts',
          `${PRIVATE_ENV}export const load = async ({ locals }) => {\n` +
            '  return { signedIn: Boolean(locals.session), key: SUPABASE_SERVICE_ROLE_KEY };\n' +
            '};\n',
        ],
      ]),
    );
    expect(findings.map((finding) => finding.filePath)).toEqual(['src/routes/+layout.server.ts']);
    expect(findings[0]?.severity).toBe('critical');
  });

  it('reports it through the concise-arrow form too', () => {
    const findings = supabaseServiceRoleExposed.run(
      memoryContext([
        SVELTE_CONFIG,
        PACKAGE_JSON,
        [
          'src/routes/+page.server.ts',
          `${PRIVATE_ENV}export const load = async ({ locals }) => ({ key: SUPABASE_SERVICE_ROLE_KEY });\n`,
        ],
      ]),
    );
    expect(findings).toHaveLength(1);
  });

  it('stays quiet when the key is USED in the load but not returned', () => {
    const findings = supabaseServiceRoleExposed.run(
      memoryContext([
        SVELTE_CONFIG,
        PACKAGE_JSON,
        [
          'src/routes/+page.server.ts',
          `${PRIVATE_ENV}import { createClient } from '@supabase/supabase-js';\n` +
            'export const load = async () => {\n' +
            "  const admin = createClient('https://x.supabase.co', SUPABASE_SERVICE_ROLE_KEY);\n" +
            "  const { count } = await admin.from('invoices').select('*', { count: 'exact' });\n" +
            '  return { paidInvoices: count ?? 0 };\n' +
            '};\n',
        ],
      ]),
    );
    expect(findings).toHaveLength(0);
  });

  it('stays quiet on a config-presence flag that only tests the key', () => {
    const findings = supabaseServiceRoleExposed.run(
      memoryContext([
        SVELTE_CONFIG,
        PACKAGE_JSON,
        [
          'src/routes/+page.server.ts',
          `${PRIVATE_ENV}export const load = async () => ({ configured: Boolean(SUPABASE_SERVICE_ROLE_KEY) });\n`,
        ],
      ]),
    );
    expect(findings).toHaveLength(0);
  });

  it('does not run at all on a +server.ts', () => {
    const findings = supabaseServiceRoleExposed.run(
      memoryContext([
        SVELTE_CONFIG,
        PACKAGE_JSON,
        [
          'src/routes/api/x/+server.ts',
          `${PRIVATE_ENV}export const load = async () => ({ key: SUPABASE_SERVICE_ROLE_KEY });\n`,
        ],
      ]),
    );
    expect(findings).toHaveLength(0);
  });
});

describe('the shared framework model: a fail-open in the handle hook', () => {
  it('reports a catch that assigns an unverified identity to locals', () => {
    const findings = failOpenAuthentication.run(
      memoryContext([
        SVELTE_CONFIG,
        PACKAGE_JSON,
        [
          'src/hooks.server.ts',
          "import { decodeToken, verifyToken } from '$lib/server/tokens';\n" +
            'export const handle = async ({ event, resolve }) => {\n' +
            "  const token = event.cookies.get('portal_session');\n" +
            '  try {\n' +
            '    event.locals.session = verifyToken(token);\n' +
            '  } catch {\n' +
            '    event.locals.session = decodeToken(token);\n' +
            '  }\n' +
            '  return resolve(event);\n' +
            '};\n',
        ],
        ['src/lib/server/tokens.ts', 'export const verifyToken = (t: string) => ({});\nexport const decodeToken = (t: string) => ({});\n'],
      ]),
    );
    expect(findings.map((finding) => finding.filePath)).toContain('src/hooks.server.ts');
  });

  it('stays quiet on a hook whose catch DENIES', () => {
    const findings = failOpenAuthentication.run(
      memoryContext([
        SVELTE_CONFIG,
        PACKAGE_JSON,
        [
          'src/hooks.server.ts',
          "import { verifyToken } from '$lib/server/tokens';\n" +
            'export const handle = async ({ event, resolve }) => {\n' +
            "  const token = event.cookies.get('portal_session');\n" +
            '  try {\n' +
            '    event.locals.session = verifyToken(token);\n' +
            '  } catch {\n' +
            '    event.locals.session = null;\n' +
            '  }\n' +
            '  return resolve(event);\n' +
            '};\n',
        ],
        ['src/lib/server/tokens.ts', 'export const verifyToken = (t: string) => ({});\n'],
      ]),
    );
    expect(findings).toHaveLength(0);
  });

  it('does not treat Express res.locals as a SvelteKit identity', () => {
    expect(SVELTEKIT_IDENTITY.test('res.locals.user = req.user;')).toBe(false);
    expect(SVELTEKIT_IDENTITY.test('app.locals.user = u;')).toBe(false);
    expect(SVELTEKIT_IDENTITY.test('event.locals.session = s;')).toBe(true);
    expect(SVELTEKIT_IDENTITY.test('const { session } = locals;')).toBe(false);
    expect(SVELTEKIT_IDENTITY.test('if (locals?.session) return;')).toBe(true);
  });
});
