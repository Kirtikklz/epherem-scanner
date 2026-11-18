import { describe, expect, it } from 'vitest';
import { loadFixtureContext } from './helpers.js';

describe('buildProjectMap', () => {
  it('maps routes, database calls, env usage, and client files in next-supabase-insecure', async () => {
    const { projectMap } = await loadFixtureContext('next-supabase-insecure');

    const adminRoute = projectMap.apiRoutes.find((route) => route.filePath.includes('app/api/admin'));
    expect(adminRoute).toBeDefined();
    expect(adminRoute?.framework).toBe('nextjs_app');
    expect(adminRoute?.methods).toContain('DELETE');

    const deleteCall = projectMap.databaseCalls.find(
      (call) => call.client === 'supabase' && call.kind === 'delete',
    );
    expect(deleteCall?.filePath).toContain('app/api/admin/users/route.ts');

    expect(projectMap.publicClientUsage).toContain('components/ProfileCard.tsx');
    expect(projectMap.envUsage.some((usage) => usage.name === 'SUPABASE_SERVICE_ROLE_KEY')).toBe(true);
    expect(projectMap.envFiles).toContain('.env');
    expect(projectMap.middlewareFiles).toHaveLength(0);
    expect(projectMap.supabaseUsage.length).toBeGreaterThan(0);
    expect(projectMap.imports.some((imports) => imports.filePath === 'lib/supabaseAdmin.ts')).toBe(true);
    const routeImports = projectMap.imports.find(
      (imports) => imports.filePath === 'app/api/admin/users/route.ts',
    );
    expect(routeImports?.imports.some((ref) => ref.resolvedPath === 'lib/supabaseAdmin.ts')).toBe(true);
    expect(projectMap.supabaseRls.sqlFileCount).toBe(1);
    expect(projectMap.supabaseRls.rlsEnabledTables).toEqual([]);
  });

  it('finds auth signals, middleware, and matchers in the clean project', async () => {
    const { projectMap } = await loadFixtureContext('clean-basic-project');
    expect(projectMap.middlewareFiles).toContain('middleware.ts');
    expect(projectMap.middlewareMatchers.length).toBeGreaterThan(0);
    expect(projectMap.middlewareMatchers.map((matcher) => matcher.source)).toContain('/dashboard/:path*');
    const sessionSignal = projectMap.authSignals.find(
      (signal) => signal.filePath === 'app/api/items/route.ts' && signal.kind === 'getSession',
    );
    expect(sessionSignal?.protective).toBe(true);
    expect(sessionSignal?.checked).toBe(true);
    expect(projectMap.authFiles).toContain('app/api/items/route.ts');
  });

  it('maps express routes and raw SQL calls', async () => {
    const { projectMap } = await loadFixtureContext('express-cors-insecure');
    const route = projectMap.apiRoutes.find((candidate) => candidate.routePath === '/api/items/:id');
    expect(route?.framework).toBe('express');
    expect(route?.methods).toEqual(['DELETE']);
    expect(projectMap.databaseCalls.some((call) => call.kind === 'raw_sql')).toBe(true);
  });

  it('maps firebase usage', async () => {
    const { projectMap } = await loadFixtureContext('firebase-open-rules');
    expect(projectMap.firebaseUsage).toContain('src/db.js');
    expect(projectMap.databaseCalls.some((call) => call.client === 'firebase' && call.kind === 'write')).toBe(true);
  });
});
