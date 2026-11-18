import { describe, expect, it } from 'vitest';
import {
  compileMatcherPattern,
  deriveFrontendRoute,
  isRouteCoveredByMiddleware,
  isRouteProtectedByMiddleware,
} from '../../src/project-map/middlewareMatchers.js';
import { memoryContext } from './helpers.js';

const MIDDLEWARE_DASHBOARD_ONLY =
  "import { NextResponse, type NextRequest } from 'next/server';\n" +
  'export function middleware(request: NextRequest) {\n' +
  "  const token = request.cookies.get('session');\n" +
  "  if (!token) return NextResponse.redirect(new URL('/login', request.url));\n" +
  '  return NextResponse.next();\n}\n' +
  "export const config = { matcher: ['/dashboard/:path*'] };\n";

describe('matcher compilation', () => {
  it.each([
    ['/dashboard/:path*', '/dashboard', true],
    ['/dashboard/:path*', '/dashboard/settings/profile', true],
    ['/dashboard/:path*', '/admin', false],
    ['/api/items/:id', '/api/items/42', true],
    ['/api/items/:id', '/api/items/42/extra', false],
    ['/about', '/about', true],
    ['/about', '/about/team', false],
  ])('pattern %s vs %s -> %s', (matcher, route, expected) => {
    expect(new RegExp(compileMatcherPattern(matcher)).test(route)).toBe(expected);
  });
});

describe('deriveFrontendRoute', () => {
  it('derives routes from app and pages files, ignoring route groups', () => {
    expect(deriveFrontendRoute('app/dashboard/page.tsx')).toBe('/dashboard');
    expect(deriveFrontendRoute('app/(marketing)/pricing/page.tsx')).toBe('/pricing');
    expect(deriveFrontendRoute('pages/settings.tsx')).toBe('/settings');
    expect(deriveFrontendRoute('pages/api/items.ts')).toBeUndefined();
  });
});

describe('middleware-to-route coverage', () => {
  const files: [string, string][] = [
    ['package.json', '{"name":"x","dependencies":{"next":"14.0.0"}}'],
    ['middleware.ts', MIDDLEWARE_DASHBOARD_ONLY],
    ['app/dashboard/page.tsx', 'export default function Dashboard() { return <main>hi</main>; }\n'],
    ['app/admin/page.tsx', 'export default function Admin() { return <main>admin</main>; }\n'],
  ];

  it('reports coverage per route, not per project', () => {
    const { projectMap } = memoryContext(files);
    expect(projectMap.middlewareMatchers).toHaveLength(1);
    expect(isRouteCoveredByMiddleware(projectMap, '/dashboard/anything')).toBe(true);
    expect(isRouteCoveredByMiddleware(projectMap, '/admin')).toBe(false);
  });

  it('middleware without an explicit matcher counts as covering everything', () => {
    const { projectMap } = memoryContext([
      ['package.json', '{"name":"x"}'],
      ['middleware.ts', 'export function middleware() { return undefined; }\n'],
    ]);
    expect(isRouteCoveredByMiddleware(projectMap, '/anything')).toBe(true);
  });
});

describe('middleware protection requires a genuine auth guard', () => {
  const LOGGING_ONLY_MIDDLEWARE =
    "import { NextResponse, type NextRequest } from 'next/server';\n" +
    'export function middleware(request: NextRequest) {\n' +
    '  console.log(request.method, request.url);\n' +
    '  return NextResponse.next();\n}\n' +
    "export const config = { matcher: ['/dashboard/:path*'] };\n";
  const DASHBOARD_PAGE: [string, string] = [
    'app/dashboard/page.tsx',
    'export default function Dashboard() { return <main>hi</main>; }\n',
  ];
  const PKG: [string, string] = ['package.json', '{"name":"x","dependencies":{"next":"14.0.0"}}'];

  it('logging-only middleware covering the route is NOT protection (unsafe case)', () => {
    const context = memoryContext([PKG, ['middleware.ts', LOGGING_ONLY_MIDDLEWARE], DASHBOARD_PAGE]);
    expect(isRouteCoveredByMiddleware(context.projectMap, '/dashboard')).toBe(true);
    expect(isRouteProtectedByMiddleware(context.projectMap, '/dashboard')).toBe(false);
  });

  it('auth middleware covering the route IS protection (safe case)', () => {
    const context = memoryContext([PKG, ['middleware.ts', MIDDLEWARE_DASHBOARD_ONLY], DASHBOARD_PAGE]);
    expect(isRouteProtectedByMiddleware(context.projectMap, '/dashboard')).toBe(true);
  });

  it('guardless middleware without a matcher does not protect anything', () => {
    const context = memoryContext([
      PKG,
      ['middleware.ts', 'export function middleware() { return undefined; }\n'],
      DASHBOARD_PAGE,
    ]);
    expect(isRouteProtectedByMiddleware(context.projectMap, '/dashboard')).toBe(false);
  });

  it('middleware that reads a cookie but never blocks is NOT protection (unsafe case)', () => {
    const cookiePassThrough =
      "import { NextResponse, type NextRequest } from 'next/server';\n" +
      'export function middleware(request: NextRequest) {\n' +
      "  const token = request.cookies.get('session');\n" +
      '  console.log(token);\n' +
      '  return NextResponse.next();\n}\n' +
      "export const config = { matcher: ['/dashboard/:path*'] };\n";
    const context = memoryContext([PKG, ['middleware.ts', cookiePassThrough], DASHBOARD_PAGE]);
    expect(isRouteProtectedByMiddleware(context.projectMap, '/dashboard')).toBe(false);
  });

  it('auth middleware without a matcher protects all routes', () => {
    const guardedNoMatcher =
      "import { NextResponse, type NextRequest } from 'next/server';\n" +
      'export function middleware(request: NextRequest) {\n' +
      "  const token = request.cookies.get('session');\n" +
      "  if (!token) return NextResponse.redirect(new URL('/login', request.url));\n" +
      '  return NextResponse.next();\n}\n';
    const context = memoryContext([PKG, ['middleware.ts', guardedNoMatcher], DASHBOARD_PAGE]);
    expect(isRouteProtectedByMiddleware(context.projectMap, '/dashboard')).toBe(true);
  });
});
