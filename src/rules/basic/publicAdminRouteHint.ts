import { effectiveGuardsInFile } from '../../project-map/buildProjectMap.js';
import { isRouteProtectedByMiddleware } from '../../project-map/middlewareMatchers.js';
import { makeFinding } from '../../shared/findingFactory.js';
import type { ApiRoute, Finding, RuleContext, ScanRule } from '../../shared/types.js';
import { routeControlProven } from '../../shared/routeControlModel.js';
import { cascadingControlProven } from '../../shared/cascadingGuard.js';
import { resolvesToRoleCheck } from '../../shared/handlerGuardCall.js';
import { pythonRouteGuard } from '../../shared/pythonGuards.js';
import {
  fileRoutedHandlerText,
  hasStrongAdminAuthorization,
  hasStrongAdminAuthorizationInHandler,
  hasSuggestiveAdminGuard,
  hasSuggestiveAuthGuard,
  routeRegistrationAroundLine,
} from '../../shared/routeAuthorization.js';

const ADMIN_SEGMENT =
  /(?:\b|(?<=[A-Za-z0-9_$]))(?:[Aa]dministrators?|ADMINISTRATORS?|[Ss]uper[Aa]dmins?|SUPERADMINS?|[Ss]uper[Uu]sers?|SUPERUSERS?|[Aa]dmins?|ADMINS?|[Ii]nternal|INTERNAL|[Bb]ack[Oo]ffice|BACKOFFICE)(?![a-z])/;

function hasAdminSegment(routePath: string): boolean {
  return routePath.split('/').some((segment) => ADMIN_SEGMENT.test(segment));
}

const FILE_ROUTED = new Set(['nextjs_app', 'nextjs_pages', 'sveltekit']);

function nextRouteLine(context: RuleContext, route: ApiRoute): number | undefined {
  let next: number | undefined;
  for (const other of context.projectMap.apiRoutes) {
    if (other.filePath !== route.filePath || other.line <= route.line) continue;
    if (next === undefined || other.line < next) next = other.line;
  }
  return next;
}

function matchingProfile(context: RuleContext, route: ApiRoute) {
  return (context.projectMap.routeSecurityProfiles ?? []).find((profile) =>
    profile.filePath === route.filePath && profile.routePath === route.routePath &&
    route.methods.some((method) => profile.method === method || method === 'ANY'),
  );
}

export const publicAdminRouteHint: ScanRule = {
  id: 'public_admin_route_hint',
  title: 'Admin-looking route without a visible admin permission check',
  category: 'authentication',
  kind: 'basic',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const route of context.projectMap.apiRoutes) {
      if (!hasAdminSegment(route.routePath)) continue;
      const entry = context.fileMap.entries.find((candidate) => candidate.path === route.filePath);
      const registration = entry === undefined ? '' : routeRegistrationAroundLine(entry.content, route.line) ?? '';

      const fileRouted = FILE_ROUTED.has(route.framework);
      const nextLine = fileRouted ? nextRouteLine(context, route) : undefined;
      const proven = fileRouted
        ? hasStrongAdminAuthorizationInHandler(context, route.filePath, route.line, nextLine)
        : hasStrongAdminAuthorization(context, route.filePath, route.line, registration);
      if (proven) continue;
      const pythonGuard = pythonRouteGuard(context, route);
      if (pythonGuard?.level === 'admin') continue;
      if (routeControlProven(context, route.filePath, route.line, 'admin')) continue;
      if (cascadingControlProven(context, {
        filePath: route.filePath,
        routePath: route.routePath,
        line: route.line,
        framework: route.framework,
        ...(route.methods[0] !== undefined ? { method: route.methods[0] } : {}),
      }, 'admin')) continue;
      const handlerScope = fileRouted
        ? fileRoutedHandlerText(entry?.content ?? '', route.line, nextLine)
        : registration;
      if (resolvesToRoleCheck(context, route.filePath, handlerScope)) continue;

      const profile = matchingProfile(context, route);
      const profileAuth = profile?.authentication.status === 'present';
      const inFileAuth = effectiveGuardsInFile(context.projectMap, route.filePath).some((guard) =>
        fileRouted
          ? guard.line >= route.line && guard.line < (nextLine ?? route.line + 120)
          : Math.abs(guard.line - route.line) <= 80,
      );
      const routeAuthMiddleware = hasSuggestiveAuthGuard(registration);
      const suggestiveAdmin = hasSuggestiveAdminGuard(registration);
      const coveredByMiddleware = isRouteProtectedByMiddleware(context.projectMap, route.routePath);
      const cascadingAuth = cascadingControlProven(context, {
        filePath: route.filePath,
        routePath: route.routePath,
        line: route.line,
        framework: route.framework,
        ...(route.methods[0] !== undefined ? { method: route.methods[0] } : {}),
      }, 'auth');
      const hasSomeAuth =
        profileAuth || inFileAuth || routeAuthMiddleware || coveredByMiddleware || cascadingAuth || pythonGuard !== undefined;
      const authenticatedButNoRole = hasSomeAuth && !suggestiveAdmin;

      findings.push(
        makeFinding({
          ruleId: this.id,
          title: this.title,
          severity: hasSomeAuth ? 'medium' : 'high',
          confidence: hasSomeAuth || suggestiveAdmin ? 'low' : 'medium',
          detectionKind: 'absence',
          filePath: route.filePath,
          lineStart: route.line,
          evidence: suggestiveAdmin
            ? `Route "${route.routePath}" (${route.methods.join(', ')}) uses admin-named middleware, but no visible role check plus rejection path was proven`
            : authenticatedButNoRole
              ? `Route "${route.routePath}" (${route.methods.join(', ')}) authenticates the caller but has no visible admin role check, so any signed-in user reaches it`
              : `Route "${route.routePath}" (${route.methods.join(', ')}) has no visible admin role guard in its route handler chain`,
          userExplanation: suggestiveAdmin
            ? 'This route looks like an admin endpoint and has admin-name evidence, but the scanner could not prove a real admin role check on this exact route. Verify that only admins can reach it.'
            : authenticatedButNoRole
              ? 'This route checks that the caller is signed in, but nothing checks that they are an administrator. Any ordinary user with an account can reach an admin endpoint. Add a role check, not just a sign-in check.'
              : 'This route looks like an admin endpoint, but the scanner found no route-specific sign-in or admin permission check. If nothing else protects it, anyone who finds the URL can use it.',
          technicalExplanation: suggestiveAdmin
            ? `${route.filePath}:${route.line} defines an admin-like route. A name such as requireAdmin only counts as strong protection when its implementation visibly checks an admin role/claim and rejects failure; that proof was not visible for this route.`
            : authenticatedButNoRole
              ? `${route.filePath}:${route.line} authenticates on this route but no role/claim/permission check plus rejection path is visible in the handler. Authentication is not authorization: every authenticated principal is currently an administrator on "${route.routePath}".`
              : `${route.filePath}:${route.line} defines an admin-like route with no visible checked auth guard, admin middleware, or covering middleware matcher for "${route.routePath}".`,
          fixHint: authenticatedButNoRole
            ? 'Add an admin role/claim check beside the existing sign-in check on this route, and reject non-admin callers with 403 before any admin action.'
            : 'At the route boundary, authenticate the caller and verify an admin role/claim before performing any admin action. Prefer explicit route middleware whose implementation rejects non-admin callers.',
          category: this.category,
        }),
      );
    }
    return findings;
  },
};
