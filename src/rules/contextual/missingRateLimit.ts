import { isRouteCoveredByMiddleware } from '../../project-map/middlewareMatchers.js';
import { pythonRouteIsSensitive, pythonRouteRateLimited } from '../../shared/pythonRateLimit.js';
import { makeFinding } from '../../shared/findingFactory.js';
import type { ApiRoute, FileMapEntry, RuleContext, Finding, ScanRule } from '../../shared/types.js';
import { findMatches } from '../../shared/utils.js';
import { routeHandlerScopeForLine } from '../../shared/handlerScope.js';
import { resolvesToRateLimit } from '../../shared/handlerGuardCall.js';
import { routeControlProven } from '../../shared/routeControlModel.js';
import { cascadingControlProven, routeRole } from '../../shared/cascadingGuard.js';

const LIMITER_ENFORCE_CALL =
  /\benforce\w*[Ll]imit\w*\s*\(|\.\s*(?:consume|tryConsume|removeTokens|tryRemoveTokens)\s*\(/;

const SENSITIVE_ROUTE =
  /login|signin|sign-in|auth|password|reset|forgot|otp|verify|register|signup|sign-up|token|session|checkout|payment/i;

const LIMITER_FACTORY =
  /\brateLimit\s*\(|\bnew\s+RateLimiter\s*\(|\bslowDown\s*\(|\bexpressSlowDown\s*\(|\bnew\s+Ratelimit\s*\(|\bRatelimit\s*\(|\bnew\s+Bottleneck\s*\(|\brateLimiter\s*\(/;
const LIMITER_USE = /\.\s*limit\s*\(|\.\s*consume\s*\(|\.\s*check\s*\(\s*[^)]*limit/i;
const LIMITER_IMPORT =
  /from\s+['"](?:express-rate-limit|express-slow-down|@upstash\/ratelimit|rate-limiter-flexible|bottleneck|@nestjs\/throttler|hono\/rate-limiter|flask-limiter|django-ratelimit)['"]|require\(\s*['"](?:express-rate-limit|express-slow-down|@upstash\/ratelimit|rate-limiter-flexible|bottleneck)['"]/;

function limiterNamesIn(entry: FileMapEntry): Set<string> {
  const names = new Set<string>();
  for (const match of findMatches(
    entry.content,
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?(?:new\s+)?(?:rateLimit|RateLimiter|slowDown|expressSlowDown|Ratelimit|Bottleneck|rateLimiter)\b/g,
  )) {
    const name = match.groups[0];
    if (name !== undefined) names.add(name);
  }
  for (const match of findMatches(
    entry.content,
    /import\s+([A-Za-z_$][\w$]*)\s+from\s+['"](?:express-rate-limit|express-slow-down)['"]/g,
  )) {
    const name = match.groups[0];
    if (name !== undefined) names.add(name);
  }
  for (const match of findMatches(
    entry.content,
    /import\s+\{([^}]*)\}\s+from\s+['"][^'"]*(?:rate-?limit|limiter|throttle)[^'"]*['"]/gi,
  )) {
    for (const raw of (match.groups[0] ?? '').split(',')) {
      const name = raw.trim().split(/\s+as\s+/).pop()?.trim();
      if (name) names.add(name);
    }
  }
  return names;
}

function fileHasRouterLevelLimiter(entry: FileMapEntry, limiterNames: Set<string>): boolean {
  for (const match of findMatches(entry.content, /\.\s*use\s*\(([^)]*)\)/g)) {
    const args = match.groups[0] ?? '';
    if (LIMITER_FACTORY.test(args)) return true;
    if ([...limiterNames].some((name) => new RegExp(`\\b${escapeRegExp(name)}\\b`).test(args))) return true;
  }
  return false;
}

function routeStatementHasLimiter(entry: FileMapEntry, route: ApiRoute, limiterNames: Set<string>): boolean {
  const lines = entry.content.split('\n');
  const statement = lines.slice(route.line - 1, route.line + 2).join('\n');
  if (LIMITER_FACTORY.test(statement)) return true;
  return [...limiterNames].some((name) => new RegExp(`\\b${escapeRegExp(name)}\\b`).test(statement));
}

function limiterAdvice(framework: ApiRoute['framework']): { example: string; hint: string } {
  if (framework === 'nextjs_app' || framework === 'nextjs_pages') {
    return {
      example: 'e.g. @upstash/ratelimit in the route handler or middleware.ts',
      hint:
        'Rate-limit inside this route handler, or in middleware.ts with a matcher that covers it, keyed by IP or user, for example with @upstash/ratelimit. Use stricter limits for login, password reset and OTP.',
    };
  }
  if (framework === 'sveltekit') {
    return {
      example: 'e.g. @upstash/ratelimit or sveltekit-rate-limiter in hooks.server.ts or the endpoint',
      hint:
        'Rate-limit in hooks.server.ts (the handle hook) for this path, or at the top of the endpoint, keyed by IP or user, for example with @upstash/ratelimit or sveltekit-rate-limiter. Use stricter limits for login, password reset and OTP.',
    };
  }
  if (framework === 'fastapi') {
    return {
      example: 'e.g. slowapi, with a Limiter registered on the app and @limiter.limit("5/minute") on the endpoint',
      hint:
        'Attach a rate limiter directly to this endpoint (e.g. with slowapi: register a Limiter on the app, decorate the endpoint with @limiter.limit("5/minute"), and give it the request: Request parameter slowapi reads) or via middleware that covers it. Use stricter limits for login, password reset, and OTP.',
    };
  }
  if (framework === 'flask') {
    return {
      example: 'e.g. Flask-Limiter, with @limiter.limit("5 per minute") on the view',
      hint:
        'Attach a rate limiter directly to this route (e.g. with Flask-Limiter: decorate the view with @limiter.limit("5 per minute")) or via a limit that covers its blueprint or app. Use stricter limits for login, password reset, and OTP.',
    };
  }
  return {
    example: 'e.g. express-rate-limit, @upstash/ratelimit',
    hint:
      'Attach a rate limiter directly to this route (e.g. app.post("/login", loginLimiter, handler)) or via a router/middleware whose matcher covers it. Use stricter limits for login, password reset, and OTP.',
  };
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function handlerBodyEnforcesLimiter(entry: FileMapEntry, route: ApiRoute, limiterNames: Set<string>): boolean {
  const scope = routeHandlerScopeForLine(entry.content, route.line);
  if (LIMITER_ENFORCE_CALL.test(scope)) return true;
  return [...limiterNames].some((name) => new RegExp(`\\b${escapeRegExp(name)}\\b`).test(scope));
}

export const missingRateLimit: ScanRule = {
  id: 'missing_rate_limit',
  title: 'Sensitive route without rate limiting',
  category: 'rate_limiting',
  kind: 'contextual',
  run(context: RuleContext): Finding[] {
    const entriesByPath = new Map(context.fileMap.entries.map((entry) => [entry.path, entry]));

    const rateLimitingMiddleware = context.projectMap.middlewareFiles.filter((filePath) => {
      const entry = entriesByPath.get(filePath);
      return entry !== undefined && (LIMITER_FACTORY.test(entry.content) || LIMITER_USE.test(entry.content) || LIMITER_IMPORT.test(entry.content));
    });

    const findings: Finding[] = [];
    const seenFiles = new Set<string>();

    for (const route of context.projectMap.apiRoutes) {
      const python = route.filePath.endsWith('.py');
      const sensitivePath = python ? pythonRouteIsSensitive(route) : SENSITIVE_ROUTE.test(route.routePath);
      if (!sensitivePath && !SENSITIVE_ROUTE.test(route.filePath)) continue;
      if (seenFiles.has(route.filePath)) continue;
      if (routeRole({
        filePath: route.filePath,
        routePath: route.routePath,
        line: route.line,
        framework: route.framework,
        ...(route.methods[0] !== undefined ? { method: route.methods[0] } : {}),
      }) === 'load') continue;

      const entry = entriesByPath.get(route.filePath);
      if (entry === undefined) continue;
      const limiterNames = limiterNamesIn(entry);

      const protectedInFile =
        routeStatementHasLimiter(entry, route, limiterNames) ||
        fileHasRouterLevelLimiter(entry, limiterNames) ||
        handlerBodyEnforcesLimiter(entry, route, limiterNames) ||
        ((route.framework === 'nextjs_app' || route.framework === 'nextjs_pages') &&
          (LIMITER_USE.test(entry.content) || (LIMITER_IMPORT.test(entry.content) && LIMITER_FACTORY.test(entry.content))));
      const protectedInInvokedPath = (context.projectMap.routeSecurityProfiles ?? []).some(
        (profile) => profile.filePath === route.filePath && profile.line === route.line && profile.rateLimit.status === 'present',
      );

      const protectedByMiddleware =
        rateLimitingMiddleware.length > 0 &&
        isRouteCoveredByMiddleware(context.projectMap, route.routePath) &&
        context.projectMap.middlewareMatchers.some(
          (matcher) => rateLimitingMiddleware.includes(matcher.filePath) && safeMatch(matcher.pattern, route.routePath),
        ) ||
        (rateLimitingMiddleware.length > 0 && context.projectMap.middlewareMatchers.length === 0 &&
          isRouteCoveredByMiddleware(context.projectMap, route.routePath));

      const protectedByRoutingTree = routeControlProven(context, route.filePath, route.line, 'rateLimit');

      const protectedByHandlerHelper = resolvesToRateLimit(
        context, route.filePath, routeHandlerScopeForLine(entry.content, route.line));

      const protectedByCascade = cascadingControlProven(context, {
        filePath: route.filePath,
        routePath: route.routePath,
        line: route.line,
        framework: route.framework,
        ...(route.methods[0] !== undefined ? { method: route.methods[0] } : {}),
      }, 'rateLimit');

      if (protectedInFile || protectedInInvokedPath || protectedByMiddleware ||
        protectedByRoutingTree || protectedByHandlerHelper || protectedByCascade) continue;
      if (python && pythonRouteRateLimited(context, route)) continue;

      seenFiles.add(route.filePath);
      const advice = limiterAdvice(route.framework);
      findings.push(
        makeFinding({
          ruleId: this.id,
          title: this.title,
          severity: 'medium',
          confidence: 'low',
          detectionKind: 'absence',
          filePath: route.filePath,
          lineStart: route.line,
          evidence: `Sensitive route "${route.routePath}" (${route.methods.join(', ')}) has no rate limiter attached to it`,
          userExplanation:
            'This looks like a login, password-reset, OTP, or payment route, and no rate limiter is actually attached to it. A rate limiter elsewhere in the project (for example on a health-check route) does not protect this one. Without a limit, attackers can try many passwords or codes, or run up costs.',
          technicalExplanation:
            `${route.filePath} exposes a sensitive route ("${route.routePath}") with no limiter attached to the route, its router/app, its handler file, or covering middleware. Attach a per-IP/per-account limiter (${advice.example}) to this route specifically.`,
          fixHint: advice.hint,
          category: this.category,
        }),
      );
    }
    return findings;
  },
};

function safeMatch(pattern: string, routePath: string): boolean {
  try {
    return new RegExp(pattern).test(routePath);
  } catch {
    return false;
  }
}
