import { makeFinding } from '../../shared/findingFactory.js';
import { hasStack } from '../../stack-detection/detectStack.js';
import type { Finding, RuleContext, ScanRule } from '../../shared/types.js';
import { creditEvidence, creditScopedEntries } from '../../shared/creditScope.js';
import { COOKIE_SESSION_HINT } from '../../shared/cookieAuthentication.js';
import { routeMiddlewareAt } from '../../shared/routeControlModel.js';
import { stripCommentsOnly, usesHashComments } from '../../shared/source.js';
import { isPythonNonProductionSetting } from '../../shared/pythonSettings.js';

const CSRF_HINT = /csrf|csurf|xsrf|sameSite|double[_-]?submit|@edge-csrf|nextjs-csrf|origin\s*header|verifyOrigin/i;
const STATE_CHANGING = new Set(['POST', 'PUT', 'DELETE', 'PATCH']);

const PROJECT_WIDE_CSRF_DEFENCE = [
  /\b(?:app|server|expressApp)\s*\.\s*use\s*\(\s*(?!['"`])[^)]{0,200}(?:csrf|csurf|xsrf|lusca)/i,
  /sameSite\s*:\s*['"`](?:lax|strict)['"`]/i,
  /sameSite=(?:lax|strict)/i,
  /@edge-csrf|nextjs-csrf|edge-csrf|next-csrf/i,
];

const CSRF_MIDDLEWARE_TOKEN = /csrf|csurf|xsrf|lusca/i;

export const csrfProtection: ScanRule = {
  id: 'missing_csrf_protection',
  title: 'State-changing routes without CSRF protection',
  category: 'csrf',
  kind: 'contextual',
  run(context: RuleContext): Finding[] {
    return [...routeLevelFinding.call(this, context), ...pythonCsrfOptOuts.call(this, context)];
  },
};

function routeLevelFinding(this: ScanRule, context: RuleContext): Finding[] {
    const usesCookieSession = context.fileMap.entries.some((entry) =>
      COOKIE_SESSION_HINT.test(entry.content),
    );
    if (!usesCookieSession) return [];

    const credited = creditScopedEntries(context);
    const hasCsrfDefence = credited.some((entry) => CSRF_HINT.test(creditEvidence(entry)));

    if (!hasStack(context.stack, 'express') && !hasStack(context.stack, 'nextjs') &&
        !hasStack(context.stack, 'flask') && !hasStack(context.stack, 'fastapi')) {
      return [];
    }

    const csrfOnRoute = (route: { filePath: string; line: number }): boolean => {
      const applied = routeMiddlewareAt(context, route.filePath, route.line);
      return applied !== undefined && applied.some((token) => CSRF_MIDDLEWARE_TOKEN.test(token));
    };

    let perRoute = false;
    if (hasCsrfDefence) {
      const coversWholeProject = credited.some((entry) => {
        const code = stripCommentsOnly(creditEvidence(entry), usesHashComments(entry.extension, entry.label));
        return PROJECT_WIDE_CSRF_DEFENCE.some((pattern) => pattern.test(code));
      });
      if (coversWholeProject) return [];
      perRoute = context.projectMap.apiRoutes.some((route) => csrfOnRoute(route));
      if (!perRoute) return [];
    }

    const stateChangingRoute = context.projectMap.apiRoutes.find((route) => {
      if (!route.methods.some((method) => STATE_CHANGING.has(method) || method === 'ANY')) return false;
      if (!perRoute) return true;
      if (routeMiddlewareAt(context, route.filePath, route.line) === undefined) return false;
      return !csrfOnRoute(route);
    });
    if (stateChangingRoute === undefined) return [];

    return [
      makeFinding({
        ruleId: this.id,
        title: this.title,
        severity: 'medium',
        confidence: 'low',
        detectionKind: 'absence',
        filePath: stateChangingRoute.filePath,
        lineStart: stateChangingRoute.line,
        evidence: perRoute
          ? `Cookie-based session with state-changing route "${stateChangingRoute.routePath}" and no CSRF middleware applied on that path (the project has CSRF elsewhere, not here)`
          : `Cookie-based session with state-changing route "${stateChangingRoute.routePath}" and no CSRF token or SameSite defence found`,
        userExplanation: perRoute
          ? 'Your app has CSRF protection, but not on this route. Because browsers attach cookies automatically, any route that changes data and is left off the protected list can be triggered by another website on behalf of a logged-in user. Apply the same CSRF middleware here, or set SameSite on the session cookie so it covers everything.'
          : 'Your app keeps users logged in with cookies and has routes that change data, but the scan found no CSRF protection. Because browsers attach cookies automatically, another website can trick a logged-in user\'s browser into submitting actions. Add CSRF tokens or set SameSite on session cookies.',
        technicalExplanation: perRoute
          ? `The project uses cookie-based sessions and applies anti-CSRF middleware somewhere, but no csrf middleware is applied to "${stateChangingRoute.routePath}" - not at the route, not on its router, and not on any mount above it. Apply it there, or move to a project-wide defence (a pathless app.use of the csrf middleware, or SameSite=Lax/Strict session cookies).`
          : `The project uses cookie-based sessions and exposes state-changing routes (e.g. "${stateChangingRoute.routePath}") with no CSRF token middleware or SameSite cookie setting detected. Add anti-CSRF tokens (double-submit or synchroniser) and set session cookies to SameSite=Lax/Strict.`,
        fixHint:
          'Set session cookies to SameSite=Lax (or Strict), and on every POST/PUT/PATCH/DELETE check that the Origin header is your own site, rejecting the request otherwise. If you also want CSRF tokens, use a maintained library for your framework. Next.js server actions already compare Origin with Host, so add the check to API route handlers.',
        category: this.category,
      }),
    ];
}

const WTF_CSRF_OFF = /\bWTF_CSRF_ENABLED\b['"]?\s*\]?\s*[:=]\s*False\b/g;
const DJANGO_CSRF_EXEMPT = /^([ \t]*)@csrf_exempt\b/gm;
const SESSION_DECORATOR = /^\s*@(?:[\w.]+\.)?(?:login_required|permission_required|staff_member_required|user_passes_test)\b/;
const SESSION_IN_BODY = /\brequest\.(?:user|session)\b/;

function decoratedView(lines: string[], line: number): { decorators: string[]; body: string } | undefined {
  const indent = /^[ \t]*/.exec(lines[line] ?? '')?.[0].length ?? 0;
  const decorators: string[] = [];
  for (let k = line - 1; k >= 0 && /^\s*@/.test(lines[k] ?? ''); k -= 1) decorators.push(lines[k] ?? '');
  let i = line;
  while (i < lines.length && /^\s*@/.test(lines[i] ?? '')) {
    decorators.push(lines[i] ?? '');
    i += 1;
  }
  if (!/^\s*(?:async\s+)?def\s/.test(lines[i] ?? '')) return undefined;
  const body: string[] = [];
  for (let j = i + 1; j < lines.length; j += 1) {
    const text = lines[j] ?? '';
    if (text.trim() !== '' && (/^[ \t]*/.exec(text)?.[0].length ?? 0) <= indent) break;
    body.push(text);
  }
  return { decorators, body: body.join('\n') };
}

function pythonCsrfOptOuts(this: ScanRule, context: RuleContext): Finding[] {
  const findings: Finding[] = [];
  const report = (path: string, line: number, evidence: string, what: string, user: string, fix: string): void => {
    findings.push(
      makeFinding({
        ruleId: this.id,
        title: 'CSRF protection switched off',
        severity: 'medium',
        confidence: 'medium',
        filePath: path,
        lineStart: line,
        evidence,
        userExplanation: user,
        technicalExplanation: `${path}:${line}: ${what}`,
        fixHint: fix,
        category: this.category,
      }),
    );
  };
  for (const entry of context.fileMap.entries) {
    if (entry.extension !== '.py') continue;
    const code = stripCommentsOnly(entry.content, true);
    const lines = entry.content.split('\n');
    for (const match of code.matchAll(WTF_CSRF_OFF)) {
      if (isPythonNonProductionSetting(entry.path, code, match.index)) continue;
      const line = code.slice(0, match.index).split('\n').length;
      report(
        entry.path,
        line,
        (lines[line - 1] ?? '').trim(),
        'WTF_CSRF_ENABLED is False, so Flask-WTF checks no CSRF token on any form while the app signs users in with a cookie session.',
        'This setting turns off CSRF protection for the whole app. Because browsers attach the login cookie automatically, any website a signed-in user visits can submit your forms as them. Turn it back on outside tests.',
        'Remove WTF_CSRF_ENABLED = False (it defaults to True), or set it only in a testing configuration.',
      );
    }
    const codeLines = code.split('\n');
    for (const match of code.matchAll(DJANGO_CSRF_EXEMPT)) {
      const line = code.slice(0, match.index).split('\n').length;
      const view = decoratedView(codeLines, line - 1);
      if (view === undefined) continue;
      if (!view.decorators.some((decorator) => SESSION_DECORATOR.test(decorator)) && !SESSION_IN_BODY.test(view.body)) continue;
      report(
        entry.path,
        line,
        (lines[line - 1] ?? '').trim(),
        '@csrf_exempt removes Django\'s CSRF check from a view that authenticates by the session cookie (a sign-in decorator, or request.user / request.session in the view).',
        'This view is excluded from CSRF protection, yet it acts as the signed-in user. Because browsers attach the login cookie automatically, any website that user visits can make this request as them. Remove the exemption.',
        'Remove @csrf_exempt and send the CSRF token with the request (the csrftoken cookie in an X-CSRFToken header for fetch calls). Exempt only views no session authenticates, such as signed webhooks.',
      );
    }
  }
  return findings;
}
