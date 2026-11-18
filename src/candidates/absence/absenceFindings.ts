import { isScannablePath } from '../../rules/index.js';
import { RULE_CATALOG, type CatalogRuleId } from '../../rules/ruleCatalog.js';
import { ruleMetadata } from '../../rules/ruleRegistry.js';
import { makeFinding } from '../../shared/findingFactory.js';
import type {
  FileMap,
  Finding,
  FindingCategory,
  ProjectMap,
  RuleFailure,
  Severity,
} from '../../shared/types.js';
import { runAbsencePass, type AbsenceHit, type AbsenceRoute } from './index.js';

export type AbsenceRuleTag =
  | 'api-mutation-without-auth'
  | 'delete-without-ownership-check'
  | 'missing-request-body-validation'
  | 'missing-rate-limit'
  | 'public-admin-route-hint'
  | 'missing-webhook-verification'
  | 'missing-security-headers';

export const ENABLED_ABSENCE_TAGS: ReadonlySet<string> = new Set<string>(['api-mutation-without-auth', 'missing-request-body-validation']);

export interface AbsenceRuleSpec {
  ruleId: CatalogRuleId;
  title: string;
  category: FindingCategory;
  userExplanation: string;
  technicalExplanation: (hit: AbsenceHit) => string;
  fixHint: string;
}

export const ABSENCE_RULES: Readonly<Record<AbsenceRuleTag, AbsenceRuleSpec>> = {
  'api-mutation-without-auth': {
    ruleId: 'api_mutation_without_auth',
    title: 'Mutation endpoint reachable without a resolved authentication guard',
    category: 'authentication',
    userExplanation:
      'This endpoint accepts a request that changes something (POST, PUT, PATCH or DELETE), and the scanner could not find an authentication check applied to it. If that is right, anyone on the internet can call it.',
    technicalExplanation: (hit) =>
      hit.route?.spanResolved === false
        ? `${hit.observation}. The route model could not read this route's registration call, so no middleware applied at the route, router or mount level was resolved — nothing was searched and nothing was ruled out. This finding rests on the absence of a reading, not on the absence of a guard: the route may well be protected. Read the registration yourself before changing anything.`
        : `${hit.observation}. The route model resolved every middleware applied at the route, router and mount level and none resolved to a recognised auth guard. The check may live somewhere static analysis cannot follow (a gateway, a wrapper, a framework default); verify before changing anything.`,
    fixHint:
      'Apply an authentication middleware to the route (or to the router it is mounted on), reject unauthenticated requests with 401, and only then run the handler.',
  },
  'delete-without-ownership-check': {
    ruleId: 'database_delete_without_ownership_check',
    title: 'Mutation endpoint performs a data-store write with no ownership scoping',
    category: 'authorization',
    userExplanation:
      'This endpoint changes or deletes stored data, and the scanner could not see it check that the caller owns the record it touches. If that is right, one user may be able to change another user\'s data.',
    technicalExplanation: (hit) =>
      `${hit.observation}. The handler file performs a data-store mutation and the route carries no resolved auth guard, so nothing in the visible call path scopes the write to the caller.`,
    fixHint:
      'Resolve the caller\'s identity first, then include it in the mutation\'s WHERE clause (or equivalent filter) so the write only affects records that caller owns.',
  },
  'missing-request-body-validation': {
    ruleId: 'missing_request_body_validation',
    title: 'Endpoint accepts a request body with no visible schema validation',
    category: 'injection',
    userExplanation:
      'This endpoint reads data the caller sends in the request body, and the scanner could not find a schema or validator checking it first. Unvalidated input is how malformed and malicious data reaches your code.',
    technicalExplanation: (hit) =>
      hit.route?.spanResolved === false
        ? `${hit.observation}. The route model could not read this route's registration call, so neither the middleware applied at the route, router or mount level nor the handler was resolved — nothing was searched and nothing was ruled out. This finding rests on the absence of a reading, not on the absence of a validator: the body may well be validated. Read the registration yourself before changing anything.`
        : `${hit.observation}. No middleware applied to the route matched a validator, schema or sanitiser name.`,
    fixHint:
      'Validate the body against an explicit schema (zod, joi, yup, celebrate, express-validator) before the handler runs, and reject anything that does not match.',
  },
  'missing-rate-limit': {
    ruleId: 'missing_rate_limit',
    title: 'Sensitive endpoint has no visible rate limiting',
    category: 'rate_limiting',
    userExplanation:
      'This endpoint handles something attackers try repeatedly (sign-in, password reset, tokens, verification codes), and the scanner could not find a rate limiter applied to it.',
    technicalExplanation: (hit) =>
      hit.route?.spanResolved === false
        ? `${hit.observation}. The route model could not read this route's registration call, so no middleware applied at the route, router or mount level was resolved — nothing was searched and nothing was ruled out. This finding rests on the absence of a reading, not on the absence of a rate limiter: the route may well be rate-limited. Read the registration yourself before changing anything.`
        : `${hit.observation}. No middleware applied to the route matched a rate-limiter or throttle name.`,
    fixHint:
      'Apply a rate limiter (express-rate-limit, @upstash/ratelimit or your gateway\'s equivalent) to the route, keyed on client identity, with a limit sized for legitimate use.',
  },
  'public-admin-route-hint': {
    ruleId: 'public_admin_route_hint',
    title: 'Admin-looking route without a resolved authentication guard',
    category: 'authentication',
    userExplanation:
      'This route\'s path suggests an administrative function, and the scanner could not find an authentication check applied to it.',
    technicalExplanation: (hit) =>
      hit.route?.spanResolved === false
        ? `${hit.observation}. The path matched an admin naming convention, but the route model could not read this route's registration call, so no middleware applied at the route, router or mount level was resolved — nothing was searched and nothing was ruled out. This finding rests on the absence of a reading, not on the absence of an auth guard: the route may well be protected. Read the registration yourself before changing anything.`
        : `${hit.observation}. The path matched an admin naming convention and no applied middleware resolved to a recognised auth guard.`,
    fixHint:
      'Require an authenticated session AND an admin role check on every admin route, at the router level so a new route cannot be added without it.',
  },
  'missing-webhook-verification': {
    ruleId: 'missing_webhook_verification',
    title: 'Webhook endpoint with no visible signature verification',
    category: 'webhooks',
    userExplanation:
      'This endpoint looks like it receives webhooks from another service, and the scanner could not find it verifying the sender\'s signature. Without that, anyone can send it a fake event.',
    technicalExplanation: (hit) =>
      `${hit.observation}. The handler file contains no recognised signature-verification call.`,
    fixHint:
      'Verify the provider\'s signature over the RAW request body (e.g. stripe.webhooks.constructEvent, svix) before acting on the event, and reject on mismatch.',
  },
  'missing-security-headers': {
    ruleId: 'missing_security_headers',
    title: 'Server entry point configures no security headers',
    category: 'headers',
    userExplanation:
      'The application\'s server entry point does not appear to set the standard security headers that protect users against common browser-side attacks.',
    technicalExplanation: (hit) =>
      `${hit.observation}. Neither helmet nor an equivalent header-setting middleware was found in the project.`,
    fixHint:
      'Add helmet (or set Content-Security-Policy, X-Content-Type-Options, X-Frame-Options and Strict-Transport-Security explicitly) at the top of the middleware chain.',
  },
};

function assertEveryRuleIdIsCatalogued(): void {
  for (const tag of Object.keys(ABSENCE_RULES) as AbsenceRuleTag[]) {
    const ruleId = ABSENCE_RULES[tag].ruleId;
    if (!(ruleId in RULE_CATALOG)) {
      throw new Error(`absence tag ${tag} maps to ${ruleId}, which is not in RULE_CATALOG`);
    }
  }
}
assertEveryRuleIdIsCatalogued();

function severityFor(ruleId: CatalogRuleId): Severity {
  const metadata = ruleMetadata(ruleId);
  if (metadata === undefined) {
    throw new Error(`no registry entry for ${ruleId}`);
  }
  return metadata.defaultSeverity;
}

export interface AbsenceFindingsInput {
  fileMap: FileMap;
  projectMap: ProjectMap;
  enabledTags: ReadonlySet<string>;
  codeFindings: readonly Finding[];
  routes?: readonly AbsenceRoute[];
}

export interface AbsenceFindingsResult {
  findings: Finding[];
  failures: RuleFailure[];
}

const KEY_SEPARATOR = '\u0000';

function lineKey(ruleId: string, filePath: string, line: number): string {
  return `${ruleId}${KEY_SEPARATOR}${filePath}${KEY_SEPARATOR}${line}`;
}

function routeKey(ruleId: string, filePath: string, method: string, relPath: string): string {
  const path = relPath.trim().replace(/\/+$/, '') || '/';
  return `${ruleId}${KEY_SEPARATOR}${filePath}${KEY_SEPARATOR}${method.toUpperCase()}${KEY_SEPARATOR}${path}`;
}

function publicKeys(codeFindings: readonly Finding[], routes: readonly AbsenceRoute[]): Set<string> {
  const keys = new Set<string>();
  const routesByFile = new Map<string, AbsenceRoute[]>();
  const routesByHandlerFile = new Map<string, AbsenceRoute[]>();
  for (const route of routes) {
    const list = routesByFile.get(route.filePath) ?? [];
    list.push(route);
    routesByFile.set(route.filePath, list);
    if (route.handler !== undefined && route.handler.kind === 'named') {
      const byHandler = routesByHandlerFile.get(route.handler.filePath) ?? [];
      byHandler.push(route);
      routesByHandlerFile.set(route.handler.filePath, byHandler);
    }
  }
  for (const finding of codeFindings) {
    keys.add(lineKey(finding.ruleId, finding.filePath, finding.lineStart));
    for (const route of routesByFile.get(finding.filePath) ?? []) {
      if (finding.lineStart >= route.line && finding.lineStart <= route.endLine) {
        keys.add(routeKey(finding.ruleId, finding.filePath, route.method, route.relPath));
      }
    }
    for (const route of routesByHandlerFile.get(finding.filePath) ?? []) {
      const handler = route.handler;
      if (handler !== undefined && finding.lineStart >= handler.line && finding.lineStart <= handler.endLine) {
        keys.add(routeKey(finding.ruleId, route.filePath, route.method, route.relPath));
      }
    }
  }
  return keys;
}

function isAlreadyReported(reported: ReadonlySet<string>, ruleId: string, hit: AbsenceHit): boolean {
  if (reported.has(lineKey(ruleId, hit.filePath, hit.line))) return true;
  return hit.route !== undefined && reported.has(routeKey(ruleId, hit.filePath, hit.route.method, hit.route.relPath));
}

function isAbsenceRuleTag(tag: string): tag is AbsenceRuleTag {
  return Object.prototype.hasOwnProperty.call(ABSENCE_RULES, tag);
}

export function absenceFindings(input: AbsenceFindingsInput): AbsenceFindingsResult {
  const enabled = [...input.enabledTags].filter(isAbsenceRuleTag).sort();
  if (enabled.length === 0) return { findings: [], failures: [] };

  const contentIndex = new Map(input.fileMap.entries.map((entry) => [entry.path, entry.content]));
  let hits: AbsenceHit[];
  let routes: AbsenceRoute[];
  try {
    ({ hits, routes } = runAbsencePass(input.fileMap, input.projectMap, (path) => contentIndex.get(path), input.routes));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const ruleIds = [...new Set(enabled.map((tag) => ABSENCE_RULES[tag].ruleId))];
    return {
      findings: [],
      failures: ruleIds.map((ruleId) => ({ ruleId, message: `absence pass failed: ${message}` })),
    };
  }

  const reported = publicKeys(input.codeFindings, routes);
  const enabledSet = new Set<string>(enabled);
  const prefix = input.projectMap.scannerRootPrefix;
  const findings: Finding[] = [];

  for (const hit of hits) {
    if (!enabledSet.has(hit.ruleTag) || !isAbsenceRuleTag(hit.ruleTag)) continue;
    if (!isScannablePath(hit.filePath, prefix)) continue;
    const spec = ABSENCE_RULES[hit.ruleTag];
    if (isAlreadyReported(reported, spec.ruleId, hit)) continue;
    findings.push(
      makeFinding({
        ruleId: spec.ruleId,
        title: spec.title,
        severity: severityFor(spec.ruleId),
        confidence: 'low',
        detectionKind: 'absence',
        filePath: hit.filePath,
        lineStart: hit.line,
        evidence: hit.evidence,
        userExplanation: spec.userExplanation,
        technicalExplanation: spec.technicalExplanation(hit),
        fixHint: spec.fixHint,
        category: spec.category,
      }),
    );
  }

  return { findings, failures: [] };
}
