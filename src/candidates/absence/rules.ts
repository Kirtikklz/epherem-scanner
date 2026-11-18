import type { AbsenceRoute } from './routeModel.js';
import { MUTATION_METHODS } from './routeModel.js';
import type { DbOp } from './dbDetect.js';
import { isAuthFlowRoute, isCatchAllRoute, isWebhookOrCronRoute } from './routeExemptions.js';
import { isFrameworkHandledBodyRoute, readsRequestBody, spanText, validatesInHandler } from './handlerEvidence.js';
import { manualControlWithoutDangerousSink, type ResolutionContext } from '../../shared/requestBodyControl.js';
import { projectUsesMongo } from '../../shared/dataStores.js';

export interface AbsenceHitRoute {
  method: string;
  relPath: string;
  line: number;
  endLine: number;
  spanResolved: boolean;
}

export interface AbsenceHit {
  filePath: string;
  line: number;
  ruleTag: string;
  sinkKind: string;
  observation: string;
  evidence: string;
  route?: AbsenceHitRoute;
}

function routeOf(r: AbsenceRoute): AbsenceHitRoute {
  return { method: r.method, relPath: r.relPath, line: r.line, endLine: r.endLine, spanResolved: r.spanResolved };
}

export interface AbsenceFacts {
  routes: AbsenceRoute[];
  dbOpsByFile: Map<string, DbOp[]>;
  hasHelmet: boolean;
  hasRateLimitDep: boolean;
  hasCsrfDep: boolean;
  usesCookieOrSession: boolean;
  entryFile: string | undefined;
  resolution?: ResolutionContext;
}

const VALIDATOR = /valid|schema|zod|joi|yup|celebrate|checkschema|sanitiz/i;
const RATE_LIMITER = /limit|throttle|slowdown|ratelimit|brute/i;
const SENSITIVE_PATH = /login|log-in|signin|sign-in|register|signup|sign-up|password|reset|token|auth|otp|verify/i;
const ADMIN_PATH = /(^|\/)admin(\/|$)|(^|\/)administrator(\/|$)|(^|\/)superuser(\/|$)/i;
const WEBHOOK_PATH = /webhook|callback\/(stripe|paypal|polar|svix)|\/(stripe|polar|svix)\/?/i;
const WEBHOOK_VERIFY = /verifyWebhook|constructEvent|svix|verifySignature|webhookSignature|verifyHmac|Webhook\s*\(/i;

const BODY_METHODS = new Set(['POST', 'PUT', 'PATCH']);

export function apiMutationWithoutAuth(facts: AbsenceFacts): AbsenceHit[] {
  const hits: AbsenceHit[] = [];
  for (const r of facts.routes) {
    if (!MUTATION_METHODS.has(r.method)) continue;
    if (r.protectedByAuth) continue;
    if (isAuthFlowRoute(r) || isWebhookOrCronRoute(r) || isCatchAllRoute(r)) continue;
    hits.push({
      filePath: r.filePath,
      line: r.line,
      ruleTag: 'api-mutation-without-auth',
      sinkKind: 'absence_auth',
      observation: `${r.method} ${r.fullPath} has no resolved authentication middleware (mutation endpoint reachable without a proven auth guard)`,
      evidence: `${r.method} ${r.fullPath}`,
      route: routeOf(r),
    });
  }
  return hits;
}

export function deleteWithoutOwnership(facts: AbsenceFacts): AbsenceHit[] {
  const hits: AbsenceHit[] = [];
  for (const r of facts.routes) {
    if (r.method !== 'DELETE' && r.method !== 'PUT' && r.method !== 'PATCH') continue;
    if (r.protectedByAuth) continue;
    const ops = facts.dbOpsByFile.get(r.filePath) ?? [];
    const mut = ops.find((o) => o.kind === 'mutation');
    if (mut === undefined) continue;
    hits.push({
      filePath: r.filePath,
      line: r.line,
      ruleTag: 'delete-without-ownership-check',
      sinkKind: 'absence_ownership',
      observation: `${r.method} ${r.fullPath} performs a ${mut.store} mutation (${mut.evidence}) with no proven auth/ownership scoping`,
      evidence: `${r.method} ${r.fullPath} -> ${mut.evidence}`,
      route: routeOf(r),
    });
  }
  return hits;
}

export function missingBodyValidation(facts: AbsenceFacts, contentOf: (p: string) => string | undefined): AbsenceHit[] {
  const hits: AbsenceHit[] = [];
  for (const r of facts.routes) {
    if (!BODY_METHODS.has(r.method)) continue;
    if (r.middlewares.some((m) => VALIDATOR.test(m))) continue;
    if (isCatchAllRoute(r)) continue;
    const handlerContent = r.handler !== undefined ? contentOf(r.handler.filePath) : undefined;
    const handlerText =
      r.handler !== undefined && handlerContent !== undefined
        ? spanText(handlerContent, r.handler.line, r.handler.endLine)
        : undefined;
    if (isFrameworkHandledBodyRoute(r, handlerText)) continue;
    if (handlerText !== undefined) {
      if (!readsRequestBody(handlerText)) continue;
      if (validatesInHandler(handlerText)) continue;
      if (facts.resolution !== undefined) {
        const control = manualControlWithoutDangerousSink(
          handlerText,
          { mongo: projectUsesMongo(facts.resolution) },
          { resolution: facts.resolution, filePath: r.handler?.filePath ?? r.filePath },
        );
        if (control.suppress) continue;
      }
    }
    hits.push({
      filePath: r.filePath,
      line: r.line,
      ruleTag: 'missing-request-body-validation',
      sinkKind: 'absence_validation',
      observation: `${r.method} ${r.fullPath} accepts a request body with no validator middleware applied`,
      evidence: `${r.method} ${r.fullPath}`,
      route: routeOf(r),
    });
  }
  return hits;
}

export function missingRateLimit(facts: AbsenceFacts): AbsenceHit[] {
  const hits: AbsenceHit[] = [];
  for (const r of facts.routes) {
    const sensitive = SENSITIVE_PATH.test(r.fullPath) || MUTATION_METHODS.has(r.method);
    if (!sensitive) continue;
    if (r.middlewares.some((m) => RATE_LIMITER.test(m))) continue;
    hits.push({
      filePath: r.filePath,
      line: r.line,
      ruleTag: 'missing-rate-limit',
      sinkKind: 'absence_rate_limit',
      observation: `${r.method} ${r.fullPath} has no rate limiter applied (sensitive or state-changing route)`,
      evidence: `${r.method} ${r.fullPath}`,
      route: routeOf(r),
    });
  }
  return hits;
}

export function publicAdminRoute(facts: AbsenceFacts): AbsenceHit[] {
  const hits: AbsenceHit[] = [];
  for (const r of facts.routes) {
    if (!ADMIN_PATH.test(r.fullPath)) continue;
    if (r.protectedByAuth) continue;
    hits.push({
      filePath: r.filePath,
      line: r.line,
      ruleTag: 'public-admin-route-hint',
      sinkKind: 'absence_admin',
      observation: `${r.method} ${r.fullPath} is an admin-shaped route with no resolved auth middleware`,
      evidence: `${r.method} ${r.fullPath}`,
      route: routeOf(r),
    });
  }
  return hits;
}

export function missingWebhookVerification(facts: AbsenceFacts, contentOf: (p: string) => string | undefined): AbsenceHit[] {
  const hits: AbsenceHit[] = [];
  for (const r of facts.routes) {
    if (!WEBHOOK_PATH.test(r.fullPath)) continue;
    const content = contentOf(r.filePath) ?? '';
    if (WEBHOOK_VERIFY.test(content)) continue;
    hits.push({
      filePath: r.filePath,
      line: r.line,
      ruleTag: 'missing-webhook-verification',
      sinkKind: 'absence_webhook',
      observation: `${r.method} ${r.fullPath} looks like a webhook endpoint with no signature verification in its file`,
      evidence: `${r.method} ${r.fullPath}`,
      route: routeOf(r),
    });
  }
  return hits;
}

export function missingSecurityHeaders(facts: AbsenceFacts): AbsenceHit[] {
  if (facts.hasHelmet) return [];
  if (facts.routes.length === 0) return [];
  const file = facts.entryFile ?? facts.routes[0]?.filePath;
  if (file === undefined) return [];
  return [
    {
      filePath: file,
      line: 1,
      ruleTag: 'missing-security-headers',
      sinkKind: 'absence_headers',
      observation: 'No helmet / security-header middleware detected for an app that serves routes',
      evidence: 'no helmet',
    },
  ];
}

export function runAbsenceRules(
  facts: AbsenceFacts,
  contentOf: (p: string) => string | undefined,
): AbsenceHit[] {
  return [
    ...apiMutationWithoutAuth(facts),
    ...deleteWithoutOwnership(facts),
    ...missingBodyValidation(facts, contentOf),
    ...missingRateLimit(facts),
    ...publicAdminRoute(facts),
    ...missingWebhookVerification(facts, contentOf),
    ...missingSecurityHeaders(facts),
  ];
}
