import { describe, expect, it } from 'vitest';
import { apiMutationWithoutAuth } from '../../src/rules/contextual/apiMutationWithoutAuth.js';
import { missingRateLimit } from '../../src/rules/contextual/missingRateLimit.js';
import { missingWebhookVerification } from '../../src/rules/contextual/missingWebhookVerification.js';
import { publicAdminRouteHint } from '../../src/rules/basic/publicAdminRouteHint.js';
import { failOpenAuthentication } from '../../src/rules/contextual/failOpenAuthentication.js';
import { placeholderAuthentication } from '../../src/rules/contextual/placeholderAuthentication.js';
import { handlerGuardEffects } from '../../src/shared/handlerGuardCall.js';
import { memoryContext } from './helpers.js';

const NEXT = ['package.json', '{"dependencies":{"next":"14.2.0"}}'] as [string, string];

const ADMIN_PREDICATE =
  'export async function getAppUser(request) {\n' +
  "  const token = request.headers.get('cookie');\n" +
  '  return token ? await lookup(token) : null;\n' +
  '}\n' +
  'export async function isAdminRequest(request) {\n' +
  "  return (await getAppUser(request))?.role === 'admin';\n" +
  '}\n';

const ADMIN_LOGGER =
  'export async function isAdminRequest(request) {\n' +
  '  const user = await getAppUser(request);\n' +
  "  console.log('admin route touched by', user?.role);\n" +
  '  return user;\n' +
  '}\n';

const ADMIN_ROUTE = (guard: string): string =>
  'import { isAdminRequest } from "../../../lib/server";\n' +
  'export async function GET(request) {\n' +
  `${guard}` +
  '  return Response.json({ expenses: [] });\n' +
  '}\n';

const REJECTING_CALL_SITE =
  '  if (!(await isAdminRequest(request)))\n' +
  "    return Response.json({ error: 'Administrator access required.' }, { status: 401 });\n";

describe('C1 role check: a role predicate the handler rejects on', () => {
  it('is SILENT when the helper tests a role and the handler rejects on the answer', () => {
    const context = memoryContext([
      NEXT,
      ['app/lib/server.js', ADMIN_PREDICATE],
      ['app/api/admin/expenses/route.js', ADMIN_ROUTE(REJECTING_CALL_SITE)],
    ]);
    expect(publicAdminRouteHint.run(context)).toHaveLength(0);
  });

  it('STILL FIRES when the same-named helper only reads the identity and logs', () => {
    const context = memoryContext([
      NEXT,
      ['app/lib/server.js', ADMIN_LOGGER],
      ['app/api/admin/expenses/route.js', ADMIN_ROUTE(REJECTING_CALL_SITE)],
    ]);
    const findings = publicAdminRouteHint.run(context);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.filePath).toBe('app/api/admin/expenses/route.js');
  });

  it('STILL FIRES when the handler calls the real predicate and ignores the answer', () => {
    const context = memoryContext([
      NEXT,
      ['app/lib/server.js', ADMIN_PREDICATE],
      ['app/api/admin/expenses/route.js', ADMIN_ROUTE('  await isAdminRequest(request);\n')],
    ]);
    expect(publicAdminRouteHint.run(context)).toHaveLength(1);
  });

  it('STILL FIRES when the helper cannot be resolved (imported from a package)', () => {
    const context = memoryContext([
      NEXT,
      [
        'app/api/admin/expenses/route.js',
        'import { isAdminRequest } from "@acme/auth-kit";\n' +
        'export async function GET(request) {\n' + REJECTING_CALL_SITE +
        '  return Response.json({ expenses: [] });\n}\n',
      ],
    ]);
    expect(publicAdminRouteHint.run(context)).toHaveLength(1);
  });

  it('is SILENT for an ownership gate that returns a 403 object the handler returns', () => {
    const context = memoryContext([
      NEXT,
      [
        'app/lib/auth.js',
        'export function isPortalOwner(user) {\n' +
        "  return user?.id === 'initial-admin' && user.role === 'admin';\n}\n" +
        'export async function authorize(request, roles) {\n' +
        '  const user = await getAppUser(request);\n' +
        "  if (!user) return { response: Response.json({ error: 'sign in' }, { status: 401 }) };\n" +
        "  if (!roles.includes(user.role)) return { response: Response.json({ error: 'no' }, { status: 403 }) };\n" +
        '  return { user };\n}\n',
      ],
      [
        'app/api/admin/users/route.js',
        'import { authorize } from "../../../lib/auth";\n' +
        'export async function GET(request) {\n' +
        "  const auth = await authorize(request, ['admin']);\n" +
        "  if ('response' in auth) return auth.response;\n" +
        '  return Response.json({ users: [] });\n}\n',
      ],
    ]);
    expect(publicAdminRouteHint.run(context)).toHaveLength(0);
  });
});

const CLERK_THROWING_GUARD =
  'export class InternalAuthorizationError extends Error {}\n' +
  'export async function requireInternalAuth() {\n' +
  '  const { isAuthenticated, userId } = await auth();\n' +
  '  if (!isAuthenticated || !userId) {\n' +
  '    throw new InternalAuthorizationError();\n' +
  '  }\n' +
  '  return { clerkUserId: userId };\n' +
  '}\n';

const OPTIONAL_GUARD =
  'export async function requireInternalAuth() {\n' +
  '  const session = await auth();\n' +
  '  if (session) {\n' +
  '    return { clerkUserId: session.userId };\n' +
  '  }\n' +
  '  return { clerkUserId: null };\n' +
  '}\n';

const STUB_GUARD =
  'export async function requireInternalAuth() {\n' +
  '  // TODO: wire real auth\n' +
  "  return { clerkUserId: 'demo-user' };\n" +
  '}\n';

const CHECK_NOT_ON_THE_PATH =
  'export async function requireInternalAuth() {\n' +
  '  onRequest((session) => {\n' +
  '    if (!session) {\n' +
  '      throw new Error("Unauthorized");\n' +
  '    }\n' +
  '  });\n' +
  '  return { clerkUserId: null };\n' +
  '}\n';

const MUTATION_ROUTE =
  'import { requireInternalAuth } from "@/server/auth";\n' +
  'export async function PATCH(req) {\n' +
  '  try {\n' +
  '    await requireInternalAuth();\n' +
  '    await prisma.project.update({ where: { id: 1 }, data: { name: "x" } });\n' +
  '    return Response.json({ ok: true });\n' +
  '  } catch (err) {\n' +
  '    return Response.json({ error: "boom" }, { status: 500 });\n' +
  '  }\n' +
  '}\n';

function mutationContext(guardSource: string) {
  return memoryContext([
    NEXT,
    ['tsconfig.json', '{"compilerOptions":{"paths":{"@/*":["./src/*"]}}}'],
    ['src/server/auth.js', guardSource],
    ['src/app/api/projects/route.js', MUTATION_ROUTE],
  ]);
}

describe('C1 rejection: a guard the handler calls that throws on a missing identity', () => {
  it('is SILENT when the helper throws on a failed identity check', () => {
    expect(apiMutationWithoutAuth.run(mutationContext(CLERK_THROWING_GUARD))).toHaveLength(0);
  });

  it('STILL FIRES when the helper reads the session and never blocks (optionalAuth)', () => {
    expect(apiMutationWithoutAuth.run(mutationContext(OPTIONAL_GUARD))).toHaveLength(1);
  });

  it('STILL FIRES when the helper is a stub that always hands back an identity', () => {
    expect(apiMutationWithoutAuth.run(mutationContext(STUB_GUARD))).toHaveLength(1);
  });

  it('STILL FIRES when the check is not on the helper\'s own path', () => {
    expect(apiMutationWithoutAuth.run(mutationContext(CHECK_NOT_ON_THE_PATH))).toHaveLength(1);
  });

  it('refuses a ban filter — it rejects, but it establishes nobody', () => {
    const context = memoryContext([
      NEXT,
      [
        'src/lib/gate.js',
        'export function checkBanned(user) {\n' +
        '  if (user.isBanned) {\n' +
        '    throw new Error("banned");\n' +
        '  }\n' +
        '  return user;\n}\n',
      ],
    ]);
    const scope =
      'const u = await checkBanned(user);\nif (!u) return Response.json({}, { status: 401 });\n';
    expect(handlerGuardEffects(context, 'src/lib/gate.js', scope).rejection).toBe(false);
  });

  it('leaves fail_open_authentication firing on a guard whose catch resumes', () => {
    const context = memoryContext([
      NEXT,
      [
        'src/middleware/auth.ts',
        'export async function requireAuth(req, res, next) {\n' +
        '  try {\n' +
        '    const session = await getSession(req);\n' +
        '    if (!session) { res.status(401).json({ error: "no" }); return; }\n' +
        '    next();\n' +
        '  } catch (err) {\n' +
        '    next();\n' +
        '  }\n' +
        '}\n',
      ],
    ]);
    expect(failOpenAuthentication.run(context).length).toBeGreaterThan(0);
  });

  it('leaves placeholder_authentication firing on a stub, and gives it no C1 credit', () => {
    const context = memoryContext([
      ['package.json', '{"dependencies":{"express":"4.18.0"}}'],
      [
        'src/middleware/auth.js',
        'export function requireAuth(req, res, next) {\n' +
        '  // TODO: check permissions\n' +
        '  next();\n' +
        '}\n',
      ],
      [
        'src/server.js',
        "const express = require('express');\n" +
        "const { requireAuth } = require('./middleware/auth');\n" +
        'const app = express();\n' +
        "app.post('/api/items', requireAuth, (req, res) => res.json({ ok: true }));\n",
      ],
    ]);
    expect(placeholderAuthentication.run(context).length).toBeGreaterThan(0);
    const scope = "app.post('/api/items', requireAuth, (req, res) => res.json({ ok: true }));";
    const effects = handlerGuardEffects(context, 'src/server.js', scope);
    expect(effects).toEqual({ role: false, rejection: false, signature: false, rateLimit: false });
  });
});

const HANDROLLED_LIMITER =
  'const store = new Map();\n' +
  'const RATE_LIMIT_CONFIG = { answer: { limit: 10, windowMs: 600000 } };\n' +
  'export class PublicRateLimitError extends Error { }\n' +
  'export function assertPublicMutationRateLimit(input) {\n' +
  '  const { action, ip } = input;\n' +
  '  const config = RATE_LIMIT_CONFIG[action];\n' +
  '  const now = Date.now();\n' +
  '  const current = store.get(`${action}:${ip}`);\n' +
  '  if (!current || current.resetAt <= now) {\n' +
  '    store.set(`${action}:${ip}`, { count: 1, resetAt: now + config.windowMs });\n' +
  '    return;\n' +
  '  }\n' +
  '  if (current.count >= config.limit) {\n' +
  '    throw new PublicRateLimitError(1);\n' +
  '  }\n' +
  '  current.count += 1;\n' +
  '}\n';

const SIZE_LIMIT =
  'export function assertPublicMutationRateLimit(input) {\n' +
  '  if (input.items.count >= input.config.limit) {\n' +
  '    throw new Error("too many items");\n' +
  '  }\n' +
  '}\n';

const LIMITED_ROUTE =
  'import { assertPublicMutationRateLimit } from "@/server/limit";\n' +
  'export async function POST(req) {\n' +
  '  assertPublicMutationRateLimit({ action: "answer", ip: "1.2.3.4" });\n' +
  '  return Response.json({ ok: true });\n' +
  '}\n';

function limiterContext(source: string) {
  return memoryContext([
    NEXT,
    ['tsconfig.json', '{"compilerOptions":{"paths":{"@/*":["./src/*"]}}}'],
    ['src/server/limit.js', source],
    ['src/app/api/auth/login/route.js', LIMITED_ROUTE],
  ]);
}

describe('C1 rate limit: a limiter the handler calls', () => {
  it('is SILENT when the helper counts over a window and rejects the excess', () => {
    expect(missingRateLimit.run(limiterContext(HANDROLLED_LIMITER))).toHaveLength(0);
  });

  it('STILL FIRES when the helper caps a quantity with no window — that is not a rate limit', () => {
    expect(missingRateLimit.run(limiterContext(SIZE_LIMIT))).toHaveLength(1);
  });
});

const SVIX_VERIFIER =
  'async function verifySvixSignature(request, body, secret) {\n' +
  "  const svixId = request.headers.get('svix-id');\n" +
  "  const svixSignature = request.headers.get('svix-signature');\n" +
  '  if (!svixId || !svixSignature) {\n' +
  "    return { ok: false, status: 401, error: 'Missing svix headers' };\n" +
  '  }\n' +
  "  const key = await crypto.subtle.importKey('raw', secret, { name: 'HMAC' }, false, ['sign']);\n" +
  "  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body));\n" +
  '  if (constantTimeEqual(svixSignature, toBase64(mac))) {\n' +
  '    return { ok: true };\n' +
  '  }\n' +
  "  return { ok: false, status: 401, error: 'Invalid signature' };\n" +
  '}\n';

const IDENTITY_ONLY =
  'async function verifySvixSignature(request) {\n' +
  "  const key = request.headers.get('x-api-key');\n" +
  '  if (!key) {\n' +
  "    return { ok: false, status: 401, error: 'no key' };\n" +
  '  }\n' +
  '  return { ok: true };\n' +
  '}\n';

function webhookContext(verifier: string) {
  return memoryContext([
    NEXT,
    [
      'src/app/api/webhooks/resend/route.js',
      verifier +
      'export async function POST(request) {\n' +
      '  const body = await request.text();\n' +
      '  const verification = await verifySvixSignature(request, body, process.env.SECRET);\n' +
      '  if (!verification.ok) {\n' +
      '    return Response.json({ error: verification.error }, { status: verification.status });\n' +
      '  }\n' +
      '  const event = JSON.parse(body);\n' +
      '  await db.suppression.create({ data: { email: event.data.to } });\n' +
      '  return Response.json({ success: true });\n' +
      '}\n',
    ],
  ]);
}

describe('C1 signature: a webhook verifier the handler calls', () => {
  it('is SILENT when the helper computes a MAC and hands back a refusal the handler returns', () => {
    expect(missingWebhookVerification.run(webhookContext(SVIX_VERIFIER))).toHaveLength(0);
  });

  it('STILL FIRES when the helper checks an identity rather than a signature', () => {
    expect(missingWebhookVerification.run(webhookContext(IDENTITY_ONLY)).length).toBeGreaterThan(0);
  });
});
