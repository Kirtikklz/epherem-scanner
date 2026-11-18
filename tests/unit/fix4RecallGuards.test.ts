import { describe, expect, it } from 'vitest';
import { commandInjection } from '../../src/rules/basic/commandInjection.js';
import { supabaseServiceRoleExposed } from '../../src/rules/basic/supabaseServiceRoleExposed.js';
import { hardcodedSecret } from '../../src/rules/basic/hardcodedSecret.js';
import { unsafeFileUpload } from '../../src/rules/basic/unsafeFileUpload.js';
import { failOpenAuthentication } from '../../src/rules/contextual/failOpenAuthentication.js';
import { sensitiveDataInLogs } from '../../src/rules/basic/sensitiveDataInLogs.js';
import { memoryContext } from './helpers.js';

const PKG: [string, string] = ['package.json', '{"name":"fix4"}'];

describe('fix4 / command_injection: the shell sink survives the RegExp narrowing', () => {
  it('STILL FIRES: an imported child_process exec built from request input', () => {
    const ctx = memoryContext([PKG, ['server/convert.js',
      'import { exec } from "child_process";\n' +
      'export function h(req){ exec(`convert ${req.query.file} out.png`); }\n']]);
    const findings = commandInjection.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('critical');
  });

  it('STILL FIRES: a namespaced child_process member call', () => {
    const ctx = memoryContext([PKG, ['server/run.js',
      'import cp from "node:child_process";\n' +
      'export function h(req){ cp.execSync("git checkout " + req.body.branch); }\n']]);
    expect(commandInjection.run(ctx).length).toBeGreaterThanOrEqual(1);
  });

  it('STILL FIRES: an inline require of child_process', () => {
    const ctx = memoryContext([PKG, ['server/run.js',
      'export function h(req){ require("child_process").exec(`ls ${req.query.dir}`); }\n']]);
    expect(commandInjection.run(ctx).length).toBeGreaterThanOrEqual(1);
  });

  it('STILL FIRES: a bare exec whose argument is a tainted VARIABLE (AST arm only)', () => {
    const ctx = memoryContext([PKG, ['server/run.js',
      'import { exec } from "child_process";\n' +
      'export function h(req){ const cmd = "ls " + req.query.dir; exec(cmd); }\n']]);
    expect(commandInjection.run(ctx).length).toBeGreaterThanOrEqual(1);
  });

  it('GOES SILENT: a regex literal .exec on request input', () => {
    const ctx = memoryContext([PKG, ['server/parse.js',
      'export function h(req){ const m = /^(\\d{4})-(\\d{2})-(\\d{2})$/.exec(req.query.date); return m; }\n']]);
    expect(commandInjection.run(ctx)).toHaveLength(0);
  });

  it('GOES SILENT: a const-bound RegExp .exec over tainted text', () => {
    const ctx = memoryContext([PKG, ['server/reply.js',
      'const QTY_RE = /qty:\\s*(\\d+)/g;\n' +
      'export function h(req){ let m; const text = req.body.text; while ((m = QTY_RE.exec(text)) !== null) { void m; } }\n']]);
    expect(commandInjection.run(ctx)).toHaveLength(0);
  });
});

describe('fix4 / supabase_service_role_exposed: exposure, not mere use', () => {
  it('STILL FIRES: the service role key read inside a "use client" module', () => {
    const ctx = memoryContext([PKG,
      ['app/page.tsx', 'import { admin } from "../lib/admin";\nexport default function P(){ return <div>{admin.name}</div>; }\n'],
      ['lib/admin.ts',
        '"use client";\n' +
        'import { createClient } from "@supabase/supabase-js";\n' +
        'export const admin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);\n'],
    ]);
    expect(supabaseServiceRoleExposed.run(ctx).length).toBeGreaterThanOrEqual(1);
  });

  it('STILL FIRES: a NEXT_PUBLIC_-prefixed service role key, even in a server module', () => {
    const ctx = memoryContext([PKG, ['lib/supabase/server.ts',
      'import { cookies } from "next/headers";\n' +
      'export function admin(){ void cookies(); return process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY; }\n']]);
    const findings = supabaseServiceRoleExposed.run(ctx);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0]?.severity).toBe('critical');
  });

  it('GOES SILENT: a plain server-only read behind next/headers', () => {
    const ctx = memoryContext([PKG,
      ['app/page.tsx', '"use client";\nimport { serviceClient } from "../lib/supabase/server";\nexport default function P(){ return <div>{String(serviceClient)}</div>; }\n'],
      ['lib/supabase/server.ts',
        'import { cookies } from "next/headers";\n' +
        'export function serviceClient(){ void cookies(); return process.env.SUPABASE_SERVICE_ROLE_KEY; }\n'],
    ]);
    expect(supabaseServiceRoleExposed.run(ctx)).toHaveLength(0);
  });

  it('GOES SILENT: a server-only module reached through the import graph', () => {
    const ctx = memoryContext([PKG,
      ['app/page.tsx', '"use client";\nimport { svc } from "../lib/supabase-service";\nexport default function P(){ return <div>{String(svc)}</div>; }\n'],
      ['lib/supabase-service.ts',
        'import "server-only";\n' +
        'export const svc = () => process.env.SUPABASE_SERVICE_ROLE_KEY;\n'],
    ]);
    expect(supabaseServiceRoleExposed.run(ctx)).toHaveLength(0);
  });
});

describe('fix4 / hardcoded_secret: a literal secret VALUE, not a marker', () => {
  it('STILL FIRES: a literal private key block with real key material', () => {
    const key = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDb3fJ8kQ2mAaXq';
    const ctx = memoryContext([PKG, ['server/key.ts',
      `const pem = \`-----BEGIN PRIV${''}ATE KEY-----\n${key}\n${key}\n-----END PRIVATE KEY-----\`;\nexport default pem;\n`]]);
    const findings = hardcodedSecret.run(ctx).filter((f) => f.title.includes('Private key block'));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('critical');
  });

  it('STILL FIRES: a one-line escaped private key, the way one actually leaks', () => {
    const key = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDb3fJ8kQ2mAaXq';
    const ctx = memoryContext([PKG, ['server/sa.ts',
      ('export const SA = { private_key: "-----BEGIN PRIV' + 'ATE KEY-----') + String.raw`\n` + key + String.raw`\n` + '-----END PRIVATE KEY-----" };\n']]);
    expect(hardcodedSecret.run(ctx).filter((f) => f.title.includes('Private key block'))).toHaveLength(1);
  });

  it('GOES SILENT: the PEM header used as a strip marker', () => {
    const ctx = memoryContext([PKG, ['server/pem.ts',
      'export function pemToBytes(pem: string){\n' +
      ("  return pem.replace(/-----BEGIN PRIV" + "ATE KEY-----/g, '').replace(/-----END PRIVATE KEY-----/g, '').trim();\n") +
      '}\n']]);
    expect(hardcodedSecret.run(ctx).filter((f) => f.title.includes('Private key block'))).toHaveLength(0);
  });

  it('GOES SILENT: the PEM header as a named constant', () => {
    const ctx = memoryContext([PKG, ['server/google.ts',
      ("const PEM_BEGIN = '-----BEGIN PRIV" + "ATE KEY-----';\n") +
      'export function normalize(k: string){ return k.startsWith(PEM_BEGIN) ? k : PEM_BEGIN + k; }\n']]);
    expect(hardcodedSecret.run(ctx).filter((f) => f.title.includes('Private key block'))).toHaveLength(0);
  });

  it('STILL FIRES: a real Stripe live secret key', () => {
    const ctx = memoryContext([PKG, ['server/pay.ts',
      ('const key = "sk' + '_live_51HxKq9BvxYtR2mLpQwErTyUi";\nexport default key;\n')]]);
    const findings = hardcodedSecret.run(ctx).filter((f) => f.title.includes('Stripe'));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('critical');
  });

  it('GOES SILENT: a DOM input id that restates its own field name', () => {
    const ctx = memoryContext([PKG, ['src/components/change-password-form.tsx',
      'export const fieldIds = {\n' +
      '  currentPassword: "current-password",\n' +
      '  newPassword: "new-password",\n' +
      '  confirmPassword: "confirm-new-password",\n' +
      '};\n']]);
    expect(hardcodedSecret.run(ctx)).toHaveLength(0);
  });

  it('STILL FIRES: a genuinely random value beside the same field name', () => {
    const ctx = memoryContext([PKG, ['src/config.ts',
      'export const cfg = { currentPassword: "Xk9mQ2vB7nR4tW8pL3zY" };\n']]);
    expect(hardcodedSecret.run(ctx).length).toBeGreaterThanOrEqual(1);
  });

  it('GOES SILENT: the published supabase-demo local service_role JWT', () => {
    const demo =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
      'eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.' +
      'EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU';
    const ctx = memoryContext([PKG, ['tests/setup/e2e.ts',
      `process.env.SUPABASE_SERVICE_ROLE_KEY ??= "${demo}";\n`]]);
    expect(hardcodedSecret.run(ctx).filter((f) => f.title.includes('service role JWT'))).toHaveLength(0);
  });

  it('STILL FIRES: a real project service_role JWT (a project-ref issuer)', () => {
    const real =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
      'eyJpc3MiOiJodHRwczovL2FiY2RlZmdoaWprbC5zdXBhYmFzZS5jby9hdXRoL3YxIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.' +
      'EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU';
    const ctx = memoryContext([PKG, ['server/admin.ts', `const k = "${real}";\nexport default k;\n`]]);
    const findings = hardcodedSecret.run(ctx).filter((f) => f.title.includes('service role JWT'));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('critical');
  });
});

describe('fix4 / unsafe_file_upload: an upload context, not a matched token', () => {
  it('STILL FIRES: a multer handler with no fileFilter and no limits', () => {
    const ctx = memoryContext([PKG, ['server/upload.js',
      'import multer from "multer";\n' +
      'const upload = multer({ dest: "uploads/" });\n' +
      'app.post("/avatar", upload.single("avatar"), (req, res) => { res.json({ ok: true, name: req.file.originalname }); });\n']]);
    const findings = unsafeFileUpload.run(ctx);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.some((f) => f.severity === 'high')).toBe(true);
  });

  it('STILL FIRES: express-fileupload .mv() reached through req.files', () => {
    const ctx = memoryContext([PKG, ['server/save.js',
      'app.post("/doc", (req, res) => {\n' +
      '  const f = req.files.document;\n' +
      '  f.mv("./uploads/" + f.name, () => res.send("ok"));\n' +
      '});\n']]);
    expect(unsafeFileUpload.run(ctx).length).toBeGreaterThanOrEqual(1);
  });

  it('STILL FIRES: a Next.js formData() upload with no type or size check', () => {
    const ctx = memoryContext([PKG, ['app/api/upload/route.ts',
      'export async function POST(request: Request) {\n' +
      '  const form = await request.formData();\n' +
      '  const file = form.get("file") as File;\n' +
      '  await file.mv("./public/" + file.name);\n' +
      '  return Response.json({ ok: true });\n' +
      '}\n']]);
    expect(unsafeFileUpload.run(ctx).length).toBeGreaterThanOrEqual(1);
  });

  it('GOES SILENT: PyTorch spectral-norm maths', () => {
    const ctx = memoryContext([PKG, ['engine/propainter/modules/spectral_norm.py',
      'import torch\n' +
      'from torch.nn.functional import normalize\n' +
      'def compute(weight_mat, u, v, eps):\n' +
      '    v = normalize(torch.mv(weight_mat.t(), u), dim=0, eps=eps)\n' +
      '    u = normalize(torch.mv(weight_mat, v), dim=0, eps=eps)\n' +
      '    sigma = torch.dot(u, torch.mv(weight_mat, v))\n' +
      '    return sigma\n']]);
    expect(unsafeFileUpload.run(ctx)).toHaveLength(0);
  });
});

describe('fix4 / fail_open_authentication: whose .catch is it', () => {
  it('STILL FIRES: a verification whose own catch returns an authorised answer', () => {
    const ctx = memoryContext([PKG, ['app/api/admin/route.ts',
      'export async function POST(req) {\n' +
      '  const ok = await verifyToken(req.headers.get("authorization")).catch(() => true);\n' +
      '  return Response.json({ ok, rows: await db.user.findMany() });\n' +
      '}\n']]);
    const findings = failOpenAuthentication.run(ctx);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0]?.severity).toBe('high');
  });

  it('STILL FIRES: the same fail-open written across two lines, semicolon-free', () => {
    const ctx = memoryContext([PKG, ['app/api/admin2/route.ts',
      'export async function POST(req) {\n' +
      '  const ok = await verifyToken(req.headers.get("authorization"))\n' +
      '    .catch(() => true)\n' +
      '  return Response.json({ ok, rows: await db.user.findMany() })\n' +
      '}\n']]);
    expect(failOpenAuthentication.run(ctx).length).toBeGreaterThanOrEqual(1);
  });

  it('GOES SILENT: a defaulted request body under a hard 401', () => {
    const ctx = memoryContext([PKG, ['app/api/bookings/route.ts',
      'export async function POST(req) {\n' +
      '  const { user, response } = await requireAuth()\n' +
      '  if (response) return response\n' +
      '  const body = await req.json().catch(() => ({}))\n' +
      '  return Response.json({ rows: await db.booking.findMany({ where: { userId: user.id, ...body } }) })\n' +
      '}\n']]);
    expect(failOpenAuthentication.run(ctx)).toHaveLength(0);
  });

  it('GOES SILENT: the same shape with semicolons (the arrangement that already worked)', () => {
    const ctx = memoryContext([PKG, ['app/api/events/route.ts',
      'export async function POST(req) {\n' +
      '  const { user, response } = await requireAuth();\n' +
      '  if (response) return response;\n' +
      '  const body = await req.json().catch(() => ({}));\n' +
      '  return Response.json({ rows: await db.event.findMany({ where: { userId: user.id, ...body } }) });\n' +
      '}\n']]);
    expect(failOpenAuthentication.run(ctx)).toHaveLength(0);
  });
});

describe('fix4 / sensitive_data_in_logs: a logged secret, not a mention of one', () => {
  it('STILL FIRES: a password logged beside its label', () => {
    const ctx = memoryContext([PKG, ['server/login.js',
      'export function h(password){ console.log("user password:", password); }\n']]);
    expect(sensitiveDataInLogs.run(ctx).length).toBeGreaterThanOrEqual(1);
  });

  it('STILL FIRES: a structured log carrying token and apiKey', () => {
    const ctx = memoryContext([PKG, ['server/req.js',
      'export function h(token, apiKey){ logger.info({ token, apiKey }); }\n']]);
    expect(sensitiveDataInLogs.run(ctx).length).toBeGreaterThanOrEqual(1);
  });

  it('STILL FIRES: an Authorization header selected out of the bag by name', () => {
    const ctx = memoryContext([PKG, ['server/dbg.js',
      'export function h(headers){ console.log("auth", headers.get("authorization")); }\n']]);
    expect(sensitiveDataInLogs.run(ctx).length).toBeGreaterThanOrEqual(1);
  });

  it('STILL FIRES: an axios error logged with its raw response', () => {
    const ctx = memoryContext([PKG, ['server/call.js',
      'export function h(requestError){ console.error("call failed", requestError.response); }\n']]);
    expect(sensitiveDataInLogs.run(ctx).length).toBeGreaterThanOrEqual(1);
  });

  it('STILL FIRES: the whole headers bag, un-selected', () => {
    const ctx = memoryContext([PKG, ['server/dump.js',
      'export function h(req){ console.log(req.headers); }\n']]);
    expect(sensitiveDataInLogs.run(ctx).length).toBeGreaterThanOrEqual(1);
  });

  it('STILL FIRES: a template that interpolates the token VALUE itself', () => {
    const ctx = memoryContext([PKG, ['server/dbg2.js',
      'export function h(token){ console.log(`bearer token: ${token}`); }\n']]);
    const findings = sensitiveDataInLogs.run(ctx);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0]?.severity).toBe('high');
  });

  it('GOES SILENT: a presence check interpolated into a template', () => {
    const ctx = memoryContext([PKG, ['scripts/verify.mjs',
      'export function h(session){ console.log(`Session active: ${Boolean(session?.session)}`); }\n']]);
    expect(sensitiveDataInLogs.run(ctx)).toHaveLength(0);
  });

  it('GOES SILENT: a credential used only as a ternary condition', () => {
    const ctx = memoryContext([PKG, ['scripts/verify2.mjs',
      'export function h(b){ console.log(`SIGNIN: ${b.access_token ? "session issued" : "no session"}`); }\n']]);
    expect(sensitiveDataInLogs.run(ctx)).toHaveLength(0);
  });

  it('GOES SILENT: a count of cookies', () => {
    const ctx = memoryContext([PKG, ['scripts/debug.mjs',
      'export function h(cookies){ console.log("cookies loaded", cookies.length); }\n']]);
    expect(sensitiveDataInLogs.run(ctx)).toHaveLength(0);
  });

  it('GOES SILENT: a static message mentioning a secret that is MISSING', () => {
    const ctx = memoryContext([PKG, ['server/worker.js',
      'export function h(){ console.error(JSON.stringify({ error: "Worker secret is not configured" })); }\n']]);
    expect(sensitiveDataInLogs.run(ctx)).toHaveLength(0);
  });

  it('GOES SILENT: a bare error object', () => {
    const ctx = memoryContext([PKG, ['server/profile.js',
      'export function h(authError){ console.error("listUsers failed", authError); }\n']]);
    expect(sensitiveDataInLogs.run(ctx)).toHaveLength(0);
  });
});
