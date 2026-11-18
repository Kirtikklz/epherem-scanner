import { describe, expect, it } from 'vitest';
import { memoryContext } from './helpers.js';
import { apiMutationWithoutAuth } from '../../src/rules/contextual/apiMutationWithoutAuth.js';
import { missingRequestBodyValidation } from '../../src/rules/contextual/missingRequestBodyValidation.js';
import { missingRateLimit } from '../../src/rules/contextual/missingRateLimit.js';
import { brokenAccessControl } from '../../src/rules/contextual/brokenAccessControl.js';
import { databaseDeleteWithoutOwnershipCheck } from '../../src/rules/contextual/databaseDeleteWithoutOwnershipCheck.js';

const pkg: [string, string] = ['package.json', '{"dependencies":{"next":"14.0.0","express":"4.19.0","@prisma/client":"5.0.0"}}'];

describe('route security profiles', () => {
  it('associates invoked auth, validation, rate limit and database helpers with a Next.js method', () => {
    const context = memoryContext([
      pkg,
      ['app/api/orders/route.ts', [
        'import { requireUser } from "../../../lib/auth";',
        'import { parseOrder } from "../../../lib/validation";',
        'import { createOrder } from "../../../lib/orders";',
        'import { checkLimit } from "../../../lib/limit";',
        'export async function POST(request){',
        '  const user = await requireUser(); checkLimit(request);',
        '  const body = parseOrder(await request.json());',
        '  return createOrder(user.id, body);',
        '}',
      ].join('\n')],
      ['lib/auth.ts', 'export async function requireUser(){ const session = await getServerSession(); if(!session?.user) throw new Error("unauthorized"); return session.user; }'],
      ['lib/validation.ts', 'export function parseOrder(value){ return orderSchema.parse(value); }'],
      ['lib/limit.ts', 'export function checkLimit(request){ return rateLimiter.limit(request); }'],
      ['lib/orders.ts', 'export function createOrder(userId, body){ audit(process.env.ORDER_AUDIT_KEY); return prisma.order.create({ data: { ...body, userId } }); }'],
    ]);
    const profiles = context.projectMap.routeSecurityProfiles ?? [];
    expect(profiles).toHaveLength(1);
    expect(profiles[0]).toMatchObject({
      method: 'POST', routePath: '/api/orders', analysisStatus: 'complete',
      authentication: { status: 'present' },
      inputValidation: { status: 'present' },
      rateLimit: { status: 'present' },
      authorization: { status: 'not_applicable' },
    });
    expect(profiles[0]?.databaseOperations).toEqual(expect.arrayContaining([
      expect.objectContaining({ filePath: 'lib/orders.ts', client: 'prisma', kind: 'insert', table: 'order' }),
    ]));
    expect(profiles[0]?.reachableFiles).toEqual(expect.arrayContaining(['lib/auth.ts', 'lib/orders.ts', 'lib/validation.ts']));
    expect(profiles[0]?.sensitiveEnvVars).toContain('ORDER_AUDIT_KEY');
    expect(missingRequestBodyValidation.run(context)).toHaveLength(0);
  });

  it('does not credit an imported but uninvoked auth helper', () => {
    const context = memoryContext([
      pkg,
      ['app/api/orders/route.ts', 'import { requireUser } from "../../../lib/auth";\nexport function POST(request){ return save(request.body); }'],
      ['lib/auth.ts', 'export async function requireUser(){ const session = await getServerSession(); if(!session?.user) throw new Error("unauthorized"); return session.user; }'],
    ]);
    expect(context.projectMap.routeSecurityProfiles?.[0]?.authentication.status).toBe('absent');
    expect(context.projectMap.routeSecurityProfiles?.[0]?.reachableFiles).not.toContain('lib/auth.ts');
  });

  it('flags an unauthenticated mutation reached through an imported repository', () => {
    const context = memoryContext([
      pkg,
      ['app/api/orders/route.ts', 'import { save } from "../../../lib/orders";\nexport async function POST(request){ return save(await request.json()); }'],
      ['lib/orders.ts', 'export function save(body){ return prisma.order.create({ data: body }); }'],
    ]);
    expect(apiMutationWithoutAuth.run(context)).toEqual([
      expect.objectContaining({ filePath: 'app/api/orders/route.ts', confidence: 'high' }),
    ]);
    expect(missingRequestBodyValidation.run(context)).toHaveLength(1);
  });

  it('credits an invoked imported limiter on a sensitive route', () => {
    const context = memoryContext([
      pkg,
      ['app/api/login/route.ts', 'import { checkLimit } from "../../../lib/limit";\nexport function POST(request){ checkLimit(request); return login(request.body); }'],
      ['lib/limit.ts', 'export function checkLimit(request){ return rateLimiter.limit(request); }'],
    ]);
    expect(context.projectMap.routeSecurityProfiles?.[0]?.rateLimit.status).toBe('present');
    expect(missingRateLimit.run(context)).toHaveLength(0);
  });

  it('models Express inline handlers and invoked service functions independently', () => {
    const context = memoryContext([
      pkg,
      ['server.ts', [
        'import express from "express"; import { save } from "./service";',
        'const router = express.Router();',
        'router.post("/orders", async (req,res) => {',
        '  const session = req.session; if(!session?.user) return res.status(401).end();',
        '  const body = orderSchema.parse(req.body); await save(session.user.id, body);',
        '});',
        'router.get("/health", (_req,res) => res.json({ok:true}));',
      ].join('\n')],
      ['service.ts', 'export function save(userId, body){ return prisma.order.create({ data: { ...body, userId } }); }'],
    ]);
    const profiles = context.projectMap.routeSecurityProfiles ?? [];
    const orders = profiles.find((profile) => profile.routePath === '/orders');
    const health = profiles.find((profile) => profile.routePath === '/health');
    expect(orders).toMatchObject({ authentication: { status: 'present' }, inputValidation: { status: 'present' }, csrfProtection: { status: 'absent' } });
    expect(orders?.databaseOperations).toHaveLength(1);
    expect(health).toMatchObject({ authentication: { status: 'absent' }, inputValidation: { status: 'not_applicable' } });
    expect(health?.databaseOperations).toHaveLength(0);
  });

  it('credits visible Supabase RLS and policy evidence for an invoked table', () => {
    const context = memoryContext([
      pkg,
      ['app/api/orders/route.ts', 'import { load } from "../../../lib/orders";\nexport function GET(req){ return load(req.query.id); }'],
      ['lib/orders.ts', 'export function load(id){ return supabase.from("orders").select("*").eq("id", id); }'],
      ['supabase/migrations/001.sql', 'ALTER TABLE orders ENABLE ROW LEVEL SECURITY; CREATE POLICY own_orders ON orders FOR SELECT USING (auth.uid() = user_id);'],
    ]);
    expect(context.projectMap.routeSecurityProfiles?.[0]?.authorization).toMatchObject({ status: 'present' });
  });

  it('reports imported record access and deletes without ownership', () => {
    const readContext = memoryContext([
      pkg,
      ['app/api/orders/route.ts', 'import { load } from "../../../lib/orders";\nexport function GET(req){ return load(req.query.id); }'],
      ['lib/orders.ts', 'export function load(id){ return prisma.order.findUnique({ where: { id } }); }'],
    ]);
    const deleteContext = memoryContext([
      pkg,
      ['app/api/orders/route.ts', 'import { remove } from "../../../lib/orders";\nexport function DELETE(req){ return remove(req.query.id); }'],
      ['lib/orders.ts', 'export function remove(id){ return prisma.order.delete({ where: { id } }); }'],
    ]);
    expect(brokenAccessControl.run(readContext)).toEqual([
      expect.objectContaining({ filePath: 'app/api/orders/route.ts', confidence: 'high' }),
    ]);
    expect(databaseDeleteWithoutOwnershipCheck.run(deleteContext)).toEqual([
      expect.objectContaining({ filePath: 'app/api/orders/route.ts' }),
    ]);
  });

  it('keeps unsupported Python route analysis partial and controls unknown', () => {
    const context = memoryContext([
      ['requirements.txt', 'fastapi==0.115.0'],
      ['app.py', '@app.post("/orders")\ndef create_order(body: dict):\n    return service.save(body)\n'],
    ]);
    const profile = context.projectMap.routeSecurityProfiles?.[0];
    expect(profile?.analysisStatus).toBe('partial');
    expect(profile?.authentication.status).toBe('unknown');
  });

  it('marks a route partial when the invoked call depth exceeds the bound', () => {
    const files: [string, string][] = [pkg];
    files.push(['app/api/deep/route.ts', 'import { f0 } from "../../../lib/f0";\nexport function GET(req){ return f0(req.query.id); }']);
    for (let index = 0; index < 11; index += 1) {
      files.push([`lib/f${index}.ts`, index === 10
        ? 'export function f10(value){ return value; }'
        : `import { f${index + 1} } from "./f${index + 1}"; export function f${index}(value){ return f${index + 1}(value); }`]);
    }
    const profile = memoryContext(files).projectMap.routeSecurityProfiles?.[0];
    expect(profile?.analysisStatus).toBe('partial');
    expect(profile?.analysisReasons.join(' ')).toMatch(/depth limit/i);
  });
});
