import { describe, expect, it } from 'vitest';
import { serverActionWithoutAuthorization } from '../../src/rules/contextual/serverActionWithoutAuthorization.js';
import { brokenAccessControl } from '../../src/rules/contextual/brokenAccessControl.js';
import {
  earlyExitOnFalsy,
  selectionBoundToIdentity,
  statementFrom,
} from '../../src/shared/importedVerifier.js';
import { parseBuilderEq } from '../../src/shared/ownership.js';
import { memoryContext } from './helpers.js';

const NEXT: [string, string] = [
  'package.json',
  '{"name":"x","dependencies":{"next":"15.0.0","drizzle-orm":"^0.30.0","jose":"^5.0.0","@prisma/client":"5.0.0"}}',
];
const APP_MARKER: [string, string] = ['app/page.tsx', 'export default function Page(){ return null; }\n'];

const TOKEN_MODULE: [string, string] = [
  'lib/auth/token.ts',
  [
    "import { jwtVerify } from 'jose';",
    'const key = new TextEncoder().encode(process.env.AUTH_SECRET);',
    'export async function verifyToken(input) {',
    "  const { payload } = await jwtVerify(input, key, { algorithms: ['HS256'] });",
    '  return payload;',
    '}',
    '',
  ].join('\n'),
];

const VERIFYING_SESSION_MODULE: [string, string] = [
  'lib/auth/session.ts',
  [
    "import { cookies } from 'next/headers';",
    "import { verifyToken } from './token';",
    'export async function getVerifiedSession() {',
    "  const cookie = (await cookies()).get('session');",
    '  if (!cookie) return null;',
    '  const data = await verifyToken(cookie.value);',
    '  if (!data) return null;',
    '  return data;',
    '}',
    '',
  ].join('\n'),
];

const NON_VERIFYING_SESSION_MODULE: [string, string] = [
  'lib/auth/session.ts',
  [
    "import { cookies } from 'next/headers';",
    'export async function getVerifiedSession() {',
    "  const cookie = (await cookies()).get('session');",
    '  if (!cookie) return null;',
    '  return JSON.parse(cookie.value);',
    '}',
    '',
  ].join('\n'),
];


const GATES_BUT_RETURNS_OTHER: [string, string] = [
  'lib/auth/session.ts',
  [
    "import { cookies } from 'next/headers';",
    "import { jwtVerify } from 'jose';",
    "import { loadCourse } from '../fs/courses';",
    'export async function getVerifiedSession(id) {',
    "  const cookie = (await cookies()).get('session');",
    '  const { payload } = await jwtVerify(cookie.value, key);',
    '  if (!payload) return null;',
    '  return loadCourse(id);',
    '}',
    '',
  ].join('\n'),
];

const action = (body: string, importFrom = '@/lib/auth/session'): string =>
  [
    "'use server';",
    `import { getVerifiedSession } from '${importFrom}';`,
    "import { db, orders } from '@/lib/db';",
    "import { and, eq } from 'drizzle-orm';",
    'export async function saveProgress(productId, lessons, formData) {',
    body,
    '}',
    '',
  ].join('\n');

const SCOPED_WRITE =
  '  await db.update(orders).set({ lessons })' +
  '.where(and(eq(orders.productId, productId), eq(orders.customerId, customerId)));';

const runAction = (files: [string, string][]): ReturnType<typeof serverActionWithoutAuthorization.run> =>
  serverActionWithoutAuthorization.run(memoryContext([NEXT, APP_MARKER, ...files]));

describe('server_action_without_authorization — cross-file verifier guard', () => {
  it('imported helper that VERIFIES + early return + identity-scoped write → clears', () => {
    const findings = runAction([
      TOKEN_MODULE,
      VERIFYING_SESSION_MODULE,
      [
        'app/actions/progress.ts',
        action(
          [
            '  const session = await getVerifiedSession();',
            "  if (!session) { redirect('/sign-in'); }",
            '  const customerId = session.user.customerId;',
            SCOPED_WRITE,
          ].join('\n'),
        ),
      ],
    ]);
    expect(findings).toHaveLength(0);
  });

  it('imported helper that does NOT verify → still fires (name is not the control)', () => {
    const findings = runAction([
      NON_VERIFYING_SESSION_MODULE,
      [
        'app/actions/progress.ts',
        action(
          [
            '  const session = await getVerifiedSession();',
            "  if (!session) { redirect('/sign-in'); }",
            '  const customerId = session.user.customerId;',
            SCOPED_WRITE,
          ].join('\n'),
        ),
      ],
    ]);
    expect(findings).toHaveLength(1);
  });

  it('verifier resolved only as a BARE npm specifier → still fires (unresolvable is not credited)', () => {
    const findings = runAction([
      TOKEN_MODULE,
      VERIFYING_SESSION_MODULE,
      [
        'app/actions/progress.ts',
        action(
          [
            '  const session = await getVerifiedSession();',
            "  if (!session) { redirect('/sign-in'); }",
            '  const customerId = session.user.customerId;',
            SCOPED_WRITE,
          ].join('\n'),
          'some-auth-package',
        ),
      ],
    ]);
    expect(findings).toHaveLength(1);
  });

  it('verified session but NO early exit on the falsy result → still fires', () => {
    const findings = runAction([
      TOKEN_MODULE,
      VERIFYING_SESSION_MODULE,
      [
        'app/actions/progress.ts',
        action(
          [
            '  const session = await getVerifiedSession();',
            '  const customerId = session.user.customerId;',
            SCOPED_WRITE,
          ].join('\n'),
        ),
      ],
    ]);
    expect(findings).toHaveLength(1);
  });

  it('verified session + early exit but NO ownership scope → still fires (authentication is not authorization)', () => {
    const findings = runAction([
      TOKEN_MODULE,
      VERIFYING_SESSION_MODULE,
      [
        'app/actions/progress.ts',
        action(
          [
            '  const session = await getVerifiedSession();',
            "  if (!session) { redirect('/sign-in'); }",
            '  await db.update(orders).set({ lessons }).where(eq(orders.productId, productId));',
          ].join('\n'),
        ),
      ],
    ]);
    expect(findings).toHaveLength(1);
  });

  it('ownership scope bound to a REQUEST value → still fires', () => {
    const findings = runAction([
      TOKEN_MODULE,
      VERIFYING_SESSION_MODULE,
      [
        'app/actions/progress.ts',
        action(
          [
            '  const session = await getVerifiedSession();',
            "  if (!session) { redirect('/sign-in'); }",
            '  await db.update(orders).set({ lessons })' +
              '.where(and(eq(orders.productId, productId), eq(orders.customerId, formData.customerId)));',
          ].join('\n'),
        ),
      ],
    ]);
    expect(findings).toHaveLength(1);
  });

  it('identity written into the PAYLOAD, row still chosen by a request id → still fires', () => {
    const findings = runAction([
      TOKEN_MODULE,
      VERIFYING_SESSION_MODULE,
      [
        'app/actions/progress.ts',
        [
          "'use server';",
          "import { getVerifiedSession } from '@/lib/auth/session';",
          'export async function saveProgress(orderId, lessons) {',
          '  const session = await getVerifiedSession();',
          "  if (!session) { redirect('/sign-in'); }",
          '  await prisma.order.update({ where: { id: orderId }, ' +
            'data: { lessons, customerId: session.user.customerId } });',
          '}',
          '',
        ].join('\n'),
      ],
    ]);
    expect(findings).toHaveLength(1);
  });

  it('helper that verifies but returns something OTHER than the session → still fires', () => {
    const findings = runAction([
      TOKEN_MODULE,
      GATES_BUT_RETURNS_OTHER,
      ['lib/fs/courses.ts', 'export function loadCourse(id) { return { id, customerId: id }; }\n'],
      [
        'app/actions/progress.ts',
        action(
          [
            '  const session = await getVerifiedSession(productId);',
            "  if (!session) { redirect('/sign-in'); }",
            '  const customerId = session.customerId;',
            SCOPED_WRITE,
          ].join('\n'),
        ),
      ],
    ]);
    expect(findings).toHaveLength(1);
  });

  it('a verifier declared in the ACTION FILE ITSELF is not this predicate\'s business → still fires', () => {
    const findings = runAction([
      [
        'app/actions/progress.ts',
        [
          "'use server';",
          "import { jwtVerify } from 'jose';",
          "import { cookies } from 'next/headers';",
          "import { db, orders } from '@/lib/db';",
          "import { and, eq } from 'drizzle-orm';",
          'async function getVerifiedSession() {',
          "  const cookie = (await cookies()).get('session');",
          '  const { payload } = await jwtVerify(cookie.value, key);',
          '  return payload;',
          '}',
          'export async function saveProgress(productId, lessons) {',
          '  const session = await getVerifiedSession();',
          "  if (!session) { redirect('/sign-in'); }",
          '  const customerId = session.user.customerId;',
          SCOPED_WRITE,
          '}',
          '',
        ].join('\n'),
      ],
    ]);
    expect(findings).toHaveLength(1);
  });

  it('a name that is ALSO bound to request data anywhere in the scope is not an identity', () => {
    const findings = runAction([
      TOKEN_MODULE,
      VERIFYING_SESSION_MODULE,
      [
        'app/actions/progress.ts',
        action(
          [
            '  const session = await getVerifiedSession();',
            "  if (!session) { redirect('/sign-in'); }",
            '  let customerId = session.user.customerId;',
            "  if (override) { const customerId = formData.get('customerId'); }",
            SCOPED_WRITE,
          ].join('\n'),
        ),
      ],
    ]);
    expect(findings).toHaveLength(1);
  });

  it('a scoped read earlier in the action does not cover an unscoped write below it', () => {
    const findings = runAction([
      TOKEN_MODULE,
      VERIFYING_SESSION_MODULE,
      [
        'app/actions/progress.ts',
        action(
          [
            '  const session = await getVerifiedSession();',
            "  if (!session) { redirect('/sign-in'); }",
            '  const customerId = session.user.customerId;',
            '  const mine = await db.select().from(orders).where(eq(orders.customerId, customerId));',
            '  await db.update(orders).set({ lessons }).where(eq(orders.productId, productId));',
          ].join('\n'),
        ),
      ],
    ]);
    expect(findings).toHaveLength(1);
  });
});

const ROUTE = (filter: string): [string, string] => [
  'app/api/orders/[id]/route.ts',
  [
    "import { getVerifiedSession } from '@/lib/auth/session';",
    "import { db } from '@/lib/db';",
    'export async function GET(req, { params }) {',
    '  const orderId = params.id;',
    '  const session = await getVerifiedSession();',
    "  if (!session) { return new Response('no', { status: 401 }); }",
    '  const customerId = session.user.customerId;',
    `  const row = await db.order.findFirst({ where: { ${filter} } });`,
    '  return Response.json(row);',
    '}',
    '',
  ].join('\n'),
];

describe('broken_access_control — cross-file verifier guard', () => {
  it('query scoped by an identity from an imported verifier → clears', () => {
    const findings = brokenAccessControl.run(
      memoryContext([NEXT, APP_MARKER, TOKEN_MODULE, VERIFYING_SESSION_MODULE, ROUTE('id: orderId, customerId: customerId')]),
    );
    expect(findings).toHaveLength(0);
  });

  it('same query scoped by a REQUEST value → still fires', () => {
    const findings = brokenAccessControl.run(
      memoryContext([
        NEXT,
        APP_MARKER,
        TOKEN_MODULE,
        VERIFYING_SESSION_MODULE,
        ROUTE('id: orderId, customerId: params.customerId'),
      ]),
    );
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('imported helper that does NOT verify → still fires', () => {
    const findings = brokenAccessControl.run(
      memoryContext([NEXT, APP_MARKER, NON_VERIFYING_SESSION_MODULE, ROUTE('id: orderId, customerId: customerId')]),
    );
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });
});

describe('importedVerifier internals', () => {
  it('a falsy check on a PROPERTY is not a falsy check on the value', () => {
    expect(earlyExitOnFalsy('if (!result.success) { return x; }', 'result')).toBe(false);
    expect(earlyExitOnFalsy('if (!result) { return x; }', 'result')).toBe(true);
    expect(earlyExitOnFalsy("if (!result) redirect('/sign-in');", 'result')).toBe(true);
    expect(earlyExitOnFalsy('if (result === null) throw new Error();', 'result')).toBe(true);
  });

  it('a write payload is never read as a row filter', () => {
    const identities = new Set(['session']);
    expect(
      selectionBoundToIdentity(
        'prisma.order.update({ where: { id: orderId }, data: { userId: session.user.id } })',
        identities,
      ),
    ).toBe(false);
    expect(
      selectionBoundToIdentity(
        'prisma.order.update({ where: { id: orderId, userId: session.user.id }, data: { x } })',
        identities,
      ),
    ).toBe(true);
  });

  it('no verified identity means nothing is ever cleared', () => {
    expect(selectionBoundToIdentity('where: { userId: session.user.id }', new Set())).toBe(false);
  });

  it('a statement stops at its own terminator', () => {
    const text = 'const a = one();\n  await db.update(t).where(eq(t.x, y));\n  const b = two();';
    const from = text.indexOf('await');
    expect(statementFrom(text, from)).toContain('where');
    expect(statementFrom(text, from)).not.toContain('two()');
  });

  it('parseBuilderEq reads an unquoted column reference as its last segment', () => {
    expect(parseBuilderEq('eq(orders.customerId, customerId)')).toEqual([
      { key: 'customerId', value: 'customerId' },
    ]);
    expect(parseBuilderEq('and(eq(t.productId, productId), eq(t.customerId, customerId))')).toEqual([
      { key: 'productId', value: 'productId' },
      { key: 'customerId', value: 'customerId' },
    ]);
  });
});
