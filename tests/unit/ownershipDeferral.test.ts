import { describe, expect, it } from 'vitest';
import { brokenAccessControl } from '../../src/rules/contextual/brokenAccessControl.js';
import { databaseDeleteWithoutOwnershipCheck } from '../../src/rules/contextual/databaseDeleteWithoutOwnershipCheck.js';
import { MUTATION_KINDS } from '../../src/rules/contextual/apiMutationWithoutAuth.js';
import { MUTATION_DB_KINDS_FOR_TEST } from '../../src/shared/unauthenticatedRoute.js';
import { memoryContext } from './helpers.js';

const PKG: [string, string] = [
  'package.json',
  '{"name":"x","dependencies":{"next":"14.0.0","@prisma/client":"5.0.0"}}',
];

const ctx = (files: [string, string][]) => memoryContext([PKG, ...files]);
const ownership = (files: [string, string][]) => {
  const context = ctx(files);
  return [
    ...brokenAccessControl.run(context),
    ...databaseDeleteWithoutOwnershipCheck.run(context),
  ];
};

describe('ownership deferral — fully unauthenticated mutation route', () => {
  const handler = (guard: string, guardImport: string) =>
    [
      'import { prisma } from "@/lib/prisma";',
      guardImport,
      '',
      'export async function DELETE(request, { params }) {',
      guard,
      '  const { id } = params;',
      '  await prisma.salesOrder.delete({ where: { id } });',
      '  return Response.json({ ok: true });',
      '}',
      '',
    ]
      .filter((line) => line !== '')
      .join('\n');

  const SESSION_LIB: [string, string] = [
    'lib/session.js',
    'export async function getServerSession() { return globalThis.__session ?? null; }\n',
  ];

  it('CONTROL: the identical delete WITH a session guard is reported', () => {
    const findings = ownership([
      [
        'app/api/orders/[id]/route.js',
        handler(
          '  const session = await getServerSession();\n  if (!session) return new Response("Unauthorized", { status: 401 });',
          'import { getServerSession } from "@/lib/session";',
        ),
      ],
      SESSION_LIB,
    ]);
    expect(findings.some((finding) => finding.ruleId === 'database_delete_without_ownership_check')).toBe(true);
  });

  it('GATE: the same delete with NO auth anywhere defers', () => {
    expect(ownership([['app/api/orders/[id]/route.js', handler('', '')]])).toHaveLength(0);
  });
});

describe('ownership deferral — an authenticated caller keeps the finding', () => {
  it('GATE: authed-but-unscoped DELETE is still reported (the real IDOR)', () => {
    const findings = ownership([
      [
        'app/api/orders/[id]/route.js',
        [
          'import { prisma } from "@/lib/prisma";',
          'import { getServerSession } from "@/lib/session";',
          '',
          'export async function DELETE(request, { params }) {',
          '  const session = await getServerSession();',
          '  if (!session) return new Response("Unauthorized", { status: 401 });',
          '  const { id } = params;',
          '  await prisma.salesOrder.delete({ where: { id } });',
          '  return Response.json({ ok: true });',
          '}',
          '',
        ].join('\n'),
      ],
      [
        'lib/session.js',
        'export async function getServerSession() { return globalThis.__session ?? null; }\n',
      ],
    ]);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some((finding) => finding.ruleId === 'database_delete_without_ownership_check')).toBe(true);
  });

  it('the same route scoped to the session identity is not reported at all', () => {
    const findings = ownership([
      [
        'app/api/orders/[id]/route.js',
        [
          'import { prisma } from "@/lib/prisma";',
          'import { getServerSession } from "@/lib/session";',
          '',
          'export async function DELETE(request, { params }) {',
          '  const session = await getServerSession();',
          '  if (!session) return new Response("Unauthorized", { status: 401 });',
          '  const { id } = params;',
          '  await prisma.salesOrder.delete({ where: { id, userId: session.user.id } });',
          '  return Response.json({ ok: true });',
          '}',
          '',
        ].join('\n'),
      ],
      [
        'lib/session.js',
        'export async function getServerSession() { return globalThis.__session ?? null; }\n',
      ],
    ]);
    expect(findings).toHaveLength(0);
  });
});

describe('ownership deferral — the course-app shape keeps firing', () => {
  it("GATE: a course app's shape (Clerk auth present, read unscoped by course id) still fires", () => {
    const findings = ownership([
      [
        'app/api/study/free/courses/[course]/route.js',
        [
          'import { auth } from "@clerk/nextjs/server";',
          'import Card from "@/models/Card";',
          '',
          'export async function GET(request, { params }) {',
          '  const { userId } = await auth();',
          '  if (!userId) return new Response("Unauthorized", { status: 401 });',
          '  const courseId = params.course;',
          '  const cards = await Card.find({ courseId: courseId });',
          '  return Response.json(cards);',
          '}',
          '',
        ].join('\n'),
      ],
    ]);
    expect(findings.some((finding) => finding.ruleId === 'broken_access_control')).toBe(true);
  });
});

describe('ownership deferral — the conditions that bound it', () => {
  it('condition 5: a READ route never defers, because no auth rule backstops it', () => {
    const findings = ownership([
      [
        'app/api/study/free/courses/[course]/route.js',
        [
          'import Card from "@/models/Card";',
          '',
          'export async function GET(request, { params }) {',
          '  const courseId = params.course;',
          '  const cards = await Card.find({ courseId: courseId });',
          '  return Response.json(cards);',
          '}',
          '',
        ].join('\n'),
      ],
    ]);
    expect(findings.some((finding) => finding.ruleId === 'broken_access_control')).toBe(true);
  });

  it('condition 6 is pinned to api_mutation_without_auth\'s own precondition', () => {
    expect([...MUTATION_DB_KINDS_FOR_TEST].sort()).toEqual([...MUTATION_KINDS].sort());
  });

  it('condition 1: a finding outside any route handler never defers', () => {
    const findings = ownership([
      [
        'app/api/parcels/route.js',
        [
          'import { prisma } from "@/lib/prisma";',
          '',
          'async function loadUser(request) {',
          '  const userId = request.headers.get("x-user-id");',
          '  return await prisma.user.findUnique({ where: { id: userId } });',
          '}',
          '',
          'export async function DELETE(request) {',
          '  const user = await loadUser(request);',
          '  const { searchParams } = new URL(request.url);',
          '  await prisma.parcel.delete({ where: { id: searchParams.get("id") } });',
          '  return Response.json({ ok: true });',
          '}',
          '',
        ].join('\n'),
      ],
    ]);
    expect(
      findings.some((finding) => finding.ruleId === 'broken_access_control' && finding.lineStart === 5),
    ).toBe(true);
  });
});
