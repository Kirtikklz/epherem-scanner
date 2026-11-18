import { describe, expect, it } from 'vitest';
import { apiMutationWithoutAuth } from '../../src/rules/contextual/apiMutationWithoutAuth.js';
import { siblingGroupOf } from '../../src/shared/siblingRouteInconsistency.js';
import { buildFindingId } from '../../src/shared/utils.js';
import { computeFindingIdentities } from '../../src/shared/findingIdentity.js';
import { loadFixtureContext, memoryContext } from './helpers.js';
import type { Finding, RuleContext } from '../../src/shared/types.js';

const GENERIC_EXPLANATION =
  'This API endpoint changes data in your database, but the code never checks who is making the request.';
const SIBLING_EXPLANATION =
  'The other API endpoints in this folder check who is making the request — this one does not.';

const mutationFindings = (context: RuleContext): Finding[] =>
  apiMutationWithoutAuth.run(context).filter((finding) => finding.ruleId === 'api_mutation_without_auth');

const byPath = (findings: Finding[], filePath: string): Finding | undefined =>
  findings.find((finding) => finding.filePath === filePath);

describe('sibling inconsistency — one forgotten route in a protected folder', () => {
  it('boosts and rewords the forgotten route, and fires on nothing else', async () => {
    const context = await loadFixtureContext('sibling-forgotten-route');
    const findings = mutationFindings(context);

    expect(findings.map((finding) => finding.filePath)).toEqual([
      'app/api/admin/settings/route.ts',
    ]);

    const forgotten = findings[0] as Finding;
    expect(forgotten.confidence).toBe('high');
    expect(forgotten.userExplanation).toContain(SIBLING_EXPLANATION);
    expect(forgotten.userExplanation).not.toContain(GENERIC_EXPLANATION);

    expect(forgotten.technicalExplanation).toContain('/api/admin');
    expect(forgotten.technicalExplanation).toContain('/api/admin/products');
    expect(forgotten.technicalExplanation).toContain('/api/admin/users');

    expect(forgotten.severity).toBe('high');
    expect(forgotten.detectionKind).toBe('absence');
    expect(forgotten.detectionMethod).toBe('heuristic');
  });

  it('leaves the finding\'s identity exactly where it was', async () => {
    const context = await loadFixtureContext('sibling-forgotten-route');
    const forgotten = mutationFindings(context)[0] as Finding;

    expect(forgotten.id).toBe(
      buildFindingId('api_mutation_without_auth', forgotten.filePath, forgotten.lineStart, forgotten.evidence),
    );

    const [identity] = computeFindingIdentities([forgotten]);
    const [bare] = computeFindingIdentities([
      {
        ruleId: forgotten.ruleId,
        filePath: forgotten.filePath,
        lineStart: forgotten.lineStart,
        lineEnd: forgotten.lineEnd,
        evidence: forgotten.evidence,
      },
    ]);
    expect(identity).toBe(bare);
  });
});

describe('sibling inconsistency — a folder with no authentication anywhere', () => {
  it('fires on every route with the ORIGINAL wording and no boost', async () => {
    const context = await loadFixtureContext('sibling-all-unauthenticated');
    const findings = mutationFindings(context);

    expect(findings.map((finding) => finding.filePath).sort()).toEqual([
      'app/api/inventory/items/route.ts',
      'app/api/inventory/locations/route.ts',
      'app/api/inventory/suppliers/route.ts',
    ]);

    for (const finding of findings) {
      expect(finding.confidence).toBe('medium');
      expect(finding.userExplanation).toContain(GENERIC_EXPLANATION);
      expect(finding.userExplanation).not.toContain(SIBLING_EXPLANATION);
      expect(finding.technicalExplanation).not.toContain('exception among protected siblings');
    }
  });
});

const PKG: [string, string] = [
  'package.json',
  '{"name":"x","dependencies":{"next":"14.0.0","next-auth":"4.24.0","@prisma/client":"5.0.0"}}',
];
const PRISMA: [string, string] = [
  'lib/prisma.js',
  'import { PrismaClient } from "@prisma/client";\nexport const prisma = new PrismaClient();\n',
];

const guarded = (model: string): string =>
  [
    'import { getServerSession } from "next-auth";',
    'import { prisma } from "../../../../lib/prisma";',
    '',
    'export async function POST(request) {',
    '  const session = await getServerSession();',
    '  if (!session) return new Response("Unauthorized", { status: 401 });',
    '  const body = await request.json();',
    `  await prisma.${model}.create({ data: { name: body.name } });`,
    '  return Response.json({ ok: true });',
    '}',
    '',
  ].join('\n');

const unguarded = (model: string): string =>
  [
    'import { prisma } from "../../../../lib/prisma";',
    '',
    'export async function POST(request) {',
    '  const body = await request.json();',
    `  await prisma.${model}.update({ where: { id: body.id }, data: { name: body.name } });`,
    '  return Response.json({ ok: true });',
    '}',
    '',
  ].join('\n');

describe('sibling inconsistency — the threshold', () => {
  it('declines with only ONE protected sibling', () => {
    const context = memoryContext([
      PKG,
      PRISMA,
      ['app/api/admin/users/route.js', guarded('user')],
      ['app/api/admin/settings/route.js', unguarded('setting')],
    ]);
    const forgotten = byPath(mutationFindings(context), 'app/api/admin/settings/route.js');
    expect(forgotten).toBeDefined();
    expect((forgotten as Finding).confidence).toBe('medium');
    expect((forgotten as Finding).userExplanation).toContain(GENERIC_EXPLANATION);
  });

  it('declines when one sibling is NOT protected, however many others are', () => {
    const context = memoryContext([
      PKG,
      PRISMA,
      ['app/api/admin/users/route.js', guarded('user')],
      ['app/api/admin/products/route.js', guarded('product')],
      ['app/api/admin/audit/route.js', unguarded('auditEntry')],
      ['app/api/admin/settings/route.js', unguarded('setting')],
    ]);
    for (const path of ['app/api/admin/settings/route.js', 'app/api/admin/audit/route.js']) {
      const finding = byPath(mutationFindings(context), path);
      expect(finding).toBeDefined();
      expect((finding as Finding).confidence).toBe('medium');
    }
  });

  it('declines across route folders — a protected neighbour elsewhere is not a sibling', () => {
    const context = memoryContext([
      PKG,
      PRISMA,
      ['app/api/billing/invoices/route.js', guarded('invoice')],
      ['app/api/billing/plans/route.js', guarded('plan')],
      ['app/api/admin/settings/route.js', unguarded('setting')],
    ]);
    const forgotten = byPath(mutationFindings(context), 'app/api/admin/settings/route.js');
    expect(forgotten).toBeDefined();
    expect((forgotten as Finding).confidence).toBe('medium');
  });
});

describe('siblingGroupOf', () => {
  it('is the route path minus its last segment', () => {
    expect(siblingGroupOf('/api/admin/settings')).toBe('/api/admin');
    expect(siblingGroupOf('/api/categories/[id]')).toBe('/api/categories');
    expect(siblingGroupOf('/api/categories')).toBe('/api');
    expect(siblingGroupOf('/login')).toBe('/');
    expect(siblingGroupOf('')).toBe('/');
  });
});
