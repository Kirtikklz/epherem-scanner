import { describe, expect, it } from 'vitest';
import { sqlInjection } from '../../src/rules/basic/sqlInjection.js';
import { commandInjection } from '../../src/rules/basic/commandInjection.js';
import { crossSiteScripting } from '../../src/rules/basic/xss.js';
import { pathTraversal } from '../../src/rules/basic/pathTraversal.js';
import { openRedirect } from '../../src/rules/basic/openRedirect.js';
import { serverSideRequestForgery } from '../../src/rules/basic/ssrf.js';
import { nosqlInjection } from '../../src/rules/basic/nosqlInjection.js';
import {
  rhsForcesScalar,
  rhsIsGuaranteedScalarSource,
  rhsIsTypedObjectSchema,
  scalarSafeLocals,
} from '../../src/shared/sinkSafety.js';
import { memoryContext } from './helpers.js';

const PKG: [string, string] = ['package.json', '{"name":"x","dependencies":{"express":"^4.18.0","zod":"^3.22.0"}}'];
const MONGO: [string, string] = ['package.json', '{"name":"x","dependencies":{"express":"^4.18.0","zod":"^3.22.0","mongoose":"^8.0.0"}}'];

const wrap = (body: string) =>
  `import { z } from 'zod';\nimport fs from 'fs';\nimport path from 'path';\nexport async function handler(req, res){\n${body}\n}\n`;

function fired(rule: { run: (c: ReturnType<typeof memoryContext>) => unknown[] }, body: string, pkg = PKG): boolean {
  return rule.run(memoryContext([pkg, ['server/a.js', wrap(body)]])).length > 0;
}

describe('sink-specific sanitization: validation is not sanitization', () => {
  const cases: Array<[string, { run: (c: ReturnType<typeof memoryContext>) => unknown[] }, string, string]> = [
    [
      'SQL — parameter binding',
      sqlInjection,
      "  const v = z.string().parse(req.query.q);\n  return db.query(`SELECT * FROM t WHERE n = '${v}'`);",
      "  const v = z.string().parse(req.query.q);\n  return db.query('SELECT * FROM t WHERE n = $1', [v]);",
    ],
    [
      'Command — no shell / arg array',
      commandInjection,
      "  const v = z.string().parse(req.query.h);\n  return require('child_process').exec('ping ' + v);",
      "  const v = z.string().parse(req.query.h);\n  return require('child_process').execFile('ping', [v]);",
    ],
    [
      'XSS — HTML escaping',
      crossSiteScripting,
      "  const v = z.string().parse(req.query.name);\n  document.body.innerHTML = '<div>' + v + '</div>';",
      "  const v = DOMPurify.sanitize(req.query.name);\n  document.body.innerHTML = '<div>' + v + '</div>';",
    ],
    [
      'File path — canonicalize + confine',
      pathTraversal,
      "  const v = z.string().parse(req.query.f);\n  return fs.readFileSync('/data/' + v);",
      "  const v = path.basename(z.string().parse(req.query.f));\n  return fs.readFileSync('/data/' + v);",
    ],
    [
      'Redirect — allowlist',
      openRedirect,
      "  const v = z.string().url().parse(req.query.next);\n  return res.redirect(v);",
      "  const v = req.query.next;\n  if (!allowlist.includes(v)) throw new Error('bad');\n  return res.redirect(v);",
    ],
    [
      'SSRF — scheme/host validation',
      serverSideRequestForgery,
      "  const v = z.string().url().parse(req.body.url);\n  return fetch(v);",
      "  const u = new URL(req.body.url);\n  if (u.protocol !== 'https:' || allowedHosts.includes(u.hostname) === false) throw new Error('bad');\n  return fetch(u.href);",
    ],
  ];

  for (const [label, rule, validationOnly, sinkEvidence] of cases) {
    it(`${label}: schema validation alone does NOT clear the finding`, () => {
      expect(fired(rule, validationOnly)).toBe(true);
    });
    it(`${label}: sink-appropriate evidence DOES clear the finding`, () => {
      expect(fired(rule, sinkEvidence)).toBe(false);
    });
  }

  it('NoSQL: a field allowlist (pick) does NOT clear — values are still raw', () => {
    expect(fired(nosqlInjection, "  const v = pick(req.body, ['email']);\n  return User.findOne(v);", MONGO)).toBe(true);
  });
  it('NoSQL: a value scalar-forced by z.string() DOES clear', () => {
    expect(fired(nosqlInjection, "  const e = z.string().parse(req.body.email);\n  return User.findOne({ email: e });", MONGO)).toBe(false);
  });
  it('NoSQL: a typed object schema (strips unknown keys) DOES clear', () => {
    expect(fired(nosqlInjection, "  const v = z.object({ email: z.string() }).parse(req.body);\n  return User.findOne(v);", MONGO)).toBe(false);
  });
  it('NoSQL: $where fed request input stays CRITICAL despite validation in scope', () => {
    const found = nosqlInjection.run(
      memoryContext([MONGO, ['server/a.js', wrap("  z.string().parse(req.query.x);\n  return Account.find({ $where: req.body.filter });")]]),
    );
    expect(found).toHaveLength(1);
    expect((found[0] as { severity: string }).severity).toBe('critical');
  });
});

describe('sinkSafety model unit', () => {
  it('recognises scalar-forcing right-hand sides', () => {
    expect(rhsForcesScalar('z.string().parse(req.body.x)')).toBe(true);
    expect(rhsForcesScalar('z.coerce.number().parse(req.body.x)')).toBe(true);
    expect(rhsForcesScalar('String(req.body.x)')).toBe(true);
    expect(rhsForcesScalar('req.body.x.toLowerCase()')).toBe(true);
    expect(rhsForcesScalar("pick(req.body, ['email'])")).toBe(false);
    expect(rhsForcesScalar('z.object({ email: z.string() }).parse(req.body)')).toBe(false);
  });

  it('recognises a typed object schema as a field allowlist, but not passthrough/record', () => {
    expect(rhsIsTypedObjectSchema('z.object({ email: z.string() }).parse(req.body)')).toBe(true);
    expect(rhsIsTypedObjectSchema('z.object({ email: z.string() }).passthrough().parse(req.body)')).toBe(false);
    expect(rhsIsTypedObjectSchema('z.record(z.any()).parse(req.body)')).toBe(false);
  });

  it('recognises framework-guaranteed scalar sources, and only when params is a route param', () => {
    expect(rhsIsGuaranteedScalarSource('params.deck', true)).toBe(true);
    expect(rhsIsGuaranteedScalarSource('(await params).deck', true)).toBe(true);
    expect(rhsIsGuaranteedScalarSource("searchParams.get('q')", true)).toBe(true);
    expect(rhsIsGuaranteedScalarSource("req.nextUrl.searchParams.get('q')", false)).toBe(true);
    expect(rhsIsGuaranteedScalarSource('params.deck', false)).toBe(false);
    expect(rhsIsGuaranteedScalarSource('params', true)).toBe(false);
    expect(rhsIsGuaranteedScalarSource('req.body.deck', true)).toBe(false);
    expect(rhsIsGuaranteedScalarSource('await req.json()', true)).toBe(false);
  });

  it('treats Next route params as scalar-safe locals, including destructured ones', () => {
    const src =
      'export async function GET(req, { params }) {\n' +
      '  const courseId = params.course;\n' +
      '  const { deck: deckId, card } = params;\n' +
      "  const q = req.nextUrl.searchParams.get('q');\n" +
      '  const body = await req.json();\n' +
      '}\n';
    const safe = scalarSafeLocals(src);
    expect(safe.scalar.has('courseId')).toBe(true);
    expect(safe.scalar.has('deckId')).toBe(true);
    expect(safe.scalar.has('card')).toBe(true);
    expect(safe.scalar.has('q')).toBe(true);
    expect(safe.scalar.has('body')).toBe(false);
  });

  it('refuses the params source when params is not a route-handler binding', () => {
    const loose = scalarSafeLocals('const params = somethingElse;\nconst id = params.id;\n');
    expect(loose.scalar.has('id')).toBe(false);
    expect(loose.scalarSources).toHaveLength(1);

    const poisoned = scalarSafeLocals(
      'export async function POST(req, { params }) {\n  const params = req.body;\n  const id = params.id;\n}\n',
    );
    expect(poisoned.scalar.has('id')).toBe(false);
  });

  it('collects scalar-safe and typed-object locals from a file', () => {
    const src =
      'const a = z.string().parse(req.body.a);\n' +
      'const b = z.object({ x: z.string() }).parse(req.body);\n' +
      "const c = pick(req.body, ['x']);\n";
    const safe = scalarSafeLocals(src);
    expect(safe.scalar.has('a')).toBe(true);
    expect(safe.typedObject.has('b')).toBe(true);
    expect(safe.scalar.has('c')).toBe(false);
    expect(safe.typedObject.has('c')).toBe(false);
  });
});


describe('nosql: framework-guaranteed scalar sources', () => {
  const route = (body: string) =>
    "import { NextResponse } from 'next/server';\nimport Card from '@/models/Card.js';\n" +
    `export async function GET(req, { params }) {\n${body}\n}\n`;

  const firesIn = (body: string): boolean =>
    nosqlInjection.run(memoryContext([MONGO, ['app/api/x/route.js', route(body)]])).length > 0;

  it('clears a route param used as a filter value, written inline or via a local', () => {
    expect(firesIn('  return Card.find({ deckId: params.deck });')).toBe(false);
    expect(firesIn('  const deckId = params.deck;\n  return Card.find({ deckId: deckId });')).toBe(false);
    expect(firesIn('  const { deck: deckId } = params;\n  return Card.findOne({ _id: deckId });')).toBe(false);
    expect(firesIn("  const q = req.nextUrl.searchParams.get('q');\n  return Card.find({ name: q });")).toBe(false);
  });

  it('STILL fires on a request body value in the same file shape', () => {
    expect(firesIn('  const data = await req.json();\n  return Card.findOne({ email: data.email });')).toBe(true);
    expect(firesIn('  const deckId = params.deck;\n  const d = await req.json();\n  return Card.find({ deckId: deckId, tag: d.tag });')).toBe(true);
  });

  it('STILL fires on the classic Express body-object query', () => {
    const goof =
      "const User = require('mongoose').model('User');\n" +
      'app.post("/login", function (req, res) {\n' +
      '  User.find({ username: req.body.username, password: req.body.password }, function (err, users) {});\n' +
      '});\n';
    expect(nosqlInjection.run(memoryContext([MONGO, ['routes/index.js', goof]])).length).toBe(1);
  });

  it('does NOT trust params in a file that never binds it as a route parameter', () => {
    const sneaky =
      "const User = require('mongoose').model('User');\n" +
      'app.post("/x", function (req, res) {\n' +
      '  const params = req.body;\n' +
      '  User.findOne({ email: params.email });\n' +
      '});\n';
    expect(nosqlInjection.run(memoryContext([MONGO, ['routes/x.js', sneaky]])).length).toBe(1);
  });
});
