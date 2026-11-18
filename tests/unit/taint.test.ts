import { describe, expect, it } from 'vitest';
import { analyzeTaint, classifyExpression, TaintMap, usesUserInput } from '../../src/shared/taint.js';

describe('taint helper', () => {
  it('classifies request sources as user and identity sources as trusted', () => {
    const m = new TaintMap();
    expect(classifyExpression('req.query.next', m)).toBe('user');
    expect(classifyExpression('req.body.userId', m)).toBe('user');
    expect(classifyExpression('session.user.id', m)).toBe('trusted');
    expect(classifyExpression('req.session.userId', m)).toBe('trusted');
    expect(classifyExpression('auth.currentUser', m)).toBe('trusted');
    expect(classifyExpression('getUser(req.query.id)', m)).toBe('user');
  });

  it('credits getAuth(req) as a session identity but never a request-fed one', () => {
    const m = new TaintMap();
    expect(classifyExpression('getAuth(req)', m)).toBe('trusted');
    expect(classifyExpression('getAuth(request)', m)).toBe('trusted');
    expect(classifyExpression('getAuth(req as NextRequest)', m)).toBe('trusted');
    expect(classifyExpression('getAuth(req.body.userId)', m)).toBe('user');
    expect(classifyExpression('getAuth(req.query.userId)', m)).toBe('user');
    expect(classifyExpression('getAuth(firebaseApp)', m)).toBe('unknown');
    expect(classifyExpression('getAuth(app)', m)).toBe('unknown');
  });

  it('binds the destructured Clerk userId as trusted, and a rebind takes it back', () => {
    const m = analyzeTaint(
      'const { userId } = getAuth(req);\n' +
        'const { userId: ownerId } = getAuth(req);\n' +
        'const claimed = req.body.userId;\n',
    );
    expect(m.get('userId')).toBe('trusted');
    expect(m.get('ownerId')).toBe('trusted');
    expect(m.get('claimed')).toBe('user');

    const rebound = analyzeTaint(
      'const { userId } = getAuth(req);\n' +
        'const invited = await User.findOne({ email: req.body.email });\n' +
        'const { clerkId: userId } = invited;\n',
    );
    expect(rebound.get('userId')).not.toBe('trusted');
  });

  it('tracks assignments, destructuring and aliases', () => {
    const m = analyzeTaint(
      'const next = req.query.next;\n' +
        'const { id, userId } = req.body;\n' +
        'const s = await getServerSession();\n' +
        'const trustedId = s.user.id;\n' +
        'const alias = next;\n',
    );
    expect(m.get('next')).toBe('user');
    expect(m.get('id')).toBe('user');
    expect(m.get('userId')).toBe('user');
    expect(m.get('trustedId')).toBe('trusted');
    expect(m.get('alias')).toBe('user');
  });

  it('a request value aliased as `currentUser` stays user-controlled', () => {
    const m = analyzeTaint('const currentUser = req.query.userId;\n');
    expect(m.get('currentUser')).toBe('user');
    expect(classifyExpression('currentUser', m)).toBe('user');
  });
});

describe('function-scoped taint', () => {
  const offsetOfLine = (source: string, line: number): number => {
    let offset = 0;
    for (let current = 1; current < line; current += 1) offset = source.indexOf('\n', offset) + 1;
    return offset;
  };

  it('(a) does not bleed a tainted name into a sibling function', () => {
    const source =
      'export async function PUT(req) {\n' +
      '  const data = await req.json();\n' +
      '  let studentId = data.studentId || userId;\n' +
      '  await Course.updateOne({ _id: id }, { $pull: { studentIds: studentId } });\n' +
      '}\n' +
      'export async function GET(req) {\n' +
      '  const rows = await Promise.all(ids.map(async (studentId) => {\n' +
      '    return User.findOne({ clerkId: studentId });\n' +
      '  }));\n' +
      '}\n';
    const map = analyzeTaint(source);
    const inPut = offsetOfLine(source, 4);
    const inGet = offsetOfLine(source, 8);

    expect(map.kindAt('studentId', inPut)).toBe('user');
    expect(map.kindAt('studentId', inGet)).toBeUndefined();
    expect(classifyExpression('studentId', map, inGet)).toBe('unknown');
    expect(usesUserInput('User.findOne({ clerkId: studentId })', map, inGet)).toBe(false);
    expect(map.kindAt('data', inGet)).toBeUndefined();
  });

  it('(b) still taints within the same function and inside a nested scope', () => {
    const source =
      'export async function POST(req) {\n' +
      '  const id = req.query.id;\n' +
      '  sink(id);\n' +
      '  items.forEach((item) => {\n' +
      '    sink(id);\n' +
      '  });\n' +
      '}\n';
    const map = analyzeTaint(source);
    expect(map.kindAt('id', offsetOfLine(source, 3))).toBe('user');
    expect(map.kindAt('id', offsetOfLine(source, 5))).toBe('user');
    expect(usesUserInput('sink(id)', map, offsetOfLine(source, 5))).toBe(true);
    const blocky = 'export function POST(req) {\n  if (x) {\n    const id = req.query.id;\n  }\n  sink(id);\n}\n';
    expect(analyzeTaint(blocky).kindAt('id', offsetOfLine(blocky, 5))).toBe('user');
  });

  it('(c) still catches request input read directly at the sink', () => {
    const source =
      'export async function A(req) {\n  const id = req.query.id;\n}\n' +
      'export async function B(req) {\n  sink(req.body.path);\n}\n';
    const map = analyzeTaint(source);
    const inB = offsetOfLine(source, 5);
    expect(map.kindAt('id', inB)).toBeUndefined();
    expect(usesUserInput('sink(req.body.path)', map, inB)).toBe(true);
    expect(classifyExpression('req.body.path', map, inB)).toBe('user');
  });

  it('keeps a module-scope binding visible inside every function', () => {
    const source =
      'const shared = req.query.x;\n' +
      'export function A() {\n  sink(shared);\n}\n' +
      'export function B() {\n  sink(shared);\n}\n';
    const map = analyzeTaint(source);
    expect(map.kindAt('shared', offsetOfLine(source, 3))).toBe('user');
    expect(map.kindAt('shared', offsetOfLine(source, 6))).toBe('user');
  });

  it('lets an inner binding shadow an outer one, inside the inner scope only', () => {
    const source =
      'export function A(req) {\n' +
      '  const id = req.query.id;\n' +
      '  run(() => {\n' +
      '    const id = SAFE_CONSTANT;\n' +
      '    sink(id);\n' +
      '  });\n' +
      '  sink(id);\n' +
      '}\n';
    const map = analyzeTaint(source);
    expect(map.kindAt('id', offsetOfLine(source, 5))).toBe('unknown');
    expect(map.kindAt('id', offsetOfLine(source, 7))).toBe('user');
  });

  it('falls back to file-wide scope when the braces do not balance', () => {
    const source =
      'export function A(req) {\n' +
      '  const id = req.query.id;\n' +
      '}\n' +
      'export function B() {\n' +
      '  sink(id);\n' +
      '}\n' +
      '}\n';
    const map = analyzeTaint(source);
    expect(map.kindAt('id', offsetOfLine(source, 5))).toBe('user');
  });

  it('does not treat a control-flow block as a function scope', () => {
    for (const head of ['if (ok)', 'for (const x of xs)', 'while (ok)', 'switch (k)']) {
      const source = `export function A(req) {\n  ${head} {\n    const id = req.query.id;\n  }\n  sink(id);\n}\n`;
      expect(analyzeTaint(source).kindAt('id', offsetOfLine(source, 5))).toBe('user');
    }
  });

  it('recognises a TypeScript-annotated function body as a scope', () => {
    const source =
      'export async function A(req: Request): Promise<void> {\n' +
      '  const id = req.query.id;\n' +
      '}\n' +
      'export async function B(): Promise<void> {\n' +
      '  sink(id);\n' +
      '}\n';
    expect(analyzeTaint(source).kindAt('id', offsetOfLine(source, 5))).toBeUndefined();
  });
});
