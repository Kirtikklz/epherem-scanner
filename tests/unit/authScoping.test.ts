import { describe, expect, it } from 'vitest';
import { apiMutationWithoutAuth } from '../../src/rules/contextual/apiMutationWithoutAuth.js';
import { effectiveGuardsInFile } from '../../src/project-map/buildProjectMap.js';
import { memoryContext } from './helpers.js';

const SUPA =
  "import { createClient } from '@supabase/supabase-js';\n" +
  "const supabase = createClient('https://x.supabase.co', 'anon');\n";
const PKG: [string, string] = ['package.json', '{"name":"x","dependencies":{"express":"4.19.0","next":"14.0.0"}}'];

describe('auth analysis is route/handler scoped', () => {
  it('a guard in ONE express handler does not suppress a finding in ANOTHER handler', () => {
    const file =
      SUPA +
      "import { getServerSession } from 'next-auth';\n" +
      'export default function mount(app) {\n' +
      "  app.post('/safe', async (req, res) => {\n" +
      '    const session = await getServerSession();\n' +
      "    if (!session) return res.status(401).json({ error: 'no' });\n" +
      "    await supabase.from('items').insert(req.body);\n" +
      '    res.json({ ok: true });\n' +
      '  });\n' +
      "  app.post('/unsafe', async (req, res) => {\n" +
      "    await supabase.from('items').delete().eq('id', req.query.id);\n" +
      '    res.json({ ok: true });\n' +
      '  });\n' +
      '}\n';
    const context = memoryContext([PKG, ['routes/api.js', file]]);
    const findings = apiMutationWithoutAuth.run(context).filter((f) => f.filePath === 'routes/api.js');
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toMatch(/delete/);
    expect(findings[0]?.evidence).not.toMatch(/insert/);
  });

  it('two unguarded handlers each produce a finding', () => {
    const file =
      SUPA +
      'export default function mount(app) {\n' +
      "  app.post('/a', async (req, res) => { await supabase.from('t').insert(req.body); res.json({}); });\n" +
      "  app.post('/b', async (req, res) => { await supabase.from('t').delete().eq('id', req.query.id); res.json({}); });\n" +
      '}\n';
    const context = memoryContext([PKG, ['routes/two.js', file]]);
    const findings = apiMutationWithoutAuth.run(context).filter((f) => f.filePath === 'routes/two.js');
    expect(findings.length).toBe(2);
  });
});

describe('guards must be REAL, not comments/strings/unrelated actions', () => {
  it('a guard written in a comment does not protect the handler', () => {
    const file =
      SUPA +
      'export default async function handler(req, res) {\n' +
      '  // if (!session) return res.status(401).json({ error: "no" });\n' +
      '  /* const session = await getServerSession(); if (!session) throw new Error("401"); */\n' +
      "  await supabase.from('items').insert(req.body);\n" +
      '  res.json({ ok: true });\n}\n';
    const context = memoryContext([PKG, ['pages/api/commented.ts', file]]);
    expect(effectiveGuardsInFile(context.projectMap, 'pages/api/commented.ts')).toHaveLength(0);
    expect(apiMutationWithoutAuth.run(context).some((f) => f.filePath === 'pages/api/commented.ts')).toBe(true);
  });

  it('a guard-looking string literal does not protect the handler', () => {
    const file =
      SUPA +
      'export default async function handler(req, res) {\n' +
      '  const msg = "if (!session) return res.status(401)";\n' +
      "  await supabase.from('items').delete().eq('id', req.query.id);\n" +
      '  res.json({ ok: true, msg });\n}\n';
    const context = memoryContext([PKG, ['pages/api/stringguard.ts', file]]);
    expect(apiMutationWithoutAuth.run(context).some((f) => f.filePath === 'pages/api/stringguard.ts')).toBe(true);
  });

  it('an unused session lookup (never checked) does not protect the handler', () => {
    const file =
      SUPA +
      "import { getServerSession } from 'next-auth';\n" +
      'export default async function handler(req, res) {\n' +
      '  const session = await getServerSession();\n' +
      '  console.log(session);\n' +
      "  await supabase.from('items').insert(req.body);\n" +
      '  res.json({ ok: true });\n}\n';
    const context = memoryContext([PKG, ['pages/api/unused.ts', file]]);
    expect(effectiveGuardsInFile(context.projectMap, 'pages/api/unused.ts')).toHaveLength(0);
    expect(apiMutationWithoutAuth.run(context).some((f) => f.filePath === 'pages/api/unused.ts')).toBe(true);
  });

  it('an unrelated redirect (not tied to an auth conditional) does not protect the handler', () => {
    const file =
      SUPA +
      "import { getServerSession } from 'next-auth';\n" +
      'export default async function handler(req, res) {\n' +
      '  const session = await getServerSession();\n' +
      "  if (req.query.go) res.redirect('/dashboard');\n" +
      "  await supabase.from('items').delete().eq('id', req.query.id);\n" +
      '  res.json({ ok: true });\n}\n';
    const context = memoryContext([PKG, ['pages/api/redir.ts', file]]);
    expect(effectiveGuardsInFile(context.projectMap, 'pages/api/redir.ts')).toHaveLength(0);
    expect(apiMutationWithoutAuth.run(context).some((f) => f.filePath === 'pages/api/redir.ts')).toBe(true);
  });
});

describe('guards reached through imports (transitive + tsconfig aliases)', () => {
  it('a guard in a directly imported helper lowers confidence (does not suppress)', () => {
    const context = memoryContext([
      PKG,
      [
        'lib/requireUser.ts',
        "import { getServerSession } from 'next-auth';\n" +
          'export async function requireUser() {\n' +
          '  const session = await getServerSession();\n' +
          "  if (!session) throw new Error('unauthorized');\n" +
          '  return session.user;\n}\n',
      ],
      [
        'pages/api/indirect.ts',
        SUPA +
          "import { requireUser } from '../../lib/requireUser';\n" +
          'export default async function handler(req, res) {\n' +
          "  await supabase.from('items').insert(req.body);\n" +
          '  res.json({ ok: true });\n}\n',
      ],
    ]);
    const finding = apiMutationWithoutAuth.run(context).find((f) => f.filePath === 'pages/api/indirect.ts');
    expect(finding?.confidence).toBe('low');
    expect(finding?.technicalExplanation).toContain('lib/requireUser.ts');
  });

  it('a guard reached TRANSITIVELY through a re-export is still found', () => {
    const context = memoryContext([
      PKG,
      [
        'lib/guard.ts',
        "import { getServerSession } from 'next-auth';\n" +
          'export async function requireUser() {\n' +
          '  const session = await getServerSession();\n' +
          "  if (!session) throw new Error('unauthorized');\n" +
          '  return session;\n}\n',
      ],
      ['lib/index.ts', "export { requireUser } from './guard';\n"],
      [
        'pages/api/trans.ts',
        SUPA +
          "import { requireUser } from '../../lib/index';\n" +
          'export default async function handler(req, res) {\n' +
          "  await supabase.from('items').insert(req.body);\n" +
          '  res.json({ ok: true });\n}\n',
      ],
    ]);
    const finding = apiMutationWithoutAuth.run(context).find((f) => f.filePath === 'pages/api/trans.ts');
    expect(finding?.confidence).toBe('low');
    expect(finding?.technicalExplanation).toContain('lib/guard.ts');
  });

  it('a guard imported via a tsconfig path alias is resolved and found', () => {
    const context = memoryContext([
      ['package.json', '{"name":"x","dependencies":{"next":"14.0.0"}}'],
      ['tsconfig.json', JSON.stringify({ compilerOptions: { baseUrl: '.', paths: { '@lib/*': ['src/lib/*'] } } })],
      [
        'src/lib/auth.ts',
        "import { getServerSession } from 'next-auth';\n" +
          'export async function requireUser() {\n' +
          '  const session = await getServerSession();\n' +
          "  if (!session) throw new Error('unauthorized');\n" +
          '  return session;\n}\n',
      ],
      [
        'src/pages/api/aliased.ts',
        SUPA +
          "import { requireUser } from '@lib/auth';\n" +
          'export default async function handler(req, res) {\n' +
          "  await supabase.from('items').insert(req.body);\n" +
          '  res.json({ ok: true });\n}\n',
      ],
    ]);
    const finding = apiMutationWithoutAuth.run(context).find((f) => f.filePath === 'src/pages/api/aliased.ts');
    expect(finding?.confidence).toBe('low');
    expect(finding?.technicalExplanation).toContain('src/lib/auth.ts');
  });
});


