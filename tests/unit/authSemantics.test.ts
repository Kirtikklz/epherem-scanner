import { describe, expect, it } from 'vitest';
import { effectiveGuardsInFile } from '../../src/project-map/buildProjectMap.js';
import { apiMutationWithoutAuth } from '../../src/rules/contextual/apiMutationWithoutAuth.js';
import { memoryContext } from './helpers.js';

const SUPABASE_IMPORT = "import { createClient } from '@supabase/supabase-js';\nconst supabase = createClient('https://x.supabase.co', 'anon');\n";

describe('auth semantics', () => {
  it('signIn/signUp are never protective', () => {
    const context = memoryContext([
      ['package.json', '{"name":"x"}'],
      [
        'pages/api/items.ts',
        SUPABASE_IMPORT +
          "export default async function handler(req, res) {\n" +
          "  signInWithPassword({ email: req.body.email });\n" +
          "  await supabase.from('items').insert(req.body);\n" +
          "  res.json({ ok: true });\n}\n",
      ],
    ]);
    expect(effectiveGuardsInFile(context.projectMap, 'pages/api/items.ts')).toHaveLength(0);
    const findings = apiMutationWithoutAuth.run(context);
    expect(findings.some((finding) => finding.filePath === 'pages/api/items.ts')).toBe(true);
  });

  it('an unchecked getSession() is not an effective guard', () => {
    const context = memoryContext([
      ['package.json', '{"name":"x"}'],
      [
        'pages/api/unchecked.ts',
        SUPABASE_IMPORT +
          "import { getServerSession } from 'next-auth';\n" +
          "export default async function handler(req, res) {\n" +
          '  getServerSession();\n' +
          '\n\n\n\n\n\n\n\n' +
          "  await supabase.from('items').delete().eq('id', req.query.id);\n" +
          '  res.json({ ok: true });\n}\n',
      ],
    ]);
    expect(effectiveGuardsInFile(context.projectMap, 'pages/api/unchecked.ts')).toHaveLength(0);
    expect(apiMutationWithoutAuth.run(context).length).toBeGreaterThan(0);
  });

  it('a checked session lookup IS an effective guard and suppresses the finding', () => {
    const context = memoryContext([
      ['package.json', '{"name":"x"}'],
      [
        'pages/api/checked.ts',
        SUPABASE_IMPORT +
          "import { getServerSession } from 'next-auth';\n" +
          'export default async function handler(req, res) {\n' +
          '  const session = await getServerSession();\n' +
          "  if (!session) return res.status(401).json({ error: 'unauthorized' });\n" +
          "  await supabase.from('items').insert(req.body);\n" +
          '  res.json({ ok: true });\n}\n',
      ],
    ]);
    expect(effectiveGuardsInFile(context.projectMap, 'pages/api/checked.ts').length).toBeGreaterThan(0);
    expect(apiMutationWithoutAuth.run(context)).toHaveLength(0);
  });

  it('reading a session and NOT blocking is not a guard (unsafe case)', () => {
    const context = memoryContext([
      ['package.json', '{"name":"x"}'],
      [
        'pages/api/pass-through.ts',
        SUPABASE_IMPORT +
          "import { getServerSession } from 'next-auth';\n" +
          'export default async function handler(req, res) {\n' +
          '  const session = await getServerSession();\n' +
          '  console.log(session);\n' +
          "  await supabase.from('items').delete().eq('id', req.query.id);\n" +
          '  return res.json({ ok: true });\n}\n',
      ],
    ]);
    expect(effectiveGuardsInFile(context.projectMap, 'pages/api/pass-through.ts')).toHaveLength(0);
    expect(apiMutationWithoutAuth.run(context).length).toBeGreaterThan(0);
  });

  it('a bare currentUser identifier is NOT protective (unsafe case)', () => {
    const context = memoryContext([
      ['package.json', '{"name":"x"}'],
      [
        'pages/api/fake-auth.ts',
        SUPABASE_IMPORT +
          'export default async function handler(req, res) {\n' +
          "  const currentUser = req.headers['x-user'];\n" +
          '  if (currentUser) {\n' +
          "    await supabase.from('items').delete().eq('id', req.query.id);\n" +
          '  }\n' +
          '  res.json({ ok: true });\n}\n',
      ],
    ]);
    expect(effectiveGuardsInFile(context.projectMap, 'pages/api/fake-auth.ts')).toHaveLength(0);
    expect(apiMutationWithoutAuth.run(context).length).toBeGreaterThan(0);
  });

  it('auth-sourced currentUser that is checked IS protective (safe cases)', () => {
    const firebaseStyle = memoryContext([
      ['package.json', '{"name":"x"}'],
      [
        'pages/api/firebase-guarded.ts',
        SUPABASE_IMPORT +
          "import { getAuth } from 'firebase-admin/auth';\n" +
          'export default async function handler(req, res) {\n' +
          '  const user = auth.currentUser;\n' +
          "  if (!user) return res.status(401).json({ error: 'unauthorized' });\n" +
          "  await supabase.from('items').insert(req.body);\n" +
          '  res.json({ ok: true });\n}\n',
      ],
    ]);
    expect(effectiveGuardsInFile(firebaseStyle.projectMap, 'pages/api/firebase-guarded.ts').length).toBeGreaterThan(0);
    expect(apiMutationWithoutAuth.run(firebaseStyle)).toHaveLength(0);

    const clerkStyle = memoryContext([
      ['package.json', '{"name":"x"}'],
      [
        'pages/api/clerk-guarded.ts',
        SUPABASE_IMPORT +
          "import { currentUser } from '@clerk/nextjs/server';\n" +
          'export default async function handler(req, res) {\n' +
          '  const user = await currentUser();\n' +
          "  if (!user) return res.status(401).json({ error: 'unauthorized' });\n" +
          "  await supabase.from('items').insert(req.body);\n" +
          '  res.json({ ok: true });\n}\n',
      ],
    ]);
    expect(apiMutationWithoutAuth.run(clerkStyle)).toHaveLength(0);
  });

  it('auth enforced in an imported module lowers confidence instead of suppressing', () => {
    const context = memoryContext([
      ['package.json', '{"name":"x"}'],
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
        SUPABASE_IMPORT +
          "import { requireUser } from '../../lib/requireUser';\n" +
          'export default async function handler(req, res) {\n' +
          "  await supabase.from('items').insert(req.body);\n" +
          '  res.json({ ok: true });\n}\n',
      ],
    ]);
    const findings = apiMutationWithoutAuth.run(context);
    const finding = findings.find((candidate) => candidate.filePath === 'pages/api/indirect.ts');
    expect(finding).toBeDefined();
    expect(finding?.confidence).toBe('low');
    expect(finding?.technicalExplanation).toContain('lib/requireUser.ts');
  });
});
