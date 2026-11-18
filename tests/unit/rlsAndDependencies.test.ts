import { describe, expect, it } from 'vitest';
import { detectSupabaseRls } from '../../src/project-map/detectRls.js';
import { supabaseClientPrivilegedOperation } from '../../src/rules/contextual/supabaseClientPrivilegedOperation.js';
import { supabaseRlsNotDetected } from '../../src/rules/contextual/supabaseRlsNotDetected.js';
import { collectDependencies } from '../../src/stack-detection/collectDependencies.js';
import { loadFixtureContext, memoryContext } from './helpers.js';

const CLIENT_SUPABASE_FILE: [string, string] = [
  'components/Notes.tsx',
  "'use client';\nimport { createClient } from '@supabase/supabase-js';\n" +
    "const supabase = createClient('https://x.supabase.co', 'anon');\n" +
    "export function addNote(text: string) { return supabase.from('notes').insert({ text }); }\n",
];
const PACKAGE_JSON: [string, string] = [
  'package.json',
  '{"name":"x","dependencies":{"@supabase/supabase-js":"2.45.0"}}',
];

describe('RLS detection', () => {
  it('extracts RLS-enabled tables and policies from SQL', () => {
    const { fileMap } = memoryContext([
      PACKAGE_JSON,
      [
        'supabase/migrations/0001.sql',
        'ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n' +
          'CREATE POLICY "own notes" ON notes FOR ALL USING (auth.uid() = user_id);\n' +
          'CREATE TABLE public.other (id uuid);\n' +
          'ALTER TABLE public.other ENABLE ROW LEVEL SECURITY;\n',
      ],
    ]);
    const rls = detectSupabaseRls(fileMap);
    expect(rls.rlsEnabledTables).toEqual(['notes', 'other']);
    expect(rls.policyTables).toEqual(['notes']);
    expect(rls.sqlFileCount).toBe(1);
  });

  it('supabase_rls_not_detected fires when client calls exist and SQL shows no RLS', async () => {
    const context = await loadFixtureContext('next-supabase-insecure');
    const findings = supabaseRlsNotDetected.run(context);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.confidence).toBe('medium');
  });

  it('one protected table does NOT hide a different unprotected table (per-table evaluation)', () => {
    const context = memoryContext([
      PACKAGE_JSON,
      [
        'components/Mixed.tsx',
        "'use client';\nimport { createClient } from '@supabase/supabase-js';\n" +
          "const supabase = createClient('https://x.supabase.co', 'anon');\n" +
          "export function addNote(text: string) { return supabase.from('notes').insert({ text }); }\n" +
          "export function addComment(text: string) { return supabase.from('comments').insert({ text }); }\n",
      ],
      ['supabase/migrations/0001.sql', 'ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\nCREATE POLICY p ON notes USING (auth.uid() = user_id);\n'],
    ]);
    const findings = supabaseRlsNotDetected.run(context);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.title).toContain('comments');
    expect(findings[0]?.evidence).toContain('comments');
    expect(findings[0]?.confidence).toBe('medium');
  });

  it('all client-touched tables protected: no findings (safe case)', () => {
    const context = memoryContext([
      PACKAGE_JSON,
      [
        'components/Mixed.tsx',
        "'use client';\nimport { createClient } from '@supabase/supabase-js';\n" +
          "const supabase = createClient('https://x.supabase.co', 'anon');\n" +
          "export function addNote(text: string) { return supabase.from('notes').insert({ text }); }\n" +
          "export function addComment(text: string) { return supabase.from('comments').insert({ text }); }\n",
      ],
      [
        'supabase/migrations/0001.sql',
        'ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\nALTER TABLE comments ENABLE ROW LEVEL SECURITY;\n' +
          'CREATE POLICY p1 ON notes USING (auth.uid() = user_id);\nCREATE POLICY p2 ON comments USING (auth.uid() = user_id);\n',
      ],
    ]);
    expect(supabaseRlsNotDetected.run(context)).toHaveLength(0);
  });

  it('supabase_rls_not_detected stays quiet when RLS is present', () => {
    const context = memoryContext([
      PACKAGE_JSON,
      CLIENT_SUPABASE_FILE,
      ['supabase/migrations/0001.sql', 'ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\nCREATE POLICY p ON notes USING (auth.uid() = user_id);\n'],
    ]);
    expect(supabaseRlsNotDetected.run(context)).toHaveLength(0);
  });

  describe('supabase_client_used_for_privileged_operation', () => {
    it('FP regression: silent when the governing policy is scoped to auth.uid()', () => {
      const context = memoryContext([
        PACKAGE_JSON,
        CLIENT_SUPABASE_FILE,
        [
          'supabase/migrations/0001.sql',
          'ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\nCREATE POLICY p ON notes USING (auth.uid() = user_id);\n',
        ],
      ]);
      expect(supabaseClientPrivilegedOperation.run(context)).toHaveLength(0);
    });

    it('FP regression: many call sites on one defective policy collapse to ONE finding', () => {
      const context = memoryContext([
        PACKAGE_JSON,
        [
          'components/Many.tsx',
          "'use client';\nimport { createClient } from '@supabase/supabase-js';\n" +
            "const supabase = createClient('https://x.supabase.co', 'anon');\n" +
            "export function a(t: string) { return supabase.from('notes').insert({ t }); }\n" +
            "export function b(t: string) { return supabase.from('notes').insert({ t }); }\n" +
            "export function c(t: string) { return supabase.from('notes').insert({ t }); }\n",
        ],
        [
          'supabase/migrations/0001.sql',
          'ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\nCREATE POLICY p ON notes FOR INSERT WITH CHECK (true);\n',
        ],
      ]);
      const findings = supabaseClientPrivilegedOperation.run(context);
      expect(findings).toHaveLength(1);
      expect(findings[0]?.evidence).toContain('3 client call site(s)');
    });

    it('TP retention: still fires when the table has no RLS at all', () => {
      const context = memoryContext([
        PACKAGE_JSON,
        CLIENT_SUPABASE_FILE,
        ['supabase/migrations/0001.sql', 'CREATE TABLE notes (id uuid);\n'],
      ]);
      const findings = supabaseClientPrivilegedOperation.run(context);
      expect(findings).toHaveLength(1);
      expect(findings[0]?.technicalExplanation).toContain('No ENABLE ROW LEVEL SECURITY');
    });

    it('TP retention: fires on WITH CHECK (true) — the defect the old rule missed', () => {
      const context = memoryContext([
        PACKAGE_JSON,
        CLIENT_SUPABASE_FILE,
        [
          'supabase/migrations/0001.sql',
          'ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n' +
            'CREATE POLICY strict ON notes FOR SELECT USING (auth.uid() = user_id);\n' +
            'CREATE POLICY loose ON notes FOR INSERT WITH CHECK (true);\n',
        ],
      ]);
      const findings = supabaseClientPrivilegedOperation.run(context);
      expect(findings).toHaveLength(1);
      expect(findings[0]?.confidence).toBe('high');
      expect(findings[0]?.technicalExplanation).toContain('WITH CHECK (true)');
    });

    it('TP retention: fires when RLS was explicitly disabled, at critical', () => {
      const context = memoryContext([
        PACKAGE_JSON,
        CLIENT_SUPABASE_FILE,
        [
          'supabase/migrations/0001.sql',
          'ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n' +
            'CREATE POLICY p ON notes USING (auth.uid() = user_id);\n' +
            'ALTER TABLE notes DISABLE ROW LEVEL SECURITY;\n',
        ],
      ]);
      const findings = supabaseClientPrivilegedOperation.run(context);
      expect(findings).toHaveLength(1);
      expect(findings[0]?.severity).toBe('critical');
    });

    it('TP retention: fires when an identity-scoped policy leaves a role column unconstrained', () => {
      const context = memoryContext([
        PACKAGE_JSON,
        CLIENT_SUPABASE_FILE,
        [
          'supabase/migrations/0001.sql',
          'CREATE TABLE notes (id uuid, user_id uuid, role text);\n' +
            'ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n' +
            'CREATE POLICY p ON notes FOR INSERT WITH CHECK (auth.uid() = user_id);\n',
        ],
      ]);
      const findings = supabaseClientPrivilegedOperation.run(context);
      expect(findings).toHaveLength(1);
      expect(findings[0]?.technicalExplanation).toContain('role');
    });

    it('TP retention: an unparsable policy must not be read as enforcement', () => {
      const context = memoryContext([
        PACKAGE_JSON,
        CLIENT_SUPABASE_FILE,
        [
          'supabase/migrations/0001.sql',
          'ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n' +
            'CREATE POLICY p ON notes USING (auth.uid() = user_id);\n' +
            'CREATE POLICY broken FOR SELECT USING (auth.uid() = user_id);\n',
        ],
      ]);
      expect(supabaseClientPrivilegedOperation.run(context)).toHaveLength(1);
    });

    it('FP regression: a policy NAME containing "on <word>" does not become the table', () => {
      const { fileMap } = memoryContext([
        PACKAGE_JSON,
        [
          'supabase/migrations/0001.sql',
          'ALTER TABLE reviews ENABLE ROW LEVEL SECURITY;\n' +
            'CREATE POLICY "Participants can create review on completed transaction"\n' +
            '  ON public.reviews FOR INSERT\n' +
            '  WITH CHECK (auth.uid() = rater_id);\n',
        ],
      ]);
      const rls = detectSupabaseRls(fileMap);
      expect(rls.policyTables).toEqual(['reviews']);
      expect(rls.policies[0]?.command).toBe('insert');
      expect(rls.policies[0]?.identityScoped).toBe(true);
      expect(rls.unparsedPolicyCount).toBe(0);
    });

    it('FP regression: silent when the policy the NAME used to hide is identity-scoped', () => {
      const context = memoryContext([
        PACKAGE_JSON,
        CLIENT_SUPABASE_FILE,
        [
          'supabase/migrations/0001.sql',
          'ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n' +
            'CREATE POLICY "Members can insert a note on any shared board"\n' +
            "  ON notes FOR INSERT WITH CHECK (auth.uid() = user_id);\n",
        ],
      ]);
      expect(supabaseClientPrivilegedOperation.run(context)).toHaveLength(0);
    });

    it('an unquoted policy name is consumed too, and a doubled quote inside one', () => {
      const { fileMap } = memoryContext([
        PACKAGE_JSON,
        [
          'supabase/migrations/0001.sql',
          'CREATE POLICY own_notes ON notes FOR ALL USING (auth.uid() = user_id);\n' +
            'CREATE POLICY "the user""s own rows on demand" ON other FOR SELECT USING (auth.uid() = user_id);\n',
        ],
      ]);
      const rls = detectSupabaseRls(fileMap);
      expect(rls.policyTables).toEqual(['notes', 'other']);
      expect(rls.unparsedPolicyCount).toBe(0);
    });

    it('FP regression: silent when RLS is on and NO policy grants the command (default-deny)', () => {
      const context = memoryContext([
        PACKAGE_JSON,
        [
          'components/Delete.tsx',
          "'use client';\nimport { createClient } from '@supabase/supabase-js';\n" +
            "const supabase = createClient('https://x.supabase.co', 'anon');\n" +
            "export function drop(id: string) { return supabase.from('notes').delete().eq('id', id); }\n",
        ],
        [
          'supabase/migrations/0001.sql',
          'ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n' +
            'CREATE POLICY p ON notes FOR SELECT USING (auth.uid() = user_id);\n',
        ],
      ]);
      expect(supabaseClientPrivilegedOperation.run(context)).toHaveLength(0);
    });

    it('TP retention: default-deny credit needs RLS ON — an unprotected table still fires', () => {
      const context = memoryContext([
        PACKAGE_JSON,
        [
          'components/Delete.tsx',
          "'use client';\nimport { createClient } from '@supabase/supabase-js';\n" +
            "const supabase = createClient('https://x.supabase.co', 'anon');\n" +
            "export function drop(id: string) { return supabase.from('notes').delete().eq('id', id); }\n",
        ],
        ['supabase/migrations/0001.sql', 'CREATE TABLE notes (id uuid);\n'],
      ]);
      const findings = supabaseClientPrivilegedOperation.run(context);
      expect(findings).toHaveLength(1);
      expect(findings[0]?.technicalExplanation).toContain('No ENABLE ROW LEVEL SECURITY');
    });

    it('TP retention: default-deny credit is withdrawn when RLS was later disabled', () => {
      const context = memoryContext([
        PACKAGE_JSON,
        [
          'components/Delete.tsx',
          "'use client';\nimport { createClient } from '@supabase/supabase-js';\n" +
            "const supabase = createClient('https://x.supabase.co', 'anon');\n" +
            "export function drop(id: string) { return supabase.from('notes').delete().eq('id', id); }\n",
        ],
        [
          'supabase/migrations/0001.sql',
          'ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n' +
            'CREATE POLICY p ON notes FOR SELECT USING (auth.uid() = user_id);\n' +
            'ALTER TABLE notes DISABLE ROW LEVEL SECURITY;\n',
        ],
      ]);
      const findings = supabaseClientPrivilegedOperation.run(context);
      expect(findings).toHaveLength(1);
      expect(findings[0]?.severity).toBe('critical');
    });

    it('TP retention: an unparsed policy anywhere withdraws the default-deny credit too', () => {
      const context = memoryContext([
        PACKAGE_JSON,
        [
          'components/Delete.tsx',
          "'use client';\nimport { createClient } from '@supabase/supabase-js';\n" +
            "const supabase = createClient('https://x.supabase.co', 'anon');\n" +
            "export function drop(id: string) { return supabase.from('notes').delete().eq('id', id); }\n",
        ],
        [
          'supabase/migrations/0001.sql',
          'ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n' +
            'CREATE POLICY p ON notes FOR SELECT USING (auth.uid() = user_id);\n' +
            'CREATE POLICY broken FOR DELETE USING (auth.uid() = user_id);\n',
        ],
      ]);
      expect(supabaseClientPrivilegedOperation.run(context)).toHaveLength(1);
    });

    it('finding order is stable across repeated runs', () => {
      const context = memoryContext([
        PACKAGE_JSON,
        [
          'components/Two.tsx',
          "'use client';\nimport { createClient } from '@supabase/supabase-js';\n" +
            "const supabase = createClient('https://x.supabase.co', 'anon');\n" +
            "export function a(t: string) { return supabase.from('alpha').insert({ t }); }\n" +
            "export function b(t: string) { return supabase.from('beta').insert({ t }); }\n",
        ],
      ]);
      const first = supabaseClientPrivilegedOperation.run(context).map((finding) => finding.id);
      const second = supabaseClientPrivilegedOperation.run(context).map((finding) => finding.id);
      expect(first).toHaveLength(2);
      expect(second).toEqual(first);
    });
  });
});

describe('dependency collection (manifests + lockfiles)', () => {
  it('merges package.json and package-lock.json, preferring exact versions', () => {
    const { fileMap } = memoryContext([
      ['package.json', '{"name":"x","dependencies":{"express":"^4.19.0"}}'],
      [
        'package-lock.json',
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            '': { name: 'x' },
            'node_modules/express': { version: '4.19.2' },
            'node_modules/@scoped/pkg': { version: '1.2.3' },
          },
        }),
      ],
    ]);
    const dependencies = collectDependencies(fileMap);
    const names = dependencies.map((dependency) => dependency.name);
    expect(names).toContain('express');
    expect(names).toContain('@scoped/pkg');
    const express = dependencies.find((dependency) => dependency.name === 'express');
    expect(express?.installedVersion).toBe('4.19.2');
    expect(express?.lockfile).toBe('package-lock.json');
    expect(express?.declaredRange).toBe('^4.19.0');
    expect(express?.declaredIn).toBe('package.json');
    expect(dependencies.find((dependency) => dependency.name === '@scoped/pkg')?.installedVersion).toBe('1.2.3');
  });

  it('without a lockfile there is NO installed version — a range is never coerced', () => {
    const { fileMap } = memoryContext([
      ['package.json', '{"name":"x","dependencies":{"express":"^4.19.0"}}'],
    ]);
    const express = collectDependencies(fileMap).find((dependency) => dependency.name === 'express');
    expect(express?.installedVersion).toBeUndefined();
    expect(express?.declaredRange).toBe('^4.19.0');
    expect(express?.source).toBe('package.json');
  });

  it('yarn.lock exact version overrides the manifest range', () => {
    const { fileMap } = memoryContext([
      ['package.json', '{"name":"x","dependencies":{"react":"^18.0.0"}}'],
      ['yarn.lock', '# yarn lockfile v1\n\nreact@^18.0.0:\n  version "18.3.1"\n'],
    ]);
    const react = collectDependencies(fileMap).find((dependency) => dependency.name === 'react');
    expect(react?.installedVersion).toBe('18.3.1');
    expect(react?.declaredRange).toBe('^18.0.0');
  });

  it('parses yarn.lock entries', () => {
    const { fileMap } = memoryContext([
      ['package.json', '{"name":"x"}'],
      ['yarn.lock', '# yarn lockfile v1\n\nreact@^18.0.0:\n  version "18.3.1"\n  resolved "https://registry.example/react"\n'],
    ]);
    const dependencies = collectDependencies(fileMap);
    expect(dependencies.find((dependency) => dependency.name === 'react')?.installedVersion).toBe('18.3.1');
  });

  it('lockfile dependencies feed stack detection', () => {
    const context = memoryContext([
      ['package.json', '{"name":"x"}'],
      [
        'package-lock.json',
        JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/express': { version: '4.19.2' } } }),
      ],
      ['server.js', 'const app = require("express")();\napp.get("/health", (req, res) => res.send("ok"));\n'],
    ]);
    expect(context.stack.stacks.some((stack) => stack.name === 'express' && stack.confidence === 'high')).toBe(true);
  });
});
