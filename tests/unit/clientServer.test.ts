import { describe, expect, it } from 'vitest';
import { directImportsOf } from '../../src/project-map/buildProjectMap.js';
import { supabaseServiceRoleExposed } from '../../src/rules/basic/supabaseServiceRoleExposed.js';
import { memoryContext } from './helpers.js';

describe('client/server classification (App Router)', () => {
  it('app router components without "use client" are server-side', () => {
    const { projectMap } = memoryContext([
      ['package.json', '{"name":"x","dependencies":{"next":"14.0.0"}}'],
      [
        'app/profile/page.tsx',
        'const key = process.env.SUPABASE_SERVICE_ROLE_KEY;\n' +
          'export default async function Profile() { return <main>{key ? "ok" : "no"}</main>; }\n',
      ],
      ['app/widget/ClientWidget.tsx', "'use client';\nexport default function Widget() { return <button>go</button>; }\n"],
    ]);
    expect(projectMap.publicClientUsage).toEqual(['app/widget/ClientWidget.tsx']);
    expect(projectMap.serverSideUsage).toContain('app/profile/page.tsx');
  });

  it('no false service-role exposure for server components', () => {
    const context = memoryContext([
      ['package.json', '{"name":"x","dependencies":{"next":"14.0.0"}}'],
      [
        'app/admin/page.tsx',
        'const key = process.env.SUPABASE_SERVICE_ROLE_KEY;\n' +
          'export default async function Admin() { return <main>{key ? "ok" : "no"}</main>; }\n',
      ],
    ]);
    expect(supabaseServiceRoleExposed.run(context)).toHaveLength(0);
  });

  it('pages router components remain client-facing', () => {
    const { projectMap } = memoryContext([
      ['package.json', '{"name":"x","dependencies":{"next":"12.0.0"}}'],
      ['pages/home.tsx', 'export default function Home() { return <main>hi</main>; }\n'],
    ]);
    expect(projectMap.publicClientUsage).toContain('pages/home.tsx');
  });
});

describe('import dependency graph', () => {
  const files: [string, string][] = [
    ['package.json', '{"name":"x","dependencies":{"next":"14.0.0"}}'],
    ['app/form/ClientForm.tsx', "'use client';\nimport { helper } from '../../lib/helper';\nexport default function Form() { return <form>{helper()}</form>; }\n"],
    ['lib/helper.ts', "import { deep } from './deep';\nexport function helper() { return deep(); }\n"],
    ['lib/deep.ts', 'export function deep() { return 1; }\n'],
    ['lib/serverOnly.ts', 'export const unused = process.env.DATABASE_URL;\n'],
  ];

  it('resolves relative imports to project files', () => {
    const { projectMap } = memoryContext(files);
    expect(directImportsOf(projectMap, 'app/form/ClientForm.tsx')).toEqual(['lib/helper.ts']);
    expect(directImportsOf(projectMap, 'lib/helper.ts')).toEqual(['lib/deep.ts']);
  });

  it('client bundle closure includes transitively imported files only', () => {
    const { projectMap } = memoryContext(files);
    expect(projectMap.publicClientUsage).toEqual([
      'app/form/ClientForm.tsx',
      'lib/deep.ts',
      'lib/helper.ts',
    ]);
    expect(projectMap.publicClientUsage).not.toContain('lib/serverOnly.ts');
  });

  it('resolves the @/ alias', () => {
    const { projectMap } = memoryContext([
      ['package.json', '{"name":"x"}'],
      ['app/x/ClientX.tsx', "'use client';\nimport { util } from '@/lib/util';\nexport default function X() { return <span>{util()}</span>; }\n"],
      ['lib/util.ts', 'export function util() { return 2; }\n'],
    ]);
    expect(directImportsOf(projectMap, 'app/x/ClientX.tsx')).toEqual(['lib/util.ts']);
  });
});
