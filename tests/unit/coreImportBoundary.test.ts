import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { dynamicCodeSites, valueUsesOf, walkImportGraph } from './importGraph.js';

const SCANNER_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const REVIEW_LAYER = /^src\/(?:adjudication|surface|live-checks)\//;
const ENTRIES = ['src/scanProject.ts', 'src/cli.ts'] as const;

const ALLOWED_PACKAGES = new Set(['typescript']);
const FORBIDDEN_BUILTINS = new Set([
  'child_process', 'cluster', 'dgram', 'dns', 'http', 'http2', 'https', 'inspector', 'net', 'repl', 'tls', 'vm', 'worker_threads',
]);
const packageOf = (specifier: string): string =>
  specifier.startsWith('@') ? specifier.split('/').slice(0, 2).join('/') : specifier.split('/')[0]!;
const builtinOf = (specifier: string): string | undefined =>
  specifier.startsWith('node:') ? specifier.slice('node:'.length).split('/')[0] : undefined;

describe('the deterministic core and the command', () => {
  for (const entry of ENTRIES) {
    it(`${entry} reaches nothing in adjudication/, surface/ or live-checks/`, () => {
      const graph = walkImportGraph(SCANNER_ROOT, [entry]);
      expect(graph.files.filter((file) => REVIEW_LAYER.test(file))).toEqual([]);
      expect(graph.files.length).toBeGreaterThan(100);
    });
  }

  it('use only Node built-ins and TypeScript, and no module that runs code or opens a connection', () => {
    const graph = walkImportGraph(SCANNER_ROOT, [...ENTRIES]);
    const external = [...graph.external.keys()];
    expect(external.filter((s) => builtinOf(s) === undefined && !ALLOWED_PACKAGES.has(packageOf(s)))).toEqual([]);
    expect(external.filter((s) => FORBIDDEN_BUILTINS.has(builtinOf(s) ?? ''))).toEqual([]);
    expect(external.filter((s) => builtinOf(s) === undefined && !s.startsWith('node:') && FORBIDDEN_BUILTINS.has(s))).toEqual([]);
  });

  it('never evaluate text as code', () => {
    const graph = walkImportGraph(SCANNER_ROOT, [...ENTRIES]);
    expect(dynamicCodeSites(SCANNER_ROOT, graph.files)).toEqual([]);
  });

  it('call fetch only in the package check client, and that client only knows api.osv.dev', async () => {
    const graph = walkImportGraph(SCANNER_ROOT, [...ENTRIES]);
    const uses = valueUsesOf(SCANNER_ROOT, graph.files, new Set(['fetch', 'XMLHttpRequest', 'WebSocket', 'EventSource']));
    expect(uses.length).toBeGreaterThan(0);
    expect(uses.filter((use) => !use.startsWith('src/dependency-audit/osvClient.ts:'))).toEqual([]);
    const { readFileSync } = await import('node:fs');
    const client = readFileSync(path.join(SCANNER_ROOT, 'src/dependency-audit/osvClient.ts'), 'utf8');
    const urls = client.match(/['"`]https?:\/\/[^'"`\s]*/g) ?? [];
    expect(urls.length).toBeGreaterThan(0);
    expect(urls.filter((url) => !url.slice(1).startsWith('https://api.osv.dev'))).toEqual([]);
  });
});

describe('the walker sees an import of the review layer (positive control)', () => {
  const temps: string[] = [];
  afterAll(async () => {
    for (const dir of temps) await rm(dir, { recursive: true, force: true });
  });

  it('follows a static import, a re-export, a type import, a dynamic import and a worker URL', async () => {
    const root = await mkdtemp(path.join(tmpdir(), 'epherem-graph-'));
    temps.push(root);
    await mkdir(path.join(root, 'src', 'adjudication'), { recursive: true });
    await mkdir(path.join(root, 'src', 'surface'), { recursive: true });
    await mkdir(path.join(root, 'src', 'live-checks'), { recursive: true });
    await writeFile(path.join(root, 'src', 'adjudication', 'a.ts'), 'export const a = 1;\n');
    await writeFile(path.join(root, 'src', 'adjudication', 'types.ts'), 'export type T = number;\n');
    await writeFile(path.join(root, 'src', 'surface', 'b.ts'), 'export const b = 2;\n');
    await writeFile(path.join(root, 'src', 'live-checks', 'c.ts'), 'export const c = 3;\n');
    await writeFile(path.join(root, 'src', 'worker.ts'), "import 'node:child_process';\n");
    await writeFile(path.join(root, 'src', 'entry.ts'), [
      "import { a } from './adjudication/a.js';",
      "import type { T } from './adjudication/types.js';",
      "export { b } from './surface/b.js';",
      "export const later = () => import('./live-checks/c.js');",
      "export const worker = new URL('./worker.js', import.meta.url);",
      'export const value: T = a;',
      '',
    ].join('\n'));
    const graph = walkImportGraph(root, ['src/entry.ts']);
    expect(graph.files).toEqual([
      'src/adjudication/a.ts', 'src/adjudication/types.ts', 'src/entry.ts', 'src/live-checks/c.ts', 'src/surface/b.ts', 'src/worker.ts',
    ]);
    expect([...graph.external.keys()]).toEqual(['node:child_process']);
  });

  it('refuses an import it cannot resolve rather than reading it as clean', async () => {
    const root = await mkdtemp(path.join(tmpdir(), 'epherem-graph-'));
    temps.push(root);
    await mkdir(path.join(root, 'src'), { recursive: true });
    await writeFile(path.join(root, 'src', 'entry.ts'), "import { x } from './missing.js';\nexport const y = x;\n");
    expect(() => walkImportGraph(root, ['src/entry.ts'])).toThrow(/resolves to nothing/);
  });
});
