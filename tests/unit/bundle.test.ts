import { spawnSync } from 'node:child_process';
import { cp, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { builtinModules, createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { bundleBytes } from '../../scripts/build-bundle.mjs';
import { VERSION } from '../../src/cli.js';
import { embedAssets } from '../../src/shared/embeddedAssets.js';
import { preparePythonReader, pythonReaderTesting, readPythonTree, releasePythonReader } from '../../src/shared/pythonParser.js';
import { fixturePath } from './helpers.js';

const SCANNER_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const LICENCE = /^\/\*!|@license|@preserve|Copyright/i;

let bundle: Buffer;
let text: string;
const temps: string[] = [];
beforeAll(async () => {
  bundle = await bundleBytes();
  text = bundle.toString('utf8');
}, 120_000);
afterAll(async () => {
  for (const dir of temps) await rm(dir, { recursive: true, force: true });
});

describe('the one-file build', () => {
  it('is the same bytes when built again', async () => {
    expect((await bundleBytes()).equals(bundle)).toBe(true);
  });

  it('starts with a shebang and carries no comment except licence notices', () => {
    expect(text.startsWith('#!/usr/bin/env node\n')).toBe(true);
    const comments = commentsIn(text);
    expect(comments.length).toBeGreaterThan(0);
    expect(comments.filter((c) => !LICENCE.test(c))).toEqual([]);
  });

  it("loads only Node's own modules, and none that starts a process or opens a connection", () => {
    const required = [...new Set([...text.matchAll(/\brequire\((["'])([^"']+)\1\)/g)].map((m) => m[2]!))].sort();
    const bare = (s: string): string => s.replace(/^node:/, '');
    expect(required.filter((s) => !builtinModules.includes(bare(s)))).toEqual(['source-map-support']);
    const forbidden = ['child_process', 'cluster', 'dgram', 'dns', 'http', 'http2', 'https', 'net', 'tls', 'vm', 'worker_threads'];
    expect(required.filter((s) => forbidden.includes(bare(s)))).toEqual([]);
  });

  it('runs on its own and scans a project, writing nothing', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'epherem-bundle-'));
    temps.push(dir);
    const file = path.join(dir, 'epherem-scanner.cjs');
    await writeFile(file, bundle);
    await cp(fixturePath('next-supabase-insecure'), path.join(dir, 'shop-app'), { recursive: true });

    const version = spawnSync(process.execPath, [file, '--version'], { cwd: dir, encoding: 'utf8' });
    expect(version.stdout).toBe(`${VERSION}\n`);

    const run = spawnSync(process.execPath, [file, 'shop-app', '--offline'], { cwd: dir, encoding: 'utf8', timeout: 120_000 });
    expect(run.stderr).toBe('');
    expect(run.status).toBe(0);
    expect(run.stdout).toMatch(/^Package check: offline, using the advisory data bundled with this scanner \(from /);
    expect(run.stdout).toContain('supabase_service_role_exposed');
    expect((await readdir(dir)).sort()).toEqual(['epherem-scanner.cjs', 'shop-app']);
  });

  it('hands the Python reader its runtime and grammar as bytes, so it needs no file beside it', async () => {
    const wasm = path.join(SCANNER_ROOT, 'node_modules', '@vscode', 'tree-sitter-wasm', 'wasm');
    const empty = await mkdtemp(path.join(tmpdir(), 'epherem-no-reader-'));
    temps.push(empty);
    pythonReaderTesting.reset();
    pythonReaderTesting.setAssetDir(empty);
    embedAssets({
      pythonReader: {
        runtime: createRequire(import.meta.url)(path.join(wasm, 'tree-sitter.js')),
        parserWasm: await readFile(path.join(wasm, 'tree-sitter.wasm')),
        grammarWasm: new Uint8Array(await readFile(path.join(wasm, 'tree-sitter-python.wasm'))),
      },
    });
    try {
      expect(await preparePythonReader()).toBe(true);
      const read = readPythonTree({ path: 'app.py', content: 'def run(cmd):\n    return cmd\n' });
      expect(read.fallback).toBeUndefined();
      expect(read.tree!.root.type).toBe('module');
      releasePythonReader();
    } finally {
      embedAssets({});
      pythonReaderTesting.setAssetDir(undefined);
      pythonReaderTesting.reset();
    }
  });
});

function commentsIn(source: string): string[] {
  const body = source.slice(source.indexOf('\n') + 1);
  const file = ts.createSourceFile('bundle.js', body, ts.ScriptTarget.Latest, false, ts.ScriptKind.JS);
  expect((file as unknown as { parseDiagnostics: unknown[] }).parseDiagnostics).toEqual([]);
  const regexAt = new Set<number>();
  const templateAt = new Set<number>();
  const visit = (node: ts.Node): void => {
    if (node.kind === ts.SyntaxKind.RegularExpressionLiteral) regexAt.add(node.getStart(file));
    if (node.kind === ts.SyntaxKind.TemplateMiddle || node.kind === ts.SyntaxKind.TemplateTail) templateAt.add(node.getStart(file));
    ts.forEachChild(node, visit);
  };
  visit(file);
  const scanner = ts.createScanner(ts.ScriptTarget.Latest, false, ts.LanguageVariant.Standard, body);
  const comments: string[] = [];
  for (let kind = scanner.scan(); kind !== ts.SyntaxKind.EndOfFileToken; kind = scanner.scan()) {
    const at = scanner.getTokenStart();
    if (kind === ts.SyntaxKind.SingleLineCommentTrivia || kind === ts.SyntaxKind.MultiLineCommentTrivia) comments.push(scanner.getTokenText());
    else if ((kind === ts.SyntaxKind.SlashToken || kind === ts.SyntaxKind.SlashEqualsToken) && regexAt.has(at)) scanner.reScanSlashToken();
    else if (kind === ts.SyntaxKind.CloseBraceToken && templateAt.has(at)) scanner.reScanTemplateToken(false);
  }
  return comments;
}
