#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const BUNDLE_PATH = path.join(root, 'dist', 'epherem-scanner.cjs');

const ENTRY = `
import { embedAssets } from './src/shared/embeddedAssets.ts';
import osvCache from './src/dependency-audit/osv-cache.json';
import parserWasm from './node_modules/@vscode/tree-sitter-wasm/wasm/tree-sitter.wasm';
import grammarWasm from './node_modules/@vscode/tree-sitter-wasm/wasm/tree-sitter-python.wasm';
import runtime from './node_modules/@vscode/tree-sitter-wasm/wasm/tree-sitter.js';
import { main } from './src/cli.ts';

embedAssets({ osvCache, pythonReader: { runtime, parserWasm, grammarWasm } });
main(process.argv.slice(2)).then((code) => { process.exitCode = code; });
`;

export async function bundleBytes() {
  const result = await build({
    stdin: { contents: ENTRY, resolveDir: root, sourcefile: 'epherem-scanner-entry.js', loader: 'js' },
    absWorkingDir: root,
    bundle: true,
    platform: 'node',
    format: 'cjs',
    target: 'node20',
    loader: { '.wasm': 'binary' },
    banner: { js: ['#!/usr/bin/env node', "const __epheremImportMetaUrl = require('node:url').pathToFileURL(__filename).href;"].join('\n') },
    define: { 'import.meta.url': '__epheremImportMetaUrl' },
    legalComments: 'inline',
    minifyWhitespace: true,
    charset: 'utf8',
    write: false,
    logLevel: 'warning',
  });
  if (result.outputFiles.length !== 1) throw new Error(`expected one output file, got ${result.outputFiles.length}`);
  return Buffer.from(result.outputFiles[0].contents);
}

async function run() {
  const bytes = await bundleBytes();
  if (process.argv.includes('--check')) {
    let onDisk;
    try {
      onDisk = readFileSync(BUNDLE_PATH);
    } catch {
      console.error(`${path.relative(root, BUNDLE_PATH)} is missing. Run npm run build:bundle.`);
      process.exit(1);
    }
    if (!onDisk.equals(bytes)) {
      console.error(`${path.relative(root, BUNDLE_PATH)} is not what the source builds. Run npm run build:bundle and commit the result.`);
      process.exit(1);
    }
    console.log(`${path.relative(root, BUNDLE_PATH)} matches the source (${bytes.length} bytes).`);
    return;
  }
  await mkdir(path.dirname(BUNDLE_PATH), { recursive: true });
  await writeFile(BUNDLE_PATH, bytes);
  console.log(`wrote ${path.relative(root, BUNDLE_PATH)} (${bytes.length} bytes)`);
}

if (process.argv[1] !== undefined && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await run();
}
