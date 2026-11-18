import { cpSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildFileMap } from '../../src/file-map/buildFileMap.js';
import { prepareInput } from '../../src/input/prepareInput.js';
import { buildProjectMap } from '../../src/project-map/buildProjectMap.js';
import { detectStack } from '../../src/stack-detection/detectStack.js';
import type { PreparedFile, PreparedInput, RuleContext } from '../../src/shared/types.js';
import { extensionOf } from '../../src/shared/utils.js';

const testDirectory = path.dirname(fileURLToPath(import.meta.url));

const FIXTURE_SECRETS: Readonly<Record<string, string>> = {
  __FAKE_STRIPE_LIVE_KEY__: 'sk' + '_live_FAKEFIXTUREKEY000000000000',
};
const materialised = new Map<string, string>();
let materialiseRoot: string | undefined;

function filesUnder(target: string): string[] {
  if (!statSync(target).isDirectory()) return [target];
  return readdirSync(target, { withFileTypes: true }).flatMap((entry) => filesUnder(path.join(target, entry.name)));
}

function holdsPlaceholder(file: string): boolean {
  const text = readFileSync(file, 'utf8');
  return Object.keys(FIXTURE_SECRETS).some((placeholder) => text.includes(placeholder));
}

export function fixturePath(name: string): string {
  const source = path.resolve(testDirectory, '../fixtures', name);
  const cached = materialised.get(source);
  if (cached !== undefined) return cached;
  if (!existsSync(source) || !filesUnder(source).some(holdsPlaceholder)) {
    materialised.set(source, source);
    return source;
  }
  if (materialiseRoot === undefined) {
    const made = mkdtempSync(path.join(tmpdir(), 'epherem-fixtures-'));
    materialiseRoot = made;
    process.on('exit', () => rmSync(made, { recursive: true, force: true }));
  }
  const copy = path.join(materialiseRoot, name);
  cpSync(source, copy, { recursive: true });
  for (const file of filesUnder(copy)) {
    if (!holdsPlaceholder(file)) continue;
    let text = readFileSync(file, 'utf8');
    for (const [placeholder, value] of Object.entries(FIXTURE_SECRETS)) text = text.split(placeholder).join(value);
    writeFileSync(file, text);
  }
  materialised.set(source, copy);
  return copy;
}

export async function loadFixtureContext(name: string): Promise<RuleContext> {
  const prepared = await prepareInput(fixturePath(name));
  const fileMap = buildFileMap(prepared);
  const stack = detectStack(fileMap);
  const projectMap = buildProjectMap(fileMap, stack);
  return { fileMap, projectMap, stack };
}

export function memoryFile(filePath: string, content = ''): PreparedFile {
  return {
    path: filePath,
    absolutePath: `/virtual/${filePath}`,
    extension: extensionOf(filePath),
    size: Buffer.byteLength(content),
    content,
  };
}


export function reproducedWindow(haystack: string, text: string, width = 12): string | undefined {
  for (let start = 0; start + width <= text.length; start += 1) {
    const window = text.slice(start, start + width);
    if (haystack.includes(window)) return window;
  }
  return undefined;
}


export function memoryContext(files: [filePath: string, content: string][]): RuleContext {
  const prepared: PreparedInput = {
    rootPath: '/virtual',
    files: files
      .map(([filePath, content]) => memoryFile(filePath, content))
      .sort((a, b) => a.path.localeCompare(b.path)),
    skipped: [],
    skippedCount: 0,
    warnings: [],
  };
  const fileMap = buildFileMap(prepared);
  const stack = detectStack(fileMap);
  const projectMap = buildProjectMap(fileMap, stack);
  return { fileMap, projectMap, stack };
}
