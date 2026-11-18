import { SVELTEKIT_CONFIG_FILE, SVELTEKIT_LIB_ALIAS } from '../shared/frameworkModel.js';
import type { FileImports, FileMap } from '../shared/types.js';

const RESOLUTION_SUFFIXES = ['', '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
  '/index.ts', '/index.tsx', '/index.js', '/index.jsx'];

export interface PathAlias {
  prefix: string;
  hasWildcard: boolean;
  targets: string[];
  scope: string;
}

export function resolveImports(
  imports: FileImports[],
  filePaths: ReadonlySet<string>,
  aliases: PathAlias[] = [],
): void {
  for (const fileImports of imports) {
    for (const importRef of fileImports.imports) {
      const resolved = resolveLocalImport(fileImports.filePath, importRef.source, filePaths, aliases);
      if (resolved !== undefined) importRef.resolvedPath = resolved;
    }
  }
}

export function resolveLocalImport(
  fromPath: string,
  source: string,
  filePaths: ReadonlySet<string>,
  aliases: PathAlias[] = [],
): string | undefined {
  const candidates: string[] = [];
  if (source.startsWith('./') || source.startsWith('../')) {
    candidates.push(joinPosix(dirnamePosix(fromPath), source));
  } else if (source.startsWith('@/')) {
    candidates.push(source.slice(2), `src/${source.slice(2)}`);
  }
  for (const alias of aliases) {
    if (!isInScope(fromPath, alias.scope)) continue;
    if (alias.hasWildcard) {
      if (source.startsWith(alias.prefix)) {
        const rest = source.slice(alias.prefix.length);
        for (const target of alias.targets) {
          candidates.push(normalizePosix(rest === '' ? target : `${target}/${rest}`));
        }
      }
    } else if (source === alias.prefix) {
      for (const target of alias.targets) candidates.push(normalizePosix(target));
    }
  }
  if (candidates.length === 0) return undefined;

  for (const candidate of candidates) {
    for (const suffix of RESOLUTION_SUFFIXES) {
      const path = normalizePosix(candidate + suffix);
      if (filePaths.has(path)) return path;
    }
    const swapped = typeScriptTwin(candidate);
    for (const path of swapped) {
      if (filePaths.has(normalizePosix(path))) return normalizePosix(path);
    }
  }
  return undefined;
}

const JS_TO_TS: ReadonlyArray<readonly [string, readonly string[]]> = [
  ['.js', ['.ts', '.tsx']],
  ['.jsx', ['.tsx']],
  ['.mjs', ['.mts']],
  ['.cjs', ['.cts']],
];
function typeScriptTwin(candidate: string): string[] {
  for (const [emitted, sources] of JS_TO_TS) {
    if (!candidate.endsWith(emitted)) continue;
    const stem = candidate.slice(0, -emitted.length);
    return sources.map((source) => stem + source);
  }
  return [];
}

function isInScope(filePath: string, scope: string): boolean {
  return scope === '' || filePath === scope || filePath.startsWith(`${scope}/`);
}

const MAX_TSCONFIGS = 64;

export function buildPathAliases(fileMap: FileMap): PathAlias[] {
  const aliases: PathAlias[] = [];
  const configs = fileMap.entries
    .filter(
      (entry) =>
        (entry.path.endsWith('tsconfig.json') || entry.path.endsWith('jsconfig.json')) &&
        /(?:^|\/)[tj]sconfig\.json$/.test(entry.path) &&
        !entry.path.includes('node_modules/'),
    )
    .sort((a, b) => a.path.split('/').length - b.path.split('/').length || a.path.localeCompare(b.path))
    .slice(0, MAX_TSCONFIGS);
  for (const config of configs) {
    aliases.push(...aliasesFromConfig(config.path, config.content));
  }
  aliases.push(...svelteKitAliases(fileMap));
  return aliases;
}

function svelteKitAliases(fileMap: FileMap): PathAlias[] {
  const aliases: PathAlias[] = [];
  for (const entry of fileMap.entries) {
    if (entry.path.includes('node_modules/')) continue;
    if (!SVELTEKIT_CONFIG_FILE.test(entry.path)) continue;
    const scope = entry.path.includes('/') ? entry.path.slice(0, entry.path.lastIndexOf('/')) : '';
    aliases.push({
      prefix: SVELTEKIT_LIB_ALIAS.prefix,
      hasWildcard: true,
      targets: [normalizePosix(joinPosix(scope, SVELTEKIT_LIB_ALIAS.target))],
      scope,
    });
  }
  return aliases;
}

function aliasesFromConfig(configPath: string, content: string): PathAlias[] {
  const scope = configPath.includes('/') ? configPath.slice(0, configPath.lastIndexOf('/')) : '';
  const parsed = parseJsonc(content);
  if (parsed === undefined) return [];
  const compilerOptions = (parsed as Record<string, unknown>).compilerOptions;
  if (compilerOptions === null || typeof compilerOptions !== 'object') return [];
  const co = compilerOptions as Record<string, unknown>;
  const baseUrl = joinPosix(scope, typeof co.baseUrl === 'string' ? co.baseUrl : '.');
  const paths = co.paths;
  if (paths === null || typeof paths !== 'object') return [];

  const aliases: PathAlias[] = [];
  for (const [pattern, targetList] of Object.entries(paths as Record<string, unknown>)) {
    if (!Array.isArray(targetList)) continue;
    const hasWildcard = pattern.includes('*');
    const starIndex = pattern.indexOf('*');
    const prefix = hasWildcard ? pattern.slice(0, starIndex) : pattern;
    const targets: string[] = [];
    for (const target of targetList) {
      if (typeof target !== 'string') continue;
      const targetStar = target.indexOf('*');
      const targetPrefix = hasWildcard && targetStar >= 0 ? target.slice(0, targetStar) : target;
      targets.push(normalizePosix(joinPosix(baseUrl, targetPrefix)));
    }
    if (targets.length > 0) aliases.push({ prefix, hasWildcard, targets, scope });
  }
  return aliases;
}

export function buildImportAdjacency(imports: FileImports[]): Map<string, Set<string>> {
  const adjacency = new Map<string, Set<string>>();
  for (const fileImports of imports) {
    const targets = new Set<string>();
    for (const importRef of fileImports.imports) {
      if (importRef.resolvedPath !== undefined) targets.add(importRef.resolvedPath);
    }
    if (targets.size > 0) adjacency.set(fileImports.filePath, targets);
  }
  return adjacency;
}

function parseJsonc(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
  }
  let out = '';
  let i = 0;
  const n = text.length;
  while (i < n) {
    const c = text[i];
    const next = text[i + 1];
    if (c === '"') {
      out += c;
      i += 1;
      while (i < n) {
        out += text[i];
        if (text[i] === '\\') {
          out += text[i + 1] ?? '';
          i += 2;
          continue;
        }
        if (text[i] === '"') {
          i += 1;
          break;
        }
        i += 1;
      }
      continue;
    }
    if (c === '/' && next === '/') {
      i += 2;
      while (i < n && text[i] !== '\n') i += 1;
      continue;
    }
    if (c === '/' && next === '*') {
      i += 2;
      while (i < n && !(text[i] === '*' && text[i + 1] === '/')) i += 1;
      i += 2;
      continue;
    }
    out += c;
    i += 1;
  }
  out = out.replace(/,(\s*[}\]])/g, '$1');
  try {
    return JSON.parse(out);
  } catch {
    return undefined;
  }
}

function dirnamePosix(path: string): string {
  const index = path.lastIndexOf('/');
  return index === -1 ? '' : path.slice(0, index);
}

function joinPosix(base: string, relative: string): string {
  return normalizePosix(base === '' ? relative : `${base}/${relative}`);
}

function normalizePosix(path: string): string {
  const segments: string[] = [];
  for (const segment of path.split('/')) {
    if (segment === '' || segment === '.') continue;
    if (segment === '..') {
      segments.pop();
    } else {
      segments.push(segment);
    }
  }
  return segments.join('/');
}

const MAX_WORKSPACE_PACKAGES = 64;

export function buildWorkspacePackages(fileMap: FileMap): PathAlias[] {
  const aliases: PathAlias[] = [];
  const manifests = fileMap.entries
    .filter((entry) => /(?:^|\/)package\.json$/.test(entry.path) && !entry.path.includes('node_modules/'))
    .slice(0, MAX_WORKSPACE_PACKAGES);

  for (const manifest of manifests) {
    const directory = dirnamePosix(manifest.path);
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(manifest.content) as Record<string, unknown>;
    } catch {
      continue;
    }
    const name = typeof parsed['name'] === 'string' ? parsed['name'] : undefined;
    if (name === undefined || name === '' || name.startsWith('.') || directory === '') continue;

    const roots = new Set<string>();
    for (const field of ['main', 'module', 'types'] as const) {
      const value = parsed[field];
      if (typeof value === 'string' && value !== '') roots.add(joinPosix(directory, value));
    }
    const exportsField = parsed['exports'];
    const subpaths = new Map<string, string[]>();
    if (typeof exportsField === 'string') roots.add(joinPosix(directory, exportsField));
    else if (exportsField !== null && typeof exportsField === 'object') {
      for (const [key, value] of Object.entries(exportsField as Record<string, unknown>)) {
        const target = exportTarget(value);
        if (target === undefined) continue;
        const resolved = joinPosix(directory, target);
        if (key === '.') roots.add(resolved);
        else if (key.startsWith('./')) subpaths.set(key.slice(2), [resolved]);
      }
    }
    roots.add(directory);
    aliases.push({ prefix: name, hasWildcard: false, targets: [...roots], scope: '' });
    for (const [subpath, targets] of subpaths) {
      aliases.push({ prefix: `${name}/${subpath}`, hasWildcard: false, targets, scope: '' });
    }
    aliases.push({ prefix: `${name}/`, hasWildcard: true, targets: [directory, joinPosix(directory, 'src')], scope: '' });
  }
  return aliases;
}

function exportTarget(value: unknown): string | undefined {
  if (typeof value === 'string') return value;
  if (value === null || typeof value !== 'object') return undefined;
  for (const condition of ['import', 'default', 'require', 'types'] as const) {
    const nested = (value as Record<string, unknown>)[condition];
    if (typeof nested === 'string') return nested;
  }
  return undefined;
}
