import type { FileMapEntry } from './types.js';

export interface SelfTestLibrarySpec {
  namePattern: RegExp;
  mainExportPattern: RegExp;
}

const TEST_SEGMENT = /^(?:tests?|__tests__|spec|__spec__)$/i;

function dirOf(path: string): string {
  const cut = path.lastIndexOf('/');
  return cut === -1 ? '' : path.slice(0, cut);
}

function joinPath(dir: string, rest: string): string {
  const cleaned = rest.replace(/^\.\//, '');
  return dir === '' ? cleaned : `${dir}/${cleaned}`;
}

function mainCandidates(dir: string, main: string): string[] {
  const base = main.replace(/\/+$/, '');
  const out = [joinPath(dir, base)];
  for (const extension of ['.js', '.cjs', '.mjs', '.ts']) out.push(joinPath(dir, `${base}${extension}`));
  for (const index of ['index.js', 'index.cjs', 'index.mjs', 'index.ts']) {
    out.push(joinPath(dir, base === '' ? index : `${base}/${index}`));
  }
  return out;
}

export function selfImplementingPackages(
  entries: readonly FileMapEntry[],
  spec: SelfTestLibrarySpec,
): ReadonlySet<string> {
  const byPath = new Map<string, FileMapEntry>();
  for (const entry of entries) byPath.set(entry.path, entry);

  const packages = new Set<string>();
  for (const entry of entries) {
    if (!entry.path.endsWith('package.json')) continue;
    if (entry.path.includes('node_modules/')) continue;
    let manifest: { name?: unknown; main?: unknown };
    try {
      manifest = JSON.parse(entry.content) as { name?: unknown; main?: unknown };
    } catch {
      continue;
    }
    const name = typeof manifest.name === 'string' ? manifest.name : '';
    if (name === '' || !spec.namePattern.test(name)) continue;

    const dir = dirOf(entry.path);
    const main = typeof manifest.main === 'string' && manifest.main !== '' ? manifest.main : 'index.js';
    const publishesApi = mainCandidates(dir, main).some((candidate) => {
      const module = byPath.get(candidate);
      return module !== undefined && spec.mainExportPattern.test(module.content);
    });
    if (publishesApi) packages.add(dir);
  }
  return packages;
}

export function librarySelfTestScope(
  entries: readonly FileMapEntry[],
  spec: SelfTestLibrarySpec,
): (path: string) => boolean {
  const packages = selfImplementingPackages(entries, spec);
  if (packages.size === 0) return () => false;
  return (path: string): boolean => {
    for (const dir of packages) {
      if (dir !== '' && !path.startsWith(`${dir}/`)) continue;
      const relative = dir === '' ? path : path.slice(dir.length + 1);
      const segments = relative.split('/');
      const inTestTree = segments.slice(0, -1).some((segment) => TEST_SEGMENT.test(segment));
      const testFileName = /\.(?:tests?|spec)\.[cm]?[jt]sx?$/i.test(segments[segments.length - 1] ?? '');
      if (inTestTree || testFileName) return true;
    }
    return false;
  };
}
