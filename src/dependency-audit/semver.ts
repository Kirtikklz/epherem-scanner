export interface ParsedVersion {
  major: number;
  minor: number;
  patch: number;
  prerelease: string[];
}

export function coerceVersion(raw: string): string | undefined {
  const match = /(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+][0-9A-Za-z.-]+)?/.exec(raw);
  if (match === null) return undefined;
  return match[0];
}

export function parseVersion(raw: string): ParsedVersion | undefined {
  const core = coerceVersion(raw);
  if (core === undefined) return undefined;
  const withoutBuild = core.split('+', 1)[0] ?? '';
  const [main, pre] = withoutBuild.split('-', 2);
  const parts = (main ?? '').split('.');
  const major = Number(parts[0] ?? 0);
  const minor = Number(parts[1] ?? 0);
  const patch = Number(parts[2] ?? 0);
  if ([major, minor, patch].some((value) => Number.isNaN(value))) return undefined;
  return {
    major,
    minor,
    patch,
    prerelease: pre === undefined || pre === '' ? [] : pre.split('.'),
  };
}

export function compareVersions(a: string, b: string): number | undefined {
  const va = parseVersion(a);
  const vb = parseVersion(b);
  if (va === undefined || vb === undefined) return undefined;
  for (const key of ['major', 'minor', 'patch'] as const) {
    if (va[key] !== vb[key]) return va[key] < vb[key] ? -1 : 1;
  }
  if (va.prerelease.length === 0 && vb.prerelease.length === 0) return 0;
  if (va.prerelease.length === 0) return 1;
  if (vb.prerelease.length === 0) return -1;
  const length = Math.max(va.prerelease.length, vb.prerelease.length);
  for (let index = 0; index < length; index += 1) {
    const pa = va.prerelease[index];
    const pb = vb.prerelease[index];
    if (pa === undefined) return -1;
    if (pb === undefined) return 1;
    if (pa === pb) continue;
    const na = Number(pa);
    const nb = Number(pb);
    const bothNumeric = !Number.isNaN(na) && !Number.isNaN(nb);
    if (bothNumeric) return na < nb ? -1 : 1;
    return pa < pb ? -1 : 1;
  }
  return 0;
}

export interface VersionBounds {
  introduced?: string;
  fixed?: string;
  lastAffected?: string;
}

export type VersionComparator = (a: string, b: string) => number | undefined;

export function isVersionAffectedWith(
  version: string,
  bounds: VersionBounds,
  compare: VersionComparator,
): boolean {
  if (bounds.introduced !== undefined) {
    const cmp = compare(version, bounds.introduced);
    if (cmp === undefined || cmp < 0) return false;
  }
  if (bounds.fixed !== undefined) {
    const cmp = compare(version, bounds.fixed);
    if (cmp === undefined) return false;
    if (cmp >= 0) return false;
  }
  if (bounds.lastAffected !== undefined) {
    const cmp = compare(version, bounds.lastAffected);
    if (cmp === undefined || cmp > 0) return false;
  }
  return true;
}

export function isVersionAffected(version: string, bounds: VersionBounds): boolean {
  return isVersionAffectedWith(version, bounds, compareVersions);
}
