import { describe, expect, it } from 'vitest';
import { OsvDependencyScanner } from '../../src/dependency-audit/osvDependencyScanner.js';
import { CachedOsvClient, FallbackOsvClient, type OsvClient, type OsvCacheFile } from '../../src/dependency-audit/osvClient.js';
import { compareVersions, isVersionAffected, parseVersion } from '../../src/dependency-audit/semver.js';
import type { CollectedDependency } from '../../src/stack-detection/collectDependencies.js';

function dep(name: string, installedVersion?: string, declaredRange?: string): CollectedDependency {
  return {
    ecosystem: 'npm',
    name,
    ...(installedVersion !== undefined ? { installedVersion, lockfile: 'package-lock.json' } : {}),
    ...(declaredRange !== undefined ? { declaredRange } : {}),
    source: installedVersion !== undefined ? 'package-lock.json' : 'package.json',
  };
}

const TEST_CACHE: OsvCacheFile = {
  source: 'bundled-osv-cache',
  generatedAt: '2025-05-01',
  advisories: [
    { id: 'GHSA-lodash', package: 'lodash', ecosystem: 'npm', severity: 'high', summary: 'proto pollution', ranges: [{ fixed: '4.17.12' }] },
    { id: 'GHSA-scope', package: '@scope/pkg', ecosystem: 'npm', severity: 'critical', summary: 'scoped bug', ranges: [{ introduced: '1.0.0', fixed: '1.2.0' }] },
    { id: 'GHSA-pre', package: 'preview', ecosystem: 'npm', severity: 'medium', summary: 'prerelease bug', ranges: [{ introduced: '2.0.0-alpha.1', fixed: '2.0.0' }] },
  ],
};

function liveLikeClient(now: string): OsvClient {
  const cache = new CachedOsvClient(TEST_CACHE);
  return {
    source: 'osv.dev',
    live: true,
    generatedAt: now,
    queryPackage: (q) => cache.queryPackage(q),
  };
}

describe('semver', () => {
  it('compares versions incl. prereleases', () => {
    expect(compareVersions('1.2.3', '1.2.4')).toBe(-1);
    expect(compareVersions('1.0.0-rc.1', '1.0.0')).toBe(-1);
    expect(parseVersion('2.0.0-alpha.1')?.prerelease).toEqual(['alpha', '1']);
  });
  it('evaluates bounds', () => {
    expect(isVersionAffected('4.17.11', { fixed: '4.17.12' })).toBe(true);
    expect(isVersionAffected('4.17.12', { fixed: '4.17.12' })).toBe(false);
    expect(isVersionAffected('2.0.0-alpha.2', { introduced: '2.0.0-alpha.1', fixed: '2.0.0' })).toBe(true);
  });
});

describe('OsvDependencyScanner', () => {
  const NOW = () => new Date('2025-05-10T00:00:00Z');

  it('audits only exact versions; a range-only dependency is NOT checked', async () => {
    const scanner = new OsvDependencyScanner({ client: new CachedOsvClient(TEST_CACHE), now: NOW });
    const result = await scanner.scanDependencies([
      dep('lodash', '4.17.11'),
      dep('express', undefined, '^4.19.0'),
    ]);
    expect(result.performed).toBe(true);
    expect(result.checked).toBe(1);
    expect(result.notChecked.some((entry) => entry.includes('express'))).toBe(true);
    expect(result.vulnerabilities.map((v) => v.dependency)).toContain('lodash');
    expect(result.incomplete).toBe(true);
    expect(result.source).toBe('bundled-osv-cache');
    expect(result.datasetDate).toBe('2025-05-01');
  });

  it('handles scoped packages and exact prereleases', async () => {
    const scanner = new OsvDependencyScanner({ client: new CachedOsvClient(TEST_CACHE), now: NOW });
    const result = await scanner.scanDependencies([
      dep('@scope/pkg', '1.1.0'),
      dep('@scope/pkg', '1.2.0'),
      dep('preview', '2.0.0-alpha.2'),
      dep('preview', '2.0.0'),
    ]);
    const affected = result.vulnerabilities.map((v) => `${v.dependency}@${v.version}`);
    expect(affected).toContain('@scope/pkg@1.1.0');
    expect(affected).toContain('preview@2.0.0-alpha.2');
    expect(affected).not.toContain('@scope/pkg@1.2.0');
    expect(affected).not.toContain('preview@2.0.0');
  });

  it('with a fresh LIVE source and all versions checked, the audit is complete', async () => {
    const scanner = new OsvDependencyScanner({ client: liveLikeClient('2025-05-10'), now: NOW });
    const result = await scanner.scanDependencies([dep('lodash', '4.17.21')]);
    expect(result.incomplete).toBe(false);
    expect(result.checked).toBe(1);
    expect(result.vulnerabilities).toEqual([]);
    expect(result.note).toMatch(/No known vulnerabilities/i);
  });

  it('a stale FALLBACK dataset is marked incomplete (freshness applies only to fallback data)', async () => {
    const failingPrimary: OsvClient = { source: 'osv.dev', live: true, generatedAt: '2025-05-10', queryPackage: async () => undefined };
    const client = new FallbackOsvClient(failingPrimary, new CachedOsvClient(TEST_CACHE));
    const staleNow = () => new Date('2025-09-01T00:00:00Z');
    const scanner = new OsvDependencyScanner({ client, now: staleNow, freshnessDays: 30 });
    const result = await scanner.scanDependencies([dep('lodash', '4.17.21')]);
    expect(result.incomplete).toBe(true);
    expect(result.note).toMatch(/INCOMPLETE/i);
    expect(result.note).toMatch(/stale/i);
  });

  it('a failed lookup marks the dependency not-checked and the audit incomplete', async () => {
    const failing: OsvClient = { source: 'osv.dev', live: true, generatedAt: '2025-05-10', queryPackage: async () => undefined };
    const scanner = new OsvDependencyScanner({ client: failing, now: NOW });
    const result = await scanner.scanDependencies([dep('lodash', '4.17.11')]);
    expect(result.checked).toBe(0);
    expect(result.notChecked.some((entry) => entry.includes('lodash'))).toBe(true);
    expect(result.incomplete).toBe(true);
    expect(result.note).not.toMatch(/No known vulnerabilities/i);
  });

  it('is deterministic', async () => {
    const scanner = new OsvDependencyScanner({ client: new CachedOsvClient(TEST_CACHE), now: NOW });
    const deps = [dep('lodash', '4.17.11'), dep('@scope/pkg', '1.1.0')];
    expect(await scanner.scanDependencies(deps)).toEqual(await scanner.scanDependencies(deps));
  });

  it('the bundled cache loads and is non-trivial', async () => {
    const { loadBundledOsvCache } = await import('../../src/dependency-audit/osvClient.js');
    expect(loadBundledOsvCache().advisories.length).toBeGreaterThan(15);
  });
});
