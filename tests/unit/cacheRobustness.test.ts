import { describe, expect, it } from 'vitest';
import {
  MockDependencyVulnerabilityScanner,
} from '../../src/dependency-audit/dependencyAudit.js';
import {
  CachedOsvClient,
  FallbackOsvClient,
  validateOsvCacheFile,
  safeLoadBundledOsvCache,
  type OsvCacheFile,
  type OsvClient,
} from '../../src/dependency-audit/osvClient.js';
import {
  OsvDependencyScanner,
} from '../../src/dependency-audit/osvDependencyScanner.js';
import type { CollectedDependency } from '../../src/stack-detection/collectDependencies.js';

const NOW = () => new Date('2025-05-10T00:00:00Z');
const dep = (name: string, version: string): CollectedDependency => ({
  ecosystem: 'npm', name, installedVersion: version, lockfile: 'package-lock.json', source: 'package-lock.json',
});

const GOOD: OsvCacheFile = {
  source: 'bundled-osv-cache',
  generatedAt: '2025-05-01',
  advisories: [{ id: 'GHSA-x', package: 'lodash', ecosystem: 'npm', severity: 'high', summary: 's', ranges: [{ fixed: '4.17.12' }] }],
};

describe('OSV cache validation (schema)', () => {
  it('accepts a well-formed cache', () => {
    const v = validateOsvCacheFile(GOOD);
    expect(v.ok).toBe(true);
  });
  it('rejects non-object, missing fields, bad advisories, bad ecosystem/severity', () => {
    expect(validateOsvCacheFile(null).ok).toBe(false);
    expect(validateOsvCacheFile('nope').ok).toBe(false);
    expect(validateOsvCacheFile({ source: 'x' }).ok).toBe(false);
    expect(validateOsvCacheFile({ source: 'x', generatedAt: 'd', advisories: 'no' }).ok).toBe(false);
    expect(validateOsvCacheFile({ source: 'x', generatedAt: 'd', advisories: [{ id: 1 }] }).ok).toBe(false);
    expect(
      validateOsvCacheFile({ source: 'x', generatedAt: 'd', advisories: [{ id: 'a', package: 'p', ecosystem: 'evil', severity: 'high', summary: 's', ranges: [] }] }).ok,
    ).toBe(false);
    expect(
      validateOsvCacheFile({ source: 'x', generatedAt: 'd', advisories: [{ id: 'a', package: 'p', ecosystem: 'npm', severity: 'ultra', summary: 's', ranges: [] }] }).ok,
    ).toBe(false);
  });
});

describe('CachedOsvClient degrades safely (never crashes, never false-clean)', () => {
  it('a schema-invalid provided cache does not throw at construction (lazy)', () => {
    const bad = { source: 1, advisories: 'x' } as unknown as OsvCacheFile;
    expect(() => new CachedOsvClient(bad)).not.toThrow();
  });

  it('malformed cache → lookup is a failure (network_error) carrying a diagnostic, not a false empty', async () => {
    const bad = { source: 'x', generatedAt: '2025-01-01', advisories: [{ id: 'a' }] } as unknown as OsvCacheFile;
    const client = new CachedOsvClient(bad);
    const r = await client.lookup({ ecosystem: 'npm', name: 'lodash', version: '4.17.11' });
    expect(r.status).toBe('network_error');
    expect(r.diagnostic).toMatch(/schema-invalid/i);
    expect(client.loadDiagnostic).toMatch(/schema-invalid/i);
    expect(await client.queryPackage({ ecosystem: 'npm', name: 'lodash', version: '4.17.11' })).toBeUndefined();
  });

  it('audit over an invalid-schema cache is INCOMPLETE with diagnostics and checks nothing', async () => {
    const bad = { source: 'x', generatedAt: '2025-01-01', advisories: [{ nope: true }] } as unknown as OsvCacheFile;
    const scanner = new OsvDependencyScanner({ client: new CachedOsvClient(bad), now: NOW });
    const res = await scanner.scanDependencies([dep('lodash', '4.17.11')]);
    expect(res.incomplete).toBe(true);
    expect(res.checked).toBe(0);
    expect(res.notChecked).toHaveLength(1);
    expect(res.vulnerabilities).toHaveLength(0);
    expect(res.diagnostics.some((d) => /schema-invalid/i.test(d))).toBe(true);
    expect(res.note).toMatch(/INCOMPLETE/i);
  });

  it('a degraded fallback cache still surfaces its diagnostic through FallbackOsvClient', async () => {
    const failingPrimary: OsvClient = { source: 'osv.dev', live: true, generatedAt: '2025-05-10', queryPackage: async () => undefined };
    const badCache = { source: 'x', generatedAt: 'd', advisories: 'no' } as unknown as OsvCacheFile;
    const client = new FallbackOsvClient(failingPrimary, new CachedOsvClient(badCache));
    const scanner = new OsvDependencyScanner({ client, now: NOW });
    const res = await scanner.scanDependencies([dep('lodash', '4.17.11')]);
    expect(res.incomplete).toBe(true);
    expect(res.checked).toBe(0);
    expect(res.diagnostics.some((d) => /invalid|unavailable/i.test(d))).toBe(true);
  });
});

describe('bundled cache loader is safe + present', () => {
  it('safeLoadBundledOsvCache returns the real cache (present, valid) without throwing', () => {
    const result = safeLoadBundledOsvCache();
    expect(result.diagnostic).toBeUndefined();
    expect(result.cache.advisories.length).toBeGreaterThan(0);
  });
});

describe('dependency auditing can be disabled without touching a cache', () => {
  it('MockDependencyVulnerabilityScanner performs no lookup and is explicitly incomplete', async () => {
    const res = await new MockDependencyVulnerabilityScanner().scanDependencies([dep('lodash', '4.17.11')]);
    expect(res.performed).toBe(false);
    expect(res.incomplete).toBe(true);
    expect(res.source).toBe('disabled');
    expect(res.checked).toBe(0);
    expect(res.vulnerabilities).toHaveLength(0);
  });
});
