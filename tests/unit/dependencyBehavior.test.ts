import { describe, expect, it } from 'vitest';
import {
  collectDependenciesWithDiagnostics,
  type CollectedDependency,
} from '../../src/stack-detection/collectDependencies.js';
import { OsvDependencyScanner } from '../../src/dependency-audit/osvDependencyScanner.js';
import { dependencyVulnerabilitiesToFindings } from '../../src/dependency-audit/dependencyFindings.js';
import type { FileMap, SkippedFile } from '../../src/shared/types.js';
import type { OsvClient, OsvQuery, OsvVulnerability } from '../../src/dependency-audit/osvClient.js';

function fileMap(entries: Array<[string, string]>): FileMap {
  return {
    rootPath: '/',
    entries: entries.map(([path, content]) => ({
      path,
      content,
      extension: path.slice(path.lastIndexOf('.')),
      label: 'other' as const,
    })),
    skipped: [],
    skippedCount: 0,
    warnings: [],
  } as unknown as FileMap;
}

const pkg = (deps: Record<string, string>) => JSON.stringify({ name: 'x', dependencies: deps });
const npmLock = (map: Record<string, string>) =>
  JSON.stringify({ packages: Object.fromEntries(Object.entries(map).map(([n, v]) => [`node_modules/${n}`, { version: v }])) });

function mockClient(vulnDb: Record<string, OsvVulnerability[]>): OsvClient {
  return {
    source: 'mock-osv',
    live: true,
    generatedAt: '2026-07-20',
    // eslint-disable-next-line @typescript-eslint/require-await
    async queryPackage(q: OsvQuery): Promise<OsvVulnerability[]> {
      return vulnDb[`${q.name}@${q.version}`] ?? [];
    },
  };
}

const LODASH_VULN: Record<string, OsvVulnerability[]> = {
  'lodash@4.17.11': [{ id: 'GHSA-lodash', severity: 'high', summary: 'prototype pollution' }],
};

const collect = (fm: FileMap): { dependencies: CollectedDependency[]; diagnostics: string[] } =>
  collectDependenciesWithDiagnostics(fm);
const audit = (fm: FileMap, db: Record<string, OsvVulnerability[]> = {}) => {
  const { dependencies, diagnostics } = collect(fm);
  return new OsvDependencyScanner({ client: mockClient(db) }).scanDependencies(dependencies, { parseDiagnostics: diagnostics });
};

describe('Section 8 — dependency collection across ecosystems and roots', () => {
  it('parses package-lock.json (v3 packages map) to exact installed versions', () => {
    const { dependencies } = collect(fileMap([['package.json', pkg({ lodash: '^4.0.0' })], ['package-lock.json', npmLock({ lodash: '4.17.11' })]]));
    expect(dependencies.find((d) => d.name === 'lodash')?.installedVersion).toBe('4.17.11');
  });

  it('parses yarn.lock', () => {
    const { dependencies } = collect(fileMap([['package.json', pkg({ axios: '^1.0.0' })], ['yarn.lock', '"axios@^1.0.0":\n  version "1.2.3"\n']]));
    expect(dependencies.find((d) => d.name === 'axios')?.installedVersion).toBe('1.2.3');
  });

  it('parses pnpm-lock.yaml', () => {
    const { dependencies } = collect(fileMap([['package.json', pkg({ react: '^18.0.0' })], ['pnpm-lock.yaml', 'packages:\n  /react@18.2.0:\n    resolution: {integrity: sha512-x}\n']]));
    expect(dependencies.find((d) => d.name === 'react')?.installedVersion).toBe('18.2.0');
  });

  it('handles multiple package roots (monorepo) and keeps each lockfile source', () => {
    const { dependencies } = collect(fileMap([
      ['apps/web/package.json', pkg({ lodash: '^4.0.0' })],
      ['apps/web/package-lock.json', npmLock({ lodash: '4.17.11' })],
      ['apps/api/package.json', pkg({ express: '^4.0.0' })],
      ['apps/api/package-lock.json', npmLock({ express: '4.18.2' })],
    ]));
    expect(dependencies.find((d) => d.name === 'lodash')?.lockfile).toBe('apps/web/package-lock.json');
    expect(dependencies.find((d) => d.name === 'express')?.lockfile).toBe('apps/api/package-lock.json');
  });

  it('keeps duplicate versions of the same package as distinct auditable entries', () => {
    const { dependencies } = collect(fileMap([
      ['package.json', pkg({ lodash: '^4.0.0' })],
      ['package-lock.json', JSON.stringify({ packages: { 'node_modules/lodash': { version: '4.17.11' }, 'node_modules/a/node_modules/lodash': { version: '4.17.21' } } })],
    ]));
    const versions = dependencies.filter((d) => d.name === 'lodash').map((d) => d.installedVersion).sort();
    expect(versions).toEqual(['4.17.11', '4.17.21']);
  });

  it('records a diagnostic for a malformed lockfile (never silently drops it)', () => {
    const { diagnostics } = collect(fileMap([['package.json', pkg({ x: '^1.0.0' })], ['package-lock.json', '{ not json ']]));
    expect(diagnostics.some((d) => /Malformed lockfile/i.test(d))).toBe(true);
  });
});

describe('Section 8 — three distinct product categories (never all "vulnerable")', () => {
  it('separates confirmed-vulnerable, installed-version-unknown, and could-not-check', async () => {
    const result = await audit(fileMap([
      ['package.json', pkg({ lodash: '^4.0.0', requests: '^2.0.0', 'left-pad': '^1.0.0' })],
      ['package-lock.json', npmLock({ lodash: '4.17.11', 'left-pad': '1.3.0' })],
    ]), LODASH_VULN);

    const findings = dependencyVulnerabilitiesToFindings(result);
    expect(findings.map((f) => f.dependency?.package)).toEqual(['lodash']);
    expect(findings.every((f) => f.ruleId === 'dependency_vulnerability')).toBe(true);

    expect(result.checkCoverage?.skipped.some((s) => s.includes('requests'))).toBe(true);

    expect(result.checked).toBe(2);
    expect(findings.some((f) => f.dependency?.package === 'left-pad')).toBe(false);
    expect(result.vulnerabilities.map((v) => v.dependency)).toEqual(['lodash']);
  });
});

describe('Section 8 — deduplication', () => {
  it('collapses the SAME advisory for a package@version present in multiple lockfiles to one row', async () => {
    const result = await audit(fileMap([
      ['apps/web/package.json', pkg({ lodash: '^4.0.0' })],
      ['apps/web/package-lock.json', npmLock({ lodash: '4.17.11' })],
      ['apps/api/package.json', pkg({ lodash: '^4.0.0' })],
      ['apps/api/package-lock.json', npmLock({ lodash: '4.17.11' })],
    ]), LODASH_VULN);
    const findings = dependencyVulnerabilitiesToFindings(result);
    expect(findings).toHaveLength(1);
    const advisoryIds = findings[0]?.dependency?.relatedAdvisoryIds ?? [findings[0]?.dependency?.advisoryId];
    expect(advisoryIds).toEqual(['GHSA-lodash']);
    expect(findings[0]?.title).toContain('GHSA-lodash');
    expect(findings[0]?.title).not.toMatch(/\(2 advisories\)/);
  });
});

describe('Section 8 — definition of done: no false clean bill of health', () => {
  it('a missing lockfile (manifest only) is never a complete clean audit', async () => {
    const result = await audit(fileMap([['package.json', pkg({ lodash: '^4.0.0', express: '^4.0.0' })]]));
    expect(result.checked).toBe(0);
    expect(result.notChecked.length).toBe(2);
    expect(result.incomplete).toBe(true);
    expect(result.vulnerabilities).toEqual([]);
  });

  it('an unsupported-ecosystem project (Cargo.lock only) is incomplete, not a clean bill', async () => {
    const result = await audit(fileMap([
      ['Cargo.toml', '[dependencies]\nserde = "1.0"'],
      ['Cargo.lock', '[[package]]\nname = "serde"\nversion = "1.0.100"'],
    ]));
    expect(result.incomplete).toBe(true);
    expect(result.diagnostics.some((d) => /Unsupported dependency ecosystem.*Rust\/Cargo/i.test(d))).toBe(true);
    expect(result.vulnerabilities).toEqual([]);
  });

  it('a JS+Go monorepo audits JS but stays incomplete because Go deps are unverified', async () => {
    const result = await audit(fileMap([
      ['package.json', pkg({ lodash: '^4.0.0' })],
      ['package-lock.json', npmLock({ lodash: '4.17.11' })],
      ['service/go.mod', 'module x\n'],
      ['service/go.sum', 'example.com/foo v1.0.0 h1:abc=\n'],
    ]), LODASH_VULN);
    expect(result.checked).toBe(1);
    expect(result.incomplete).toBe(true);
    expect(result.diagnostics.some((d) => /Unsupported dependency ecosystem.*Go/i.test(d))).toBe(true);
  });
});

function walkedFileMap(
  entries: Array<[string, string]>,
  skipped: Array<[string, SkippedFile['reason']]>,
  skippedCountOverride?: number,
): FileMap {
  return {
    rootPath: '/',
    entries: entries.map(([path, content]) => ({
      path,
      content,
      extension: path.slice(path.lastIndexOf('.')),
      label: 'other' as const,
    })),
    skipped: skipped.map(([path, reason]) => ({ path, reason })),
    skippedCount: skippedCountOverride ?? skipped.length,
    warnings: [],
  } as unknown as FileMap;
}

const UNSUPPORTED_SENTENCE = /Unsupported dependency ecosystem/i;
const UNPARSED_SENTENCE = /Dependency file format not read/i;
const SELF_INCOMPLETE_SENTENCE = /Dependency-file detection was incomplete/i;

describe('Section 8b — a dependency file the input walk REFUSED still forces incomplete', () => {
  it('a Go project, in the shape the walk actually produces, is incomplete and says why', async () => {
    const result = await audit(walkedFileMap([], [
      ['go.mod', 'not_useful'],
      ['go.sum', 'not_useful'],
    ]));
    expect(result.incomplete).toBe(true);
    expect(result.diagnostics.some((d) => /Unsupported dependency ecosystem.*Go/i.test(d))).toBe(true);
    expect(result.vulnerabilities).toEqual([]);
  });

  it('a Ruby project whose Gemfile.lock was refused as a lockfile is incomplete', async () => {
    const result = await audit(walkedFileMap([], [
      ['Gemfile', 'not_useful'],
      ['Gemfile.lock', 'lockfile'],
    ]));
    expect(result.incomplete).toBe(true);
    expect(result.diagnostics.some((d) => /Unsupported dependency ecosystem.*Ruby/i.test(d))).toBe(true);
  });

  it('a fully-audited npm project stays incomplete when a Gradle lockfile was skipped beside it', async () => {
    const result = await audit(walkedFileMap(
      [['package.json', pkg({ lodash: '^4.0.0' })], ['package-lock.json', npmLock({ lodash: '4.17.11' })]],
      [['android/gradle.lockfile', 'not_useful']],
    ), LODASH_VULN);
    expect(result.checked).toBe(1);
    expect(result.incomplete).toBe(true);
    expect(result.diagnostics.some((d) => /Unsupported dependency ecosystem.*Gradle/i.test(d))).toBe(true);
  });
});

describe('Section 8c — an audited ecosystem whose FILE FORMAT is not parsed', () => {
  it('npm-shrinkwrap.json is reported as an unread FORMAT, never as an unsupported ecosystem', async () => {
    const result = await audit(fileMap([['npm-shrinkwrap.json', '{"lockfileVersion":3}']]));
    expect(result.incomplete).toBe(true);
    const unparsed = result.diagnostics.filter((d) => UNPARSED_SENTENCE.test(d));
    expect(unparsed).toHaveLength(1);
    expect(unparsed[0]).toMatch(/npm-shrinkwrap\.json/);
    expect(unparsed[0]).toMatch(/ecosystem \(npm\) IS audited/);
    expect(unparsed[0]).toMatch(/package-lock\.json/);
    expect(result.diagnostics.some((d) => UNSUPPORTED_SENTENCE.test(d))).toBe(false);
  });

  it('a large shrinkwrap refused as too_large reaches the same statement through skipped', async () => {
    const result = await audit(walkedFileMap([], [['npm-shrinkwrap.json', 'too_large']]));
    expect(result.incomplete).toBe(true);
    expect(result.diagnostics.some((d) => UNPARSED_SENTENCE.test(d))).toBe(true);
  });

  it('a bun-only npm project is READ now, and says nothing about an unread format', async () => {
    const result = await audit(fileMap([
      ['package.json', pkg({ lodash: '^4.0.0' })],
      ['bun.lock', '{ "packages": { "lodash": ["lodash@4.17.11", "", {}, "sha512-x"] } }'],
    ]), LODASH_VULN);
    expect(result.checked).toBe(1);
    expect(result.vulnerabilities.map((v) => v.dependency)).toEqual(['lodash']);
    expect(result.diagnostics.filter((d) => UNPARSED_SENTENCE.test(d))).toEqual([]);
    expect(result.diagnostics.some((d) => UNSUPPORTED_SENTENCE.test(d))).toBe(false);
  });

  it('the binary bun lockfile, refused as a lockfile, reaches the same statement', async () => {
    const result = await audit(walkedFileMap([], [['bun.lockb', 'lockfile']]));
    expect(result.incomplete).toBe(true);
    expect(result.diagnostics.some((d) => /bun\.lockb/.test(d) && UNPARSED_SENTENCE.test(d))).toBe(true);
  });

  it('uv.lock names PyPI as audited and points at the formats that ARE read', async () => {
    const result = await audit(walkedFileMap(
      [['pyproject.toml', '[project]\nname = "x"\n']],
      [['uv.lock', 'not_useful']],
    ));
    expect(result.incomplete).toBe(true);
    const unparsed = result.diagnostics.filter((d) => UNPARSED_SENTENCE.test(d));
    expect(unparsed).toHaveLength(1);
    expect(unparsed[0]).toMatch(/uv\.lock/);
    expect(unparsed[0]).toMatch(/ecosystem \(PyPI\) IS audited/);
    expect(unparsed[0]).toMatch(/requirements\.txt/);
    expect(result.diagnostics.some((d) => UNSUPPORTED_SENTENCE.test(d))).toBe(false);
  });

  it('a bun.lock BESIDE a package-lock contributes the versions only IT records', async () => {
    const result = await audit(fileMap([
      ['package.json', pkg({ lodash: '^4.0.0', express: '^4.0.0' })],
      ['package-lock.json', npmLock({ lodash: '4.17.11' })],
      ['bun.lock', '{ "packages": { "express": ["express@4.18.2", "", {}, "sha512-y"] } }'],
    ]), LODASH_VULN);
    expect(result.checked).toBe(2);
    expect(result.vulnerabilities.map((v) => v.dependency)).toEqual(['lodash']);
    expect(result.diagnostics.filter((d) => UNPARSED_SENTENCE.test(d))).toEqual([]);
  });

  it('Pipenv files name PyPI as audited and point at requirements.txt', async () => {
    const result = await audit(walkedFileMap([], [
      ['Pipfile', 'not_useful'],
      ['Pipfile.lock', 'lockfile'],
    ]));
    expect(result.incomplete).toBe(true);
    const unparsed = result.diagnostics.filter((d) => UNPARSED_SENTENCE.test(d));
    expect(unparsed).toHaveLength(2);
    expect(unparsed.every((d) => /ecosystem \(PyPI\) IS audited/.test(d))).toBe(true);
    expect(unparsed.every((d) => /requirements\.txt/.test(d))).toBe(true);
    expect(result.diagnostics.some((d) => UNSUPPORTED_SENTENCE.test(d))).toBe(false);
  });
});

describe('Section 8d — the check refuses to vouch for itself when its input was truncated', () => {
  it('a truncated skipped list forces incomplete even with nothing recognisable in it', async () => {
    const result = await audit(walkedFileMap(
      [['package.json', pkg({ lodash: '^4.0.0' })], ['package-lock.json', npmLock({ lodash: '4.17.11' })]],
      [['src/a.png', 'ignored_extension']],
      5000,
    ), LODASH_VULN);
    expect(result.incomplete).toBe(true);
    expect(result.diagnostics.some((d) => SELF_INCOMPLETE_SENTENCE.test(d))).toBe(true);
  });

  it('the truncation sentence talks about the CHECK, never about an ecosystem', async () => {
    const result = await audit(walkedFileMap([], [['x.png', 'ignored_extension']], 9000));
    const sentence = result.diagnostics.find((d) => SELF_INCOMPLETE_SENTENCE.test(d));
    expect(sentence).toBeDefined();
    expect(sentence).toMatch(/not a statement about any ecosystem/i);
    expect(UNSUPPORTED_SENTENCE.test(sentence as string)).toBe(false);
    expect(UNPARSED_SENTENCE.test(sentence as string)).toBe(false);
  });

  it('an untruncated skipped list says nothing — the check only speaks when it cannot vouch', async () => {
    const result = await audit(walkedFileMap(
      [['package.json', pkg({ lodash: '^4.0.0' })], ['package-lock.json', npmLock({ lodash: '4.17.11' })]],
      [['src/a.png', 'ignored_extension']],
    ), LODASH_VULN);
    expect(result.diagnostics.some((d) => SELF_INCOMPLETE_SENTENCE.test(d))).toBe(false);
  });
});
