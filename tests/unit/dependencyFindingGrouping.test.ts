import { describe, expect, it } from 'vitest';
import { dependencyVulnerabilitiesToFindings } from '../../src/dependency-audit/dependencyFindings.js';
import { createDependencyOriginResolver } from '../../src/dependency-audit/dependencyOrigin.js';
import { memoryContext } from './helpers.js';
import type { DependencyAuditSummary, DependencyVulnerability, Severity } from '../../src/shared/types.js';

function vuln(
  dependency: string,
  version: string,
  advisoryId: string,
  severity: Severity = 'high',
): DependencyVulnerability {
  return {
    ecosystem: 'npm',
    dependency,
    version,
    advisoryId,
    severity,
    summary: `${advisoryId} summary`,
    sourcePath: 'package-lock.json',
    dataSource: 'fallback',
  } as DependencyVulnerability;
}

function audit(vulnerabilities: DependencyVulnerability[]): DependencyAuditSummary {
  return {
    performed: true,
    incomplete: false,
    source: 'bundled-osv-cache',
    dependenciesCollected: 1,
    checked: 1,
    notChecked: [],
    vulnerabilities,
    diagnostics: [],
  } as unknown as DependencyAuditSummary;
}

describe('dependency_vulnerability grouping', () => {
  it('collapses many advisories for one package@version into ONE finding', () => {
    const findings = dependencyVulnerabilitiesToFindings(
      audit([
        vuln('next', '16.0.7', 'GHSA-aaaa'),
        vuln('next', '16.0.7', 'GHSA-bbbb'),
        vuln('next', '16.0.7', 'GHSA-cccc'),
      ]),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.title).toContain('3 advisories');
  });

  it('keeps a different VERSION of the same package as its own finding', () => {
    const findings = dependencyVulnerabilitiesToFindings(
      audit([vuln('next', '16.0.7', 'GHSA-aaaa'), vuln('next', '15.2.4', 'GHSA-aaaa')]),
    );
    expect(findings).toHaveLength(2);
  });

  it('keeps different packages as separate findings', () => {
    const findings = dependencyVulnerabilitiesToFindings(
      audit([vuln('next', '16.0.7', 'GHSA-aaaa'), vuln('axios', '0.21.4', 'GHSA-bbbb')]),
    );
    expect(findings).toHaveLength(2);
  });

  it('loses no advisory id: every one is retained on the grouped finding', () => {
    const findings = dependencyVulnerabilitiesToFindings(
      audit([
        vuln('lodash', '4.17.21', 'GHSA-two', 'medium'),
        vuln('lodash', '4.17.21', 'GHSA-one', 'critical'),
      ]),
    );
    expect(findings[0]?.dependency?.relatedAdvisoryIds).toEqual(['GHSA-one', 'GHSA-two']);
    expect(findings[0]?.evidence).toContain('GHSA-one');
    expect(findings[0]?.evidence).toContain('GHSA-two');
  });

  it('takes the HIGHEST severity in the group, so nothing is de-prioritised', () => {
    const findings = dependencyVulnerabilitiesToFindings(
      audit([
        vuln('lodash', '4.17.21', 'GHSA-low', 'low'),
        vuln('lodash', '4.17.21', 'GHSA-crit', 'critical'),
        vuln('lodash', '4.17.21', 'GHSA-med', 'medium'),
      ]),
    );
    expect(findings[0]?.severity).toBe('critical');
    expect(findings[0]?.dependency?.advisoryId).toBe('GHSA-crit');
  });

  it('a single-advisory package keeps its original single-advisory title', () => {
    const findings = dependencyVulnerabilitiesToFindings(audit([vuln('qs', '6.5.2', 'GHSA-only')]));
    expect(findings[0]?.title).toBe('Vulnerable dependency: qs@6.5.2 (GHSA-only)');
    expect(findings[0]?.dependency?.relatedAdvisoryIds).toBeUndefined();
  });

  it('carries EVERY advisory id in advisoryIds, always, including for one', () => {
    const many = dependencyVulnerabilitiesToFindings(
      audit([
        vuln('minimatch', '9.0.5', 'GHSA-b'),
        vuln('minimatch', '9.0.5', 'GHSA-a'),
        vuln('minimatch', '9.0.5', 'GHSA-c'),
      ]),
    );
    expect(many[0]?.dependency?.advisoryIds).toEqual(['GHSA-a', 'GHSA-b', 'GHSA-c']);

    const one = dependencyVulnerabilitiesToFindings(audit([vuln('qs', '6.5.2', 'GHSA-only')]));
    expect(one[0]?.dependency?.advisoryIds).toEqual(['GHSA-only']);
  });

  it('advisoryId is always the FIRST of advisoryIds, so the two can never disagree', () => {
    const findings = dependencyVulnerabilitiesToFindings(
      audit([
        vuln('lodash', '4.17.21', 'GHSA-low', 'low'),
        vuln('lodash', '4.17.21', 'GHSA-crit', 'critical'),
      ]),
    );
    const detail = findings[0]?.dependency;
    expect(detail?.advisoryId).toBe(detail?.advisoryIds?.[0]);
    expect(detail?.advisoryId).toBe('GHSA-crit');
  });

  it('the structured advisory COUNT equals the count named in the title', () => {
    for (const ids of [['GHSA-1'], ['GHSA-1', 'GHSA-2'], ['GHSA-1', 'GHSA-2', 'GHSA-3', 'GHSA-4']]) {
      const findings = dependencyVulnerabilitiesToFindings(
        audit(ids.map((id) => vuln('pkg', '1.0.0', id))),
      );
      const finding = findings[0];
      const title = finding?.title ?? '';
      const named = /\((\d+) advisories\)$/.exec(title);
      const titleCount = named?.[1] === undefined ? 1 : Number(named[1]);
      expect(titleCount).toBe(ids.length);
      expect(finding?.dependency?.advisoryIds).toHaveLength(titleCount);
    }
  });

  it('deduplicated advisories are counted once in the title AND in advisoryIds', () => {
    const findings = dependencyVulnerabilitiesToFindings(
      audit([vuln('pkg', '1.0.0', 'GHSA-1'), vuln('pkg', '1.0.0', 'GHSA-1'), vuln('pkg', '1.0.0', 'GHSA-2')]),
    );
    expect(findings[0]?.title).toContain('2 advisories');
    expect(findings[0]?.dependency?.advisoryIds).toEqual(['GHSA-1', 'GHSA-2']);
  });

  it('marks dependency findings as NOT requiring AI adjudication, with its basis', () => {
    const findings = dependencyVulnerabilitiesToFindings(audit([vuln('qs', '6.5.2', 'GHSA-only')]));
    expect(findings[0]?.adjudication?.required).toBe(false);
    expect(findings[0]?.adjudication?.reason).toBe('database_backed_dependency_advisory');
    const basis = findings[0]?.adjudication?.basis ?? '';
    expect(basis).toContain('232');
    expect(basis).toContain('12-project');
    expect(basis).toContain('388-finding');
    expect(basis).toContain('offline');
  });

  it('DIRECT: the fix hint says so and names the manifest, with no "if" for the reader', () => {
    const resolver = createDependencyOriginResolver(memoryContext([
      ['package.json', JSON.stringify({ dependencies: { express: '^4.17.1' } })],
      ['package-lock.json', JSON.stringify({
        lockfileVersion: 3,
        packages: { '': { dependencies: { express: '^4.17.1' } }, 'node_modules/express': { version: '4.17.1' } },
      })],
    ]).fileMap);
    const findings = dependencyVulnerabilitiesToFindings(
      audit([vuln('express', '4.17.1', 'GHSA-x')]),
      resolver,
    );
    expect(findings[0]?.fixHint).toContain('You depend on express directly');
    expect(findings[0]?.fixHint).toContain('package.json');
    expect(findings[0]?.fixHint).not.toContain('If express is not listed');
    expect(findings[0]?.dependency?.origin?.relationship).toBe('direct');
  });

  it('TRANSITIVE: the fix hint names the chain and the package to actually upgrade', () => {
    const resolver = createDependencyOriginResolver(memoryContext([
      ['package.json', JSON.stringify({ devDependencies: { eslint: '^8.0.0' } })],
      ['package-lock.json', JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { devDependencies: { eslint: '^8.0.0' } },
          'node_modules/eslint': { version: '8.0.0', dependencies: { glob: '^7.0.0' } },
          'node_modules/glob': { version: '7.2.0', dependencies: { minimatch: '^3.1.2' } },
          'node_modules/minimatch': { version: '3.1.2' },
        },
      })],
    ]).fileMap);
    const findings = dependencyVulnerabilitiesToFindings(
      audit([vuln('minimatch', '3.1.2', 'GHSA-x')]),
      resolver,
    );
    expect(findings[0]?.fixHint).toContain('minimatch is required by glob, which is required by eslint');
    expect(findings[0]?.fixHint).toContain('Upgrade eslint');
    expect(findings[0]?.fixHint).toContain('overrides');
    expect(findings[0]?.dependency?.origin?.chain).toEqual(['eslint', 'glob', 'minimatch']);
  });

  it('UNDETERMINED: says outright that it could not tell, and names why', () => {
    const findings = dependencyVulnerabilitiesToFindings(audit([vuln('minimatch', '3.1.2', 'GHSA-x')]));
    expect(findings[0]?.fixHint).toContain('We could not determine where minimatch came from');
    expect(findings[0]?.dependency?.origin).toBeUndefined();
  });

  it('never invents a parent when the lockfile does not name one', () => {
    const resolver = createDependencyOriginResolver(memoryContext([
      ['package.json', JSON.stringify({ dependencies: { unrelated: '^1.0.0' } })],
      ['package-lock.json', JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { unrelated: '^1.0.0' } },
          'node_modules/unrelated': { version: '1.0.0' },
          'node_modules/minimatch': { version: '3.1.2' },
        },
      })],
    ]).fileMap);
    const findings = dependencyVulnerabilitiesToFindings(
      audit([vuln('minimatch', '3.1.2', 'GHSA-x')]),
      resolver,
    );
    expect(findings[0]?.dependency?.origin?.relationship).toBe('undetermined');
    expect(findings[0]?.dependency?.origin?.chain).toBeUndefined();
    expect(findings[0]?.fixHint).toContain('We could not determine where minimatch came from');
  });

  it('naming the origin changes NO advisory, severity or grouping', () => {
    const vulnerabilities = [
      vuln('minimatch', '3.1.2', 'GHSA-a', 'critical'),
      vuln('minimatch', '3.1.2', 'GHSA-b'),
      vuln('express', '4.17.1', 'GHSA-c', 'medium'),
    ];
    const resolver = createDependencyOriginResolver(memoryContext([
      ['package.json', JSON.stringify({ dependencies: { express: '^4.17.1' } })],
      ['package-lock.json', JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { express: '^4.17.1' } },
          'node_modules/express': { version: '4.17.1', dependencies: { minimatch: '^3.1.2' } },
          'node_modules/minimatch': { version: '3.1.2' },
        },
      })],
    ]).fileMap);
    const without = dependencyVulnerabilitiesToFindings(audit(vulnerabilities));
    const with_ = dependencyVulnerabilitiesToFindings(audit(vulnerabilities), resolver);

    expect(with_.map((f) => f.id)).toEqual(without.map((f) => f.id));
    expect(with_.map((f) => f.severity)).toEqual(without.map((f) => f.severity));
    expect(with_.map((f) => f.title)).toEqual(without.map((f) => f.title));
    expect(with_.map((f) => f.evidence)).toEqual(without.map((f) => f.evidence));
    expect(with_.map((f) => f.dependency?.advisoryIds)).toEqual(without.map((f) => f.dependency?.advisoryIds));
  });

  it('produces identical ids and order regardless of advisory arrival order', () => {
    const forward = dependencyVulnerabilitiesToFindings(
      audit([
        vuln('a', '1.0.0', 'GHSA-2', 'medium'),
        vuln('a', '1.0.0', 'GHSA-1', 'medium'),
        vuln('b', '2.0.0', 'GHSA-3'),
      ]),
    );
    const reversed = dependencyVulnerabilitiesToFindings(
      audit([
        vuln('a', '1.0.0', 'GHSA-1', 'medium'),
        vuln('a', '1.0.0', 'GHSA-2', 'medium'),
        vuln('b', '2.0.0', 'GHSA-3'),
      ]),
    );
    expect(forward.map((finding) => finding.id)).toEqual(reversed.map((finding) => finding.id));
  });

  it('is empty for an audit with no vulnerabilities', () => {
    expect(dependencyVulnerabilitiesToFindings(audit([]))).toEqual([]);
  });
});
