import { describe, expect, it } from 'vitest';
import {
  LiveOsvClient,
  OSV_SEVERITY_FALLBACK,
  MAX_OSV_BATCH_PAGES,
  cvssV3BaseScore,
  severityFromCvssScore,
} from '../../src/dependency-audit/osvClient.js';
import {
  OsvDependencyScanner,
} from '../../src/dependency-audit/osvDependencyScanner.js';
import type { CollectedDependency } from '../../src/stack-detection/collectDependencies.js';

const NOW = (): Date => new Date('2026-09-21T00:00:00Z');
const immediateSleep = async (): Promise<void> => undefined;

function dep(name: string, version: string, source = 'package-lock.json'): CollectedDependency {
  return { ecosystem: 'npm', name, installedVersion: version, lockfile: source, source };
}

interface BatchQuery {
  version: string;
  package: { name: string; ecosystem: string };
  page_token?: string;
}

const QS_ADVISORIES: Record<string, Record<string, unknown>> = {
  'GHSA-4mjr-xmp4-gh2g': {
    id: 'GHSA-4mjr-xmp4-gh2g',
    summary: 'qs: Denial of Service via Attacker Controlled isBuffer',
    severity: [
      { type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L' },
      { type: 'CVSS_V4', score: 'CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N' },
    ],
    database_specific: { severity: 'MODERATE' },
    references: [{ url: 'https://github.com/ljharb/qs/security/advisories/GHSA-4mjr-xmp4-gh2g' }],
  },
  'GHSA-x5fp-wj9c-mxmx': {
    id: 'GHSA-x5fp-wj9c-mxmx',
    summary: 'qs array-limit bypass via bracket-key comma parsing',
    severity: [
      { type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L' },
      { type: 'CVSS_V4', score: 'CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N' },
    ],
    database_specific: { severity: 'MODERATE' },
    references: [{ url: 'https://github.com/ljharb/qs/security/advisories/GHSA-w7fw-mjwx-w883' }],
  },
};

function expectedSeverityOf(id: string): string {
  const entries = QS_ADVISORIES[id]?.severity as { type: string; score: string }[];
  const v3 = entries.find((entry) => entry.score.startsWith('CVSS:3'));
  const score = cvssV3BaseScore(v3?.score ?? '');
  expect(score, `${id} must carry a computable CVSS v3 vector`).toBeDefined();
  return severityFromCvssScore(score as number);
}

function osvStub(options: {
  advisoriesFor: (name: string, version: string) => string[];
  onBatch?: (queries: BatchQuery[], call: number) => Response | undefined;
  detail?: (id: string) => Response | undefined;
  record?: { batchCalls: number; detailIds: string[] };
}): typeof fetch {
  let batchCalls = 0;
  return (async (url: string, init?: { body?: string }) => {
    const target = String(url);
    if (target.includes('/querybatch')) {
      batchCalls += 1;
      if (options.record !== undefined) options.record.batchCalls = batchCalls;
      const queries = (JSON.parse(init?.body ?? '{"queries":[]}') as { queries: BatchQuery[] }).queries;
      const override = options.onBatch?.(queries, batchCalls);
      if (override !== undefined) return override;
      const results = queries.map((query) => {
        const ids = options.advisoriesFor(query.package.name, query.version);
        if (ids.length === 0) return {};
        return { vulns: ids.map((id) => ({ id, modified: '2026-09-10T03:51:14Z' })) };
      });
      return new Response(JSON.stringify({ results }), { status: 200 });
    }
    const id = target.slice(target.lastIndexOf('/') + 1);
    if (options.record !== undefined) options.record.detailIds.push(id);
    const override = options.detail?.(id);
    if (override !== undefined) return override;
    const record = QS_ADVISORIES[id];
    if (record === undefined) return new Response('{}', { status: 404 });
    return new Response(JSON.stringify(record), { status: 200 });
  }) as unknown as typeof fetch;
}

function scannerWith(fetchImpl: typeof fetch, batchSize = 500): OsvDependencyScanner {
  return new OsvDependencyScanner({
    client: new LiveOsvClient({ fetchImpl, now: NOW, maxRetries: 0, sleep: immediateSleep, batchSize }),
    now: NOW,
  });
}

describe('an advisory is described by its own record, never by the batch reference', () => {
  it('reports BOTH qs@6.15.3 advisories at the severity their own CVSS vectors imply', async () => {
    const expectedMedium = expectedSeverityOf('GHSA-4mjr-xmp4-gh2g');
    const expectedLow = expectedSeverityOf('GHSA-x5fp-wj9c-mxmx');
    expect(expectedMedium, 'the pair must disagree for this test to mean anything').not.toBe(expectedLow);
    expect(expectedLow).not.toBe(OSV_SEVERITY_FALLBACK);

    const scanner = scannerWith(osvStub({ advisoriesFor: (name) => (name === 'qs' ? Object.keys(QS_ADVISORIES) : []) }));
    const audit = await scanner.scanDependencies([dep('qs', '6.15.3')]);

    const bySeverity = new Map(audit.vulnerabilities.map((v) => [v.advisoryId, v.severity]));
    expect(bySeverity.get('GHSA-4mjr-xmp4-gh2g')).toBe(expectedMedium);
    expect(bySeverity.get('GHSA-x5fp-wj9c-mxmx')).toBe(expectedLow);
    expect(audit.vulnerabilities.find((v) => v.advisoryId === 'GHSA-x5fp-wj9c-mxmx')?.summary).toContain('array-limit');
  });

  it('a package whose advisory record cannot be fetched is NOT CHECKED, never described from the reference', async () => {
    const scanner = scannerWith(
      osvStub({
        advisoriesFor: (name) => (name === 'qs' ? ['GHSA-4mjr-xmp4-gh2g'] : []),
        detail: () => new Response('{}', { status: 500 }),
      }),
    );
    const audit = await scanner.scanDependencies([dep('qs', '6.15.3')]);
    expect(audit.vulnerabilities).toHaveLength(0);
    expect(audit.checked).toBe(0);
    expect(audit.notChecked).toContain('npm:qs@6.15.3');
    expect(audit.incomplete).toBe(true);
    expect(audit.diagnostics.join(' ')).toContain('GHSA-4mjr-xmp4-gh2g');
  });

  it('fetches each DISTINCT advisory once, however many packages carry it', async () => {
    const record = { batchCalls: 0, detailIds: [] as string[] };
    const scanner = scannerWith(
      osvStub({ advisoriesFor: () => ['GHSA-4mjr-xmp4-gh2g'], record }),
    );
    await scanner.scanDependencies([
      dep('qs', '6.15.3', 'a/package-lock.json'),
      dep('body-parser', '1.20.0'),
      dep('express', '4.22.2'),
    ]);
    expect(record.detailIds.filter((id) => id === 'GHSA-4mjr-xmp4-gh2g')).toHaveLength(1);
  });
});

describe('a failed batch names every package in it, individually', () => {
  const twelve = Array.from({ length: 12 }, (_unused, i) => dep(`pkg-${i}`, `1.0.${i}`));

  it('a batch that fails outright leaves all twelve NAMED in notChecked', async () => {
    const scanner = scannerWith(
      osvStub({ advisoriesFor: () => [], onBatch: () => new Response('nope', { status: 503 }) }),
    );
    const audit = await scanner.scanDependencies(twelve);
    for (const dependency of twelve) {
      expect(audit.notChecked, `${dependency.name} must be named, not counted`).toContain(
        `npm:${dependency.name}@${dependency.installedVersion}`,
      );
    }
    expect(audit.notChecked).toHaveLength(twelve.length);
    expect(audit.checked).toBe(0);
  });

  it('a short result array is refused outright, not aligned by guesswork', async () => {
    const scanner = scannerWith(
      osvStub({
        advisoriesFor: () => [],
        onBatch: () => new Response(JSON.stringify({ results: [{}, {}] }), { status: 200 }),
      }),
    );
    const audit = await scanner.scanDependencies(twelve);
    expect(audit.checked).toBe(0);
    expect(audit.notChecked).toHaveLength(twelve.length);
  });
});

describe('a package with more advisories than one page is never treated as fully answered', () => {
  it('follows next_page_token to exhaustion and keeps every advisory', async () => {
    const scanner = scannerWith(
      osvStub({
        advisoriesFor: () => [],
        onBatch: (queries, call) =>
          call === 1
            ? new Response(
                JSON.stringify({
                  results: [{ vulns: [{ id: 'GHSA-4mjr-xmp4-gh2g' }], next_page_token: 'page-2' }],
                }),
                { status: 200 },
              )
            : new Response(JSON.stringify({ results: [{ vulns: [{ id: 'GHSA-x5fp-wj9c-mxmx' }] }] }), { status: 200 }),
      }),
    );
    const audit = await scanner.scanDependencies([dep('qs', '6.15.3')]);
    expect(audit.checked).toBe(1);
    expect(audit.vulnerabilities.map((v) => v.advisoryId).sort()).toEqual([
      'GHSA-4mjr-xmp4-gh2g',
      'GHSA-x5fp-wj9c-mxmx',
    ]);
  });

  it('a token that never exhausts sends the package to notChecked BY NAME, not to a short answer', async () => {
    const record = { batchCalls: 0, detailIds: [] as string[] };
    const scanner = scannerWith(
      osvStub({
        advisoriesFor: () => [],
        record,
        onBatch: () =>
          new Response(
            JSON.stringify({ results: [{ vulns: [{ id: 'GHSA-4mjr-xmp4-gh2g' }], next_page_token: 'forever' }] }),
            { status: 200 },
          ),
      }),
    );
    const audit = await scanner.scanDependencies([dep('qs', '6.15.3')]);
    expect(audit.checked).toBe(0);
    expect(audit.notChecked).toContain('npm:qs@6.15.3');
    expect(audit.vulnerabilities).toHaveLength(0);
    expect(audit.incomplete).toBe(true);
    expect(record.batchCalls).toBeLessThanOrEqual(MAX_OSV_BATCH_PAGES + 1);
  });
});

describe('one query per DISTINCT package-version, keyed on all three parts', () => {
  it('two versions of one package get their own answers; the clean one stays clean', async () => {
    const scanner = scannerWith(
      osvStub({
        advisoriesFor: (name, version) =>
          name === 'qs' && version === '6.15.3' ? ['GHSA-4mjr-xmp4-gh2g'] : [],
      }),
    );
    const audit = await scanner.scanDependencies([dep('qs', '6.15.3'), dep('qs', '6.14.0')]);
    expect(audit.checked).toBe(2);
    const vulnerable = audit.vulnerabilities.map((v) => v.version);
    expect(vulnerable).toContain('6.15.3');
    expect(vulnerable, '6.14.0 carries no advisory and must not inherit one').not.toContain('6.14.0');
  });

  it('the same package-version in two lockfiles is asked once and answered twice', async () => {
    const record = { batchCalls: 0, detailIds: [] as string[] };
    const seen: string[] = [];
    const scanner = scannerWith(
      osvStub({
        advisoriesFor: (name, version) => {
          seen.push(`${name}@${version}`);
          return name === 'qs' ? ['GHSA-4mjr-xmp4-gh2g'] : [];
        },
        record,
      }),
    );
    const audit = await scanner.scanDependencies([
      dep('qs', '6.15.3', 'backend/package-lock.json'),
      dep('qs', '6.15.3', 'scanner/package-lock.json'),
    ]);
    expect(seen.filter((entry) => entry === 'qs@6.15.3')).toHaveLength(1);
    expect(audit.checked).toBe(2);
    expect(audit.vulnerabilities).toHaveLength(2);
  });
});

describe('the report says WHY a dependency went unchecked', () => {
  it('a package with no pin and a package that ran out of time are described differently', async () => {
    const scanner = new OsvDependencyScanner({
      client: new LiveOsvClient({
        fetchImpl: osvStub({ advisoriesFor: () => [] }),
        now: NOW,
        maxRetries: 0,
        sleep: immediateSleep,
      }),
      now: NOW,
      setTimer: (callback) => {
        callback();
        return { cancel: () => undefined };
      },
    });
    const audit = await scanner.scanDependencies([
      { ecosystem: 'npm', name: 'unpinned', declaredRange: '^1.0.0', source: 'package.json' },
      dep('timed-out', '2.0.0'),
    ]);

    expect(audit.note).toContain('1 dependencies had no exact version to check');
    expect(audit.note).toContain("1 dependencies were not checked before the audit's time budget ran out");

    const causes = audit.checkCoverage?.notCheckedByCause ?? {};
    expect(causes['no-exact-version']).toEqual(['npm:unpinned@^1.0.0']);
    expect(causes['time-budget']).toEqual(['npm:timed-out@2.0.0']);
  });

  it('a lookup that failed is not described as a missing pin', async () => {
    const scanner = scannerWith(
      osvStub({ advisoriesFor: () => [], onBatch: () => new Response('nope', { status: 503 }) }),
    );
    const audit = await scanner.scanDependencies([dep('asked-and-failed', '1.2.3')]);
    expect(audit.note).toContain('1 dependencies whose lookup failed or could not be completed');
    expect(audit.note).not.toContain('had no exact version to check');
  });
});
