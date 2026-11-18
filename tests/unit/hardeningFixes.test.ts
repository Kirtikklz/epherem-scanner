import { describe, expect, it } from 'vitest';
import { collectDependenciesWithDiagnostics } from '../../src/stack-detection/collectDependencies.js';
import { OsvDependencyScanner } from '../../src/dependency-audit/osvDependencyScanner.js';
import {
  CachedOsvClient,
  FallbackOsvClient,
  LiveOsvClient,
  type OsvCacheFile,
  type OsvClient,
} from '../../src/dependency-audit/osvClient.js';
import { findMatches } from '../../src/shared/utils.js';
import { memoryContext } from './helpers.js';

const CACHE: OsvCacheFile = {
  source: 'bundled-osv-cache',
  generatedAt: '2025-05-01',
  advisories: [
    { id: 'GHSA-lodash', package: 'lodash', ecosystem: 'npm', severity: 'high', summary: 'proto pollution', ranges: [{ fixed: '4.17.12' }] },
  ],
};

function liveLikeClient(now: string): OsvClient {
  const cache = new CachedOsvClient(CACHE);
  return { source: 'osv.dev', live: true, generatedAt: now, queryPackage: (q) => cache.queryPackage(q) };
}

describe('Python dependency collection (issue 6)', () => {
  it('parses requirements.txt pins/ranges, poetry.lock versions, and reports parse diagnostics', () => {
    const { fileMap } = memoryContext([
      ['package.json', '{ this is not valid json'],
      ['requirements.txt', 'flask==2.0.1\nrequests>=2.28\nuvicorn[standard]==0.23.2\n# a comment\n-e .\n'],
      ['service/poetry.lock', '[[package]]\nname = "jinja2"\nversion = "3.1.2"\n\n[[package]]\nname = "click"\nversion = "8.1.7"\n'],
    ]);

    const { dependencies, diagnostics } = collectDependenciesWithDiagnostics(fileMap);
    const byName = new Map(dependencies.map((d) => [d.name, d]));

    expect(byName.get('flask')?.installedVersion).toBe('2.0.1');
    expect(byName.get('requests')?.installedVersion).toBeUndefined();
    expect(byName.get('requests')?.declaredRange).toBe('>=2.28');
    expect(byName.get('uvicorn')?.installedVersion).toBe('0.23.2');
    expect(byName.get('jinja2')?.installedVersion).toBe('3.1.2');
    expect(byName.get('click')?.installedVersion).toBe('8.1.7');
    expect(diagnostics.some((d) => /package\.json/i.test(d))).toBe(true);
  });
});

describe('dependency audit incompleteness (issues 1 + 6)', () => {
  const NOW = () => new Date('2025-05-10T00:00:00Z');
  const pinned = { ecosystem: 'npm' as const, name: 'lodash', installedVersion: '4.17.21', lockfile: 'package-lock.json', source: 'package-lock.json' };

  it('is complete with a fresh live source and no diagnostics', async () => {
    const scanner = new OsvDependencyScanner({ client: liveLikeClient('2025-05-10'), now: NOW });
    const res = await scanner.scanDependencies([pinned]);
    expect(res.incomplete).toBe(false);
  });

  it('is forced incomplete when parse diagnostics are present', async () => {
    const scanner = new OsvDependencyScanner({ client: liveLikeClient('2025-05-10'), now: NOW });
    const res = await scanner.scanDependencies([pinned], { parseDiagnostics: ['Malformed manifest x'] });
    expect(res.incomplete).toBe(true);
    expect(res.diagnostics).toContain('Malformed manifest x');
    expect(res.note).toMatch(/INCOMPLETE/i);
  });
});

describe('findMatches caps + line index (issue 5)', () => {
  it('caps returned matches and resolves correct line numbers', () => {
    const content = Array.from({ length: 50 }, () => 'needle here').join('\n');
    const matches = findMatches(content, /needle/g, { maxMatches: 5 });
    expect(matches).toHaveLength(5);
    expect(matches[0]?.line).toBe(1);
    expect(matches[4]?.line).toBe(5);
    expect(matches[2]?.snippet).toBe('needle here');
  });
});

describe('LiveOsvClient resilience (issues 2 + 7)', () => {
  it('retries on HTTP 429 (honoring Retry-After) then succeeds', async () => {
    let calls = 0;
    const fetchImpl = (async () => {
      calls += 1;
      if (calls === 1) return new Response('', { status: 429, headers: { 'retry-after': '0' } });
      return new Response(JSON.stringify({ vulns: [] }), { status: 200 });
    }) as unknown as typeof fetch;
    const client = new LiveOsvClient({ fetchImpl, maxRetries: 2, sleep: async () => undefined });
    const result = await client.queryPackage({ ecosystem: 'npm', name: 'x', version: '1.0.0' });
    expect(result).toEqual([]);
    expect(calls).toBe(2);
  });

  it('times out a hung request and returns undefined ("not checked", never safe)', async () => {
    const fetchImpl = ((_url: string, init?: { signal?: AbortSignal }) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new Error('aborted')));
      })) as unknown as typeof fetch;
    const client = new LiveOsvClient({ fetchImpl, timeoutMs: 20, maxRetries: 0 });
    const result = await client.queryPackage({ ecosystem: 'npm', name: 'x', version: '1.0.0' });
    expect(result).toBeUndefined();
  });

  it('aborts in-flight requests on the scan-wide signal', async () => {
    const controller = new AbortController();
    const fetchImpl = ((_url: string, init?: { signal?: AbortSignal }) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new Error('aborted')));
      })) as unknown as typeof fetch;
    const client = new LiveOsvClient({ fetchImpl, timeoutMs: 10_000, maxRetries: 3 });
    const promise = client.queryPackage({ ecosystem: 'npm', name: 'x', version: '1.0.0' }, { signal: controller.signal });
    controller.abort();
    expect(await promise).toBeUndefined();
  });
});

describe('FallbackOsvClient (issue 7)', () => {
  it('falls back to the offline cache and stays non-authoritative (audit incomplete)', async () => {
    const primary: OsvClient = { source: 'osv.dev', live: true, generatedAt: '2025-05-10', queryPackage: async () => undefined };
    const client = new FallbackOsvClient(primary, new CachedOsvClient(CACHE));
    expect(client.live).toBe(false);
    const result = await client.queryPackage({ ecosystem: 'npm', name: 'lodash', version: '4.17.11' });
    expect(result?.map((v) => v.id)).toContain('GHSA-lodash');
  });

  it('returns the live answer when the primary succeeds', async () => {
    const primary: OsvClient = { source: 'osv.dev', live: true, generatedAt: '2025-05-10', queryPackage: async () => [] };
    const client = new FallbackOsvClient(primary, new CachedOsvClient(CACHE));
    const result = await client.queryPackage({ ecosystem: 'npm', name: 'lodash', version: '4.17.11' });
    expect(result).toEqual([]);
  });
});
