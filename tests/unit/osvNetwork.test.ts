import { describe, expect, it } from 'vitest';
import {
  LiveOsvClient,
  parseAndValidateOsvResponse,
  MAX_OSV_RESPONSE_BYTES,
  type OsvClient,
} from '../../src/dependency-audit/osvClient.js';
import {
  OsvDependencyScanner,
} from '../../src/dependency-audit/osvDependencyScanner.js';
import type { CollectedDependency } from '../../src/stack-detection/collectDependencies.js';

const NOW = () => new Date('2025-05-10T00:00:00Z');
const immediateSleep = async (): Promise<void> => undefined;
const dep = (name: string, version: string): CollectedDependency => ({
  ecosystem: 'npm', name, installedVersion: version, lockfile: 'package-lock.json', source: 'package-lock.json',
});
const q = { ecosystem: 'npm' as const, name: 'lodash', version: '4.17.11' };

describe('LiveOsvClient network resilience', () => {
  it('hung fetch → per-request timeout → not a false clean (status timeout)', async () => {
    const hangingFetch = ((_url: string, opts: { signal: AbortSignal }) =>
      new Promise((_resolve, reject) => {
        opts.signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
      })) as unknown as typeof fetch;
    const client = new LiveOsvClient({ fetchImpl: hangingFetch, timeoutMs: 5, maxRetries: 1, sleep: immediateSleep, now: NOW });
    const r = await client.lookup(q);
    expect(r.status).toBe('timeout');
    expect(r.vulnerabilities).toBeUndefined();
  });

  it('aborted fetch → status aborted, never falls through to success', async () => {
    const controller = new AbortController();
    controller.abort();
    const neverFetch = (() => new Promise(() => undefined)) as unknown as typeof fetch;
    const client = new LiveOsvClient({ fetchImpl: neverFetch, now: NOW });
    const r = await client.lookup(q, { signal: controller.signal });
    expect(r.status).toBe('aborted');
  });

  it('oversized response (declared content-length) → network_error, body never buffered', async () => {
    const bigHeaderFetch = (async () =>
      new Response('{}', { status: 200, headers: { 'content-length': String(MAX_OSV_RESPONSE_BYTES + 1) } })) as unknown as typeof fetch;
    const client = new LiveOsvClient({ fetchImpl: bigHeaderFetch, maxRetries: 0, sleep: immediateSleep, now: NOW });
    const r = await client.lookup(q);
    expect(r.status).toBe('network_error');
  });

  it('oversized streamed body → network_error', async () => {
    const huge = 'x'.repeat(MAX_OSV_RESPONSE_BYTES + 10);
    const streamFetch = (async () => new Response(huge, { status: 200 })) as unknown as typeof fetch;
    const client = new LiveOsvClient({ fetchImpl: streamFetch, maxRetries: 0, sleep: immediateSleep, now: NOW });
    const r = await client.lookup(q);
    expect(r.status).toBe('network_error');
  });

  it('invalid OSV JSON → network_error, never mapped into findings', async () => {
    const badJsonFetch = (async () => new Response('not json {[', { status: 200 })) as unknown as typeof fetch;
    const client = new LiveOsvClient({ fetchImpl: badJsonFetch, maxRetries: 0, sleep: immediateSleep, now: NOW });
    const r = await client.lookup(q);
    expect(r.status).toBe('network_error');
  });

  it('schema-invalid vulns entries are dropped, valid ones kept', () => {
    expect(parseAndValidateOsvResponse('nope')).toBeUndefined();
    expect(parseAndValidateOsvResponse('{"vulns": 5}')).toBeUndefined();
    expect(parseAndValidateOsvResponse('{}')).toEqual([]);
    const cleaned = parseAndValidateOsvResponse('{"vulns":[{"id":"OK"},{"noId":true},null,"str"]}');
    expect(cleaned).toHaveLength(1);
    expect(cleaned?.[0]?.id).toBe('OK');
  });

  it('429 rate-limit is retried with backoff, then succeeds', async () => {
    let calls = 0;
    const flakyFetch = (async () => {
      calls += 1;
      if (calls < 3) return new Response('rate', { status: 429 });
      return new Response(JSON.stringify({ vulns: [] }), { status: 200 });
    }) as unknown as typeof fetch;
    const client = new LiveOsvClient({ fetchImpl: flakyFetch, maxRetries: 5, sleep: immediateSleep, now: NOW });
    const r = await client.lookup(q);
    expect(r.status).toBe('success');
    expect(calls).toBe(3);
  });

  it('429 past all retries → rate_limited, not success', async () => {
    const alwaysThrottled = (async () => new Response('rate', { status: 429 })) as unknown as typeof fetch;
    const client = new LiveOsvClient({ fetchImpl: alwaysThrottled, maxRetries: 2, sleep: immediateSleep, now: NOW });
    const r = await client.lookup(q);
    expect(r.status).toBe('rate_limited');
  });
});

describe('total dependency-audit deadline + cancellation', () => {
  it('stops scheduling new lookups after the deadline and reports the rest not-checked', async () => {
    let started = 0;
    const slowClient: OsvClient = {
      source: 'test', live: true, generatedAt: '2025-05-10',
      queryPackage: async () => {
        started += 1;
        await new Promise((r) => setTimeout(r, 40));
        return [];
      },
    };
    const scanner = new OsvDependencyScanner({
      client: slowClient,
      now: NOW,
      concurrency: 2,
      setTimer: (cb) => {
        const h = setTimeout(cb, 5);
        return { cancel: () => clearTimeout(h) };
      },
    });
    const deps = Array.from({ length: 50 }, (_, i) => dep(`p${i}`, '1.0.0'));
    const res = await scanner.scanDependencies(deps);
    expect(res.incomplete).toBe(true);
    expect(started).toBeLessThan(50);
    expect(res.checked).toBeLessThan(50);
    expect(res.notChecked.length).toBeGreaterThan(0);
    expect(res.outcomes?.aborted).toBeGreaterThan(0);
    expect(res.diagnostics.some((d) => /total deadline/i.test(d))).toBe(true);
  });

  it('an external abort signal cancels the audit promptly (thousands of deps)', async () => {
    const controller = new AbortController();
    const slowClient: OsvClient = {
      source: 'test', live: true, generatedAt: '2025-05-10',
      queryPackage: async () => {
        await new Promise((r) => setTimeout(r, 30));
        return [];
      },
    };
    const scanner = new OsvDependencyScanner({ client: slowClient, now: NOW, concurrency: 4 });
    const deps = Array.from({ length: 2000 }, (_, i) => dep(`p${i}`, '1.0.0'));
    setTimeout(() => controller.abort(), 5);
    const res = await scanner.scanDependencies(deps, { signal: controller.signal });
    expect(res.incomplete).toBe(true);
    expect(res.checked).toBeLessThan(2000);
    expect(res.notChecked.length).toBeGreaterThan(1000);
  });
});
