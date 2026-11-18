import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { OsvLookupStatus, Severity } from '../shared/types.js';
import { validateConcurrency, validateCountLimit, validateRetries, validateTimeoutMs } from '../shared/config.js';
import { embeddedAssets } from '../shared/embeddedAssets.js';
import { comparePep440 } from './pep440.js';
import { compareVersions, isVersionAffectedWith, type VersionBounds, type VersionComparator } from './semver.js';

export type OsvEcosystem = 'npm' | 'PyPI';

export interface OsvQuery {
  ecosystem: OsvEcosystem;
  name: string;
  version: string;
}

export interface OsvQueryOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
}

export interface OsvVulnerability {
  id: string;
  summary: string;
  severity: Severity;
  reference?: string;
}

export interface OsvLookupResult {
  status: OsvLookupStatus;
  vulnerabilities?: OsvVulnerability[];
  dataSource: 'live' | 'fallback';
  source: string;
  generatedAt?: string;
  diagnostic?: string;
  fallbackStatus?: OsvLookupStatus;
}

// Larger responses are refused, so a bad server cannot exhaust memory.
export const MAX_OSV_RESPONSE_BYTES = 5_000_000;

export const DEFAULT_OSV_BATCH_SIZE = 500;
export const MAX_OSV_BATCH_SIZE = 1000;

// Page tokens come from the server: cap them so a bad one cannot loop.
export const MAX_OSV_BATCH_PAGES = 20;

export const MAX_OSV_DETAIL_CACHE_ENTRIES = 5_000;

export interface OsvClient {
  readonly source: string;
  readonly live: boolean;
  readonly generatedAt?: string;
  queryPackage(query: OsvQuery, options?: OsvQueryOptions): Promise<OsvVulnerability[] | undefined>;
  lookup?(query: OsvQuery, options?: OsvQueryOptions): Promise<OsvLookupResult>;
  lookupMany?(queries: OsvQuery[], options?: OsvQueryOptions): Promise<OsvLookupResult[]>;
}

export async function structuredLookup(
  client: OsvClient,
  query: OsvQuery,
  options?: OsvQueryOptions,
): Promise<OsvLookupResult> {
  if (client.lookup !== undefined) return client.lookup(query, options);
  const vulns = await client.queryPackage(query, options);
  if (vulns === undefined) {
    return { status: 'network_error', dataSource: client.live ? 'live' : 'fallback', source: client.source };
  }
  return {
    status: 'success',
    vulnerabilities: vulns,
    dataSource: client.live ? 'live' : 'fallback',
    source: client.source,
    ...(client.generatedAt !== undefined ? { generatedAt: client.generatedAt } : {}),
  };
}

export async function structuredLookupMany(
  client: OsvClient,
  queries: OsvQuery[],
  options?: OsvQueryOptions,
): Promise<OsvLookupResult[]> {
  if (client.lookupMany !== undefined) {
    const results = await client.lookupMany(queries, options);
    if (results.length === queries.length) return results;
    return queries.map(
      (_query, i) =>
        results[i] ?? { status: 'network_error' as const, dataSource: client.live ? 'live' as const : 'fallback' as const, source: client.source },
    );
  }
  return Promise.all(queries.map((query) => structuredLookup(client, query, options)));
}

export interface OsvCacheAdvisory {
  id: string;
  package: string;
  ecosystem: OsvEcosystem;
  severity: Severity;
  summary: string;
  ranges: VersionBounds[];
  references?: string[];
}

export interface OsvCacheFile {
  source: string;
  generatedAt: string;
  advisories: OsvCacheAdvisory[];
}

function indexKey(ecosystem: string, name: string): string {
  return `${ecosystem.toLowerCase()} ${name.toLowerCase()}`;
}

export function versionIsComparable(version: string, compare: VersionComparator): boolean {
  return compare(version, version) !== undefined;
}

export function comparatorFor(ecosystem: OsvEcosystem): VersionComparator {
  return ecosystem === 'PyPI' ? comparePep440 : compareVersions;
}

export type CacheValidation =
  | { ok: true; value: OsvCacheFile }
  | { ok: false; error: string };

const VALID_ECOSYSTEMS: ReadonlySet<string> = new Set(['npm', 'PyPI']);
const VALID_SEVERITIES: ReadonlySet<string> = new Set(['critical', 'high', 'medium', 'low']);

export function validateOsvCacheFile(input: unknown): CacheValidation {
  if (input === null || typeof input !== 'object') return { ok: false, error: 'cache is not an object' };
  const obj = input as Record<string, unknown>;
  if (typeof obj.source !== 'string') return { ok: false, error: 'missing/invalid "source"' };
  if (typeof obj.generatedAt !== 'string') return { ok: false, error: 'missing/invalid "generatedAt"' };
  if (!Array.isArray(obj.advisories)) return { ok: false, error: 'missing/invalid "advisories" array' };

  const advisories: OsvCacheAdvisory[] = [];
  for (let i = 0; i < obj.advisories.length; i += 1) {
    const raw = obj.advisories[i];
    if (raw === null || typeof raw !== 'object') return { ok: false, error: `advisory[${i}] is not an object` };
    const a = raw as Record<string, unknown>;
    if (typeof a.id !== 'string') return { ok: false, error: `advisory[${i}].id invalid` };
    if (typeof a.package !== 'string') return { ok: false, error: `advisory[${i}].package invalid` };
    if (typeof a.ecosystem !== 'string' || !VALID_ECOSYSTEMS.has(a.ecosystem)) {
      return { ok: false, error: `advisory[${i}].ecosystem invalid` };
    }
    if (typeof a.severity !== 'string' || !VALID_SEVERITIES.has(a.severity)) {
      return { ok: false, error: `advisory[${i}].severity invalid` };
    }
    if (typeof a.summary !== 'string') return { ok: false, error: `advisory[${i}].summary invalid` };
    if (!Array.isArray(a.ranges)) return { ok: false, error: `advisory[${i}].ranges invalid` };
    for (let j = 0; j < a.ranges.length; j += 1) {
      const r = a.ranges[j];
      if (r === null || typeof r !== 'object') return { ok: false, error: `advisory[${i}].ranges[${j}] invalid` };
    }
    advisories.push({
      id: a.id,
      package: a.package,
      ecosystem: a.ecosystem as OsvEcosystem,
      severity: a.severity as Severity,
      summary: a.summary,
      ranges: a.ranges as VersionBounds[],
      ...(Array.isArray(a.references) ? { references: a.references.filter((x): x is string => typeof x === 'string') } : {}),
    });
  }
  return { ok: true, value: { source: obj.source, generatedAt: obj.generatedAt, advisories } };
}

const UNAVAILABLE_CACHE_SOURCE = 'bundled-osv-cache(unavailable)';

// Offline: answers from the bundled data and never touches the network.
export class CachedOsvClient implements OsvClient {
  readonly live = false;
  private readonly providedCache?: OsvCacheFile;
  private index?: Map<string, OsvCacheAdvisory[]>;
  private loadedSource = 'bundled-osv-cache';
  private loadedGeneratedAt = '';
  private loadDiagnosticMsg?: string;

  constructor(cache?: OsvCacheFile) {
    this.providedCache = cache;
    if (cache !== undefined) {
      if (typeof cache.source === 'string') this.loadedSource = cache.source;
      if (typeof cache.generatedAt === 'string') this.loadedGeneratedAt = cache.generatedAt;
    }
  }

  get source(): string {
    return this.loadedSource;
  }

  get generatedAt(): string {
    return this.loadedGeneratedAt;
  }

  get loadDiagnostic(): string | undefined {
    this.ensureLoaded();
    return this.loadDiagnosticMsg;
  }

  private ensureLoaded(): void {
    if (this.index !== undefined) return;
    let cache: OsvCacheFile;
    if (this.providedCache !== undefined) {
      const validation = validateOsvCacheFile(this.providedCache);
      if (validation.ok) {
        cache = validation.value;
      } else {
        this.loadDiagnosticMsg = `OSV cache is schema-invalid and was ignored: ${validation.error}.`;
        cache = { source: UNAVAILABLE_CACHE_SOURCE, generatedAt: '', advisories: [] };
      }
    } else {
      const result = safeLoadBundledOsvCache();
      cache = result.cache;
      if (result.diagnostic !== undefined) this.loadDiagnosticMsg = result.diagnostic;
    }
    this.loadedSource = cache.source;
    this.loadedGeneratedAt = cache.generatedAt;
    this.index = new Map();
    for (const advisory of cache.advisories) {
      const key = indexKey(advisory.ecosystem, advisory.package);
      const list = this.index.get(key) ?? [];
      list.push(advisory);
      this.index.set(key, list);
    }
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async queryPackage(query: OsvQuery): Promise<OsvVulnerability[] | undefined> {
    this.ensureLoaded();
    // Unusable data means "not checked", never "no vulnerabilities".
    if (this.loadDiagnosticMsg !== undefined) return undefined;
    const key = indexKey(query.ecosystem, query.name);
    if (!this.index?.has(key)) return undefined;
    const advisories = this.index.get(key) ?? [];
    const compare = comparatorFor(query.ecosystem);
    // A version that cannot be compared is not checked, not reported clean.
    if (!versionIsComparable(query.version, compare)) return undefined;
    const hits: OsvVulnerability[] = [];
    for (const advisory of advisories) {
      if (!advisory.ranges.some((bounds) => isVersionAffectedWith(query.version, bounds, compare))) continue;
      hits.push({
        id: advisory.id,
        summary: advisory.summary,
        severity: advisory.severity,
        ...(advisory.references?.[0] !== undefined ? { reference: advisory.references[0] } : {}),
      });
    }
    return hits;
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async lookup(query: OsvQuery): Promise<OsvLookupResult> {
    this.ensureLoaded();
    if (this.loadDiagnosticMsg !== undefined) {
      return {
        status: 'network_error',
        dataSource: 'fallback',
        source: this.loadedSource,
        diagnostic: this.loadDiagnosticMsg,
      };
    }
    const key = indexKey(query.ecosystem, query.name);
    if (!this.index?.has(key)) {
      return {
        status: 'network_error',
        dataSource: 'fallback',
        source: this.loadedSource,
        diagnostic: `Fallback cache miss for ${query.ecosystem}:${query.name}@${query.version}; dependency was not checked.`,
      };
    }
    const advisories = this.index.get(key) ?? [];
    const compare = comparatorFor(query.ecosystem);
    if (!versionIsComparable(query.version, compare)) {
      return {
        status: 'network_error',
        dataSource: 'fallback',
        source: this.loadedSource,
        diagnostic: `Version "${query.version}" of ${query.ecosystem}:${query.name} could not be parsed, so no advisory range could be evaluated; dependency was not checked.`,
      };
    }
    const vulnerabilities: OsvVulnerability[] = [];
    for (const advisory of advisories) {
      if (!advisory.ranges.some((bounds) => isVersionAffectedWith(query.version, bounds, compare))) continue;
      vulnerabilities.push({
        id: advisory.id,
        summary: advisory.summary,
        severity: advisory.severity,
        ...(advisory.references?.[0] !== undefined ? { reference: advisory.references[0] } : {}),
      });
    }
    return { status: 'success', vulnerabilities, dataSource: 'fallback', source: this.loadedSource, generatedAt: this.loadedGeneratedAt };
  }
}

// Neither a CVSS score nor a label: medium, never inflated to high.
export const OSV_SEVERITY_FALLBACK: Severity = 'medium';

export interface OsvSeverityEntry {
  type?: string;
  score?: string;
}

export interface OsvApiVuln {
  id: string;
  summary?: string;
  details?: string;
  references?: { url: string }[];
  severity?: OsvSeverityEntry[];
  database_specific?: { severity?: string };
  affected?: {
    database_specific?: { severity?: string };
    ecosystem_specific?: { severity?: string };
  }[];
}

function roundUp1(value: number): number {
  return Math.ceil(value * 10) / 10;
}

export function cvssV3BaseScore(vector: string): number | undefined {
  const metrics = new Map<string, string>();
  for (const part of vector.split('/')) {
    const [key, value] = part.split(':');
    if (key !== undefined && value !== undefined) metrics.set(key.toUpperCase(), value.toUpperCase());
  }
  const scopeChanged = metrics.get('S') === 'C';
  const av = ({ N: 0.85, A: 0.62, L: 0.55, P: 0.2 } as Record<string, number>)[metrics.get('AV') ?? ''];
  const ac = ({ L: 0.77, H: 0.44 } as Record<string, number>)[metrics.get('AC') ?? ''];
  const ui = ({ N: 0.85, R: 0.62 } as Record<string, number>)[metrics.get('UI') ?? ''];
  const prRaw = metrics.get('PR');
  const pr =
    prRaw === 'N' ? 0.85
      : prRaw === 'L' ? (scopeChanged ? 0.68 : 0.62)
        : prRaw === 'H' ? (scopeChanged ? 0.5 : 0.27)
          : undefined;
  const impactMetric = (value?: string): number | undefined =>
    ({ H: 0.56, L: 0.22, N: 0 } as Record<string, number>)[value ?? ''];
  const conf = impactMetric(metrics.get('C'));
  const integ = impactMetric(metrics.get('I'));
  const avail = impactMetric(metrics.get('A'));
  if (
    metrics.get('S') === undefined ||
    av === undefined || ac === undefined || ui === undefined || pr === undefined ||
    conf === undefined || integ === undefined || avail === undefined
  ) {
    return undefined;
  }
  const iss = 1 - (1 - conf) * (1 - integ) * (1 - avail);
  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av * ac * pr * ui;
  const combined = scopeChanged
    ? Math.min(1.08 * (impact + exploitability), 10)
    : Math.min(impact + exploitability, 10);
  return roundUp1(combined);
}

export function severityFromCvssScore(score: number): Severity {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  return 'low';
}

function qualitativeSeverity(label?: string): Severity | undefined {
  switch (label?.trim().toLowerCase()) {
    case 'critical':
      return 'critical';
    case 'high':
    case 'important':
      return 'high';
    case 'moderate':
    case 'medium':
      return 'medium';
    case 'low':
      return 'low';
    default:
      return undefined;
  }
}

function cvssVersionRank(type?: string): number {
  const t = (type ?? '').toUpperCase();
  if (t.includes('V4')) return 4;
  if (t.includes('V3')) return 3;
  if (t.includes('V2')) return 2;
  return 1;
}

function cvssScoreFrom(entries?: OsvSeverityEntry[]): number | undefined {
  if (entries === undefined || entries.length === 0) return undefined;
  const ordered = [...entries].sort((a, b) => cvssVersionRank(b.type) - cvssVersionRank(a.type));
  for (const entry of ordered) {
    const score = entry.score?.trim();
    if (score === undefined || score === '') continue;
    if (/^CVSS:3/i.test(score) || cvssVersionRank(entry.type) === 3) {
      const computed = cvssV3BaseScore(score);
      if (computed !== undefined) return computed;
    }
    const numeric = Number(score);
    if (Number.isFinite(numeric) && numeric >= 0 && numeric <= 10) return numeric;
  }
  return undefined;
}

function firstAffectedSeverity(affected?: OsvApiVuln['affected']): Severity | undefined {
  for (const entry of affected ?? []) {
    const severity =
      qualitativeSeverity(entry.database_specific?.severity) ??
      qualitativeSeverity(entry.ecosystem_specific?.severity);
    if (severity !== undefined) return severity;
  }
  return undefined;
}

export function mapOsvSeverity(vuln: OsvApiVuln): Severity {
  const cvss = cvssScoreFrom(vuln.severity);
  if (cvss !== undefined) return severityFromCvssScore(cvss);

  const labelled =
    qualitativeSeverity(vuln.database_specific?.severity) ??
    firstAffectedSeverity(vuln.affected);
  if (labelled !== undefined) return labelled;

  return OSV_SEVERITY_FALLBACK;
}

export interface LiveOsvClientOptions {
  fetchImpl?: typeof fetch;
  now?: () => Date;
  timeoutMs?: number;
  maxRetries?: number;
  retryBaseMs?: number;
  maxRetryDelayMs?: number;
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
  batchSize?: number;
  detailConcurrency?: number;
}

type AttemptOutcome =
  | { kind: 'ok'; value: OsvVulnerability[] }
  | { kind: 'fatal'; status: OsvLookupStatus }
  | { kind: 'retry'; status: OsvLookupStatus; retryAfterMs?: number };

// Every request has a timeout, honours cancellation and retries with a cap.
export class LiveOsvClient implements OsvClient {
  readonly source = 'osv.dev';
  readonly live = true;
  readonly generatedAt: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly retryBaseMs: number;
  private readonly maxRetryDelayMs: number;
  private readonly sleep: (ms: number, signal?: AbortSignal) => Promise<void>;
  private readonly batchSize: number;
  private readonly detailConcurrency: number;
  private readonly detailCache = new Map<string, OsvApiVuln>();

  constructor(options: LiveOsvClientOptions = {}) {
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.timeoutMs = validateTimeoutMs('LiveOsvClient.timeoutMs', options.timeoutMs ?? 8_000);
    this.maxRetries = validateRetries('LiveOsvClient.maxRetries', options.maxRetries ?? 3);
    this.retryBaseMs = validateTimeoutMs('LiveOsvClient.retryBaseMs', options.retryBaseMs ?? 250);
    this.maxRetryDelayMs = validateTimeoutMs('LiveOsvClient.maxRetryDelayMs', options.maxRetryDelayMs ?? 10_000);
    this.sleep = options.sleep ?? defaultSleep;
    this.batchSize = validateCountLimit(
      'LiveOsvClient.batchSize',
      Math.min(options.batchSize ?? DEFAULT_OSV_BATCH_SIZE, MAX_OSV_BATCH_SIZE),
    );
    this.detailConcurrency = validateConcurrency('LiveOsvClient.detailConcurrency', options.detailConcurrency ?? 8);
    this.generatedAt = (options.now ?? (() => new Date()))().toISOString().slice(0, 10);
  }

  async queryPackage(query: OsvQuery, options: OsvQueryOptions = {}): Promise<OsvVulnerability[] | undefined> {
    const result = await this.lookup(query, options);
    return result.status === 'success' ? (result.vulnerabilities ?? []) : undefined;
  }

  async lookup(query: OsvQuery, options: OsvQueryOptions = {}): Promise<OsvLookupResult> {
    const timeoutMs = options.timeoutMs ?? this.timeoutMs;
    let lastStatus: OsvLookupStatus = 'network_error';
    for (let attempt = 0; attempt <= this.maxRetries; attempt += 1) {
      if (options.signal?.aborted === true) return this.fail('aborted');
      const outcome = await this.attempt(query, timeoutMs, options.signal);
      if (outcome.kind === 'ok') {
        return { status: 'success', vulnerabilities: outcome.value, dataSource: 'live', source: this.source, generatedAt: this.generatedAt };
      }
      if (outcome.kind === 'fatal') return this.fail(outcome.status);
      lastStatus = outcome.status;
      if (attempt === this.maxRetries) return this.fail(lastStatus);
      const backoff = Math.min(this.maxRetryDelayMs, outcome.retryAfterMs ?? this.retryBaseMs * 2 ** attempt);
      try {
        await this.sleep(backoff, options.signal);
      } catch {
        return this.fail('aborted');
      }
    }
    return this.fail(lastStatus);
  }

  private fail(status: OsvLookupStatus): OsvLookupResult {
    return { status, dataSource: 'live', source: this.source };
  }

  private async attempt(query: OsvQuery, timeoutMs: number, signal?: AbortSignal): Promise<AttemptOutcome> {
    const controller = new AbortController();
    const onAbort = (): void => controller.abort();
    if (signal !== undefined) {
      if (signal.aborted) return { kind: 'fatal', status: 'aborted' };
      signal.addEventListener('abort', onAbort, { once: true });
    }
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeoutMs);
    try {
      const response = await this.fetchImpl('https://api.osv.dev/v1/query', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ version: query.version, package: { name: query.name, ecosystem: query.ecosystem } }),
        signal: controller.signal,
      });
      if (response.status === 429) {
        const retryAfterMs = parseRetryAfter(response);
        return { kind: 'retry', status: 'rate_limited', ...(retryAfterMs !== undefined ? { retryAfterMs } : {}) };
      }
      if (response.status >= 500) {
        const retryAfterMs = parseRetryAfter(response);
        return { kind: 'retry', status: 'network_error', ...(retryAfterMs !== undefined ? { retryAfterMs } : {}) };
      }
      if (!response.ok) return { kind: 'fatal', status: 'network_error' };
      let body: string;
      try {
        body = await readBodyBounded(response, MAX_OSV_RESPONSE_BYTES);
      } catch {
        return { kind: 'fatal', status: 'network_error' };
      }
      const vulns = parseAndValidateOsvResponse(body);
      if (vulns === undefined) return { kind: 'fatal', status: 'network_error' };
      return { kind: 'ok', value: vulns.map(toVulnerability) };
    } catch {
      if (signal?.aborted === true && !timedOut) return { kind: 'fatal', status: 'aborted' };
      if (timedOut) return { kind: 'retry', status: 'timeout' };
      return { kind: 'retry', status: 'network_error' };
    } finally {
      clearTimeout(timer);
      if (signal !== undefined) signal.removeEventListener('abort', onAbort);
    }
  }

  async lookupMany(queries: OsvQuery[], options: OsvQueryOptions = {}): Promise<OsvLookupResult[]> {
    const timeoutMs = options.timeoutMs ?? this.timeoutMs;
    const signal = options.signal;
    const results = new Array<OsvLookupResult | undefined>(queries.length);
    const refs = new Array<OsvBatchVulnRef[] | undefined>(queries.length);

    for (let start = 0; start < queries.length; start += this.batchSize) {
      const end = Math.min(start + this.batchSize, queries.length);
      const chunk = queries.slice(start, end);
      if (signal?.aborted === true) {
        fillRange(results, start, end, () => this.fail('aborted'));
        continue;
      }
      const response = await this.requestWithRetries(
        OSV_BATCH_URL,
        JSON.stringify({ queries: chunk.map((query) => toBatchQuery(query)) }),
        timeoutMs,
        signal,
      );
      if (!response.ok) {
        fillRange(results, start, end, () => this.fail(response.status));
        continue;
      }
      const parsed = parseAndValidateOsvBatchResponse(response.body, chunk.length);
      if (parsed === undefined) {
        fillRange(results, start, end, () => this.fail('network_error'));
        continue;
      }
      for (let j = 0; j < chunk.length; j += 1) {
        const entry = parsed[j] as OsvBatchResult;
        const query = chunk[j] as OsvQuery;
        const complete = await this.followPages(query, entry, timeoutMs, signal);
        if (complete === undefined) {
          results[start + j] = {
            status: 'network_error',
            dataSource: 'live',
            source: this.source,
            diagnostic:
              `OSV returned more advisories for ${queryLabel(query)} than could be paged through; ` +
              'the package was NOT checked (a partial page is not an answer).',
          };
          continue;
        }
        refs[start + j] = complete;
      }
    }

    const wanted = new Set<string>();
    for (const list of refs) for (const ref of list ?? []) wanted.add(ref.id);
    const details = await this.fetchAdvisoryDetails([...wanted], timeoutMs, signal);

    for (let i = 0; i < queries.length; i += 1) {
      if (results[i] !== undefined) continue;
      const list = refs[i];
      const query = queries[i] as OsvQuery;
      if (list === undefined) {
        results[i] = this.fail(signal?.aborted === true ? 'aborted' : 'network_error');
        continue;
      }
      const vulnerabilities: OsvVulnerability[] = [];
      let unresolved: string | undefined;
      for (const ref of list) {
        // Severity comes from the full record, never from the batch reference.
        const record = details.get(ref.id);
        if (record === undefined) {
          unresolved = ref.id;
          break;
        }
        vulnerabilities.push(toVulnerability(record));
      }
      if (unresolved !== undefined) {
        results[i] = {
          status: 'network_error',
          dataSource: 'live',
          source: this.source,
          diagnostic:
            `OSV advisory ${unresolved} affects ${queryLabel(query)}, but its record could not be retrieved, ` +
            'so its real severity and summary are unknown; the dependency was NOT checked.',
        };
        continue;
      }
      results[i] = {
        status: 'success',
        vulnerabilities,
        dataSource: 'live',
        source: this.source,
        generatedAt: this.generatedAt,
      };
    }
    return results as OsvLookupResult[];
  }

  private async followPages(
    query: OsvQuery,
    first: OsvBatchResult,
    timeoutMs: number,
    signal?: AbortSignal,
  ): Promise<OsvBatchVulnRef[] | undefined> {
    const collected = [...first.vulns];
    let token = first.nextPageToken;
    for (let page = 0; token !== undefined; page += 1) {
      if (page >= MAX_OSV_BATCH_PAGES) return undefined;
      if (signal?.aborted === true) return undefined;
      const response = await this.requestWithRetries(
        OSV_BATCH_URL,
        JSON.stringify({ queries: [toBatchQuery(query, token)] }),
        timeoutMs,
        signal,
      );
      if (!response.ok) return undefined;
      const parsed = parseAndValidateOsvBatchResponse(response.body, 1);
      const entry = parsed?.[0];
      if (entry === undefined) return undefined;
      collected.push(...entry.vulns);
      token = entry.nextPageToken;
    }
    return collected;
  }

  private async fetchAdvisoryDetails(
    ids: string[],
    timeoutMs: number,
    signal?: AbortSignal,
  ): Promise<Map<string, OsvApiVuln>> {
    const resolved = new Map<string, OsvApiVuln>();
    const outstanding: string[] = [];
    for (const id of ids) {
      const cached = this.detailCache.get(id);
      if (cached !== undefined) resolved.set(id, cached);
      else outstanding.push(id);
    }
    let next = 0;
    const worker = async (): Promise<void> => {
      for (;;) {
        if (signal?.aborted === true) return;
        const index = next;
        next += 1;
        if (index >= outstanding.length) return;
        const id = outstanding[index] as string;
        const response = await this.requestWithRetries(
          `${OSV_VULN_URL}${encodeURIComponent(id)}`,
          undefined,
          timeoutMs,
          signal,
        );
        if (!response.ok) continue;
        const record = parseAndValidateOsvVulnDetail(response.body);
        if (record === undefined) continue;
        resolved.set(id, record);
        if (this.detailCache.size < MAX_OSV_DETAIL_CACHE_ENTRIES) this.detailCache.set(id, record);
      }
    };
    const workers: Promise<void>[] = [];
    for (let i = 0; i < Math.min(this.detailConcurrency, outstanding.length); i += 1) workers.push(worker());
    await Promise.all(workers);
    return resolved;
  }

  private async requestWithRetries(
    url: string,
    body: string | undefined,
    timeoutMs: number,
    signal?: AbortSignal,
  ): Promise<{ ok: true; body: string } | { ok: false; status: OsvLookupStatus }> {
    let lastStatus: OsvLookupStatus = 'network_error';
    for (let attempt = 0; attempt <= this.maxRetries; attempt += 1) {
      if (signal?.aborted === true) return { ok: false, status: 'aborted' };
      const outcome = await this.requestOnce(url, body, timeoutMs, signal);
      if (outcome.kind === 'ok') return { ok: true, body: outcome.body };
      if (outcome.kind === 'fatal') return { ok: false, status: outcome.status };
      lastStatus = outcome.status;
      if (attempt === this.maxRetries) return { ok: false, status: lastStatus };
      const backoff = Math.min(this.maxRetryDelayMs, outcome.retryAfterMs ?? this.retryBaseMs * 2 ** attempt);
      try {
        await this.sleep(backoff, signal);
      } catch {
        return { ok: false, status: 'aborted' };
      }
    }
    return { ok: false, status: lastStatus };
  }

  private async requestOnce(
    url: string,
    body: string | undefined,
    timeoutMs: number,
    signal?: AbortSignal,
  ): Promise<{ kind: 'ok'; body: string } | { kind: 'fatal'; status: OsvLookupStatus } | { kind: 'retry'; status: OsvLookupStatus; retryAfterMs?: number }> {
    const controller = new AbortController();
    const onAbort = (): void => controller.abort();
    if (signal !== undefined) {
      if (signal.aborted) return { kind: 'fatal', status: 'aborted' };
      signal.addEventListener('abort', onAbort, { once: true });
    }
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeoutMs);
    try {
      const response = await this.fetchImpl(url, {
        method: body === undefined ? 'GET' : 'POST',
        ...(body === undefined ? {} : { headers: { 'content-type': 'application/json' }, body }),
        signal: controller.signal,
      });
      if (response.status === 429) {
        const retryAfterMs = parseRetryAfter(response);
        return { kind: 'retry', status: 'rate_limited', ...(retryAfterMs !== undefined ? { retryAfterMs } : {}) };
      }
      if (response.status >= 500) {
        const retryAfterMs = parseRetryAfter(response);
        return { kind: 'retry', status: 'network_error', ...(retryAfterMs !== undefined ? { retryAfterMs } : {}) };
      }
      if (!response.ok) return { kind: 'fatal', status: 'network_error' };
      try {
        return { kind: 'ok', body: await readBodyBounded(response, MAX_OSV_RESPONSE_BYTES) };
      } catch {
        return { kind: 'fatal', status: 'network_error' };
      }
    } catch {
      if (signal?.aborted === true && !timedOut) return { kind: 'fatal', status: 'aborted' };
      if (timedOut) return { kind: 'retry', status: 'timeout' };
      return { kind: 'retry', status: 'network_error' };
    } finally {
      clearTimeout(timer);
      if (signal !== undefined) signal.removeEventListener('abort', onAbort);
    }
  }
}

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN_URL = 'https://api.osv.dev/v1/vulns/';

// The only data sent anywhere: ecosystem, package name and version.
function toBatchQuery(query: OsvQuery, pageToken?: string): Record<string, unknown> {
  return {
    version: query.version,
    package: { name: query.name, ecosystem: query.ecosystem },
    ...(pageToken !== undefined ? { page_token: pageToken } : {}),
  };
}

function queryLabel(query: OsvQuery): string {
  return `${query.ecosystem}:${query.name}@${query.version}`;
}

function toVulnerability(vuln: OsvApiVuln): OsvVulnerability {
  return {
    id: vuln.id,
    summary: vuln.summary ?? vuln.details ?? vuln.id,
    severity: mapOsvSeverity(vuln),
    ...(vuln.references?.[0]?.url !== undefined ? { reference: vuln.references[0].url } : {}),
  };
}

function fillRange<T>(target: (T | undefined)[], start: number, end: number, make: () => T): void {
  for (let i = start; i < end; i += 1) target[i] = make();
}

// Stops reading at maxBytes instead of buffering the whole body.
async function readBodyBounded(
  response: { headers: { get(name: string): string | null }; body?: unknown; text?: () => Promise<string> },
  maxBytes: number,
): Promise<string> {
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw new Error(`OSV response too large (${declared} bytes)`);
  }
  const body = response.body as
    | { getReader?: () => { read: () => Promise<{ done: boolean; value?: Uint8Array }>; cancel: () => Promise<void> } }
    | null
    | undefined;
  const reader = body?.getReader?.();
  if (reader === undefined) {
    const text = (await response.text?.()) ?? '';
    if (Buffer.byteLength(text) > maxBytes) throw new Error('OSV response too large');
    return text;
  }
  const chunks: Uint8Array[] = [];
  let received = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value !== undefined) {
      received += value.byteLength;
      if (received > maxBytes) {
        await reader.cancel().catch(() => undefined);
        throw new Error('OSV response too large');
      }
      chunks.push(value);
    }
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');
}

export function parseAndValidateOsvResponse(body: string): OsvApiVuln[] | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return undefined;
  }
  if (parsed === null || typeof parsed !== 'object') return undefined;
  const vulnsRaw = (parsed as Record<string, unknown>).vulns;
  if (vulnsRaw === undefined) return [];
  if (!Array.isArray(vulnsRaw)) return undefined;
  const out: OsvApiVuln[] = [];
  for (const raw of vulnsRaw) {
    if (raw === null || typeof raw !== 'object') continue;
    const v = raw as Record<string, unknown>;
    if (typeof v.id !== 'string') continue;
    out.push(v as unknown as OsvApiVuln);
  }
  return out;
}

export interface OsvBatchVulnRef {
  id: string;
  modified?: string;
}

export interface OsvBatchResult {
  vulns: OsvBatchVulnRef[];
  nextPageToken?: string;
}

// Exactly one result per query sent, or the whole batch is rejected.
export function parseAndValidateOsvBatchResponse(
  body: string,
  expectedCount: number,
): OsvBatchResult[] | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return undefined;
  }
  if (parsed === null || typeof parsed !== 'object') return undefined;
  const resultsRaw = (parsed as Record<string, unknown>).results;
  if (!Array.isArray(resultsRaw)) return undefined;
  if (resultsRaw.length !== expectedCount) return undefined;
  const out: OsvBatchResult[] = [];
  for (const raw of resultsRaw) {
    if (raw === null || typeof raw !== 'object') return undefined;
    const entry = raw as Record<string, unknown>;
    const vulnsRaw = entry.vulns;
    const vulns: OsvBatchVulnRef[] = [];
    if (vulnsRaw !== undefined) {
      if (!Array.isArray(vulnsRaw)) return undefined;
      for (const v of vulnsRaw) {
        if (v === null || typeof v !== 'object') continue;
        const ref = v as Record<string, unknown>;
        if (typeof ref.id !== 'string' || ref.id === '') continue;
        vulns.push({ id: ref.id, ...(typeof ref.modified === 'string' ? { modified: ref.modified } : {}) });
      }
    }
    const token = entry.next_page_token;
    out.push({ vulns, ...(typeof token === 'string' && token !== '' ? { nextPageToken: token } : {}) });
  }
  return out;
}

export function parseAndValidateOsvVulnDetail(body: string): OsvApiVuln | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return undefined;
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return undefined;
  const record = parsed as Record<string, unknown>;
  if (typeof record.id !== 'string' || record.id === '') return undefined;
  return record as unknown as OsvApiVuln;
}

function parseRetryAfter(response: { headers: { get(name: string): string | null } }): number | undefined {
  const header = response.headers.get('retry-after');
  if (header === null) return undefined;
  const seconds = Number(header);
  if (Number.isFinite(seconds)) return Math.max(0, seconds * 1000);
  const date = Date.parse(header);
  if (!Number.isNaN(date)) return Math.max(0, date - Date.now());
  return undefined;
}

function defaultSleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted === true) {
      reject(new Error('aborted'));
      return;
    }
    const timer = setTimeout(() => {
      if (signal !== undefined) signal.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(new Error('aborted'));
    };
    if (signal !== undefined) signal.addEventListener('abort', onAbort, { once: true });
  });
}

// Live first; offline answers mark the audit incomplete.
export class FallbackOsvClient implements OsvClient {
  readonly source: string;
  readonly live = false;
  readonly generatedAt: string | undefined;

  constructor(
    private readonly primary: OsvClient,
    private readonly fallback: OsvClient = new CachedOsvClient(),
  ) {
    this.source = `${primary.source}+${fallback.source}`;
    this.generatedAt = olderDate(primary.generatedAt, fallback.generatedAt);
  }

  async queryPackage(query: OsvQuery, options?: OsvQueryOptions): Promise<OsvVulnerability[] | undefined> {
    const result = await this.lookup(query, options);
    return result.status === 'success' ? (result.vulnerabilities ?? []) : undefined;
  }

  async lookupMany(queries: OsvQuery[], options?: OsvQueryOptions): Promise<OsvLookupResult[]> {
    const primary =
      this.primary.lookupMany !== undefined
        ? await this.primary.lookupMany(queries, options)
        : await Promise.all(queries.map((query) => structuredLookup(this.primary, query, options)));
    const out: OsvLookupResult[] = [];
    for (let i = 0; i < queries.length; i += 1) {
      const result = primary[i] ?? { status: 'network_error' as const, dataSource: 'live' as const, source: this.source };
      out.push(await this.repair(queries[i] as OsvQuery, result, options));
    }
    return out;
  }

  async lookup(query: OsvQuery, options?: OsvQueryOptions): Promise<OsvLookupResult> {
    return this.repair(query, await structuredLookup(this.primary, query, options), options);
  }

  private async repair(
    query: OsvQuery,
    primary: OsvLookupResult,
    options?: OsvQueryOptions,
  ): Promise<OsvLookupResult> {
    if (primary.status === 'success') return { ...primary, dataSource: 'live' };
    if (primary.status === 'aborted') return primary;
    const fallback = await structuredLookup(this.fallback, query, options);
    if (fallback.status === 'success') {
      return {
        status: 'success',
        ...(fallback.vulnerabilities !== undefined ? { vulnerabilities: fallback.vulnerabilities } : { vulnerabilities: [] }),
        dataSource: 'fallback',
        source: this.source,
        ...(fallback.generatedAt ?? this.fallback.generatedAt) !== undefined
          ? { generatedAt: fallback.generatedAt ?? this.fallback.generatedAt }
          : {},
      };
    }
    return {
      ...primary,
      source: this.source,
      fallbackStatus: fallback.status,
      ...(fallback.diagnostic !== undefined ? { diagnostic: fallback.diagnostic } : {}),
    };
  }
}

function olderDate(a?: string, b?: string): string | undefined {
  if (a === undefined) return b;
  if (b === undefined) return a;
  return a < b ? a : b;
}

let cachedResult: { cache: OsvCacheFile; diagnostic?: string } | undefined;

const EMPTY_UNAVAILABLE_CACHE: OsvCacheFile = { source: UNAVAILABLE_CACHE_SOURCE, generatedAt: '', advisories: [] };

// Never throws: bad bundled data leaves the package check incomplete.
export function safeLoadBundledOsvCache(): { cache: OsvCacheFile; diagnostic?: string } {
  if (cachedResult !== undefined) return cachedResult;
  try {
    const parsed: unknown = embeddedAssets().osvCache ?? JSON.parse(readFileSync(fileURLToPath(new URL('./osv-cache.json', import.meta.url)), 'utf8'));
    const validation = validateOsvCacheFile(parsed);
    cachedResult = validation.ok
      ? { cache: validation.value }
      : { cache: EMPTY_UNAVAILABLE_CACHE, diagnostic: `Bundled OSV cache is schema-invalid: ${validation.error}.` };
  } catch (error) {
    cachedResult = {
      cache: EMPTY_UNAVAILABLE_CACHE,
      diagnostic: `Bundled OSV cache is missing or unreadable: ${error instanceof Error ? error.message : String(error)}.`,
    };
  }
  return cachedResult;
}

export function loadBundledOsvCache(): OsvCacheFile {
  return safeLoadBundledOsvCache().cache;
}
