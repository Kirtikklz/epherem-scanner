import { validateConcurrency, validateCountLimit, validateFreshnessDays, validateTimeoutMs } from '../shared/config.js';
import { MAX_DEPENDENCY_VULNERABILITIES, MAX_OSV_LOOKUPS } from '../shared/constants.js';
import type {
  CollectedDependency,
} from '../stack-detection/collectDependencies.js';
import type {
  DependencyAuditSummary,
  DependencyEcosystem,
  DependencyLookupOutcomes,
  DependencyVulnerability,
  OsvLookupStatus,
  Severity,
} from '../shared/types.js';
import type { DependencyAuditContext, DependencyVulnerabilityScanner } from './dependencyAudit.js';
import {
  CachedOsvClient,
  structuredLookup,
  structuredLookupMany,
  type OsvClient,
  type OsvLookupResult,
  type OsvQuery,
  type OsvQueryOptions,
} from './osvClient.js';

const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const DEFAULT_FRESHNESS_DAYS = 30;
const DEFAULT_CONCURRENCY = 8;
const DEFAULT_PER_REQUEST_TIMEOUT_MS = 10_000;
const DEFAULT_TOTAL_DEADLINE_MS = 60_000;

export interface OsvDependencyScannerOptions {
  client?: OsvClient;
  freshnessDays?: number;
  now?: () => Date;
  concurrency?: number;
  perRequestTimeoutMs?: number;
  maxLookups?: number;
  maxVulnerabilities?: number;
  totalDeadlineMs?: number;
  setTimer?: (callback: () => void, ms: number) => { cancel: () => void };
}

function emptyOutcomes(): DependencyLookupOutcomes {
  return { success: 0, timeout: 0, aborted: 0, rate_limited: 0, network_error: 0, live: 0, fallback: 0 };
}

export type NotCheckedCause =
  | 'no-exact-version'
  | 'time-budget'
  | 'lookup-cap'
  | 'cancelled'
  | 'lookup-failed';

const NOT_CHECKED_REASON: Record<NotCheckedCause, (count: number) => string> = {
  'no-exact-version': (n) => `${n} dependencies had no exact version to check`,
  'time-budget': (n) => `${n} dependencies were not checked before the audit's time budget ran out`,
  'lookup-cap': (n) => `${n} dependencies were not checked because the audit's lookup cap was reached`,
  cancelled: (n) => `${n} dependencies were not checked because the audit was cancelled`,
  'lookup-failed': (n) => `${n} dependencies whose lookup failed or could not be completed`,
};

const NOT_CHECKED_ORDER: NotCheckedCause[] = [
  'no-exact-version',
  'time-budget',
  'lookup-cap',
  'cancelled',
  'lookup-failed',
];

export class OsvDependencyScanner implements DependencyVulnerabilityScanner {
  private readonly client: OsvClient;
  private readonly freshnessDays: number;
  private readonly now: () => Date;
  private readonly concurrency: number;
  private readonly perRequestTimeoutMs: number;
  private readonly maxLookups: number;
  private readonly maxVulnerabilities: number;
  private readonly totalDeadlineMs: number;
  private readonly setTimer: (callback: () => void, ms: number) => { cancel: () => void };

  constructor(options: OsvDependencyScannerOptions = {}) {
    this.client = options.client ?? new CachedOsvClient();
    this.freshnessDays = validateFreshnessDays(options.freshnessDays ?? DEFAULT_FRESHNESS_DAYS);
    this.now = options.now ?? (() => new Date());
    this.concurrency = validateConcurrency('OsvDependencyScanner.concurrency', options.concurrency ?? DEFAULT_CONCURRENCY);
    this.perRequestTimeoutMs = validateTimeoutMs(
      'OsvDependencyScanner.perRequestTimeoutMs',
      options.perRequestTimeoutMs ?? DEFAULT_PER_REQUEST_TIMEOUT_MS,
    );
    this.maxLookups = validateCountLimit('OsvDependencyScanner.maxLookups', options.maxLookups ?? MAX_OSV_LOOKUPS);
    this.maxVulnerabilities = validateCountLimit(
      'OsvDependencyScanner.maxVulnerabilities',
      options.maxVulnerabilities ?? MAX_DEPENDENCY_VULNERABILITIES,
    );
    this.totalDeadlineMs = validateTimeoutMs(
      'OsvDependencyScanner.totalDeadlineMs',
      options.totalDeadlineMs ?? DEFAULT_TOTAL_DEADLINE_MS,
    );
    this.setTimer =
      options.setTimer ??
      ((callback, ms) => {
        const handle = setTimeout(callback, ms);
        if (typeof handle.unref === 'function') handle.unref();
        return { cancel: () => clearTimeout(handle) };
      });
  }

  async scanDependencies(
    dependencies: CollectedDependency[],
    context: DependencyAuditContext = {},
  ): Promise<DependencyAuditSummary> {
    const vulnerabilities: DependencyVulnerability[] = [];
    const notChecked: string[] = [];
    const notCheckedCauses: NotCheckedCause[] = [];
    const markNotChecked = (label: string, cause: NotCheckedCause): void => {
      notChecked.push(label);
      notCheckedCauses.push(cause);
    };
    const diagnostics: string[] = [...(context.parseDiagnostics ?? [])];
    const outcomes = emptyOutcomes();
    const checkedLive: string[] = [];
    const checkedFromCache: string[] = [];
    const skippedNoExactVersion: string[] = [];
    const missed: string[] = [];
    const cacheMisses: string[] = [];
    const networkFailures: string[] = [];
    let checked = 0;
    let lookupFailed = false;
    let timedOut = false;
    let usedFallback = false;
    let vulnerabilitiesCapped = false;
    let oldestFallbackDate: string | undefined;
    let liveDataDate: string | undefined;

    const allAuditable = dependencies.filter((d) => d.installedVersion !== undefined);
    for (const dependency of dependencies) {
      if (dependency.installedVersion === undefined) {
        const label = labelFor(dependency);
        markNotChecked(label, 'no-exact-version');
        skippedNoExactVersion.push(label);
      }
    }

    let auditable = allAuditable;
    if (allAuditable.length > this.maxLookups) {
      auditable = allAuditable.slice(0, this.maxLookups);
      const dropped = allAuditable.slice(this.maxLookups);
      for (const dependency of dropped) {
        const label = labelFor(dependency);
        markNotChecked(label, 'lookup-cap');
        missed.push(label);
      }
      diagnostics.push(
        `Dependency audit lookup cap reached: ${allAuditable.length} pinned version(s) exceed the maximum of ` +
          `${this.maxLookups}; ${dropped.length} were not checked.`,
      );
    }

    const controller = new AbortController();
    let deadlineHit = false;
    const external = context.signal;
    const onExternalAbort = (): void => controller.abort();
    if (external !== undefined) {
      if (external.aborted) controller.abort();
      else external.addEventListener('abort', onExternalAbort, { once: true });
    }
    const timer = this.setTimer(() => {
      deadlineHit = true;
      controller.abort();
    }, this.totalDeadlineMs);

    let results: (PromiseSettledResult<OsvLookupResult> | undefined)[];
    try {
      results = await this.lookupAll(auditable, controller.signal);
    } finally {
      timer.cancel();
      if (external !== undefined) external.removeEventListener('abort', onExternalAbort);
    }

    if (deadlineHit) {
      diagnostics.push(
        `Dependency audit total deadline (${this.totalDeadlineMs} ms) exceeded; ` +
          'remaining lookups were not performed and are reported not-checked.',
      );
    }

    for (let i = 0; i < auditable.length; i += 1) {
      const dependency = auditable[i];
      if (dependency === undefined) continue;
      const settled = results[i];
      if (settled === undefined) {
        outcomes.aborted += 1;
        lookupFailed = true;
        const label = labelFor(dependency);
        markNotChecked(label, deadlineHit ? 'time-budget' : 'cancelled');
        missed.push(label);
        continue;
      }
      const outcome: OsvLookupResult =
        settled.status === 'fulfilled'
          ? settled.value
          : { status: 'network_error', dataSource: 'live', source: this.client.source };

      if (outcome.diagnostic !== undefined && !diagnostics.includes(outcome.diagnostic)) {
        diagnostics.push(outcome.diagnostic);
      }
      outcomes[outcome.status] += 1;
      if (outcome.status !== 'success') {
        if (outcome.status === 'timeout') {
          timedOut = true;
          diagnostics.push(`OSV lookup for ${labelFor(dependency)} timed out.`);
        }
        lookupFailed = true;
        const label = labelFor(dependency);
        markNotChecked(
          label,
          outcome.status === 'aborted' ? (deadlineHit ? 'time-budget' : 'cancelled') : 'lookup-failed',
        );
        missed.push(label);
        if (outcome.fallbackStatus !== undefined || /cache miss/i.test(outcome.diagnostic ?? '')) cacheMisses.push(label);
        if (outcome.dataSource === 'live' || outcome.fallbackStatus !== undefined) networkFailures.push(label);
        continue;
      }

      outcomes[outcome.dataSource] += 1;
      const checkedLabel = labelFor(dependency);
      if (outcome.dataSource === 'live') checkedLive.push(checkedLabel);
      else checkedFromCache.push(checkedLabel);
      if (outcome.dataSource === 'fallback') {
        usedFallback = true;
        const date = outcome.generatedAt ?? this.client.generatedAt;
        if (date !== undefined && (oldestFallbackDate === undefined || date < oldestFallbackDate)) {
          oldestFallbackDate = date;
        }
      } else {
        const date = outcome.generatedAt ?? this.client.generatedAt;
        if (date !== undefined && (liveDataDate === undefined || date < liveDataDate)) {
          liveDataDate = date;
        }
      }
      checked += 1;
      for (const vulnerability of outcome.vulnerabilities ?? []) {
        if (vulnerabilities.length >= this.maxVulnerabilities) {
          vulnerabilitiesCapped = true;
          break;
        }
        vulnerabilities.push({
          dependency: dependency.name,
          ecosystem: dependency.ecosystem,
          version: dependency.installedVersion,
          ...(dependency.source !== undefined ? { sourcePath: dependency.source } : {}),
          severity: vulnerability.severity,
          advisoryId: vulnerability.id,
          summary: vulnerability.summary,
          ...(vulnerability.reference !== undefined ? { reference: vulnerability.reference } : {}),
          dataSource: outcome.dataSource,
        });
      }
    }

    if (vulnerabilitiesCapped) {
      diagnostics.push(
        `Retained-advisory cap reached: more than ${this.maxVulnerabilities} vulnerabilities were found; ` +
          'the list was truncated. Treat the audit as incomplete and re-run after reducing the input.',
      );
    }

    vulnerabilities.sort(
      (a, b) =>
        SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
        a.dependency.localeCompare(b.dependency) ||
        (a.version ?? '').localeCompare(b.version ?? '') ||
        a.advisoryId.localeCompare(b.advisoryId),
    );
    const notCheckedByCause: Record<NotCheckedCause, string[]> = {
      'no-exact-version': [],
      'time-budget': [],
      'lookup-cap': [],
      cancelled: [],
      'lookup-failed': [],
    };
    for (let i = 0; i < notChecked.length; i += 1) {
      const cause = notCheckedCauses[i];
      const label = notChecked[i];
      if (cause !== undefined && label !== undefined) notCheckedByCause[cause].push(label);
    }
    for (const cause of NOT_CHECKED_ORDER) notCheckedByCause[cause].sort((a, b) => a.localeCompare(b));

    notChecked.sort((a, b) => a.localeCompare(b));
    for (const list of [checkedLive, checkedFromCache, skippedNoExactVersion, missed, cacheMisses, networkFailures]) {
      list.sort((a, b) => a.localeCompare(b));
    }

    const cacheAgeDays =
      usedFallback && oldestFallbackDate !== undefined ? ageInDays(oldestFallbackDate, this.now()) : undefined;
    const staleFallback =
      usedFallback &&
      (oldestFallbackDate === undefined || (cacheAgeDays !== undefined && cacheAgeDays > this.freshnessDays));

    const rawDatasetDate = usedFallback ? oldestFallbackDate : (liveDataDate ?? this.client.generatedAt);
    const datasetDate =
      typeof rawDatasetDate === 'string' && rawDatasetDate.trim() !== '' ? rawDatasetDate : undefined;

    const incomplete =
      usedFallback ||
      lookupFailed ||
      timedOut ||
      staleFallback ||
      notChecked.length > 0 ||
      diagnostics.length > 0;

    return {
      performed: true,
      incomplete,
      source: this.client.source,
      ...(datasetDate !== undefined ? { datasetDate } : {}),
      ...(cacheAgeDays !== undefined ? { cacheAgeDays } : {}),
      dependenciesCollected: dependencies.length,
      checked,
      notChecked,
      vulnerabilities,
      diagnostics,
      outcomes,
      checkCoverage: {
        checkedLive,
        checkedFromCache,
        skipped: skippedNoExactVersion,
        missed,
        cacheMisses,
        networkFailures,
        notChecked: [...notChecked],
        notCheckedByCause,
      },
      note: buildNote({
        source: this.client.source,
        datasetDate,
        cacheAgeDays,
        stale: staleFallback,
        lookupFailed,
        timedOut,
        usedFallback,
        checked,
        notChecked,
        notCheckedByCause,
        diagnostics,
        vulnerabilities,
        incomplete,
      }),
    };
  }

  private async lookupAll(
    auditable: CollectedDependency[],
    signal: AbortSignal,
  ): Promise<(PromiseSettledResult<OsvLookupResult> | undefined)[]> {
    if (this.client.lookupMany === undefined) {
      return mapWithConcurrency(auditable, this.concurrency, signal, (dependency) => this.lookup(dependency, signal));
    }
    const options: OsvQueryOptions = { timeoutMs: this.perRequestTimeoutMs, signal };
    const queries = auditable.map((dependency) => queryFor(dependency));

    const slotOfQuery: number[] = new Array(queries.length);
    const slotByKey = new Map<string, number>();
    const distinct: OsvQuery[] = [];
    for (let i = 0; i < queries.length; i += 1) {
      const query = queries[i] as OsvQuery;
      const key = `${query.ecosystem}|${query.name}|${query.version}`;
      let slot = slotByKey.get(key);
      if (slot === undefined) {
        slot = distinct.length;
        slotByKey.set(key, slot);
        distinct.push(query);
      }
      slotOfQuery[i] = slot;
    }

    const unanswered = (): OsvLookupResult => ({
      status: 'network_error',
      dataSource: this.client.live ? 'live' : 'fallback',
      source: this.client.source,
    });
    let answers: OsvLookupResult[];
    try {
      answers = await structuredLookupMany(this.client, distinct, options);
    } catch {
      answers = distinct.map(unanswered);
    }
    return queries.map((_query, i) => ({
      status: 'fulfilled' as const,
      value: answers[slotOfQuery[i] as number] ?? unanswered(),
    }));
  }

  private async lookup(dependency: CollectedDependency, signal?: AbortSignal): Promise<OsvLookupResult> {
    const options: OsvQueryOptions = {
      timeoutMs: this.perRequestTimeoutMs,
      ...(signal !== undefined ? { signal } : {}),
    };
    try {
      return await structuredLookup(this.client, queryFor(dependency), options);
    } catch {
      return { status: 'network_error', dataSource: this.client.live ? 'live' : 'fallback', source: this.client.source };
    }
  }
}

function queryFor(dependency: CollectedDependency): OsvQuery {
  return {
    ecosystem: dependency.ecosystem as DependencyEcosystem,
    name: dependency.name,
    version: dependency.installedVersion ?? '',
  };
}

function labelFor(dependency: CollectedDependency): string {
  const version = dependency.installedVersion ?? dependency.declaredRange;
  return `${dependency.ecosystem}:${dependency.name}${version !== undefined ? `@${version}` : ''}`;
}

async function mapWithConcurrency<T, R>(
  items: T[],
  limit: number,
  signal: AbortSignal,
  fn: (item: T, index: number) => Promise<R>,
): Promise<(PromiseSettledResult<R> | undefined)[]> {
  const results = new Array<PromiseSettledResult<R> | undefined>(items.length);
  let next = 0;
  const workers: Promise<void>[] = [];
  const worker = async (): Promise<void> => {
    for (;;) {
      if (signal.aborted) return;
      const index = next;
      next += 1;
      if (index >= items.length) return;
      const item = items[index] as T;
      try {
        results[index] = { status: 'fulfilled', value: await fn(item, index) };
      } catch (reason) {
        results[index] = { status: 'rejected', reason };
      }
    }
  };
  const workerCount = Math.min(limit, items.length);
  for (let i = 0; i < workerCount; i += 1) workers.push(worker());
  await Promise.all(workers);
  return results;
}

function ageInDays(isoDate: string, now: Date): number {
  const then = new Date(isoDate).getTime();
  if (Number.isNaN(then)) return Number.POSITIVE_INFINITY;
  return Math.max(0, Math.floor((now.getTime() - then) / 86_400_000));
}

interface NoteInput {
  source: string;
  datasetDate?: string;
  cacheAgeDays?: number;
  stale: boolean;
  lookupFailed: boolean;
  timedOut: boolean;
  usedFallback: boolean;
  checked: number;
  notChecked: string[];
  notCheckedByCause: Record<NotCheckedCause, string[]>;
  diagnostics: string[];
  vulnerabilities: DependencyVulnerability[];
  incomplete: boolean;
}

function buildNote(input: NoteInput): string {
  const parts: string[] = [];
  parts.push(
    `Source: ${input.source}${input.datasetDate !== undefined ? ` (data ${input.datasetDate}` +
      `${input.cacheAgeDays !== undefined ? `, ~${input.cacheAgeDays}d old` : ''})` : ''}.`,
  );
  parts.push(`Checked ${input.checked} pinned dependency version(s).`);
  if (input.vulnerabilities.length > 0) {
    parts.push(`${input.vulnerabilities.length} known vulnerable version(s) found.`);
  }
  if (input.incomplete) {
    const reasons: string[] = [];
    if (input.usedFallback) reasons.push('one or more lookups used the offline fallback');
    if (input.stale) reasons.push('fallback dataset may be stale');
    if (input.lookupFailed) reasons.push('one or more lookups failed');
    if (input.timedOut) reasons.push('one or more lookups timed out');
    for (const cause of NOT_CHECKED_ORDER) {
      const count = input.notCheckedByCause[cause].length;
      if (count > 0) reasons.push(NOT_CHECKED_REASON[cause](count));
    }
    if (input.diagnostics.length > 0) {
      reasons.push(`${input.diagnostics.length} manifest or lockfile problem(s)`);
    }
    parts.push(
      `Incomplete dependency check (${reasons.join('; ')}). ` +
        'For the most accurate results, refresh the OSV data or use a live OSV client, and include a lockfile for full coverage.',
    );
  } else if (input.vulnerabilities.length === 0) {
    parts.push('No known vulnerabilities for the checked versions.');
  }
  return parts.join(' ');
}
