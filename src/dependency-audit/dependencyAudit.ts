import type { CollectedDependency } from '../stack-detection/collectDependencies.js';
import type { DependencyAuditSummary } from '../shared/types.js';
import { OsvDependencyScanner } from './osvDependencyScanner.js';
import { CachedOsvClient, FallbackOsvClient, LiveOsvClient } from './osvClient.js';

export interface DependencyAuditContext {
  parseDiagnostics?: string[];
  signal?: AbortSignal;
}

export interface DependencyVulnerabilityScanner {
  scanDependencies(
    dependencies: CollectedDependency[],
    context?: DependencyAuditContext,
  ): Promise<DependencyAuditSummary>;
}

export class MockDependencyVulnerabilityScanner implements DependencyVulnerabilityScanner {
  // eslint-disable-next-line @typescript-eslint/require-await
  async scanDependencies(
    dependencies: CollectedDependency[],
    context: DependencyAuditContext = {},
  ): Promise<DependencyAuditSummary> {
    return {
      performed: false,
      incomplete: true,
      source: 'disabled',
      dependenciesCollected: dependencies.length,
      checked: 0,
      notChecked: dependencies.map((dependency) => dependency.name).sort((a, b) => a.localeCompare(b)),
      vulnerabilities: [],
      diagnostics: [...(context.parseDiagnostics ?? [])],
      outcomes: { success: 0, timeout: 0, aborted: 0, rate_limited: 0, network_error: 0, live: 0, fallback: 0 },
      note: 'Dependency auditing disabled for this scan.',
    };
  }
}

export function createDefaultOsvClient(): FallbackOsvClient {
  return new FallbackOsvClient(new LiveOsvClient(), new CachedOsvClient());
}

let defaultScannerSingleton: DependencyVulnerabilityScanner | undefined;

export function getDefaultDependencyScanner(): DependencyVulnerabilityScanner {
  defaultScannerSingleton ??= new OsvDependencyScanner({ client: createDefaultOsvClient() });
  return defaultScannerSingleton;
}
