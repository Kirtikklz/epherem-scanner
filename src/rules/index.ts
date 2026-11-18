import { MAX_TOTAL_FINDINGS, MAX_TOTAL_MATCH_WORK, SEVERITY_ORDER } from '../shared/constants.js';
import { isGeneratedOrVendorPath, isNonProductionCodePath, isScannerInternalPath } from '../input/fileFilters.js';
import { isVendoredBundleContent } from '../shared/liveCode.js';
import { runWithMatchBudget, type MatchBudget } from '../shared/utils.js';
import type { Finding, ProjectMap, RuleContext, RuleFailure, RuleRunResult, ScanRule } from '../shared/types.js';
import { commandInjection } from './basic/commandInjection.js';
import { dangerousDeploymentConfig } from './basic/dangerousDeploymentConfig.js';
import { exposedSourceMaps } from './basic/exposedSourceMaps.js';
import { insecureCryptography } from './basic/insecureCryptography.js';
import { massAssignment } from './basic/massAssignment.js';
import { prototypePollution } from './basic/prototypePollution.js';
import { publicCloudStorage } from './basic/publicCloudStorage.js';
import { unrestrictedGraphql } from './basic/unrestrictedGraphql.js';
import { unsafeDeserialization } from './basic/unsafeDeserialization.js';
import { unsafeDynamicCode } from './basic/unsafeDynamicCode.js';
import { verboseErrorResponse } from './basic/verboseErrorResponse.js';
import { weakPasswordStorage } from './basic/weakPasswordStorage.js';
import { nosqlInjection } from './basic/nosqlInjection.js';
import { ldapInjection } from './basic/ldapInjection.js';
import { xmlExternalEntity } from './basic/xxe.js';
import { oauthMisconfiguration } from './basic/oauthMisconfiguration.js';
import { weakSessionHandling } from './basic/weakSessionHandling.js';
import { dangerousCorsWildcard } from './basic/dangerousCorsWildcard.js';
import { debugModeEnabled } from './basic/debugModeEnabled.js';
import { envFileIncluded } from './basic/envFileIncluded.js';
import { firebaseOpenRules } from './basic/firebaseOpenRules.js';
import { hardcodedSecret } from './basic/hardcodedSecret.js';
import { clientSideAiSecret } from './basic/clientSideAiSecret.js';
import { insecureCookies } from './basic/insecureCookies.js';
import { missingSecurityHeaders } from './basic/missingSecurityHeaders.js';
import { openRedirect } from './basic/openRedirect.js';
import { pathTraversal } from './basic/pathTraversal.js';
import { publicAdminRouteHint } from './basic/publicAdminRouteHint.js';
import { sensitiveDataInLogs } from './basic/sensitiveDataInLogs.js';
import { sqlInjection } from './basic/sqlInjection.js';
import { serverSideRequestForgery } from './basic/ssrf.js';
import { supabaseServiceRoleExposed } from './basic/supabaseServiceRoleExposed.js';
import { unsafeFileUpload } from './basic/unsafeFileUpload.js';
import { weakJwtHandling } from './basic/weakJwtHandling.js';
import { crossSiteScripting } from './basic/xss.js';
import { apiMutationWithoutAuth } from './contextual/apiMutationWithoutAuth.js';
import { brokenAccessControl } from './contextual/brokenAccessControl.js';
import { clientControlledAuthorization } from './contextual/clientControlledAuthorization.js';
import { clientSideOnlyAuthorization } from './contextual/clientSideOnlyAuthorization.js';
import { csrfProtection } from './contextual/csrfProtection.js';
import { databaseDeleteWithoutOwnershipCheck } from './contextual/databaseDeleteWithoutOwnershipCheck.js';
import { envUsageWithoutServerBoundary } from './contextual/envUsageWithoutServerBoundary.js';
import { missingRateLimit } from './contextual/missingRateLimit.js';
import { missingWebhookVerification } from './contextual/missingWebhookVerification.js';
import { serverActionWithoutAuthorization } from './contextual/serverActionWithoutAuthorization.js';
import { missingRequestBodyValidation } from './contextual/missingRequestBodyValidation.js';
import { supabaseClientPrivilegedOperation } from './contextual/supabaseClientPrivilegedOperation.js';
import { supabaseReadableSensitiveData } from './contextual/supabaseReadableSensitiveData.js';
import { firebaseReadableSensitiveData } from './contextual/firebaseReadableSensitiveData.js';
import { supabaseRlsNotDetected } from './contextual/supabaseRlsNotDetected.js';
import { placeholderAuthentication } from './contextual/placeholderAuthentication.js';
import { failOpenAuthentication } from './contextual/failOpenAuthentication.js';


export const basicRules: ScanRule[] = [
  envFileIncluded,
  hardcodedSecret,
  clientSideAiSecret,
  supabaseServiceRoleExposed,
  firebaseOpenRules,
  dangerousCorsWildcard,
  missingSecurityHeaders,
  publicAdminRouteHint,
  sqlInjection,
  commandInjection,
  pathTraversal,
  serverSideRequestForgery,
  openRedirect,
  crossSiteScripting,
  weakJwtHandling,
  insecureCookies,
  unsafeFileUpload,
  sensitiveDataInLogs,
  debugModeEnabled,
  publicCloudStorage,
  verboseErrorResponse,
  unsafeDynamicCode,
  insecureCryptography,
  weakPasswordStorage,
  prototypePollution,
  massAssignment,
  unsafeDeserialization,
  unrestrictedGraphql,
  exposedSourceMaps,
  dangerousDeploymentConfig,
  nosqlInjection,
  ldapInjection,
  xmlExternalEntity,
  oauthMisconfiguration,
  weakSessionHandling,
];

export const contextualRules: ScanRule[] = [
  apiMutationWithoutAuth,
  databaseDeleteWithoutOwnershipCheck,
  supabaseClientPrivilegedOperation,
  supabaseReadableSensitiveData,
  firebaseReadableSensitiveData,
  supabaseRlsNotDetected,
  envUsageWithoutServerBoundary,
  missingWebhookVerification,
  brokenAccessControl,
  missingRateLimit,
  csrfProtection,
  missingRequestBodyValidation,
  serverActionWithoutAuthorization,
  clientControlledAuthorization,
  clientSideOnlyAuthorization,
  placeholderAuthentication,
  failOpenAuthentication,
];

export function runBasicRules(context: RuleContext, options: RunRulesOptions = {}): RuleRunResult {
  return runRules(basicRules, context, options);
}

export function runContextualRules(context: RuleContext, options: RunRulesOptions = {}): RuleRunResult {
  return runRules(contextualRules, context, options);
}

export class FindingBudget {
  private remainingCount: number;
  truncated = false;

  constructor(limit: number = MAX_TOTAL_FINDINGS) {
    this.remainingCount = Math.max(0, Math.floor(limit));
  }

  get remaining(): number {
    return this.remainingCount;
  }

  get exhausted(): boolean {
    return this.remainingCount <= 0;
  }

  take(findings: Finding[]): Finding[] {
    if (findings.length <= this.remainingCount) {
      this.remainingCount -= findings.length;
      return findings;
    }
    const accepted = findings.slice(0, this.remainingCount);
    this.remainingCount = 0;
    this.truncated = true;
    return accepted;
  }
}

export interface RunRulesOptions {
  budget?: FindingBudget;
  workBudget?: MatchBudget;
}

export function isScannablePath(filePath: string, scannerRootPrefix?: string): boolean {
  return (
    !isScannerInternalPath(filePath, scannerRootPrefix) &&
    !isNonProductionCodePath(filePath) &&
    !isGeneratedOrVendorPath(filePath)
  );
}

function filterProjectMap(projectMap: ProjectMap): ProjectMap {
  const prefix = projectMap.scannerRootPrefix;
  const s = (paths: string[]): string[] => paths.filter((path) => isScannablePath(path, prefix));
  const o = <T extends { filePath: string }>(rows: T[]): T[] =>
    rows.filter((row) => isScannablePath(row.filePath, prefix));
  return {
    ...projectMap,
    apiRoutes: o(projectMap.apiRoutes),
    frontendComponents: s(projectMap.frontendComponents),
    authFiles: s(projectMap.authFiles),
    middlewareFiles: s(projectMap.middlewareFiles),
    middlewareMatchers: o(projectMap.middlewareMatchers),
    databaseFiles: s(projectMap.databaseFiles),
    envFiles: s(projectMap.envFiles),
    configFiles: s(projectMap.configFiles),
    supabaseUsage: s(projectMap.supabaseUsage),
    firebaseUsage: s(projectMap.firebaseUsage),
    databaseCalls: o(projectMap.databaseCalls),
    imports: o(projectMap.imports),
    dangerousOperations: o(projectMap.dangerousOperations),
    publicClientUsage: s(projectMap.publicClientUsage),
    serverSideUsage: s(projectMap.serverSideUsage),
    authSignals: o(projectMap.authSignals),
    envUsage: o(projectMap.envUsage),
    ...(projectMap.routeSecurityProfiles !== undefined
      ? { routeSecurityProfiles: o(projectMap.routeSecurityProfiles) }
      : {}),
  };
}

function withNonScannablePathsExcluded(context: RuleContext): RuleContext {
  const entries = context.fileMap.entries.filter((entry) =>
    isScannablePath(entry.path, context.projectMap.scannerRootPrefix)
    && !isVendoredBundleContent(entry.content));
  const projectMap = filterProjectMap(context.projectMap);
  if (entries.length === context.fileMap.entries.length && projectMap.apiRoutes.length === context.projectMap.apiRoutes.length) {
    if (projectMap.apiRoutes === context.projectMap.apiRoutes) return context;
  }
  return { ...context, fileMap: { ...context.fileMap, entries }, projectMap };
}

export function runRules(
  rules: ScanRule[],
  context: RuleContext,
  options: RunRulesOptions = {},
): RuleRunResult {
  context = withNonScannablePathsExcluded(context);
  const budget = options.budget ?? new FindingBudget();
  const work: MatchBudget = options.workBudget ?? { remaining: MAX_TOTAL_MATCH_WORK, truncated: false };
  const findings: Finding[] = [];
  const failures: RuleFailure[] = [];
  const completedRuleIds: string[] = [];
  for (const rule of rules) {
    if (budget.exhausted) {
      budget.truncated = true;
      break;
    }
    if (work.remaining <= 0) {
      work.truncated = true;
      break;
    }
    let ruleFindings: Finding[];
    try {
      ruleFindings = runWithMatchBudget(work, () => rule.run(context));
    } catch (error) {
      failures.push({
        ruleId: rule.id,
        message: error instanceof Error ? error.message : String(error),
      });
      continue;
    }
    completedRuleIds.push(rule.id);
    findings.push(...budget.take(ruleFindings));
  }
  return {
    findings: dedupeAndSort(findings),
    failures,
    completedRuleIds,
    truncated: budget.truncated || work.truncated,
  };
}

export function dedupeAndSort(findings: Finding[]): Finding[] {
  const byId = new Map<string, Finding>();
  for (const finding of findings) {
    if (!byId.has(finding.id)) byId.set(finding.id, finding);
  }
  return [...byId.values()].sort(
    (a, b) =>
      (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9) ||
      a.filePath.localeCompare(b.filePath) ||
      a.lineStart - b.lineStart ||
      a.ruleId.localeCompare(b.ruleId) ||
      a.id.localeCompare(b.id),
  );
}
