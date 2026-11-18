import {
  ARCHIVE_ENTRY_RULE_IDS,
  NON_REGISTRY_RULE_IDS,
  RULE_CATALOG,
  labelForRule,
  type CatalogRuleId,
} from '../rules/ruleCatalog.js';
import { ruleMetadata } from '../rules/ruleRegistry.js';
import { crossFileFlowRuleIds } from '../ast/crossFileTaint.js';
import { DECLARATIVE_LANGUAGES, detectLanguages, type DetectedLanguages } from '../shared/languages.js';

import type {
  DependencyAuditStatus,
  DependencyAuditSummary,
  Finding,
  RuleContext,
  RuleResult,
} from '../shared/types.js';

export interface BuildRuleResultsInput {
  findings: readonly Finding[];
  context: RuleContext;
  codeScanComplete: boolean;
  completedRuleIds?: readonly string[];
  failedExecutionRuleIds?: readonly string[];
  dependencyAudit: DependencyAuditSummary;
  dependencyAuditStatus: DependencyAuditStatus;
  archiveObserved: boolean;
  languages: DetectedLanguages;
}

export function buildRuleResults(input: BuildRuleResultsInput): RuleResult[] {
  const findingRuleIds = new Set(input.findings.map((finding) => finding.ruleId));
  const completed = input.completedRuleIds === undefined ? undefined : new Set(input.completedRuleIds);
  const executionFailures = new Set(input.failedExecutionRuleIds ?? []);
  const context = input.context;
  const detectedLanguages = new Set(input.languages.detected);
  const analysedLanguages = new Set(input.languages.analysed);
  const unreadLanguages = new Set(input.languages.unreadLanguages);

  return Object.keys(RULE_CATALOG)
    .sort((a, b) => a.localeCompare(b))
    .map((ruleId): RuleResult => {
      const languageCoverage = withNarrowReader(ruleId, ruleLanguageCoverage(ruleId, detectedLanguages), detectedLanguages);

      if (findingRuleIds.has(ruleId)) {
        return result(ruleId, 'failed', withCrossFileLoss(ruleId, languageCoverage, context));
      }

      if (NON_REGISTRY_RULE_IDS.has(ruleId as keyof typeof RULE_CATALOG)) {
        if (ruleId === 'dependency_vulnerability') {
          return dependencyRuleResult(ruleId, input.dependencyAudit, input.dependencyAuditStatus);
        }
        if (ARCHIVE_ENTRY_RULE_IDS.has(ruleId as keyof typeof RULE_CATALOG)) {
          return archiveEntryRuleResult(ruleId, input.archiveObserved);
        }
      }

      if (!input.codeScanComplete || executionFailures.has(ruleId)) {
        return result(ruleId, 'not_completed', {
          coverage: 'none',
          coverageReason: executionFailures.has(ruleId)
            ? 'The rule failed during execution; its checks were not applied.'
            : 'The code scan did not complete; absence of findings is not proof of a pass.',
        });
      }
      if (completed !== undefined && !completed.has(ruleId)) {
        return result(ruleId, 'not_completed', {
          coverage: 'none',
          coverageReason: 'Rule execution was skipped (scan budget exhausted before this rule ran).',
        });
      }
      if (!isRuleApplicable(ruleId, context, input.languages)) {
        return result(ruleId, 'not_applicable');
      }
      const noSql = noSqlCoverage(ruleId, analysedLanguages, unreadLanguages);
      if (noSql !== undefined) return result(ruleId, 'not_completed', noSql);
      if (languageCoverage !== undefined && languageCoverage.coverage !== 'full') {
        return result(ruleId, 'not_completed', languageCoverage);
      }
      const unread = unreadCoverage(ruleId, analysedLanguages, unreadLanguages);
      if (unread !== undefined) return result(ruleId, 'not_completed', unread);
      return result(ruleId, 'passed', { coverage: 'full' });
    });
}

interface CoverageInfo {
  coverage: RuleResult['coverage'];
  coverageReason?: string;
}

export const CROSS_FILE_LOSS_COVERAGE_REASON =
  'Cross-file analysis stopped early on this project, so data passing from one function into another was not ' +
  'followed; this check ran within each file only.';

function withCrossFileLoss(
  ruleId: string,
  coverage: CoverageInfo | undefined,
  context: RuleContext,
): CoverageInfo | undefined {
  if (context.projectMap.crossFileTaint?.status !== 'truncated') return coverage;
  if (!crossFileFlowRuleIds().includes(ruleId)) return coverage;
  if (coverage === undefined || coverage.coverage === 'full') {
    return { coverage: 'partial', coverageReason: CROSS_FILE_LOSS_COVERAGE_REASON };
  }
  return {
    coverage: coverage.coverage,
    coverageReason: [coverage.coverageReason, CROSS_FILE_LOSS_COVERAGE_REASON].filter(Boolean).join(' '),
  };
}

function result(ruleId: string, status: RuleResult['status'], info?: CoverageInfo): RuleResult {
  return {
    ruleId,
    label: labelForRule(ruleId),
    status,
    ...(info?.coverage !== undefined ? { coverage: info.coverage } : {}),
    ...(info?.coverageReason !== undefined ? { coverageReason: info.coverageReason } : {}),
  };
}

export function ruleLanguageCoverage(
  ruleId: string,
  detected: ReadonlySet<string>,
): CoverageInfo | undefined {
  const meta = ruleMetadata(ruleId);
  if (meta === undefined || detected.size === 0) return undefined;
  if (meta.languages.every((language) => DECLARATIVE_LANGUAGES.has(language))) return undefined;
  const supportedLanguages = meta.languages.filter((language) => language !== 'config');
  const supported = new Set<string>(supportedLanguages);
  const covered = [...detected].filter((language) => supported.has(language));
  const missedCode = [...detected].filter(
    (language) => !supported.has(language) && !DECLARATIVE_LANGUAGES.has(language),
  );
  const uncovered = (covered.length === 0 && missedCode.length === 0
    ? [...detected].filter((language) => !supported.has(language))
    : missedCode
  ).sort((a, b) => a.localeCompare(b));
  if (uncovered.length === 0) return { coverage: 'full' };
  return {
    coverage: covered.length > 0 ? 'partial' : 'none',
    coverageReason:
      `${uncovered.join(', ')} ${uncovered.length === 1 ? 'is' : 'are'} detected but this rule currently supports ` +
      `${supportedLanguages.join(', ')} only.`,
  };
}

const NARROW_LANGUAGE_READERS: Readonly<Record<string, { language: string; reason: string }>> = {
  missing_csrf_protection: {
    language: 'python',
    reason:
      'python is detected but this rule reads only two Python shapes (CSRF protection switched off in ' +
      'Flask-WTF settings, and @csrf_exempt on a view that uses the session), so Python CSRF protection was ' +
      'only partly checked.',
  },
  api_mutation_without_auth: {
    language: 'python',
    reason:
      'python is detected but this rule reads only two Python write shapes in a route file (an INSERT, UPDATE ' +
      'or DELETE written as SQL text in an execute or query call, and a db.insert, db.update or db.delete ' +
      'call), so Python routes that write data were only partly checked for a sign-in check.',
  },
  broken_access_control: {
    language: 'python',
    reason:
      'python is detected but this rule reads only one Python shape (a select, update or find call whose own ' +
      'arguments carry a Flask request value such as request.args, request.form or request.json), so Python ' +
      'record access was only partly checked for an ownership check.',
  },
  database_delete_without_ownership_check: {
    language: 'python',
    reason:
      'python is detected but this rule reads only four Python delete shapes (a DELETE written as SQL text, ' +
      'SQLAlchemy deletes, Django ORM deletes and supabase-py delete chains, the last three only when the ' +
      'deleted rows come from a filter or fetch it recognises), so Python deletes were only partly checked for ' +
      'an ownership check.',
  },
  mass_assignment: {
    language: 'python',
    reason:
      'python is detected but this rule reads only one Python shape (a create, update, upsert or set call ' +
      'given request.json or request.data whole), so Python mass assignment was only partly checked.',
  },
  missing_rate_limit: {
    language: 'python',
    reason:
      'python is detected but this rule reads only FastAPI, Flask and Django routes whose path names sign-in, ' +
      'sign-up, a password, a token, verification or payment, and credits only a Flask-Limiter or slowapi ' +
      'limit, a project middleware that answers 429, or a handler that answers 429 itself, so Python rate ' +
      'limiting was only partly checked.',
  },
  missing_request_body_validation: {
    language: 'python',
    reason:
      'python is detected but this rule reads only four Python body shapes (request.form, request.json, ' +
      'request.data and FastAPI Body(...), in the file of a route that changes data) and credits only pydantic, ' +
      'marshmallow or serializer.is_valid(), so Python request validation was only partly checked.',
  },
  missing_webhook_verification: {
    language: 'python',
    reason:
      'python is detected but this rule reads only one Python shape (a webhook route file that reads the ' +
      'request body or a payload) and credits only a .verify( call beside a signature header, so Python ' +
      'webhook verification was only partly checked.',
  },
};

function withNarrowReader(
  ruleId: string,
  coverage: CoverageInfo | undefined,
  detected: ReadonlySet<string>,
): CoverageInfo | undefined {
  const narrow = NARROW_LANGUAGE_READERS[ruleId];
  if (narrow === undefined || !detected.has(narrow.language)) return coverage;
  if (coverage === undefined || coverage.coverage === 'full') {
    return { coverage: 'partial', coverageReason: narrow.reason };
  }
  return {
    coverage: coverage.coverage,
    coverageReason: [coverage.coverageReason, narrow.reason].filter(Boolean).join(' '),
  };
}

function unreadCoverage(
  ruleId: string,
  analysed: ReadonlySet<string>,
  unread: ReadonlySet<string>,
): CoverageInfo | undefined {
  if (unread.size === 0) return undefined;
  const meta = ruleMetadata(ruleId);
  if (meta === undefined) return undefined;
  const supported = meta.languages.filter((language) => language !== 'config');
  if (supported.length === 0) return undefined;
  const affected = supported.filter((language) => unread.has(language)).sort((a, b) => a.localeCompare(b));
  if (affected.length === 0) return undefined;
  const examined = supported.filter((language) => analysed.has(language));
  return {
    coverage: examined.length > 0 ? 'partial' : 'none',
    coverageReason:
      `Some of this project's ${affected.join(', ')} source was never opened by this scan ` +
      '(see the unread file types in the coverage section), so no finding from this check covers it.',
  };
}

export const NO_SQL_COVERAGE_REASON =
  'No database SQL was found in this project, so its row-level security rules could not be read. ' +
  'Rules set only in the Supabase dashboard cannot be checked from the code.';

export const DATABASE_RULE_CHECK_IDS: ReadonlySet<CatalogRuleId> = new Set<CatalogRuleId>([
  'supabase_readable_sensitive_data',
  'supabase_rls_not_detected',
]);

function noSqlCoverage(
  ruleId: string,
  analysed: ReadonlySet<string>,
  unread: ReadonlySet<string>,
): CoverageInfo | undefined {
  if (!DATABASE_RULE_CHECK_IDS.has(ruleId as CatalogRuleId)) return undefined;
  if (analysed.has('sql') || unread.has('sql')) return undefined;
  return { coverage: 'none', coverageReason: NO_SQL_COVERAGE_REASON };
}

function archiveEntryRuleResult(ruleId: string, archiveObserved: boolean): RuleResult {
  if (!archiveObserved) {
    return result(ruleId, 'not_completed', {
      coverage: 'none',
      coverageReason:
        "This check reads the uploaded archive's list of file names. This scan did not come from an uploaded archive, so it did not run; no finding here is not proof that no such file exists.",
    });
  }
  return result(ruleId, 'passed', { coverage: 'full' });
}

function dependencyRuleResult(
  ruleId: string,
  audit: DependencyAuditSummary,
  status: DependencyAuditStatus,
): RuleResult {
  if (status !== 'complete') {
    const unchecked = audit.dependenciesCollected - audit.checked;
    return result(ruleId, 'not_completed', {
      coverage: audit.checked > 0 ? 'partial' : 'none',
      coverageReason:
        audit.checked > 0
          ? `${audit.checked} of ${audit.dependenciesCollected} collected dependencies were checked; ` +
            `${unchecked} could not be verified (no exact version or lookup not completed).`
          : 'No dependency could be verified against advisory data.',
    });
  }
  if (audit.dependenciesCollected === 0) return result(ruleId, 'not_applicable');
  return result(ruleId, 'passed', { coverage: 'full' });
}

export function isRuleApplicable(
  ruleId: string,
  context: RuleContext,
  languages: Pick<DetectedLanguages, 'detected'> = detectLanguages(context.fileMap),
): boolean {
  const stacks = new Set(context.stack.stacks.map((stack) => stack.name));
  const { fileMap, projectMap } = context;
  const supabase = stacks.has('supabase');
  const hasFirebase =
    stacks.has('firebase') ||
    projectMap.firebaseUsage.length > 0 ||
    fileMap.entries.some((entry) => entry.label === 'firebase_rules');
  const routeText = projectMap.apiRoutes.map((route) => `${route.routePath} ${route.filePath}`);
  const mutationKinds = new Set(['insert', 'update', 'delete', 'upsert', 'write', 'raw_sql']);
  const hasMutation = projectMap.databaseCalls.some((call) => mutationKinds.has(call.kind));

  switch (ruleId) {
    case 'supabase_service_role_exposed':
    case 'supabase_client_used_for_privileged_operation':
    case 'supabase_rls_not_detected':
      return supabase;
    case 'supabase_readable_sensitive_data':
      return supabase || languages.detected.includes('sql');
    case 'firebase_open_rules':
    case 'firebase_readable_sensitive_data':
      return hasFirebase;
    case 'public_cloud_storage':
      return supabase || hasFirebase;
    case 'missing_security_headers':
      return stacks.has('nextjs') || stacks.has('express');
    case 'public_admin_route_hint':
      return routeText.some((text) => /admin|internal|superuser|backoffice/i.test(text));
    case 'api_mutation_without_auth':
      return projectMap.apiRoutes.length > 0 && hasMutation;
    case 'database_delete_without_ownership_check':
      return projectMap.databaseCalls.some((call) => call.kind === 'delete');
    case 'env_usage_without_server_boundary':
      return projectMap.envUsage.length > 0 && projectMap.publicClientUsage.length > 0;
    case 'missing_webhook_verification':
      return routeText.some((text) => /webhook|stripe|callback/i.test(text));
    case 'broken_access_control':
      return (
        projectMap.apiRoutes.length > 0 &&
        projectMap.databaseCalls.some((call) => ['select', 'read', 'update'].includes(call.kind))
      );
    case 'missing_rate_limit':
      return routeText.some((text) => /login|sign[-_]?in|password|reset|otp|payment|checkout|billing/i.test(text));
    case 'missing_csrf_protection': {
      const usesCookieSession = fileMap.entries.some((entry) =>
        /cookie-session|express-session|connect\.sid|req\.session\b|cookies\(\)\.set|res\.cookie\s*\(/i.test(entry.content),
      );
      const hasStateChangingRoute = projectMap.apiRoutes.some((route) =>
        route.methods.some((method) => ['POST', 'PUT', 'DELETE', 'PATCH', 'ANY'].includes(method)),
      );
      return usesCookieSession && hasStateChangingRoute;
    }
    case 'missing_request_body_validation':
      return projectMap.apiRoutes.some((route) =>
        route.methods.some((method) => ['POST', 'PUT', 'DELETE', 'PATCH', 'ANY'].includes(method)),
      );
    case 'unrestricted_graphql':
      return fileMap.entries.some((entry) => /(?:apollo|graphql|createYoga|mercurius)/i.test(entry.content));
    case 'dangerous_deployment_config':
      return fileMap.entries.some((entry) =>
        /(?:docker-compose|k8s|kubernetes|helm|deployment|service|terraform|vercel|netlify)/i.test(entry.path) ||
        /privileged|allowPrivilegeEscalation|hostNetwork|cap_add/i.test(entry.content),
      );
    default:
      return fileMap.entries.length > 0;
  }
}
