import type { FindingIdentity } from './findingIdentity.js';

import type { CurrentReportVersion } from './reportVersion.js';

import type { ArchiveShape, ProjectHygiene } from './archiveObservations.js';

import type { ScannerErrorReasonCode } from './errors.js';

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type Confidence = 'high' | 'medium' | 'low';

export type FileTypeLabel =
  | 'api_route'
  | 'frontend_component'
  | 'config'
  | 'env'
  | 'database_schema'
  | 'migration'
  | 'middleware'
  | 'auth'
  | 'package_manifest'
  | 'lockfile'
  | 'firebase_rules'
  | 'supabase_config'
  | 'unknown_useful';

export interface SkippedFile {
  path: string;
  reason:
    | 'ignored_directory'
    | 'ignored_extension'
    | 'lockfile'
    | 'minified'
    | 'too_large'
    | 'binary'
    | 'not_useful'
    | 'unreadable'
    | 'directory_unreadable'
    | 'max_depth_exceeded'
    | 'nesting_too_deep'
    | 'scan_limit_reached'
    | 'os_metadata';
}

export interface PreparedFile {
  path: string;
  absolutePath: string;
  extension: string;
  size: number;
  content: string;
}

export interface LinksNotFollowed {
  named: string[];
  total: number;
}

export interface PreparedInput {
  rootPath: string;
  files: PreparedFile[];
  linksNotFollowed?: LinksNotFollowed;
  skipped: SkippedFile[];
  skippedCount: number;
  skippedByReason?: Partial<Record<SkippedFile['reason'], number>>;
  warnings: string[];
}

export interface InputLimits {
  maxFileSizeBytes: number;
  maxLockfileSizeBytes: number;
  maxTotalFiles: number;
  maxTotalContentBytes: number;
  maxDirectoryDepth: number;
  maxVisitedEntries: number;
  maxDirectories: number;
  maxSkippedDetails: number;
  maxSourceNestingDepth: number;
  maxScanDurationMs: number;
}

export interface FileMapEntry {
  path: string;
  extension: string;
  label: FileTypeLabel;
  size: number;
  isLikelyConfig: boolean;
  isLikelyApiRoute: boolean;
  isLikelyAuthRelated: boolean;
  isLikelyDatabaseRelated: boolean;
  isLikelyMiddleware: boolean;
  usesEnvVariables: boolean;
  technologyHints: string[];
  content: string;
}

export interface FileMap {
  rootPath: string;
  entries: FileMapEntry[];
  skipped: SkippedFile[];
  skippedCount: number;
  skippedByReason?: Partial<Record<SkippedFile['reason'], number>>;
  warnings: string[];
}

export type StackName =
  | 'nextjs'
  | 'react'
  | 'nodejs'
  | 'express'
  | 'supabase'
  | 'firebase'
  | 'python'
  | 'fastapi'
  | 'flask'
  | 'django'
  | 'prisma'
  | 'drizzle'
  | 'tailwind'
  | 'vite'
  | 'ai_agent_mcp';

export interface StackDetection {
  name: StackName;
  confidence: Confidence;
  evidence: string[];
}

export interface DetectedStack {
  stacks: StackDetection[];
}

export interface ImportRef {
  source: string;
  line: number;
  resolvedPath?: string;
  bindings?: string[];
}

export interface FileImports {
  filePath: string;
  imports: ImportRef[];
}

export type DatabaseCallKind =
  | 'select'
  | 'insert'
  | 'update'
  | 'delete'
  | 'upsert'
  | 'read'
  | 'write'
  | 'raw_sql';

export type DatabaseClientKind = 'supabase' | 'prisma' | 'drizzle' | 'firebase' | 'sql';

export interface DatabaseCall {
  filePath: string;
  line: number;
  index?: number;
  client: DatabaseClientKind;
  kind: DatabaseCallKind;
  table?: string;
  snippet: string;
}

export type AuthSignalKind =
  | 'getUser'
  | 'getSession'
  | 'auth_call'
  | 'currentUser'
  | 'onAuthStateChanged'
  | 'signIn'
  | 'signUp'
  | 'middleware_protection'
  | 'jwt_check'
  | 'session_cookie_check';

export interface AuthSignal {
  filePath: string;
  line: number;
  index?: number;
  kind: AuthSignalKind;
  snippet: string;
  protective: boolean;
  checked: boolean;
}

export interface DangerousOperation {
  filePath: string;
  line: number;
  kind: string;
  snippet: string;
}

export interface EnvVariableUsage {
  filePath: string;
  line: number;
  name: string;
  accessor?: 'process.env' | 'import.meta.env' | 'other';
}

export type ApiRouteFramework =
  | 'nextjs_pages'
  | 'nextjs_app'
  | 'sveltekit'
  | 'express'
  | 'fastapi'
  | 'flask'
  | 'django'
  | 'generic';

export interface ApiRoute {
  filePath: string;
  framework: ApiRouteFramework;
  routePath: string;
  methods: string[];
  line: number;
  declaredPath?: string;
  wrappedBy?: string[];
}

export type RouteControlStatus = 'present' | 'absent' | 'unknown' | 'not_applicable';

export interface RouteSecurityEvidence {
  filePath: string;
  line: number;
  kind: string;
  detail: string;
}

export interface RouteControlAssessment {
  status: RouteControlStatus;
  evidence: RouteSecurityEvidence[];
  reason: string;
}

export interface RouteDatabaseOperation {
  filePath: string;
  line: number;
  client: DatabaseClientKind;
  kind: DatabaseCallKind;
  table?: string;
}

export interface RouteSecurityProfile {
  id: string;
  filePath: string;
  framework: ApiRouteFramework;
  routePath: string;
  method: string;
  line: number;
  analysisStatus: 'complete' | 'partial';
  analysisReasons: string[];
  reachableFiles: string[];
  authentication: RouteControlAssessment;
  authorization: RouteControlAssessment;
  inputValidation: RouteControlAssessment;
  rateLimit: RouteControlAssessment;
  csrfProtection: RouteControlAssessment;
  databaseOperations: RouteDatabaseOperation[];
  sensitiveEnvVars: string[];
  securitySinks: RouteSecurityEvidence[];
}

export interface MiddlewareMatcher {
  filePath: string;
  source: string;
  pattern: string;
}

export interface MiddlewareCoverage {
  filePath: string;
  entrypoint: boolean;
  exemptPatterns: string[];
  protectedPatterns: string[];
}

export type RlsPolicyCommand = 'all' | 'select' | 'insert' | 'update' | 'delete';

export interface SupabaseRlsPolicy {
  table: string;
  command: RlsPolicyCommand;
  filePath: string;
  line: number;
  usingExpression?: string;
  withCheckExpression?: string;
  identityScoped: boolean;
  usingUnrestricted: boolean;
  withCheckUnrestricted: boolean;
  roles: string[];
  anonymousUsingPermissive: boolean;
  anonymousWithCheckPermissive: boolean;
  authenticatedUsingPermissive: boolean;
  authenticatedWithCheckPermissive: boolean;
  unreadableExpression: boolean;
  missingCheckExpression: boolean;
}

export interface SupabaseRlsInfo {
  rlsEnabledTables: string[];
  rlsDisabledTables: string[];
  policyTables: string[];
  policies: SupabaseRlsPolicy[];
  sqlFileCount: number;
  unparsedPolicyCount: number;
  tableColumns: Record<string, string[]>;
  committedFunctions: string[];
  identityBoundFunctions: string[];
  uncertainTables: string[];
  uncertainSwitchTables: string[];
  unsettledPolicies: { table: string; filePath: string; line: number }[];
  unreadRlsStatements: { filePath: string; line: number }[];
  rollbackFilesNotApplied: string[];
}

export interface SchemaModel {
  key: string;
  name: string;
  source: 'prisma' | 'mongoose' | 'sql';
  hasOwnerLink: boolean;
}

export interface SchemaModelMap {
  models: SchemaModel[];
  aliases: Record<string, string>;
  sourcesParsed: number;
}

export interface ProjectMap {
  apiRoutes: ApiRoute[];
  frontendComponents: string[];
  authFiles: string[];
  middlewareFiles: string[];
  middlewareMatchers: MiddlewareMatcher[];
  middlewareCoverage?: MiddlewareCoverage[];
  databaseFiles: string[];
  envFiles: string[];
  configFiles: string[];
  supabaseUsage: string[];
  firebaseUsage: string[];
  supabaseRls: SupabaseRlsInfo;
  scannerRootPrefix?: string;
  databaseCalls: DatabaseCall[];
  imports: FileImports[];
  dangerousOperations: DangerousOperation[];
  publicClientUsage: string[];
  serverSideUsage: string[];
  authSignals: AuthSignal[];
  envUsage: EnvVariableUsage[];
  crossFileTaint?: import('../ast/crossFileTaint.js').CrossFileTaintResult;
  routeSecurityProfiles?: RouteSecurityProfile[];
  schemaModels?: SchemaModelMap;
}

export type FindingCategory =
  | 'secrets'
  | 'authentication'
  | 'authorization'
  | 'configuration'
  | 'data_exposure'
  | 'headers'
  | 'cors'
  | 'injection'
  | 'file_upload'
  | 'path_traversal'
  | 'ssrf'
  | 'xss'
  | 'csrf'
  | 'open_redirect'
  | 'rate_limiting'
  | 'logging'
  | 'cookies'
  | 'webhooks'
  | 'dependencies';

export type DetectionKind = 'pattern' | 'absence';

export type DetectionMethod = 'deterministic' | 'heuristic';

export interface Finding {
  id: string;
  ruleId: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  detectionKind: DetectionKind;
  detectionMethod: DetectionMethod;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  evidence: string;
  userExplanation: string;
  technicalExplanation: string;
  fixHint: string;
  fixPrompt: string;
  category: FindingCategory;
  dependency?: DependencyFindingDetail;
  adjudication?: FindingAdjudicationPolicy;
  stableId?: FindingIdentity;
  aiReview?: AiReview;
}

export type AiReviewOutcome =
  | 'verified'
  | 'provider-error'
  | 'budget-exhausted'
  | 'timed-out'
  | 'not-required'
  | 'withheld';

export type AiReviewCacheState = 'hit' | 'miss' | 'unkeyable' | 'ambiguous-identity' | 'not-consulted';

export interface AiReviewEvidenceLocation {
  filePath: string;
  line?: number;
}

export interface AiReviewResponse {
  reasoning: string;
  evidenceLocations: AiReviewEvidenceLocation[];
  controlFound?: string;
  verdict: 'confirmed' | 'false_positive' | 'unsure';
  confidence: 'high' | 'medium' | 'low';
  recommendedSeverity?: Severity;
  impact?: 'serious' | 'worth_fixing' | 'minor';
  impactReason?: string;
  explanation: string;
}

export interface AiReviewRecord {
  response: AiReviewResponse;
  resolverVersion: number;
}

export type AiReview = {
  outcome: AiReviewOutcome;
  cache: AiReviewCacheState;
  reasoningWithheld?: true;
} & (
  | { placement: 'ranked'; recommendedSeverity: Severity; adjudication?: AiReviewRecord }
  | { placement: 'needs_review'; reason: AiReviewNeedsReviewReason; adjudication?: AiReviewRecord }
  | { placement: 'dismissed_visible'; severityClass: 'routine'; adjudication?: AiReviewRecord }
  | {
      placement: 'dismissed_visible';
      severityClass: 'serious';
      reviewAvailable: true;
      scannerSeverity: 'critical' | 'high';
      adjudication?: AiReviewRecord;
    }
  | { placement: 'rules_only'; reason: AiReviewRulesOnlyReason; aiJudged: false }
);

export type AiReviewNeedsReviewReason =
  | 'model_unsure'
  | 'low_confidence_dismissal'
  | 'serious_dismissal_not_confident'
  | 'no_control_named'
  | 'inapplicable_not_corroborated'
  | 'no_usable_response'
  | 'evidence_check_failed'
  | 'untrusted_input_markers';

export type AiReviewRulesOnlyReason = 'budget_exhausted' | 'not_required';

export type AiAdjudication =
  | {
      state: 'not_run';
      reason: 'not_entitled' | 'unavailable' | 'not_attempted';
      detail?: 'no_api_key' | 'no_model' | 'provider_unavailable' | 'deadline_exceeded' | 'engine_error';
    }
  | {
      state: 'ran';
      byOutcome: Record<AiReviewOutcome, number>;
      findingsJudged: number;
      budget: {
        limit: number;
        spent: number;
        remaining: number;
        ceilingHit?: 'purchase' | 'scan';
      };
      question: {
        model: string;
        promptVersion: string;
        packetVersion: string;
        resolverVersion: number;
      };
    };

export type FindingAdjudicationReason =
  | 'database_backed_dependency_advisory'
  | 'archive_entry_name_observation'
  | 'storage_bucket_public_flag_observation'
  | 'supabase_rls_unverifiable_from_source';

export interface FindingAdjudicationPolicy {
  required: boolean;
  reason: FindingAdjudicationReason;
  basis: string;
}

export interface RuleContext {
  fileMap: FileMap;
  projectMap: ProjectMap;
  stack: DetectedStack;
}

export interface GuardLookup {
  fileMap: FileMap;
  projectMap: ProjectMap;
}

export interface ScanRule {
  id: string;
  title: string;
  category: FindingCategory;
  kind: 'basic' | 'contextual';
  run(context: RuleContext): Finding[];
}

export interface RuleFailure {
  ruleId: string;
  message: string;
}

export interface RuleRunResult {
  findings: Finding[];
  failures: RuleFailure[];
  completedRuleIds: string[];
  truncated: boolean;
}

export interface ScanSummary {
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  detectedStacks: StackName[];
}

export interface RuleFindingSummary {
  ruleId: string;
  label: string;
  occurrences: number;
  highestSeverity: Severity;
}

export type RuleResultStatus = 'failed' | 'passed' | 'not_applicable' | 'not_completed';

export type RuleCoverage = 'full' | 'partial' | 'none';

export interface RuleResult {
  ruleId: string;
  label: string;
  status: RuleResultStatus;
  coverage?: RuleCoverage;
  coverageReason?: string;
}

export interface ReportCoverage {
  languagesDetected: string[];
  languagesAnalysed: string[];
  analysisMethodByLanguage: Record<string, string>;
  frameworksDetected: string[];
  filesAnalysed: number;
  filesSkipped: number;
  filesSkippedUnsafe?: number;
  filesSkippedInWalk: number;
  unreadExtensions?: Record<string, number>;
  skippedByReason?: Record<string, number>;
  scanFit?: {
    reasons: ('few_code_files' | 'other_language' | 'no_recognised_setup' | 'no_package_list')[];
    codeFilesRead?: number;
    lead?: string;
    also: string[];
  };
  partiallyCoveredRules: { ruleId: string; coverage: RuleCoverage; coverageReason: string }[];
  unsupportedLanguages: string[];
  reasons: string[];
}

export interface FileMapSummary {
  totalFiles: number;
  totalSkipped: number;
  byLabel: Record<string, number>;
}

export interface ProjectMapSummary {
  apiRoutes: number;
  frontendComponents: number;
  authFiles: number;
  middlewareFiles: number;
  databaseFiles: number;
  envFiles: number;
  configFiles: number;
  databaseCalls: number;
  dangerousOperations: number;
}

export type DependencyEcosystem = 'npm' | 'PyPI';

export type OsvLookupStatus =
  | 'success'
  | 'timeout'
  | 'aborted'
  | 'rate_limited'
  | 'network_error';

export interface DependencyVulnerability {
  dependency: string;
  ecosystem: DependencyEcosystem;
  version?: string;
  sourcePath?: string;
  severity: Severity;
  advisoryId: string;
  summary: string;
  reference?: string;
  dataSource?: 'live' | 'fallback';
}

export type DependencyOriginRelationship = 'direct' | 'transitive' | 'undetermined';

export type DependencyOriginUndeterminedReason =
  | 'no_manifest_found'
  | 'no_dependency_graph'
  | 'package_not_in_graph'
  | 'no_path_to_a_direct_dependency'
  | 'search_bounded';

export interface DependencyOrigin {
  relationship: DependencyOriginRelationship;
  declaredIn?: string;
  chain?: string[];
  manifestControlsInstalledCopy?: boolean;
  undeterminedReason?: DependencyOriginUndeterminedReason;
  searchBounds?: string[];
  graphSource?: string;
}

export interface DependencyFindingDetail {
  ecosystem: DependencyEcosystem;
  package: string;
  installedVersion: string;
  advisoryId: string;
  advisoryIds: string[];
  relatedAdvisoryIds?: string[];
  origin?: DependencyOrigin;
  sourcePath?: string;
  dataSource: 'live' | 'fallback';
  reference?: string;
}

export interface DependencyLookupOutcomes {
  success: number;
  timeout: number;
  aborted: number;
  rate_limited: number;
  network_error: number;
  live: number;
  fallback: number;
}

export interface DependencyAuditSummary {
  performed: boolean;
  incomplete: boolean;
  source: string;
  datasetDate?: string;
  cacheAgeDays?: number;
  dependenciesCollected: number;
  checked: number;
  notChecked: string[];
  vulnerabilities: DependencyVulnerability[];
  diagnostics: string[];
  outcomes?: DependencyLookupOutcomes;
  checkCoverage?: DependencyCheckCoverage;
  note: string;
}

export interface DependencyCheckCoverage {
  checkedLive: string[];
  checkedFromCache: string[];
  skipped: string[];
  missed: string[];
  cacheMisses: string[];
  networkFailures: string[];
  notChecked: string[];
  notCheckedByCause?: Record<string, string[]>;
}

export type DependencyAuditStatus = 'complete' | 'incomplete' | 'not_performed';

export type ScanState = 'complete_clean' | 'complete_with_findings' | 'partial' | 'failed';

export type CompletionReasonCode =
  | 'complete_no_findings'
  | 'complete_with_findings'
  | 'rule_execution_failed'
  | 'finding_budget_exhausted'
  | 'cross_file_budget_exhausted'
  | 'report_findings_truncated'
  | 'dependency_audit_incomplete'
  | 'dependency_audit_not_performed'
  | 'dependency_versions_unresolved'
  | 'files_skipped'
  | 'unsafe_files_skipped'
  | 'unsupported_languages'
  | 'unread_extensions'
  | 'partial_rule_coverage'
  | 'scan_deadline_exceeded'
  | 'scan_failed'
  | ScannerErrorReasonCode;

export interface StatusSummary {
  state: ScanState;
  headline: string;
  reasonCodes: CompletionReasonCode[];
}

export interface ScanReport {
  reportVersion: CurrentReportVersion;
  scanId: string;
  createdAt: string;
  statusSummary: StatusSummary;
  scanStatus: 'complete' | 'incomplete';
  codeScanStatus: 'complete' | 'incomplete';
  dependencyAuditStatus: DependencyAuditStatus;
  warnings: string[];
  summary: ScanSummary;
  findingsByRule: RuleFindingSummary[];
  ruleImpacts?: Record<string, string>;
  ruleResults: RuleResult[];
  coverage: ReportCoverage;
  findings: Finding[];
  fileMapSummary: FileMapSummary;
  projectMapSummary: ProjectMapSummary;
  routeSecurityProfiles: RouteSecurityProfile[];
  dependencyAudit: DependencyAuditSummary;
  aiAdjudication: AiAdjudication;
  projectHygiene: ProjectHygiene;
  archiveShape: ArchiveShape;
}
