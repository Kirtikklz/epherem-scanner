import { MAX_TOTAL_FINDINGS } from '../shared/constants.js';
import { CURRENT_REPORT_VERSION } from '../shared/reportVersion.js';
import {
  unobservedArchiveShape,
  unobservedProjectHygiene,
} from '../shared/archiveObservations.js';
import { emptyArchiveIgnoredCarry, type ArchiveIgnoredCarry } from '../shared/archiveCoverage.js';
import type { ScanFit } from '../input/emptyInputMessage.js';
import { ANALYSIS_METHOD_BY_LANGUAGE, COMPONENT_EXTENSIONS, detectLanguages } from '../shared/languages.js';
import { RULE_CATALOG, labelForRule } from '../rules/ruleCatalog.js';
import { buildFindingsByRule, buildRuleImpacts, withReadDumpImpact } from './buildFindingsByRule.js';
import { buildRuleResults } from './buildRuleResults.js';
import type {
  CompletionReasonCode,
  DependencyAuditStatus,
  DependencyAuditSummary,
  DetectedStack,
  FileMap,
  FileMapSummary,
  Finding,
  ProjectMap,
  ReportCoverage,
  RuleFailure,
  ScanReport,
  ScanSummary,
  StatusSummary,
} from '../shared/types.js';
import { sha1Hex } from '../shared/utils.js';
import { scannerErrorReasonCode, type ScannerErrorCode } from '../shared/errors.js';

export interface BuildReportInput {
  findings: Finding[];
  fileMap: FileMap;
  detectedStack: DetectedStack;
  projectMap: ProjectMap;
  ruleFailures?: RuleFailure[];
  completedRuleIds?: string[];
  dependencyAudit?: DependencyAuditSummary;
  codeScanTruncated?: boolean;
  crossFileBudgetTruncated?: boolean;
  findingLimit?: number;
  archiveSkippedFileCount?: number;
  archiveIgnored?: ArchiveIgnoredCarry;
  scanFit?: ScanFit;
  archiveObserved?: boolean;
  archiveWarnings?: string[];
  gapWarnings?: readonly string[];
  now?: () => Date;
}

const EMPTY_DEPENDENCY_AUDIT: DependencyAuditSummary = {
  performed: false,
  incomplete: true,
  source: 'none',
  dependenciesCollected: 0,
  checked: 0,
  notChecked: [],
  vulnerabilities: [],
  diagnostics: [],
  note: 'Dependency audit was not run for this scan.',
};

function sanitizedArchiveIgnored(carry: ArchiveIgnoredCarry | undefined): ArchiveIgnoredCarry {
  if (carry === undefined) return emptyArchiveIgnoredCarry();
  const positive = (value: unknown): number =>
    Number.isSafeInteger(value) && Number(value) > 0 ? Number(value) : 0;
  const byExtension: Record<string, number> = {};
  for (const [extension, files] of Object.entries(carry.byExtension ?? {})) {
    const count = positive(files);
    if (count > 0) byExtension[extension] = count;
  }
  const byReason: Record<string, number> = {};
  for (const [reason, files] of Object.entries(carry.byReason ?? {})) {
    const count = positive(files);
    if (count > 0) byReason[reason] = count;
  }
  return { files: positive(carry.files), byExtension, byReason };
}

function skippedByReasonOf(fileMap: FileMap, archiveSkippedFileCount: number, archiveIgnored: ArchiveIgnoredCarry): Record<string, number> {
  const out: Record<string, number> = {};
  const add = (reason: string, files: number): void => {
    if (Number.isSafeInteger(files) && files > 0) out[reason] = (out[reason] ?? 0) + files;
  };
  const addTerm = (byReason: Readonly<Record<string, number>>, total: number): void => {
    let named = 0;
    for (const [reason, files] of Object.entries(byReason)) {
      if (!Number.isSafeInteger(files) || files <= 0) continue;
      const take = Math.min(files, total - named);
      add(reason, take);
      named += take;
    }
    add('unknown', total - named);
  };
  const walk: Record<string, number> = {};
  if (fileMap.skippedByReason !== undefined) Object.assign(walk, fileMap.skippedByReason);
  else for (const s of fileMap.skipped) walk[s.reason] = (walk[s.reason] ?? 0) + 1;
  addTerm(walk, fileMap.skippedCount);
  add('archive_unsafe', archiveSkippedFileCount);
  addTerm(archiveIgnored.byReason ?? {}, archiveIgnored.files);
  return out;
}

export function buildReport(input: BuildReportInput): ScanReport {
  const { findings, fileMap, detectedStack, projectMap } = input;
  const archiveSkippedFileCount =
    Number.isSafeInteger(input.archiveSkippedFileCount) && Number(input.archiveSkippedFileCount) > 0
      ? Number(input.archiveSkippedFileCount)
      : 0;
  const archiveIgnored = sanitizedArchiveIgnored(input.archiveIgnored);
  const totalSkippedFiles =
    fileMap.skippedCount + archiveSkippedFileCount + archiveIgnored.files;
  const ruleFailures = input.ruleFailures ?? [];
  const dependencyAudit = input.dependencyAudit ?? EMPTY_DEPENDENCY_AUDIT;
  const findingLimit = input.findingLimit ?? MAX_TOTAL_FINDINGS;
  const createdAt = (input.now?.() ?? new Date()).toISOString();

  const fingerprint = fileMap.entries
    .map((entry) => `${entry.path}:${sha1Hex(entry.content)}`)
    .join('|');
  const scanId = `scan_${sha1Hex(fingerprint).slice(0, 16)}`;

  const isDependencyFinding = (finding: Finding): boolean => finding.category === 'dependencies';

  const finalReportTruncated = findings.length > findingLimit;
  const cappedFindings = finalReportTruncated ? findings.slice(0, findingLimit) : findings;
  const droppedFindings = finalReportTruncated ? findings.slice(findingLimit) : [];
  const droppedDependencyCount = droppedFindings.filter(isDependencyFinding).length;
  const droppedCodeCount = droppedFindings.length - droppedDependencyCount;

  const codeWarnings: string[] = [
    ...fileMap.warnings,
    ...ruleFailures.map(
      (failure) => `Rule "${failure.ruleId}" failed and its checks were not applied: ${failure.message}`,
    ),
  ];
  if (input.codeScanTruncated === true) {
    codeWarnings.push(
      `Finding limit (${findingLimit}) reached while code rules were running; some rules were skipped and code results are incomplete.`,
    );
  }
  if (input.crossFileBudgetTruncated === true) {
    codeWarnings.push(
      'The cross-file analysis budget was exhausted before every check finished, so some cross-file checks stopped early and code results are incomplete.',
    );
  }

  const codeScanStatus: 'complete' | 'incomplete' = codeWarnings.length > 0 ? 'incomplete' : 'complete';
  const dependencyAuditStatus: DependencyAuditStatus = !dependencyAudit.performed
    ? 'not_performed'
    : dependencyAudit.incomplete
      ? 'incomplete'
      : 'complete';

  const warnings = [...codeWarnings, ...(input.archiveWarnings ?? [])];
  if (dependencyAuditStatus !== 'complete') {
    warnings.push(
      `Dependency audit is ${dependencyAuditStatus === 'not_performed' ? 'not performed' : 'incomplete'}. ` +
        'Dependency safety is not fully verified yet. ' +
        dependencyAudit.note,
    );
  }
  if (finalReportTruncated) {
    warnings.push(
      `The report shows the first ${findingLimit} findings out of ${findings.length} found. ` +
        'Some findings are not shown because the report reached its size limit.',
    );
    if (droppedDependencyCount > 0) {
      warnings.push(
        `${droppedDependencyCount} dependency issue(s) are not shown because the report reached its size limit.`,
      );
    }
    if (droppedCodeCount > 0) {
      warnings.push(
        `${droppedCodeCount} code issue(s) are not shown because the report reached its size limit.`,
      );
    }
  }
  warnings.push(...(input.gapWarnings ?? []));

  const languageInfo = detectLanguages(fileMap, archiveIgnored.byExtension);
  const unreadCodeFileCount = Object.values(languageInfo.unreadExtensions).reduce(
    (sum, count) => sum + count,
    0,
  );

  const scanStatus: 'complete' | 'incomplete' =
    codeScanStatus === 'incomplete' ||
    dependencyAuditStatus !== 'complete' ||
    finalReportTruncated ||
    languageInfo.unsupported.length > 0 ||
    unreadCodeFileCount > 0
      ? 'incomplete'
      : 'complete';

  const summary: ScanSummary = {
    totalFindings: cappedFindings.length,
    critical: cappedFindings.filter((finding) => finding.severity === 'critical').length,
    high: cappedFindings.filter((finding) => finding.severity === 'high').length,
    medium: cappedFindings.filter((finding) => finding.severity === 'medium').length,
    low: cappedFindings.filter((finding) => finding.severity === 'low').length,
    detectedStacks: detectedStack.stacks.map((stack) => stack.name),
  };
  const findingsByRule = buildFindingsByRule(cappedFindings);
  const ruleImpacts = buildRuleImpacts(findingsByRule);
  const ruleResults = buildRuleResults({
    findings,
    context: { fileMap, projectMap, stack: detectedStack },
    codeScanComplete: codeScanStatus === 'complete',
    ...(input.completedRuleIds !== undefined ? { completedRuleIds: input.completedRuleIds } : {}),
    failedExecutionRuleIds: ruleFailures.map((failure) => failure.ruleId),
    dependencyAudit,
    dependencyAuditStatus,
    archiveObserved: input.archiveObserved === true,
    languages: languageInfo,
  });

  const byLabel: Record<string, number> = {};
  for (const entry of fileMap.entries) {
    byLabel[entry.label] = (byLabel[entry.label] ?? 0) + 1;
  }
  const fileMapSummary: FileMapSummary = {
    totalFiles: fileMap.entries.length,
    totalSkipped: totalSkippedFiles,
    byLabel,
  };

  const analysisMethodByLanguage: Record<string, string> = {};
  for (const language of languageInfo.analysed) {
    const method = (ANALYSIS_METHOD_BY_LANGUAGE as Record<string, string>)[language];
    if (method !== undefined) analysisMethodByLanguage[language] = method;
  }
  const coverage: ReportCoverage = {
    languagesDetected: languageInfo.detected,
    languagesAnalysed: languageInfo.analysed,
    analysisMethodByLanguage,
    frameworksDetected: detectedStack.stacks.map((stack) => stack.name),
    filesAnalysed: fileMap.entries.length,
    filesSkipped: totalSkippedFiles,
    filesSkippedUnsafe: archiveSkippedFileCount,
    filesSkippedInWalk: fileMap.skippedCount,
    skippedByReason: skippedByReasonOf(fileMap, archiveSkippedFileCount, archiveIgnored),
    ...(input.scanFit !== undefined ? { scanFit: { ...input.scanFit, reasons: [...input.scanFit.reasons], also: [...input.scanFit.also] } } : {}),
    partiallyCoveredRules: ruleResults
      .filter((entry) => entry.coverage === 'partial' || entry.coverage === 'none')
      .map((entry) => ({
        ruleId: entry.ruleId,
        coverage: entry.coverage ?? 'none',
        coverageReason: entry.coverageReason ?? '',
      })),
    unsupportedLanguages: languageInfo.unsupported,
    unreadExtensions: languageInfo.unreadExtensions,
    reasons: coverageReasons({
      unsupportedLanguages: languageInfo.unsupported,
      unreadExtensions: languageInfo.unreadExtensions,
      fileCountByLanguage: languageInfo.fileCountByLanguage,
      skippedFilesSeen: languageInfo.skippedFilesSeen,
      skippedFilesTotal: languageInfo.skippedFilesTotal,
      filesSkipped: totalSkippedFiles,
      archiveSkippedFileCount,
      codeScanComplete: codeScanStatus === 'complete',
      dependencyAuditStatus,
      partiallyCoveredRuleCount: ruleResults.filter(
        (entry) => entry.coverage === 'partial' || entry.coverage === 'none',
      ).length,
    }),
  };

  const projectMapSummary = {
    apiRoutes: projectMap.apiRoutes.length,
    frontendComponents: projectMap.frontendComponents.length,
    authFiles: projectMap.authFiles.length,
    middlewareFiles: projectMap.middlewareFiles.length,
    databaseFiles: projectMap.databaseFiles.length,
    envFiles: projectMap.envFiles.length,
    configFiles: projectMap.configFiles.length,
    databaseCalls: projectMap.databaseCalls.length,
    dangerousOperations: projectMap.dangerousOperations.length,
  };

  const statusSummary = buildStatusSummary({
    scanStatus,
    totalFindings: summary.totalFindings,
    reasonCodes: collectReasonCodes({
      totalFindings: summary.totalFindings,
      ruleFailuresCount: ruleFailures.length,
      findingBudgetTruncated: input.codeScanTruncated === true,
      crossFileBudgetTruncated: input.crossFileBudgetTruncated === true,
      finalReportTruncated,
      dependencyAuditStatus,
      dependencyAudit,
      nonArchiveSkipped: Math.max(0, totalSkippedFiles - archiveSkippedFileCount - unreadCodeFileCount),
      archiveSkippedFileCount,
      unsupportedLanguageCount: coverage.unsupportedLanguages.length,
      unreadExtensionCount: Object.keys(languageInfo.unreadExtensions).length,
      partiallyCoveredRuleCount: coverage.partiallyCoveredRules.length,
    }),
  });

  return {
    reportVersion: CURRENT_REPORT_VERSION,
    scanId,
    createdAt,
    statusSummary,
    scanStatus,
    codeScanStatus,
    dependencyAuditStatus,
    warnings,
    summary,
    findingsByRule,
    ruleImpacts: withReadDumpImpact(ruleImpacts, cappedFindings),
    ruleResults,
    coverage,
    findings: cappedFindings,
    fileMapSummary,
    projectMapSummary,
    routeSecurityProfiles: projectMap.routeSecurityProfiles ?? [],
    dependencyAudit,
    aiAdjudication: { state: 'not_run', reason: 'not_attempted' },
    projectHygiene: unobservedProjectHygiene(),
    archiveShape: unobservedArchiveShape(),
  };
}

export function buildTimeoutReport(input: {
  reason: string;
  kind?: 'deadline' | 'failed';
  scannerErrorCode?: ScannerErrorCode;
  now?: () => Date;
}): ScanReport {
  const createdAt = (input.now?.() ?? new Date()).toISOString();
  const deadline = input.kind === 'deadline';
  const stoppedBy = input.scannerErrorCode !== undefined ? [scannerErrorReasonCode(input.scannerErrorCode)] : [];
  return {
    reportVersion: CURRENT_REPORT_VERSION,
    scanId: `scan_incomplete_${sha1Hex(input.reason).slice(0, 12)}`,
    createdAt,
    statusSummary: {
      state: 'failed',
      headline: deadline
        ? 'The scan ran out of time before it could finish, so these results are incomplete — not an all-clear.'
        : 'The scan stopped before it could finish, so these results are incomplete — not an all-clear.',
      reasonCodes: deadline ? ['scan_deadline_exceeded'] : ['scan_failed', ...stoppedBy],
    },
    scanStatus: 'incomplete',
    codeScanStatus: 'incomplete',
    dependencyAuditStatus: 'not_performed',
    warnings: [input.reason, 'The scan stopped before it finished, so the results are incomplete. Try scanning again for a more complete report.'],
    summary: { totalFindings: 0, critical: 0, high: 0, medium: 0, low: 0, detectedStacks: [] },
    findingsByRule: [],
    ruleImpacts: {},
    ruleResults: Object.keys(RULE_CATALOG)
      .sort((a, b) => a.localeCompare(b))
      .map((ruleId) => ({
        ruleId,
        label: labelForRule(ruleId),
        status: 'not_completed' as const,
        coverage: 'none' as const,
        coverageReason: 'Scan did not complete; no analysis result is available for this rule.',
      })),
    coverage: {
      languagesDetected: [],
      languagesAnalysed: [],
      analysisMethodByLanguage: {},
      frameworksDetected: [],
      filesAnalysed: 0,
      filesSkipped: 0,
      filesSkippedUnsafe: 0,
      filesSkippedInWalk: 0,
      partiallyCoveredRules: Object.keys(RULE_CATALOG)
        .sort((a, b) => a.localeCompare(b))
        .map((ruleId) => ({
          ruleId,
          coverage: 'none' as const,
          coverageReason: 'Scan did not complete; no analysis result is available for this rule.',
        })),
      unsupportedLanguages: [],
      unreadExtensions: {},
      reasons: [input.reason, 'No security checks could finish because the scan stopped early.'],
    },
    findings: [],
    fileMapSummary: { totalFiles: 0, totalSkipped: 0, byLabel: {} },
    projectMapSummary: {
      apiRoutes: 0,
      frontendComponents: 0,
      authFiles: 0,
      middlewareFiles: 0,
      databaseFiles: 0,
      envFiles: 0,
      configFiles: 0,
      databaseCalls: 0,
      dangerousOperations: 0,
    },
    routeSecurityProfiles: [],
    dependencyAudit: { ...EMPTY_DEPENDENCY_AUDIT, note: input.reason },
    aiAdjudication: { state: 'not_run', reason: 'not_attempted' },
    projectHygiene: unobservedProjectHygiene(),
    archiveShape: unobservedArchiveShape(),
  };
}

function collectReasonCodes(input: {
  totalFindings: number;
  ruleFailuresCount: number;
  findingBudgetTruncated: boolean;
  crossFileBudgetTruncated: boolean;
  finalReportTruncated: boolean;
  dependencyAuditStatus: DependencyAuditStatus;
  dependencyAudit: DependencyAuditSummary;
  nonArchiveSkipped: number;
  archiveSkippedFileCount: number;
  unsupportedLanguageCount: number;
  unreadExtensionCount: number;
  partiallyCoveredRuleCount: number;
}): CompletionReasonCode[] {
  const codes: CompletionReasonCode[] = [];
  if (input.ruleFailuresCount > 0) codes.push('rule_execution_failed');
  if (input.findingBudgetTruncated) codes.push('finding_budget_exhausted');
  if (input.crossFileBudgetTruncated) codes.push('cross_file_budget_exhausted');
  if (input.finalReportTruncated) codes.push('report_findings_truncated');
  if (input.dependencyAuditStatus === 'not_performed') codes.push('dependency_audit_not_performed');
  else if (input.dependencyAuditStatus === 'incomplete') codes.push('dependency_audit_incomplete');
  if (
    input.dependencyAudit.performed &&
    input.dependencyAudit.dependenciesCollected > 0 &&
    input.dependencyAudit.checked === 0
  ) {
    codes.push('dependency_versions_unresolved');
  }
  if (input.nonArchiveSkipped > 0) codes.push('files_skipped');
  if (input.archiveSkippedFileCount > 0) codes.push('unsafe_files_skipped');
  if (input.unsupportedLanguageCount > 0) codes.push('unsupported_languages');
  if (input.unreadExtensionCount > 0) codes.push('unread_extensions');
  if (input.partiallyCoveredRuleCount > 0) codes.push('partial_rule_coverage');

  codes.push(input.totalFindings > 0 ? 'complete_with_findings' : 'complete_no_findings');
  return codes;
}

function buildStatusSummary(input: {
  scanStatus: 'complete' | 'incomplete';
  totalFindings: number;
  reasonCodes: CompletionReasonCode[];
}): StatusSummary {
  const complete = input.scanStatus === 'complete';
  const hasFindings = input.totalFindings > 0;
  const count = input.totalFindings;
  const issueWord = count === 1 ? 'issue' : 'issues';

  if (complete && !hasFindings) {
    return {
      state: 'complete_clean',
      headline:
        'No issues were found in the files this scan analysed. ' +
        'This is not a statement about any file it did not analyse.',
      reasonCodes: input.reasonCodes,
    };
  }
  if (complete && hasFindings) {
    return {
      state: 'complete_with_findings',
      headline:
        `${count} potential ${issueWord} found in the files this scan analysed. ` +
        'This is not a statement about any file it did not analyse.',
      reasonCodes: input.reasonCodes,
    };
  }
  if (!hasFindings) {
    return {
      state: 'partial',
      headline:
        'No findings were detected in the successfully analysed portion of the project. ' +
        'Part of the project was not fully analysed, so this is not a clean bill of health.',
      reasonCodes: input.reasonCodes,
    };
  }
  return {
    state: 'partial',
    headline:
      `${count} potential ${issueWord} found in the successfully analysed portion of the project. ` +
      'Part of the project was not fully analysed, so more may remain.',
    reasonCodes: input.reasonCodes,
  };
}

function coverageReasons(input: {
  unsupportedLanguages: readonly string[];
  unreadExtensions: Readonly<Record<string, number>>;
  fileCountByLanguage: Readonly<Record<string, number>>;
  skippedFilesSeen: number;
  skippedFilesTotal: number;
  filesSkipped: number;
  archiveSkippedFileCount?: number;
  codeScanComplete: boolean;
  dependencyAuditStatus: DependencyAuditStatus;
  partiallyCoveredRuleCount: number;
}): string[] {
  const reasons: string[] = [];
  const archiveSkipped = input.archiveSkippedFileCount ?? 0;
  if (input.unsupportedLanguages.length > 0) {
    const named = input.unsupportedLanguages.map(
      (language) => `${language} (${input.fileCountByLanguage[language] ?? 0} file(s))`,
    );
    reasons.push(`Unsupported detected languages: ${named.join(', ')}.`);
  }
  if (input.skippedFilesTotal > input.skippedFilesSeen) {
    reasons.push(
      `Unread-language detection was incomplete: the input walk lists only ${input.skippedFilesSeen} of the ` +
        `${input.skippedFilesTotal} file(s) it did not read, so source in a language this scanner cannot ` +
        'analyse may exist without being named above. This is a limit of this check, not a statement about ' +
        'the project.',
    );
  }
  const unreadCodeFiles = Object.values(input.unreadExtensions).reduce((sum, count) => sum + count, 0);
  if (unreadCodeFiles > 0) {
    const namedExtensions = Object.keys(input.unreadExtensions)
      .sort((a, b) => a.localeCompare(b))
      .map((extension) => `${extension} (${input.unreadExtensions[extension] ?? 0} file(s))`);
    reasons.push(
      `File types this scanner cannot open yet: ${namedExtensions.join(', ')}. ` +
        'Those files hold source code in a language this scanner does analyse, so they were not ' +
        'examined and no result below covers them.',
    );
    const components = Object.keys(input.unreadExtensions)
      .filter((extension) => COMPONENT_EXTENSIONS.has(extension))
      .sort((a, b) => a.localeCompare(b))
      .map((extension) => `${extension} (${input.unreadExtensions[extension] ?? 0} file(s))`);
    if (components.length > 0) {
      reasons.push(
        `Component files are a file type this scanner cannot open yet: ${components.join(', ')}. ` +
          'Nothing inside them was read — not the JavaScript or TypeScript in their script blocks, and not ' +
          'their templates — so code written there, such as data calls, keys and client-side logic, was not scanned.',
      );
    }
  }
  const nonArchiveSkipped = Math.max(0, input.filesSkipped - archiveSkipped - unreadCodeFiles);
  if (nonArchiveSkipped > 0) {
    reasons.push(`${nonArchiveSkipped} unsupported or non-code file(s) were skipped.`);
  }
  if (archiveSkipped > 0) {
    reasons.push(
      `${archiveSkipped} file(s) in the upload could not be safely extracted and were skipped, ` +
        'so they were not scanned. This usually means a file was too large, was compressed in an ' +
        'unsupported or unreadable way, or used a file path we do not accept. The rest of the ' +
        'project was still scanned normally.',
    );
  }
  if (!input.codeScanComplete) reasons.push('Code analysis stopped early, so missing findings are not proof that everything is safe.');
  if (input.dependencyAuditStatus !== 'complete') {
    reasons.push(`Dependency check is ${input.dependencyAuditStatus}; dependency safety is not fully verified yet.`);
  }
  if (input.partiallyCoveredRuleCount > 0) {
    reasons.push(`${input.partiallyCoveredRuleCount} security check(s) had limited coverage; review the detailed coverage section.`);
  }
  return reasons;
}
