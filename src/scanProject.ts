import {
  getDefaultDependencyScanner,
  type DependencyVulnerabilityScanner,
} from './dependency-audit/dependencyAudit.js';
import { dependencyVulnerabilitiesToFindings } from './dependency-audit/dependencyFindings.js';
import { createDependencyOriginResolver } from './dependency-audit/dependencyOrigin.js';
import { archiveEntryFindings } from './archive-findings/archiveEntryFindings.js';
import { folderWatchList } from './archive-findings/folderWatchList.js';
import { sqlDumpContentLookup } from './archive-findings/sqlDumpContent.js';
import { absenceFindings, ENABLED_ABSENCE_TAGS } from './candidates/absence/absenceFindings.js';
import { buildFileMap } from './file-map/buildFileMap.js';
import { prepareInput, type PrepareInputOptions } from './input/prepareInput.js';
import { scanFitNote } from './input/emptyInputMessage.js';
import { buildProjectMap } from './project-map/buildProjectMap.js';
import { buildReport } from './report/buildReport.js';
import { dedupeAndSort, FindingBudget, isScannablePath, runBasicRules, runContextualRules } from './rules/index.js';
import { withFindingIdentities } from './shared/findingIdentity.js';
import { absenceRoutesFor } from './shared/routeControlModel.js';
import { unreadRouteWarnings } from './shared/unreadRouteWarning.js';
import { resolveInputLimits, validateDeadlineMs, validateMaxFindings } from './shared/config.js';
import { MAX_TOTAL_FINDINGS, MAX_TOTAL_MATCH_WORK } from './shared/constants.js';
import type { ArchiveIgnoredCarry } from './shared/archiveCoverage.js';
import type { ArchiveWatchListCarry } from './shared/archiveObservations.js';
import type { DependencyAuditSummary, Finding, InputLimits, RuleContext, ScanReport } from './shared/types.js';
import { astAnalysisGaps, degradedAstFiles, degradedAstFilesUnnamed, runWithAstCache } from './ast/astAnalysis.js';
import { astGapWarnings, linkWarnings, routeProtectionGapWarnings } from './shared/analysisGapWarnings.js';
import { routeCallWalkFailures } from './project-map/buildRouteSecurity.js';
import { runWithLineIndexCache, type MatchBudget } from './shared/utils.js';
import { collectDependenciesWithDiagnostics, isDependencyListPath, pythonDependencyLine } from './stack-detection/collectDependencies.js';
import { detectStack } from './stack-detection/detectStack.js';
import { preparePythonReader, releasePythonReader } from './shared/pythonParser.js';

export interface ScanOptions {
  dependencyScanner?: DependencyVulnerabilityScanner;
  inputLimits?: Partial<InputLimits>;
  now?: () => Date;
  signal?: AbortSignal;
  deadlineMs?: number;
  maxFindings?: number;
  archiveSkippedFileCount?: number;
  archiveIgnored?: ArchiveIgnoredCarry;
  archiveWatchList?: ArchiveWatchListCarry;
  watchFolderNames?: boolean;
  onlyPaths?: ReadonlySet<string>;
  absenceTags?: ReadonlySet<string>;
  // Optional extra pass after the rules; absent means nothing runs.
  extraFindings?: (context: RuleContext) => Promise<{ findings: readonly Finding[]; warnings: readonly string[] }>;
}

export async function scanProject(inputPath: string, options: ScanOptions = {}): Promise<ScanReport> {
  const limits = resolveInputLimits(options.inputLimits);
  const deadlineMs = validateDeadlineMs(options.deadlineMs);
  const maxFindings = validateMaxFindings(options.maxFindings ?? MAX_TOTAL_FINDINGS);

  const folderNames = options.watchFolderNames === true && options.archiveWatchList === undefined ? folderWatchList() : undefined;
  const prepareOptions: PrepareInputOptions = {
    limits,
    ...(folderNames !== undefined ? { onFileName: (relativePath: string) => folderNames.observe(relativePath) } : {}),
    ...(options.onlyPaths !== undefined ? { onlyPaths: options.onlyPaths } : {}),
    ...(options.archiveIgnored !== undefined
      ? { refusedBeforeWalk: { byExtension: options.archiveIgnored.byExtension, ...(options.archiveIgnored.nestedArchive !== undefined ? { nestedArchive: options.archiveIgnored.nestedArchive } : {}) } }
      : {}),
  };
  const prepared = await prepareInput(inputPath, prepareOptions);
  if (folderNames !== undefined) options = { ...options, archiveWatchList: folderNames.carry() };
  const fileMap = buildFileMap(prepared);
  const detectedStack = detectStack(fileMap);
  const scanFit = options.onlyPaths === undefined && (prepared.skippedByReason?.scan_limit_reached ?? 0) === 0
    ? scanFitNote({
      readPaths: fileMap.entries.map((entry) => entry.path),
      skipped: fileMap.skipped,
      maxFileSizeBytes: limits.maxFileSizeBytes,
      ...(prepareOptions.refusedBeforeWalk !== undefined ? { refusedBeforeWalk: prepareOptions.refusedBeforeWalk } : {}),
      stacks: detectedStack.stacks.map((stack) => stack.name),
      packageListRead: fileMap.entries.some((entry) => isDependencyListPath(entry.path)),
    })
    : undefined;
  const projectMap = buildProjectMap(fileMap, detectedStack);

  const context: RuleContext = { fileMap, projectMap, stack: detectedStack };

  const budget = new FindingBudget(maxFindings);
  const workBudget: MatchBudget = { remaining: MAX_TOTAL_MATCH_WORK, truncated: false };
  // The Python parser loads only for projects with Python files.
  const readsPython = fileMap.entries.some((entry) => entry.extension === '.py');
  if (readsPython) await preparePythonReader();
  let rulePhase;
  try {
    rulePhase = runWithLineIndexCache(() => runWithAstCache(() => {
      const basicResult = runBasicRules(context, { budget, workBudget });
      const contextualResult = runContextualRules(context, { budget, workBudget });
      return {
        codeFindings: dedupeAndSort([...basicResult.findings, ...contextualResult.findings]),
        ruleFailures: [...basicResult.failures, ...contextualResult.failures],
        completedRuleIds: [...basicResult.completedRuleIds, ...contextualResult.completedRuleIds],
        degradedFiles: degradedAstFiles(),
        degradedUnnamed: degradedAstFilesUnnamed(),
        astGaps: astGapWarnings(astAnalysisGaps()),
      };
    }));
  } finally {
    if (readsPython) releasePythonReader();
  }
  const { codeFindings, ruleFailures, completedRuleIds, degradedFiles, degradedUnnamed, astGaps } = rulePhase;

  for (const filePath of degradedFiles) {
    fileMap.warnings.push(
      `"${filePath}" could not be analysed in full. ` +
        'Findings in that file rest on pattern matching alone; every other file in the scan is unaffected.',
    );
  }
  if (degradedUnnamed > 0) {
    fileMap.warnings.push(
      `…and ${degradedUnnamed} more file${degradedUnnamed === 1 ? '' : 's'} could not be analysed in full; ` +
        `findings in ${degradedUnnamed === 1 ? 'that file rest' : 'those files rest'} on pattern matching alone.`,
    );
  }

  const absenceRoutes = absenceRoutesFor(context);
  for (const warning of unreadRouteWarnings(context)) fileMap.warnings.push(warning);

  const routeGaps = routeProtectionGapWarnings(
    projectMap.routeSecurityProfiles ?? [],
    routeCallWalkFailures(projectMap),
    (filePath) => isScannablePath(filePath, projectMap.scannerRootPrefix),
  );

  const { signal, dispose } = createScanSignal(options.signal, deadlineMs);
  const { dependencies, diagnostics } = collectDependenciesWithDiagnostics(fileMap);
  let dependencyAudit: DependencyAuditSummary;
  try {
    dependencyAudit = await (options.dependencyScanner ?? getDefaultDependencyScanner())
      .scanDependencies(dependencies, { parseDiagnostics: diagnostics, signal })
      .catch(
        (error: unknown): DependencyAuditSummary => ({
          performed: false,
          incomplete: true,
          source: 'error',
          dependenciesCollected: dependencies.length,
          checked: 0,
          notChecked: dependencies
            .map((dependency) => `${dependency.ecosystem}:${dependency.name}`)
            .sort((a, b) => a.localeCompare(b)),
          vulnerabilities: [],
          diagnostics: [...diagnostics],
          note:
            'Dependency audit failed to run; treat as incomplete (not a clean bill of health): ' +
            (error instanceof Error ? error.message : String(error)),
        }),
      );
  } finally {
    dispose();
  }

  const originResolver = createDependencyOriginResolver(fileMap);
  const dependencyFileContent = new Map(fileMap.entries.map((entry) => [entry.path, entry.content]));
  const dependencyFindings = dependencyVulnerabilitiesToFindings(
    dependencyAudit,
    originResolver,
    (sourcePath, packageName, installedVersion) => {
      const content = dependencyFileContent.get(sourcePath);
      return content === undefined ? undefined : pythonDependencyLine(sourcePath, content, packageName, installedVersion);
    },
  );
  const archiveFindings = archiveEntryFindings(
    options.archiveWatchList,
    sqlDumpContentLookup(fileMap, options.archiveWatchList),
  );
  const absence = absenceFindings({
    fileMap,
    projectMap,
    enabledTags: options.absenceTags ?? ENABLED_ABSENCE_TAGS,
    codeFindings,
    routes: absenceRoutes,
  });
  let extraFindings: readonly Finding[] = [];
  if (options.extraFindings !== undefined) {
    const extra = await options.extraFindings(context);
    extraFindings = extra.findings;
    for (const warning of extra.warnings) fileMap.warnings.push(warning);
  }
  const findings = withFindingIdentities(
    dedupeAndSort([...codeFindings, ...dependencyFindings, ...archiveFindings.findings, ...absence.findings, ...extraFindings]),
  );

  return buildReport({
    findings,
    fileMap,
    detectedStack,
    projectMap,
    ruleFailures: [...ruleFailures, ...absence.failures],
    completedRuleIds,
    dependencyAudit,
    codeScanTruncated: budget.truncated,
    crossFileBudgetTruncated: workBudget.truncated,
    findingLimit: maxFindings,
    archiveObserved: options.archiveWatchList !== undefined,
    archiveWarnings: archiveFindings.warnings,
    gapWarnings: [...linkWarnings(prepared.linksNotFollowed), ...astGaps, ...routeGaps],
    ...(options.archiveSkippedFileCount !== undefined
      ? { archiveSkippedFileCount: options.archiveSkippedFileCount }
      : {}),
    ...(options.archiveIgnored !== undefined ? { archiveIgnored: options.archiveIgnored } : {}),
    ...(scanFit !== undefined ? { scanFit } : {}),
    ...(options.now !== undefined ? { now: options.now } : {}),
  });
}

function createScanSignal(
  external: AbortSignal | undefined,
  deadlineMs: number | undefined,
): { signal: AbortSignal; dispose: () => void } {
  const controller = new AbortController();
  const cleanups: (() => void)[] = [];

  if (external !== undefined) {
    if (external.aborted) controller.abort();
    else {
      const onAbort = (): void => controller.abort();
      external.addEventListener('abort', onAbort, { once: true });
      cleanups.push(() => external.removeEventListener('abort', onAbort));
    }
  }
  if (deadlineMs !== undefined && deadlineMs > 0) {
    const timer = setTimeout(() => controller.abort(), deadlineMs);
    cleanups.push(() => clearTimeout(timer));
  }

  return {
    signal: controller.signal,
    dispose: () => {
      for (const cleanup of cleanups) cleanup();
    },
  };
}
