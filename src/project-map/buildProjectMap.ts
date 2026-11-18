import { findScannerRootPrefix } from '../input/fileFilters.js';
import { emptySupabaseRlsInfo } from './detectRls.js';
import type { AuthSignal, DetectedStack, FileMap, ProjectMap } from '../shared/types.js';
import { computeClientFiles, isServerSide } from './clientServerSplit.js';
import { detectAuthSignals, effectiveGuards } from './detectAuthSignals.js';
import { detectDangerousOperations } from './detectDangerousOperations.js';
import { detectDatabaseCalls } from './detectDatabaseCalls.js';
import { detectEnvUsage } from './detectEnvUsage.js';
import { detectSupabaseRls } from './detectRls.js';
import { detectSchemaModels, emptySchemaModelMap } from './detectSchemaModels.js';
import { extractApiRoutes } from './extractApiRoutes.js';
import { withPythonRouteTree } from '../shared/pythonRoutes.js';
import { extractFileImports } from './extractImports.js';
import { extractMiddlewareCoverage, extractMiddlewareMatchers } from './middlewareMatchers.js';
import {
  buildImportAdjacency,
  buildPathAliases,
  buildWorkspacePackages,
  resolveImports,
} from './resolveImports.js';
import { analyzeCrossFileTaint, crossFileTruncationWarning } from '../ast/crossFileTaint.js';
import { buildRouteSecurityProfiles } from './buildRouteSecurity.js';
import { hasStack } from '../stack-detection/detectStack.js';

const SUPABASE_USAGE_PATTERN = /@supabase\/|\bsupabase\w*\s*\.\s*(from|auth|storage|rpc)\b/;
const SUPABASE_CLIENT_FACTORY_PATTERN = /createClient\s*\(/;
const FIREBASE_USAGE_PATTERN = /['"]firebase(-admin)?(\/|['"])|getFirestore|initializeApp\s*\(|firebase\.firestore/;

export function buildProjectMap(fileMap: FileMap, detectedStack: DetectedStack): ProjectMap {
  const supabaseStack = hasStack(detectedStack, 'supabase');
  const projectMap: ProjectMap = {
    apiRoutes: [],
    frontendComponents: [],
    authFiles: [],
    middlewareFiles: [],
    middlewareMatchers: [],
    middlewareCoverage: [],
    databaseFiles: [],
    envFiles: [],
    configFiles: [],
    supabaseUsage: [],
    firebaseUsage: [],
    supabaseRls: emptySupabaseRlsInfo(),
    databaseCalls: [],
    imports: [],
    dangerousOperations: [],
    publicClientUsage: [],
    serverSideUsage: [],
    authSignals: [],
    envUsage: [],
    crossFileTaint: { hits: [], status: 'complete' },
    schemaModels: emptySchemaModelMap(),
  };

  for (const entry of fileMap.entries) {
    projectMap.apiRoutes.push(...extractApiRoutes(entry));
    projectMap.databaseCalls.push(...detectDatabaseCalls(entry));
    projectMap.authSignals.push(...detectAuthSignals(entry));
    projectMap.envUsage.push(...detectEnvUsage(entry));
    projectMap.dangerousOperations.push(...detectDangerousOperations(entry));
    projectMap.middlewareMatchers.push(...extractMiddlewareMatchers(entry));
    const coverage = extractMiddlewareCoverage(entry);
    if (coverage !== undefined) (projectMap.middlewareCoverage ??= []).push(coverage);

    const fileImports = extractFileImports(entry);
    if (fileImports.imports.length > 0) projectMap.imports.push(fileImports);

    if (entry.label === 'frontend_component') projectMap.frontendComponents.push(entry.path);
    if (entry.label === 'env') projectMap.envFiles.push(entry.path);
    if (entry.isLikelyMiddleware) projectMap.middlewareFiles.push(entry.path);
    if (entry.isLikelyConfig) projectMap.configFiles.push(entry.path);
    if (entry.isLikelyDatabaseRelated) projectMap.databaseFiles.push(entry.path);
    if (
      SUPABASE_USAGE_PATTERN.test(entry.content) ||
      (supabaseStack && SUPABASE_CLIENT_FACTORY_PATTERN.test(entry.content))
    ) {
      projectMap.supabaseUsage.push(entry.path);
    }
    if (FIREBASE_USAGE_PATTERN.test(entry.content)) projectMap.firebaseUsage.push(entry.path);
  }
  projectMap.apiRoutes = withPythonRouteTree(fileMap, projectMap.apiRoutes);

  const filePaths = new Set(fileMap.entries.map((entry) => entry.path));
  const pathAliases = [...buildPathAliases(fileMap), ...buildWorkspacePackages(fileMap)];
  resolveImports(projectMap.imports, filePaths, pathAliases);
  const importAdjacency = buildImportAdjacency(projectMap.imports);
  projectMap.crossFileTaint = analyzeCrossFileTaint(fileMap, projectMap.imports);
  if (projectMap.crossFileTaint.status === 'truncated') {
    fileMap.warnings.push(crossFileTruncationWarning(projectMap.crossFileTaint));
  }

  const clientFiles = computeClientFiles(fileMap, importAdjacency);
  projectMap.publicClientUsage = [...clientFiles].sort();
  projectMap.serverSideUsage = fileMap.entries
    .filter((entry) => isServerSide(entry, clientFiles))
    .map((entry) => entry.path);

  projectMap.supabaseRls = detectSupabaseRls(fileMap);
  projectMap.schemaModels = detectSchemaModels(fileMap);
  const scannerRootPrefix = findScannerRootPrefix(fileMap.entries);
  if (scannerRootPrefix !== undefined) projectMap.scannerRootPrefix = scannerRootPrefix;

  const authSignalFiles = new Set(projectMap.authSignals.map((signal) => signal.filePath));
  projectMap.authFiles = fileMap.entries
    .filter((entry) => entry.label === 'auth' || entry.isLikelyAuthRelated || authSignalFiles.has(entry.path))
    .map((entry) => entry.path);

  projectMap.routeSecurityProfiles = buildRouteSecurityProfiles(fileMap, projectMap);

  return projectMap;
}

export function authSignalsInFile(projectMap: ProjectMap, filePath: string): AuthSignal[] {
  return projectMap.authSignals.filter((signal) => signal.filePath === filePath);
}

export function effectiveGuardsInFile(projectMap: ProjectMap, filePath: string): AuthSignal[] {
  return effectiveGuards(authSignalsInFile(projectMap, filePath));
}

export function directImportsOf(projectMap: ProjectMap, filePath: string): string[] {
  const fileImports = projectMap.imports.find((imports) => imports.filePath === filePath);
  if (fileImports === undefined) return [];
  const resolved = fileImports.imports
    .map((importRef) => importRef.resolvedPath)
    .filter((path): path is string => path !== undefined);
  return [...new Set(resolved)].sort();
}

export function databaseCallsInFile(projectMap: ProjectMap, filePath: string) {
  return projectMap.databaseCalls.filter((call) => call.filePath === filePath);
}
