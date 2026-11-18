import {
  IGNORED_DIRECTORIES,
  IGNORED_EXTENSIONS,
  INGESTED_LOCKFILE_NAMES,
  RETAINED_LOCKFILE_NAMES,
  SKIPPED_LOCKFILE_NAMES,
  USEFUL_EXTENSIONS,
  USEFUL_FILENAMES,
} from '../shared/constants.js';
import type { InputLimits, SkippedFile } from '../shared/types.js';
import { extensionOf } from '../shared/utils.js';
import { isPythonRequirementsPath } from '../shared/pythonRequirementFiles.js';

export function isIgnoredDirectory(name: string): boolean {
  return IGNORED_DIRECTORIES.has(name.toLowerCase());
}

export function isIngestedLockfile(fileName: string): boolean {
  return INGESTED_LOCKFILE_NAMES.has(fileName.toLowerCase());
}

export function isSkippedLockfile(fileName: string): boolean {
  return SKIPPED_LOCKFILE_NAMES.has(fileName.toLowerCase());
}

export function isRetainedLockfile(fileName: string): boolean {
  return RETAINED_LOCKFILE_NAMES.has(fileName.toLowerCase());
}

export function isMinified(fileName: string): boolean {
  return /\.min\.(js|css|mjs)$/i.test(fileName);
}

// The scanner's own files are not judged when a project contains them.
const SCANNER_INTERNAL_SUFFIXES: readonly RegExp[] = [
  /^src\/rules\//,
  /^(?:src|dist)\/dependency-audit\/osv-cache\.json$/,
  /^scripts\/[^/]+\.(?:mjs|cjs|js|ts)$/,
  /^src\/archive-findings\//,
];

export function findScannerRootPrefix(
  files: readonly { path: string; content: string }[],
): string | undefined {
  let best: string | undefined;
  for (const file of files) {
    const normalized = file.path.replace(/\\/g, '/');
    if (!/(?:^|\/)package\.json$/.test(normalized)) continue;
    if (!/"name"\s*:\s*"@epherem\/scanner"/.test(file.content)) continue;
    const prefix = normalized.slice(0, normalized.length - 'package.json'.length);
    if (best === undefined || prefix.length < best.length) best = prefix;
  }
  return best;
}

export function isScannerInternalPath(filePath: string, rootPrefix?: string): boolean {
  if (rootPrefix === undefined) return false;
  const normalized = filePath.replace(/\\/g, '/');
  if (!normalized.startsWith(rootPrefix)) return false;
  const relative = normalized.slice(rootPrefix.length);
  return SCANNER_INTERNAL_SUFFIXES.some((pattern) => pattern.test(relative));
}

// Folders that are never the deployed app; kept narrow to avoid misses.
const NON_PRODUCTION_DIR_PATTERN =
  /(^|\/)(__tests__|__mocks__|__fixtures__|__snapshots__|cypress|mockserver|mock-server|mock_server)(\/)/i;
const TEST_FILE_SUFFIX_PATTERN = /\.(?:test|spec|stories|e2e|cy)\.(?:m|c)?[jt]sx?$/i;
const BACKUP_FILE_PATTERN =
  /(?:\.(?:bak|old|orig|save|tmp)$|\.backup(?:[.\-][^/]*)?$|\.[^/]*\.(?:bak|old|orig)$|[.\-_]backup[.\-][^/]*$|~$|\.swp$|^#.*#$)/i;
const PREVIEW_SCRATCH_PATTERN = /[._-]preview\.[a-z0-9]+$/i;

// Precision only: skips test, mock and backup code; loosens no rule.
export function isNonProductionCodePath(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, '/');
  const fileName = normalized.slice(normalized.lastIndexOf('/') + 1);
  return (
    NON_PRODUCTION_DIR_PATTERN.test(normalized) ||
    TEST_FILE_SUFFIX_PATTERN.test(fileName) ||
    BACKUP_FILE_PATTERN.test(fileName) ||
    PREVIEW_SCRATCH_PATTERN.test(fileName)
  );
}

// Wider on purpose: such files may not vouch for the whole project.
const CREDIT_NON_PRODUCTION_DIR_PATTERN =
  /(^|\/)(tests?|__tests__|__mocks__|__fixtures__|__snapshots__|spec|specs|e2e|cypress|mocks?|mockserver|mock-server|mock_server|fixtures?|examples?|samples?|_local|_backup|_backups|backup|backups)(\/)/i;

export function mayVouchForProject(filePath: string, scannerRootPrefix?: string): boolean {
  if (isScannerInternalPath(filePath, scannerRootPrefix)) return false;
  if (isGeneratedOrVendorPath(filePath)) return false;
  const normalized = filePath.replace(/\\/g, '/');
  const fileName = normalized.slice(normalized.lastIndexOf('/') + 1);
  return !(
    CREDIT_NON_PRODUCTION_DIR_PATTERN.test(normalized) ||
    TEST_FILE_SUFFIX_PATTERN.test(fileName) ||
    PYTHON_TEST_MODULE.test(fileName) ||
    BACKUP_FILE_PATTERN.test(fileName) ||
    PREVIEW_SCRATCH_PATTERN.test(fileName)
  );
}

// pytest's test files: test_*.py, *_test.py, conftest.py.
const PYTHON_TEST_MODULE = /^(?:test|tests|conftest|test_\w+|tests_\w+|\w+_test|\w+_tests)\.py$/;

export function isPythonTestModule(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, '/');
  return PYTHON_TEST_MODULE.test(normalized.slice(normalized.lastIndexOf('/') + 1));
}

// A hint only, never proof that a file is not deployed.
export function pathSuggestsNonProduction(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, '/');
  const fileName = normalized.slice(normalized.lastIndexOf('/') + 1);
  return (
    CREDIT_NON_PRODUCTION_DIR_PATTERN.test(normalized) ||
    TEST_FILE_SUFFIX_PATTERN.test(fileName) ||
    BACKUP_FILE_PATTERN.test(fileName) ||
    PREVIEW_SCRATCH_PATTERN.test(fileName)
  );
}

// Generated or vendored output: not the project's own code.
const GENERATED_VENDOR_DIR_PATTERN =
  /(^|\/)(node_modules|bower_components|jspm_packages|dist|dev-dist|build|\.next|\.nuxt|out|coverage|\.output|\.svelte-kit|\.vercel|\.netlify|\.turbo|\.cache|vendor|target|test-results|playwright-report|allure-results|allure-report)(\/)/i;

// Workbox runtime bundles, recognised by name alone.
const GENERATED_FILE_NAME_PATTERN = /^workbox-[0-9a-f]{6,}\.(?:js|mjs|cjs)$/i;
const EXTRA_GENERATED_MANIFESTS: ReadonlySet<string> = new Set(['npm-shrinkwrap.json']);

export function isGeneratedOrVendorPath(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, '/');
  const fileName = normalized.slice(normalized.lastIndexOf('/') + 1).toLowerCase();
  if (
    isIngestedLockfile(fileName) ||
    isSkippedLockfile(fileName) ||
    isRetainedLockfile(fileName) ||
    EXTRA_GENERATED_MANIFESTS.has(fileName) ||
    /^bun\.lock/.test(fileName)
  ) {
    return true;
  }
  if (isMinified(fileName)) return true;
  if (GENERATED_FILE_NAME_PATTERN.test(fileName)) return true;
  return GENERATED_VENDOR_DIR_PATTERN.test(normalized);
}

export function looksBinary(buffer: Buffer): boolean {
  const window = buffer.subarray(0, 8192);
  return window.includes(0);
}

export function preContentSkipReason(
  fileName: string,
  extension: string,
  size: number,
  limits: InputLimits,
): SkippedFile['reason'] | undefined {
  const lowerName = fileName.toLowerCase();
  if (isOsMetadataFile(lowerName)) return 'os_metadata';
  if (isIngestedLockfile(lowerName)) {
    return size > limits.maxLockfileSizeBytes ? 'too_large' : undefined;
  }
  if (isSkippedLockfile(lowerName)) return 'lockfile';
  if (isMinified(lowerName)) return 'minified';
  if (IGNORED_EXTENSIONS.has(extension)) return 'ignored_extension';
  if (size > limits.maxFileSizeBytes) return 'too_large';
  const isUseful =
    USEFUL_EXTENSIONS.has(extension) ||
    USEFUL_FILENAMES.has(lowerName) ||
    lowerName.startsWith('.env');
  if (!isUseful) return 'not_useful';
  return undefined;
}

export function isOsMetadataFile(fileName: string): boolean {
  return fileName.startsWith('._') && fileName.length > 2;
}

export type ArchiveIgnoreReason =
  | 'ignored_directory'
  | 'ignored_extension'
  | 'lockfile'
  | 'minified'
  | 'too_large'
  | 'not_useful'
  | 'invalid_path'
  | 'os_metadata';

export interface ArchiveEntryDecision {
  eligible: boolean;
  reason?: ArchiveIgnoreReason;
  directory?: string;
}

const ELIGIBLE: ArchiveEntryDecision = Object.freeze({ eligible: true });

export function classifyArchiveFile(
  filePath: string,
  size: number,
  limits: InputLimits,
): ArchiveEntryDecision {
  const segments = filePath.split('/');
  const fileName = segments.pop();
  if (fileName === undefined || fileName.length === 0) {
    return { eligible: false, reason: 'invalid_path' };
  }
  const ignoredSegment = segments.find(isIgnoredDirectory);
  if (ignoredSegment !== undefined) {
    return { eligible: false, reason: 'ignored_directory', directory: ignoredSegment.toLowerCase() };
  }
  if (isRetainedLockfile(fileName)) {
    return size > limits.maxLockfileSizeBytes
      ? { eligible: false, reason: 'too_large' }
      : ELIGIBLE;
  }
  const reason = preContentSkipReason(fileName, extensionOf(fileName), size, limits);
  if (reason === 'not_useful' && isPythonRequirementsPath(filePath)) return ELIGIBLE;
  return reason === undefined ? ELIGIBLE : { eligible: false, reason: toArchiveIgnoreReason(reason) };
}

function toArchiveIgnoreReason(reason: NonNullable<SkippedFile['reason']>): ArchiveIgnoreReason {
  return ARCHIVE_IGNORE_REASONS.has(reason) ? (reason as ArchiveIgnoreReason) : 'not_useful';
}

const ARCHIVE_IGNORE_REASONS: ReadonlySet<string> = new Set<ArchiveIgnoreReason>([
  'ignored_directory',
  'ignored_extension',
  'lockfile',
  'minified',
  'too_large',
  'not_useful',
  'invalid_path',
  'os_metadata',
]);

export function isEligibleArchiveFile(
  filePath: string,
  size: number,
  limits: InputLimits,
): boolean {
  return classifyArchiveFile(filePath, size, limits).eligible;
}

export function preOpenSkipReason(
  fileName: string,
  extension: string,
): SkippedFile['reason'] | undefined {
  const lowerName = fileName.toLowerCase();
  if (isOsMetadataFile(lowerName)) return 'os_metadata';
  if (isIngestedLockfile(lowerName)) return undefined;
  if (isSkippedLockfile(lowerName)) return 'lockfile';
  if (isMinified(lowerName)) return 'minified';
  if (IGNORED_EXTENSIONS.has(extension)) return 'ignored_extension';
  const isUseful =
    USEFUL_EXTENSIONS.has(extension) ||
    USEFUL_FILENAMES.has(lowerName) ||
    lowerName.startsWith('.env');
  if (!isUseful) return 'not_useful';
  return undefined;
}
