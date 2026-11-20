export type HygieneCheckId =
  | 'gitignore'
  | 'dockerignore'
  | 'lockfile'
  | 'env_template'
  | 'dependency_updates';

export type HygieneCheckStatus = 'present' | 'absent' | 'not_applicable';

export type UnexpectedFileCategoryId =
  | 'private_keys'
  | 'cloud_credentials'
  | 'database_dumps'
  | 'infrastructure_state';

export type ArchiveWalkTruncationReasonId =
  | 'scanned_path_cap'
  | 'directory_path_cap';

export const HYGIENE_CHECK_ORDER: readonly HygieneCheckId[] = [
  'gitignore',
  'dockerignore',
  'lockfile',
  'env_template',
  'dependency_updates',
];

export const UNEXPECTED_CATEGORY_ORDER: readonly UnexpectedFileCategoryId[] = [
  'private_keys',
  'cloud_credentials',
  'database_dumps',
  'infrastructure_state',
];

export interface ReportedPathList {
  paths: string[];
  shortened: number[];
}

export function emptyReportedPathList(): ReportedPathList {
  return { paths: [], shortened: [] };
}

export interface HygieneCheckResult {
  check: HygieneCheckId;
  status: HygieneCheckStatus;
}

export interface HygieneCheckTotals {
  present: number;
  absent: number;
  notApplicable: number;
  evaluated: number;
}

export interface ProjectHygieneObserved {
  state: 'observed';
  checks: HygieneCheckResult[];
  totals: HygieneCheckTotals;
}

export interface ProjectHygieneNotObserved {
  state: 'not_observed';
  reason: 'no_archive';
}

export type ProjectHygiene = ProjectHygieneObserved | ProjectHygieneNotObserved;

export function unobservedProjectHygiene(): ProjectHygieneNotObserved {
  return { state: 'not_observed', reason: 'no_archive' };
}

export interface UnexpectedFileGroupRecord {
  category: UnexpectedFileCategoryId;
  count: number;
  sample: ReportedPathList;
}

export interface ArchiveWatchListCarry {
  rootPrefix?: string;
  groups: UnexpectedFileGroupRecord[];
  source?: 'folder';
}

export interface IgnoredDirectoryTally {
  directory: string;
  files: number;
}

export interface ArchiveShapeTotals {
  scannedFiles: number;
  scannedFilesListed: number;
  directoriesListed: number;
  ignoredFiles: number;
  ignoredDirectories: number;
  unexpectedFiles: number;
  truncated: boolean;
}

export interface ArchiveShapeObserved {
  state: 'observed';
  rootPrefix?: string;
  scannedFiles: ReportedPathList;
  directories: ReportedPathList;
  unexpectedFiles: UnexpectedFileGroupRecord[];
  ignoredDirectories: IgnoredDirectoryTally[];
  truncationReasons: ArchiveWalkTruncationReasonId[];
  totals: ArchiveShapeTotals;
}

export interface ArchiveShapeNotObserved {
  state: 'not_observed';
  reason: 'no_archive';
}

export interface ArchiveShapeWithheld {
  state: 'withheld';
  reason: 'free_plan';
}

export type ArchiveShape = ArchiveShapeObserved | ArchiveShapeNotObserved | ArchiveShapeWithheld;

export function unobservedArchiveShape(): ArchiveShapeNotObserved {
  return { state: 'not_observed', reason: 'no_archive' };
}

export function withheldArchiveShape(): ArchiveShapeWithheld {
  return { state: 'withheld', reason: 'free_plan' };
}
