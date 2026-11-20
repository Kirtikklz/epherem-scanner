import { IGNORED_DIRECTORIES } from '../shared/constants.js';
import {
  UNEXPECTED_CATEGORY_ORDER,
  type ArchiveWalkTruncationReasonId,
  type HygieneCheckId,
  type HygieneCheckStatus,
  type UnexpectedFileCategoryId,
} from '../shared/archiveObservations.js';
import {
  MAX_REPORTED_PATH_SAMPLE,
  MAX_REPORTED_WATCHLIST_PATH_LENGTH,
  reportedPath,
  stripHostileCharacters,
  type ReportedPath,
} from './reportedPath.js';

export const MAX_RECORDED_SCANNED_PATHS = 5_000;

export const MAX_RECORDED_DIRECTORY_PATHS = 2_000;

export type UnexpectedFileCategory = UnexpectedFileCategoryId;

export type ExpectedFileCheck = HygieneCheckId;

export type HygienePresence = HygieneCheckStatus;

export interface UnexpectedFileGroup {
  count: number;
  sample: ReportedPath[];
}

export type ArchiveWalkTruncationReason = ArchiveWalkTruncationReasonId;

export interface ArchiveNameScan {
  rootPrefix?: string;
  unexpectedFiles: Record<UnexpectedFileCategory, UnexpectedFileGroup>;
  expectedFiles: Record<ExpectedFileCheck, HygienePresence>;
  scannedPaths: ReportedPath[];
  directoryPaths: ReportedPath[];
  truncationReasons: ArchiveWalkTruncationReason[];
}

export interface ArchiveNameObservation {
  path: string;
  isDirectory: boolean;
  eligible: boolean;
}

export interface ArchiveNameCollector {
  observe(entry: ArchiveNameObservation): void;
  result(): ArchiveNameScan;
}

const PRIVATE_KEY_NAMES: ReadonlySet<string> = new Set([
  'id_rsa',
  'id_dsa',
  'id_ecdsa',
  'id_ed25519',
]);

const PRIVATE_KEY_SUFFIXES: readonly string[] = [
  '.pem',
  '.key',
  '.p12',
  '.pfx',
  '.jks',
  '.keystore',
];

const CLOUD_CREDENTIAL_NAMES: ReadonlySet<string> = new Set([
  'serviceaccountkey.json',
  'service-account.json',
]);

const DATABASE_SUFFIXES: readonly string[] = [
  '.sqlite',
  '.sqlite3',
  '.db',
  '.dump',
];

const BACKED_UP_DATABASE_SUFFIXES: readonly string[] = ['.sql', '.sqlite', '.sqlite3', '.db', '.dump', '.tfstate'];

const SQL_DUMP_WORDS: readonly string[] = ['dump', 'backup', 'export'];

const INFRASTRUCTURE_STATE_NAMES: ReadonlySet<string> = new Set([
  'terraform.tfstate',
  'terraform.tfstate.backup',
]);

const LOCKFILE_NAMES: ReadonlySet<string> = new Set([
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'bun.lockb',
  'poetry.lock',
  'pipfile.lock',
]);

const ENV_TEMPLATE_NAMES: ReadonlySet<string> = new Set([
  '.env.example',
  '.env.sample',
  '.env.template',
]);

const DEPENDENCY_MANIFEST_NAMES: ReadonlySet<string> = new Set([
  'package.json',
  'pyproject.toml',
  'requirements.txt',
  'pipfile',
  'composer.json',
  'cargo.toml',
  'gemfile',
  'go.mod',
]);

const DEPENDENCY_UPDATE_PATHS: ReadonlySet<string> = new Set([
  '.github/dependabot.yml',
  '.github/renovate.json',
  'renovate.json',
]);

const UNEXPECTED_CATEGORIES: readonly UnexpectedFileCategory[] = UNEXPECTED_CATEGORY_ORDER;

function unexpectedCategoryOf(
  baseName: string,
  segments: readonly string[],
): UnexpectedFileCategory | undefined {
  if (PRIVATE_KEY_NAMES.has(baseName)) return 'private_keys';
  if (PRIVATE_KEY_SUFFIXES.some((suffix) => baseName.endsWith(suffix))) return 'private_keys';

  if (CLOUD_CREDENTIAL_NAMES.has(baseName)) return 'cloud_credentials';
  if (baseName.startsWith('firebase-adminsdk-') && baseName.endsWith('.json')) {
    return 'cloud_credentials';
  }
  if (baseName.endsWith('-credentials.json')) return 'cloud_credentials';
  if (baseName === 'credentials' && segments[segments.length - 1] === '.aws') {
    return 'cloud_credentials';
  }

  if (INFRASTRUCTURE_STATE_NAMES.has(baseName)) return 'infrastructure_state';

  if (DATABASE_SUFFIXES.some((suffix) => baseName.endsWith(suffix))) return 'database_dumps';
  if (
    baseName.endsWith('.bak') &&
    BACKED_UP_DATABASE_SUFFIXES.some((suffix) => baseName.slice(0, -'.bak'.length).endsWith(suffix))
  ) {
    return 'database_dumps';
  }
  if (baseName.endsWith('.sql') && SQL_DUMP_WORDS.some((word) => baseName.includes(word))) {
    return 'database_dumps';
  }
  return undefined;
}

function insideIgnoredDirectory(segments: readonly string[]): boolean {
  return segments.some((segment) => IGNORED_DIRECTORIES.has(segment.toLowerCase()));
}

function isDockerfileName(baseName: string): boolean {
  return baseName === 'dockerfile' || baseName.startsWith('dockerfile.');
}

interface MutableGroup {
  count: number;
  sample: ReportedPath[];
  rawSample: string[];
}

interface RootAnchoredFlags {
  gitignore: boolean;
  dockerignore: boolean;
  dependencyUpdates: boolean;
}

function emptyRootAnchoredFlags(): RootAnchoredFlags {
  return { gitignore: false, dockerignore: false, dependencyUpdates: false };
}

export function createArchiveNameCollector(
  caps: { maxScannedPaths?: number; maxDirectoryPaths?: number } = {},
): ArchiveNameCollector {
  const maxScannedPaths = caps.maxScannedPaths ?? MAX_RECORDED_SCANNED_PATHS;
  const maxDirectoryPaths = caps.maxDirectoryPaths ?? MAX_RECORDED_DIRECTORY_PATHS;

  const groups = new Map<UnexpectedFileCategory, MutableGroup>(
    UNEXPECTED_CATEGORIES.map((category) => [category, { count: 0, sample: [], rawSample: [] }]),
  );

  let sawAnyEntry = false;
  let candidateRoot: string | undefined;
  let candidateAlive = false;

  const underCandidate = emptyRootAnchoredFlags();
  const atArchiveRoot = emptyRootAnchoredFlags();

  let sawDockerfile = false;
  let sawLockfile = false;
  let sawEnvTemplate = false;
  let sawDependencyManifest = false;

  const rawScannedPaths: string[] = [];
  const rawDirectoryPaths: string[] = [];
  const truncationReasons = new Set<ArchiveWalkTruncationReason>();

  function noteRoot(segments: readonly string[], isDirectory: boolean): void {
    const first = segments[0];
    if (!sawAnyEntry) {
      sawAnyEntry = true;
      if (first !== undefined && (segments.length > 1 || isDirectory)) {
        candidateRoot = first;
        candidateAlive = true;
      }
      return;
    }
    if (!candidateAlive) return;
    if (first !== candidateRoot || (segments.length === 1 && !isDirectory)) {
      candidateAlive = false;
    }
  }

  function observe(entry: ArchiveNameObservation): void {
    const cleaned = stripHostileCharacters(entry.path);
    const segments = cleaned.split('/');
    const entryName = segments.pop() ?? '';
    const baseName = entryName.toLowerCase();
    if (baseName.length === 0) return;

    noteRoot([...segments, entryName], entry.isDirectory);

    if (insideIgnoredDirectory(entry.isDirectory ? [...segments, baseName] : segments)) return;

    if (entry.isDirectory) {
      if (rawDirectoryPaths.length < maxDirectoryPaths) rawDirectoryPaths.push(cleaned);
      else truncationReasons.add('directory_path_cap');
      return;
    }

    const category = unexpectedCategoryOf(baseName, segments);
    if (category !== undefined) {
      const group = groups.get(category);
      if (group !== undefined) {
        group.count += 1;
        if (group.rawSample.length < MAX_REPORTED_PATH_SAMPLE) group.rawSample.push(cleaned);
      }
    }

    if (isDockerfileName(baseName)) sawDockerfile = true;
    if (LOCKFILE_NAMES.has(baseName)) sawLockfile = true;
    if (ENV_TEMPLATE_NAMES.has(baseName)) sawEnvTemplate = true;
    if (DEPENDENCY_MANIFEST_NAMES.has(baseName)) sawDependencyManifest = true;

    recordRootAnchored(segments, baseName);

    if (!entry.eligible) return;
    if (rawScannedPaths.length < maxScannedPaths) rawScannedPaths.push(cleaned);
    else truncationReasons.add('scanned_path_cap');
  }

  function recordRootAnchored(segments: readonly string[], baseName: string): void {
    const full = segments.length === 0 ? baseName : `${segments.join('/')}/${baseName}`;
    if (segments.length === 0) {
      if (baseName === '.gitignore') atArchiveRoot.gitignore = true;
      if (baseName === '.dockerignore') atArchiveRoot.dockerignore = true;
    }
    if (DEPENDENCY_UPDATE_PATHS.has(full)) atArchiveRoot.dependencyUpdates = true;

    if (candidateRoot === undefined || !candidateAlive) return;
    if (segments.length === 0 || segments[0] !== candidateRoot) return;
    const relative = full.slice(candidateRoot.length + 1);
    if (relative === '.gitignore') underCandidate.gitignore = true;
    if (relative === '.dockerignore') underCandidate.dockerignore = true;
    if (DEPENDENCY_UPDATE_PATHS.has(relative)) underCandidate.dependencyUpdates = true;
  }

  function result(): ArchiveNameScan {
    const rootPrefix = candidateAlive ? candidateRoot : undefined;
    const flags = rootPrefix === undefined ? atArchiveRoot : underCandidate;
    const strip = (raw: string): ReportedPath => stripRoot(raw, rootPrefix);

    const unexpectedFiles = Object.fromEntries(
      UNEXPECTED_CATEGORIES.map((category) => {
        const group = groups.get(category);
        return [
          category,
          {
            count: group?.count ?? 0,
            sample: (group?.rawSample ?? []).map(strip),
          },
        ];
      }),
    ) as Record<UnexpectedFileCategory, UnexpectedFileGroup>;

    return {
      ...(rootPrefix === undefined ? {} : { rootPrefix }),
      unexpectedFiles,
      expectedFiles: {
        gitignore: flags.gitignore ? 'present' : 'absent',
        dockerignore: !sawDockerfile
          ? 'not_applicable'
          : flags.dockerignore
            ? 'present'
            : 'absent',
        lockfile: !sawDependencyManifest
          ? 'not_applicable'
          : sawLockfile
            ? 'present'
            : 'absent',
        env_template: sawEnvTemplate ? 'present' : 'absent',
        dependency_updates: flags.dependencyUpdates ? 'present' : 'absent',
      },
      scannedPaths: rawScannedPaths.map(strip),
      directoryPaths: rawDirectoryPaths.map(strip),
      truncationReasons: [...truncationReasons].sort(),
    };
  }

  return { observe, result };
}

function stripRoot(raw: string, rootPrefix: string | undefined): ReportedPath {
  if (rootPrefix === undefined) return reportedPath(raw, MAX_REPORTED_WATCHLIST_PATH_LENGTH);
  const prefix = `${rootPrefix}/`;
  if (raw === rootPrefix) return { path: '', truncated: false };
  const relative = raw.startsWith(prefix) ? raw.slice(prefix.length) : raw;
  return reportedPath(relative, MAX_REPORTED_WATCHLIST_PATH_LENGTH);
}

export function emptyArchiveNameScan(): ArchiveNameScan {
  return createArchiveNameCollector().result();
}

export function scanArchiveNames(
  entries: readonly ArchiveNameObservation[],
  caps?: { maxScannedPaths?: number; maxDirectoryPaths?: number },
): ArchiveNameScan {
  const collector = createArchiveNameCollector(caps);
  for (const entry of entries) collector.observe(entry);
  return collector.result();
}

export function archiveScannedFolders(scan: ArchiveNameScan): string[] {
  const folders = new Set<string>();
  for (const file of scan.scannedPaths) {
    const segments = file.path.split('/');
    segments.pop();
    for (let depth = 1; depth <= segments.length; depth += 1) {
      folders.add(segments.slice(0, depth).join('/'));
    }
  }
  for (const directory of scan.directoryPaths) {
    if (directory.path.length === 0) continue;
    const segments = directory.path.split('/');
    for (let depth = 1; depth <= segments.length; depth += 1) {
      folders.add(segments.slice(0, depth).join('/'));
    }
  }
  return [...folders].sort();
}
