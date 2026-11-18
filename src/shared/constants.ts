import type { InputLimits } from './types.js';

export const IGNORED_DIRECTORIES: ReadonlySet<string> = new Set([
  'node_modules',
  'bower_components',
  'jspm_packages',
  '.git',
  '.svn',
  '.hg',
  '.next',
  '.nuxt',
  'dist',
  'dev-dist',
  'build',
  'coverage',
  '.cache',
  '.turbo',
  'vendor',
  'out',
  'target',
  'tmp',
  'temp',
  '.vercel',
  '.netlify',
  '.output',
  '.svelte-kit',
  '__pycache__',
  '.pytest_cache',
  '.venv',
  'venv',
  '.idea',
  '__macosx',
  '.dart_tool',
]);

export const IGNORED_EXTENSIONS: ReadonlySet<string> = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.avif', '.bmp', '.ico', '.svg',
  '.mp4', '.mov', '.avi', '.webm', '.mkv',
  '.mp3', '.wav', '.ogg', '.flac',
  '.woff', '.woff2', '.ttf', '.otf', '.eot',
  '.zip', '.tar', '.gz', '.rar', '.7z',
  '.exe', '.dll', '.so', '.dylib', '.bin', '.wasm',
  '.jar', '.class', '.pyc',
  '.pdf', '.psd', '.sketch',
]);

export const INGESTED_LOCKFILE_NAMES: ReadonlySet<string> = new Set([
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'poetry.lock',
  'bun.lock',
]);

export const SKIPPED_LOCKFILE_NAMES: ReadonlySet<string> = new Set([
  'bun.lockb',
  'pipfile.lock',
  'composer.lock',
  'cargo.lock',
  'gemfile.lock',
]);

export const RETAINED_LOCKFILE_NAMES: ReadonlySet<string> = new Set([
  'pipfile.lock',
  'composer.lock',
  'cargo.lock',
  'bun.lockb',
  'uv.lock',
  'gemfile',
  'gemfile.lock',
  'go.mod',
  'go.sum',
  'podfile.lock',
  'pubspec.lock',
  'packages.config',
  'gradle.lockfile',
  'mix.lock',
  'pipfile',
  'npm-shrinkwrap.json',
]);

export const DEFAULT_INPUT_LIMITS: InputLimits = {
  maxFileSizeBytes: 1_000_000,
  maxLockfileSizeBytes: 10_000_000,
  maxTotalFiles: 5_000,
  maxTotalContentBytes: 50_000_000,
  maxDirectoryDepth: 32,
  maxVisitedEntries: 250_000,
  maxDirectories: 25_000,
  maxSkippedDetails: 5_000,
  maxScanDurationMs: 150_000,
  maxSourceNestingDepth: 200,
};

export const MAX_MATCHES_PER_FIND = 2_000;
export const MAX_TOTAL_FINDINGS = 5_000;

export const MAX_TOTAL_MATCH_WORK = 2_000_000;

export const MAX_AUDITED_DEPENDENCIES = 10_000;
export const MAX_OSV_LOOKUPS = 10_000;
export const MAX_DEPENDENCY_VULNERABILITIES = 5_000;

export const CONFIG_BOUNDS = {
  maxByteSize: 1_073_741_824,
  maxCount: 10_000_000,
  maxDurationMs: 3_600_000,
  maxDepth: 1_024,
  maxConcurrency: 1_024,
  maxRetries: 100,
} as const;

export const USEFUL_EXTENSIONS: ReadonlySet<string> = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  '.py',
  '.sql', '.prisma', '.tf',
  '.json', '.toml', '.yaml', '.yml',
  '.rules',
  '.map',
  '.html',
  '.pem', '.key',
  '.ejs', '.hbs', '.handlebars', '.pug', '.jade', '.njk', '.nunjucks', '.erb', '.mustache',
]);

export const USEFUL_FILENAMES: ReadonlySet<string> = new Set([
  'dockerfile',
  'requirements.txt',
  'procfile',
  'firestore.rules',
  'storage.rules',
  'database.rules.json',
  'firebase.json',
]);

export const SENSITIVE_ENV_NAME_PATTERN =
  /(SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|PASSWD|API_KEY|APIKEY|ACCESS_KEY|AUTH_TOKEN|SIGNING|DATABASE_URL|CONNECTION_STRING)/;

export const PUBLIC_ENV_PREFIXES = ['NEXT_PUBLIC_', 'VITE_', 'REACT_APP_', 'EXPO_PUBLIC_', 'PUBLIC_'] as const;

export const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};
