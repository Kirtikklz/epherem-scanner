import type { FileMapEntry, FileTypeLabel, PreparedFile } from '../shared/types.js';
import { basename } from '../shared/utils.js';

const CODE_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py']);

const API_ROUTE_PATH_PATTERN =
  /(^|\/)pages\/api\/|(^|\/)app\/.*route\.(ts|js|tsx|jsx|mjs)$|(^|\/)\+(server|page\.server|layout\.server)\.(ts|js|mts|mjs)$|(^|\/)(api|routes)\/.*\.(ts|js|mjs|cjs|py)$/;
const EXPRESS_ROUTE_PATTERN = /\b(?:app|router)\.(get|post|put|delete|patch|all)\s*\(\s*['"`]/;
const PYTHON_ROUTE_PATTERN = /@(?:app|router|bp)\.(?:get|post|put|delete|patch|route)\s*\(/;

const AUTH_PATH_PATTERN = /(^|\/|[._-])(auth|login|logout|signin|sign-in|signup|sign-up|session)(\/|[._-]|$)/i;
const SVELTEKIT_HOOKS_PATTERN = /(^|\/)hooks\.server\.(ts|js|mts|mjs)$/;
const MIDDLEWARE_PATTERN = /(^|\/)middleware\.(ts|js|mjs|py)$|(^|\/)middlewares?\//i;
const PROXY_ENTRYPOINT_PATTERN = /^(?:src\/)?proxy\.(ts|tsx|js|jsx|mjs|cjs)$/i;
const MIGRATION_PATH_PATTERN = /(^|\/)migrations?\//i;
const DATABASE_PATH_PATTERN = /(^|\/)(db|database|models|schema|prisma|drizzle)(\/|\.)/i;

const CONFIG_FILENAME_PATTERN =
  /^(next|vite|tailwind|drizzle|jest|vitest|babel|postcss|webpack|rollup|astro|svelte|nuxt|remix|playwright|eslint)\.config\.(js|ts|mjs|cjs|json)$|^tsconfig(\..*)?\.json$|^\.eslintrc(\..*)?$|^vercel\.json$|^netlify\.toml$|^docker-compose\.ya?ml$|^dockerfile$|^requirements\.txt$|^pyproject\.toml$|^firebase\.json$|^\.firebaserc$|^mcp\.json$/i;

const ENV_USAGE_PATTERN =
  /process\.env[.[]|import\.meta\.env[.[]|os\.environ|getenv\(|Deno\.env/;

const DB_CONTENT_PATTERN =
  /\bsupabase\s*\.\s*from\s*\(|\bprisma\.\w+\.(create|update|delete|find|upsert)|\bdrizzle\b|getFirestore|firebase\.firestore|\b(SELECT|INSERT INTO|UPDATE|DELETE FROM)\b/i;

interface TechnologyHintProbe {
  hint: string;
  pattern: RegExp;
}

const TECHNOLOGY_PROBES: TechnologyHintProbe[] = [
  { hint: 'nextjs', pattern: /from\s+['"]next[/'"]|require\(['"]next|['"]next\/(server|navigation|headers)/ },
  { hint: 'react', pattern: /from\s+['"]react['"]|require\(['"]react['"]\)/ },
  { hint: 'express', pattern: /from\s+['"]express['"]|require\(['"]express['"]\)/ },
  { hint: 'supabase', pattern: /@supabase\/|createClient\s*\(\s*.*supabase|SUPABASE_/i },
  { hint: 'firebase', pattern: /['"]firebase(-admin)?(\/|['"])|initializeApp\s*\(|getFirestore|firebase\.firestore/ },
  { hint: 'prisma', pattern: /@prisma\/client|PrismaClient|\bprisma\.\w+\./ },
  { hint: 'drizzle', pattern: /drizzle-orm|drizzle\(/ },
  { hint: 'tailwind', pattern: /tailwindcss/ },
  { hint: 'vite', pattern: /\bvite\b|import\.meta\.env/ },
  { hint: 'fastapi', pattern: /from\s+fastapi\s+import|FastAPI\(/ },
  { hint: 'flask', pattern: /from\s+flask\s+import|Flask\(__name__\)/ },
  { hint: 'ai_agent_mcp', pattern: /@modelcontextprotocol\/|@anthropic-ai\/|\bfrom\s+['"]openai['"]|langchain|llamaindex|\bfrom\s+openai\s+import|\bfrom\s+anthropic\s+import/ },
];

const AUTH_CONTENT_PATTERN =
  /getUser\s*\(|getSession\s*\(|getServerSession\s*\(|\bauth\s*\(\)|currentUser|onAuthStateChanged|signIn\w*\s*\(|signUp\w*\s*\(|verifyIdToken|jwt\.verify|next-auth|@clerk\//;

export function classifyFile(file: PreparedFile): FileMapEntry {
  const name = basename(file.path).toLowerCase();
  const { path: filePath, content } = file;

  const isEnv = name.startsWith('.env');
  const isPackageManifest = name === 'package.json';
  const isLockfile =
    name === 'package-lock.json' ||
    name === 'yarn.lock' ||
    name === 'pnpm-lock.yaml' ||
    name === 'bun.lock';
  const isFirebaseRules =
    name === 'firestore.rules' || name === 'storage.rules' || name === 'database.rules.json';
  const isSupabaseConfig =
    /(^|\/)supabase\//.test(filePath) && (name === 'config.toml' || name.endsWith('.toml'));
  const isMigration = MIGRATION_PATH_PATTERN.test(filePath) || /^\d{3,}_.*\.sql$/.test(name);
  const isDatabaseSchema =
    file.extension === '.sql' || file.extension === '.prisma' || name === 'schema.prisma';
  const isMiddleware =
    MIDDLEWARE_PATTERN.test(filePath) ||
    PROXY_ENTRYPOINT_PATTERN.test(filePath) ||
    SVELTEKIT_HOOKS_PATTERN.test(filePath);
  const isCode = CODE_EXTENSIONS.has(file.extension);
  const isApiRoute =
    API_ROUTE_PATH_PATTERN.test(filePath) ||
    (isCode && (EXPRESS_ROUTE_PATTERN.test(content) || PYTHON_ROUTE_PATTERN.test(content)));
  const isAuthRelated =
    AUTH_PATH_PATTERN.test(filePath) || (isCode && AUTH_CONTENT_PATTERN.test(content));
  const isConfigFile = CONFIG_FILENAME_PATTERN.test(name);
  const isFrontendComponent =
    (file.extension === '.jsx' || file.extension === '.tsx') && !isApiRoute;
  const isDatabaseRelated =
    isDatabaseSchema || isMigration || DATABASE_PATH_PATTERN.test(filePath) ||
    (isCode && DB_CONTENT_PATTERN.test(content));

  const label = pickLabel({
    isEnv,
    isPackageManifest,
    isLockfile,
    isFirebaseRules,
    isSupabaseConfig,
    isMigration,
    isDatabaseSchema,
    isMiddleware,
    isAuthRelated,
    isApiRoute,
    isConfigFile,
    isFrontendComponent,
  });

  const technologyHints = TECHNOLOGY_PROBES
    .filter((probe) => probe.pattern.test(content) || probe.pattern.test(filePath))
    .map((probe) => probe.hint)
    .sort();

  return {
    path: filePath,
    extension: file.extension,
    label,
    size: file.size,
    isLikelyConfig: isConfigFile || isPackageManifest || isSupabaseConfig,
    isLikelyApiRoute: isApiRoute,
    isLikelyAuthRelated: isAuthRelated,
    isLikelyDatabaseRelated: isDatabaseRelated,
    isLikelyMiddleware: isMiddleware,
    usesEnvVariables: isEnv || ENV_USAGE_PATTERN.test(content),
    technologyHints,
    content,
  };
}

interface LabelSignals {
  isEnv: boolean;
  isPackageManifest: boolean;
  isLockfile: boolean;
  isFirebaseRules: boolean;
  isSupabaseConfig: boolean;
  isMigration: boolean;
  isDatabaseSchema: boolean;
  isMiddleware: boolean;
  isAuthRelated: boolean;
  isApiRoute: boolean;
  isConfigFile: boolean;
  isFrontendComponent: boolean;
}

function pickLabel(signals: LabelSignals): FileTypeLabel {
  if (signals.isEnv) return 'env';
  if (signals.isPackageManifest) return 'package_manifest';
  if (signals.isLockfile) return 'lockfile';
  if (signals.isFirebaseRules) return 'firebase_rules';
  if (signals.isSupabaseConfig) return 'supabase_config';
  if (signals.isMigration) return 'migration';
  if (signals.isDatabaseSchema) return 'database_schema';
  if (signals.isMiddleware) return 'middleware';
  if (signals.isApiRoute) return 'api_route';
  if (signals.isAuthRelated) return 'auth';
  if (signals.isConfigFile) return 'config';
  if (signals.isFrontendComponent) return 'frontend_component';
  return 'unknown_useful';
}
