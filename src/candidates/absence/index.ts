import type { FileMap, ProjectMap } from '../../shared/types.js';
import { buildAbsenceRouteModel, type AbsenceRoute } from './routeModel.js';
import { detectBroadenedDbOps, type DbOp } from './dbDetect.js';
import { runAbsenceRules, type AbsenceFacts, type AbsenceHit } from './rules.js';

export type { AbsenceRoute } from './routeModel.js';
export type { DbOp } from './dbDetect.js';
export type { AbsenceHit, AbsenceFacts } from './rules.js';
export { buildAbsenceRouteModel } from './routeModel.js';
export { detectBroadenedDbOps } from './dbDetect.js';

const ENTRY_FILE = /(^|\/)(app|server|index|main)\.[cm]?[jt]sx?$/i;
const HELMET = /\bhelmet\s*\(|require\(\s*['"]helmet['"]|from\s+['"]helmet['"]/;
const RATE_DEP = /express-rate-limit|rate-limiter|express-slow-down|@upstash\/ratelimit|express-brute/;
const CSRF_DEP = /\bcsurf\b|\bcsrf\b/;
const COOKIE_SESSION = /req\.session|express-session|cookie-session|req\.cookies|cookies\(\)/;

const JS_TS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);

export interface AbsencePassResult {
  routes: AbsenceRoute[];
  hits: AbsenceHit[];
  dbOps: DbOp[];
}

export function runAbsencePass(
  fileMap: FileMap,
  projectMap: ProjectMap,
  contentOf: (path: string) => string | undefined,
  prebuiltRoutes?: readonly AbsenceRoute[],
): AbsencePassResult {
  const routes = prebuiltRoutes !== undefined ? [...prebuiltRoutes] : buildAbsenceRouteModel(fileMap, projectMap);

  const dbOps: DbOp[] = [];
  const dbOpsByFile = new Map<string, DbOp[]>();
  let concatenated = '';
  let entryFile: string | undefined;
  let entryFallback: string | undefined;
  for (const entry of fileMap.entries) {
    if (!JS_TS.has(entry.extension)) continue;
    concatenated += entry.content;
    if (ENTRY_FILE.test(entry.path)) {
      if (/\bapp\s*\.\s*(?:use|listen)\s*\(/.test(entry.content)) {
        if (entryFile === undefined) entryFile = entry.path;
      } else if (entryFallback === undefined) {
        entryFallback = entry.path;
      }
    }
    const ops = detectBroadenedDbOps(entry.path, entry.content);
    if (ops.length > 0) {
      dbOps.push(...ops);
      dbOpsByFile.set(entry.path, ops);
    }
  }
  if (entryFile === undefined) entryFile = entryFallback;

  const facts: AbsenceFacts = {
    routes,
    dbOpsByFile,
    hasHelmet: HELMET.test(concatenated),
    hasRateLimitDep: RATE_DEP.test(concatenated),
    hasCsrfDep: CSRF_DEP.test(concatenated),
    usesCookieOrSession: COOKIE_SESSION.test(concatenated),
    entryFile,
    resolution: { fileMap, projectMap },
  };

  const hits = runAbsenceRules(facts, contentOf);
  return { routes, hits, dbOps };
}
