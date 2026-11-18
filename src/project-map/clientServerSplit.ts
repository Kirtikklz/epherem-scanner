import type { FileMap, FileMapEntry } from '../shared/types.js';

const CLIENT_DIRECTIVE = /^\s*['"]use client['"]/m;
const SERVER_DIRECTIVE = /^\s*['"]use server['"]/m;
const SERVER_PATH_PATTERN = /(^|\/)(server|api|functions|lambda)\//;
const SERVER_ONLY_IMPORTS =
  /from\s+['"](node:)?(fs|path|child_process|crypto)['"]|require\(['"](node:)?(fs|path|child_process)['"]\)|from\s+['"]express['"]|require\(['"]express['"]\)|(?:from\s+|import\s+)['"]server-only['"]/;
const NEXT_SERVER_ONLY_IMPORT = /from\s+['"]next\/headers['"]|require\(['"]next\/headers['"]\)/;

const PAGES_ROUTER_COMPONENT = /(^|\/)pages\/(?!api\/).+\.(tsx|jsx)$/;
const SERVER_FILENAME = /(^|\/)[^/]+\.server\.(ts|tsx|js|jsx|mjs|cjs)$/;
const APP_ROUTER_FILE = /(^|\/)app\/.+\.(tsx|jsx|ts|js)$/;
const COMPONENT_EXTENSIONS = new Set(['.jsx', '.tsx']);

export function usesAppRouter(fileMap: FileMap): boolean {
  return fileMap.entries.some((entry) =>
    /(^|\/)app\/.*(page|layout|route)\.(tsx|jsx|ts|js)$/.test(entry.path),
  );
}

export function isClientSeed(entry: FileMapEntry, appRouterProject: boolean): boolean {
  if (entry.isLikelyApiRoute || entry.isLikelyMiddleware) return false;
  if (SERVER_FILENAME.test(entry.path)) return false;
  if (SERVER_DIRECTIVE.test(entry.content)) return false;
  if (CLIENT_DIRECTIVE.test(entry.content)) return true;
  if (PAGES_ROUTER_COMPONENT.test(entry.path)) return true;
  if (APP_ROUTER_FILE.test(entry.path)) return false;
  if (!appRouterProject && COMPONENT_EXTENSIONS.has(entry.extension)) {
    return !SERVER_ONLY_IMPORTS.test(entry.content);
  }
  return false;
}

export function isServerOnlyModule(entry: FileMapEntry): boolean {
  if (CLIENT_DIRECTIVE.test(entry.content)) return false;
  if (SERVER_DIRECTIVE.test(entry.content)) return true;
  if (SERVER_FILENAME.test(entry.path)) return true;
  if (entry.isLikelyApiRoute || entry.isLikelyMiddleware) return true;
  if (NEXT_SERVER_ONLY_IMPORT.test(entry.content)) return true;
  return SERVER_ONLY_IMPORTS.test(entry.content);
}
export function computeClientFiles(
  fileMap: FileMap,
  importAdjacency: Map<string, Set<string>>,
): Set<string> {
  const appRouterProject = usesAppRouter(fileMap);
  const entriesByPath = new Map(fileMap.entries.map((entry) => [entry.path, entry]));

  const clientFiles = new Set<string>();
  const queue: string[] = [];
  for (const entry of fileMap.entries) {
    if (isClientSeed(entry, appRouterProject)) {
      clientFiles.add(entry.path);
      queue.push(entry.path);
    }
  }

  while (queue.length > 0) {
    const current = queue.shift();
    if (current === undefined) break;
    for (const imported of importAdjacency.get(current) ?? []) {
      if (clientFiles.has(imported)) continue;
      const entry = entriesByPath.get(imported);
      if (entry === undefined || isServerOnlyModule(entry)) continue;
      clientFiles.add(imported);
      queue.push(imported);
    }
  }
  return clientFiles;
}

export function isServerSide(entry: FileMapEntry, clientFiles: ReadonlySet<string>): boolean {
  if (clientFiles.has(entry.path)) return false;
  if (entry.extension === '.py') return true;
  if (isServerOnlyModule(entry)) return true;
  if (SERVER_PATH_PATTERN.test(entry.path)) return true;
  if (APP_ROUTER_FILE.test(entry.path) && !CLIENT_DIRECTIVE.test(entry.content)) return true;
  return false;
}
