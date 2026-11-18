import type { ApiRoute, ApiRouteFramework, FileMapEntry } from './types.js';
import { findMatches } from './utils.js';

const SVELTEKIT_ROUTE_FILE =
  /(?:^|\/)routes\/(.*?)\/?\+(server|page\.server|layout\.server)\.(?:ts|js|mts|mjs)$/;

export const SVELTEKIT_HOOKS_FILE = /(?:^|\/)hooks\.server\.(?:ts|js|mts|mjs)$/;

const METHOD_EXPORT =
  /export\s+(?:async\s+)?(?:function|const|let|var)\s+(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b/g;

const LOAD_EXPORT = /export\s+(?:async\s+)?(?:function|const|let|var)\s+load\b/g;

const ACTIONS_EXPORT = /export\s+(?:const|let|var)\s+actions\b/g;

const HANDLE_EXPORT = /export\s+(?:async\s+)?(?:function|const|let|var)\s+handle\b/g;

export type FileRoutedDialect = 'nextjs_app' | 'nextjs_pages' | 'sveltekit';

const NEXT_APP_ROUTE_FILE = /(^|\/)app\/(.*)\/route\.(ts|js|tsx|jsx|mjs)$/;
const NEXT_PAGES_API_FILE = /(^|\/)pages\/api\/(.+)\.(ts|js|tsx|jsx|mjs)$/;

export const NEXT_LAYOUT_FILE = /(^|\/)app\/(?:.*\/)?layout\.(?:ts|tsx|js|jsx|mjs)$/;
export const NEXT_PAGE_FILE = /(^|\/)app\/(?:.*\/)?page\.(?:ts|tsx|js|jsx|mjs)$/;
export const USE_SERVER_DIRECTIVE = /^\s*(?:\/\/[^\n]*\n|\/\*[\s\S]*?\*\/\s*)*['"]use server['"]/;

export function nextJsFileKind(
  filePath: string,
): 'app-route' | 'pages-api' | 'app-page' | 'app-layout' | undefined {
  if (NEXT_APP_ROUTE_FILE.test(filePath)) return 'app-route';
  if (NEXT_PAGES_API_FILE.test(filePath)) return 'pages-api';
  if (NEXT_PAGE_FILE.test(filePath)) return 'app-page';
  if (NEXT_LAYOUT_FILE.test(filePath)) return 'app-layout';
  return undefined;
}

export const VITE_CONFIG_FILE = /(?:^|\/)vite\.config\.(?:js|ts|mjs|cjs|mts|cts)$/;
export const REACT_COMPONENT_FILE = /\.(?:tsx|jsx)$/;

export function svelteKitRouteKind(
  filePath: string,
): { kind: 'server' | 'page.server' | 'layout.server'; routePath: string } | undefined {
  const match = SVELTEKIT_ROUTE_FILE.exec(filePath);
  if (match === null) return undefined;
  const directory = match[1] ?? '';
  const suffix = match[2];
  const kind = suffix === 'server' ? 'server' : suffix === 'page.server' ? 'page.server' : 'layout.server';
  const routePath = `/${directory}`.replace(/\/\(([^)]+)\)/g, '').replace(/\/{2,}/g, '/');
  return { kind, routePath: routePath === '' ? '/' : routePath };
}

export function svelteKitRouteId(filePath: string): string | undefined {
  const match = SVELTEKIT_ROUTE_FILE.exec(filePath);
  if (match === null) return undefined;
  const id = `/${match[1] ?? ''}`.replace(/\/{2,}/g, '/');
  return id === '' ? '/' : id;
}

export function isSvelteKitServerModule(filePath: string): boolean {
  return svelteKitRouteKind(filePath) !== undefined || SVELTEKIT_HOOKS_FILE.test(filePath);
}

export function fileRoutedHandlers(entry: FileMapEntry): ApiRoute[] | undefined {
  const { path: filePath, content } = entry;

  const appMatch = NEXT_APP_ROUTE_FILE.exec(filePath);
  if (appMatch !== null) {
    const routePath = `/${appMatch[2] ?? ''}`.replace(/\/\(([^)]+)\)/g, '');
    return methodRoutes(filePath, 'nextjs_app', routePath, content);
  }

  const pagesMatch = NEXT_PAGES_API_FILE.exec(filePath);
  if (pagesMatch !== null) {
    return [
      {
        filePath,
        framework: 'nextjs_pages',
        routePath: `/api/${(pagesMatch[2] ?? '').replace(/\/index$/, '')}`,
        methods: ['ANY'],
        line: 1,
      },
    ];
  }

  const svelte = svelteKitRouteKind(filePath);
  if (svelte === undefined) return undefined;

  if (svelte.kind === 'server') return methodRoutes(filePath, 'sveltekit', svelte.routePath, content);

  const routes: ApiRoute[] = [];
  for (const match of findMatches(content, LOAD_EXPORT)) {
    routes.push({ filePath, framework: 'sveltekit', routePath: svelte.routePath, methods: ['GET'], line: match.line });
  }
  for (const match of findMatches(content, ACTIONS_EXPORT)) {
    routes.push({ filePath, framework: 'sveltekit', routePath: svelte.routePath, methods: ['POST'], line: match.line });
  }
  return routes;
}

function methodRoutes(
  filePath: string,
  framework: ApiRouteFramework,
  routePath: string,
  content: string,
): ApiRoute[] {
  const routes: ApiRoute[] = [];
  for (const match of findMatches(content, METHOD_EXPORT)) {
    const method = match.groups[0];
    if (method !== undefined) routes.push({ filePath, framework, routePath, methods: [method], line: match.line });
  }
  if (routes.length === 0) routes.push({ filePath, framework, routePath, methods: ['ANY'], line: 1 });
  return routes;
}

export function resolvesRouteRootByMethodExport(framework: ApiRouteFramework): boolean {
  return framework === 'nextjs_app' || framework === 'sveltekit';
}

export function svelteKitDeclarationRange(
  content: string,
  line: number,
): { start: number; end: number } | undefined {
  if (line < 1) return undefined;
  let offset = 0;
  for (let n = 1; n < line; n += 1) {
    const next = content.indexOf('\n', offset);
    if (next === -1) return undefined;
    offset = next + 1;
  }
  return loadBodyRange(content, offset);
}

export function isSvelteKitHooksFile(entry: FileMapEntry): boolean {
  if (!SVELTEKIT_HOOKS_FILE.test(entry.path)) return false;
  HANDLE_EXPORT.lastIndex = 0;
  return HANDLE_EXPORT.test(entry.content);
}

export const SVELTEKIT_IDENTITY =
  /(?<![\w$.])(?:event\s*\.\s*)?locals\s*(?:\?\.|\.)\s*(?:session|user|account|member|auth|claims|userId)\b/;

export const SVELTEKIT_BODY_SOURCE =
  /\b(?:event\s*\.\s*)?request\s*\.\s*(?:json|formData|text|arrayBuffer|blob)\s*\(\s*\)/;

export const SVELTEKIT_REQUEST_INPUT =
  /\b(?:event\s*\.\s*)?(?:url\s*\.\s*searchParams\s*\.\s*get\s*\(|params\s*[?.]\s*[A-Za-z_$]|request\s*\.\s*headers\s*\.\s*get\s*\()/;

export const SVELTEKIT_DENIAL = /\bthrow\s+(?:new\s+)?(?:error\s*\(\s*(?:401|403)\b|redirect\s*\()/;

export const SVELTEKIT_CONFIG_FILE = /(?:^|\/)svelte\.config\.(?:js|ts|mjs|cjs)$/;

export const SVELTEKIT_LIB_ALIAS = { prefix: '$lib/', target: 'src/lib/' } as const;

export const SVELTEKIT_IMPORT = /from\s+['"](?:@sveltejs\/kit|\$app\/[a-z]+|\$env\/(?:static|dynamic)\/[a-z]+)['"]/;

export const SVELTEKIT_PRIVATE_ENV_IMPORT =
  /import\s*(?:type\s+)?\{([^}]{0,500})\}\s*from\s*['"]\$env\/(?:static|dynamic)\/private['"]/g;

function importedBindings(clause: string): { imported: string; local: string }[] {
  const bindings: { imported: string; local: string }[] = [];
  for (const part of clause.split(',')) {
    const trimmed = part.trim();
    if (trimmed === '') continue;
    const aliased = /^([A-Za-z_$][\w$]*)\s+as\s+([A-Za-z_$][\w$]*)$/.exec(trimmed);
    if (aliased?.[1] !== undefined && aliased[2] !== undefined) {
      bindings.push({ imported: aliased[1], local: aliased[2] });
    } else if (/^[A-Za-z_$][\w$]*$/.test(trimmed)) {
      bindings.push({ imported: trimmed, local: trimmed });
    }
  }
  return bindings;
}

function loadBodyRange(content: string, index: number): { start: number; end: number } | undefined {
  let depth = 0;
  let start = -1;
  for (let i = index; i < content.length && i < index + 400; i += 1) {
    const ch = content[i];
    if (ch === '(') depth += 1;
    else if (ch === ')') depth -= 1;
    else if (ch === '{' && depth === 0) { start = i; break; }
    else if (ch === '{' && depth === 1 && content.slice(Math.max(0, i - 4), i).includes('=> (')) {
      start = i;
      break;
    }
  }
  if (start === -1) return undefined;
  let braces = 0;
  for (let i = start; i < content.length; i += 1) {
    if (content[i] === '{') braces += 1;
    else if (content[i] === '}') {
      braces -= 1;
      if (braces === 0) return { start, end: i + 1 };
    }
  }
  return undefined;
}

export function svelteKitLoadReturnedPrivateEnv(
  content: string,
  nameFilter: RegExp,
): { name: string; line: number }[] {
  const names: string[] = [];
  for (const match of findMatches(content, SVELTEKIT_PRIVATE_ENV_IMPORT)) {
    for (const binding of importedBindings(match.groups[0] ?? '')) {
      if (nameFilter.test(binding.imported) || nameFilter.test(binding.local)) names.push(binding.local);
    }
  }
  if (names.length === 0) return [];

  const found: { name: string; line: number }[] = [];
  for (const load of findMatches(content, LOAD_EXPORT)) {
    const body = loadBodyRange(content, load.index);
    if (body === undefined) continue;
    const source = content.slice(body.start, body.end);
    for (const name of names) {
      const inValue = new RegExp(`(?:[:,{]|^)\\s*${name}\\s*(?=[,}\\n]|$)`, 'm');
      const at = inValue.exec(source);
      if (at === null) continue;
      found.push({
        name,
        line: 1 + content.slice(0, body.start + at.index).split('\n').length - 1,
      });
    }
  }
  return found;
}
