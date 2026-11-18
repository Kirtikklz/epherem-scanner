import { isNextMiddlewareEntrypoint } from '../project-map/middlewareMatchers.js';
import {
  NEXT_LAYOUT_FILE,
  NEXT_PAGE_FILE,
  svelteKitRouteId,
  svelteKitRouteKind,
  SVELTEKIT_HOOKS_FILE,
  USE_SERVER_DIRECTIVE,
} from './frameworkModel.js';
import {
  blankNestedFunctions,
  classifyGuardBody,
  COUNTER_OVER_LIMIT,
  resolvesToRateLimit,
  resolvesToRejection,
  resolvesToRoleCheck,
} from './handlerGuardCall.js';
import {
  conditionals,
  FAILED_TEST,
  IDENTITY_SUBJECT,
  resolveMiddleware,
  ROLE_SUBJECT,
  stripComments,
} from './middlewareGuard.js';
import { stripCommentsOnly } from './source.js';
import { isStrongAdminText, resolvesToStrongAdminHelper } from './routeAuthorization.js';
import type { ApiRouteFramework, FileMapEntry, GuardLookup } from './types.js';
import { lineNumberAt } from './utils.js';

export type CascadeControl = 'auth' | 'admin' | 'rateLimit';

export type CascadeVia =
  | 'sveltekit_hook'
  | 'sveltekit_layout'
  | 'next_middleware'
  | 'next_layout'
  | 'express_use';

export interface CascadingGuard {
  control: CascadeControl;
  via: CascadeVia;
  filePath: string;
  line: number;
}

export type RouteRole = 'load' | 'action' | 'endpoint' | 'page' | 'unknown';

export interface CascadeQuery {
  filePath: string;
  routePath: string;
  line: number;
  framework: ApiRouteFramework;
  method?: string;
}

export function routeRole(query: CascadeQuery): RouteRole {
  if (query.framework === 'sveltekit') {
    const kind = svelteKitRouteKind(query.filePath);
    if (kind === undefined) return 'unknown';
    if (kind.kind === 'server') return 'endpoint';
    return (query.method ?? 'GET').toUpperCase() === 'GET' ? 'load' : 'action';
  }
  if (query.framework === 'nextjs_app' || query.framework === 'nextjs_pages') return 'endpoint';
  return 'unknown';
}

interface CascadeIndex {
  svelteLayouts: { dir: string; entry: FileMapEntry }[];
  svelteHooks: FileMapEntry[];
  nextLayouts: { dir: string; entry: FileMapEntry }[];
  nextMiddleware: FileMapEntry[];
  guards: Map<string, CascadeControl[]>;
}

const indexCache = new WeakMap<GuardLookup, CascadeIndex>();

const SVELTE_LAYOUT_FILE = /(?:^|\/)routes\/(.*?)\/?\+layout(?:\.server)?\.(?:ts|js|mts|mjs)$/;

function directoryOf(filePath: string): string {
  const cut = filePath.lastIndexOf('/');
  return cut === -1 ? '' : filePath.slice(0, cut);
}

function buildIndex(lookup: GuardLookup): CascadeIndex {
  const cached = indexCache.get(lookup);
  if (cached !== undefined) return cached;
  const index: CascadeIndex = {
    svelteLayouts: [],
    svelteHooks: [],
    nextLayouts: [],
    nextMiddleware: [],
    guards: new Map(),
  };
  for (const entry of lookup.fileMap.entries) {
    if (SVELTE_LAYOUT_FILE.test(entry.path)) index.svelteLayouts.push({ dir: directoryOf(entry.path), entry });
    if (SVELTEKIT_HOOKS_FILE.test(entry.path)) index.svelteHooks.push(entry);
    if (NEXT_LAYOUT_FILE.test(entry.path)) index.nextLayouts.push({ dir: directoryOf(entry.path), entry });
    if (isNextMiddlewareEntrypoint(entry.path)) index.nextMiddleware.push(entry);
  }
  indexCache.set(lookup, index);
  return index;
}

const EXPORTED_BINDING = (name: string): RegExp =>
  name === 'default'
    ? /export\s+default\s+(?:async\s+)?(?:function\b|\(|[A-Za-z_$][\w$]*\s*(?:=>|\())/
    : new RegExp(`export\\s+(?:async\\s+)?(?:const|let|var|function)\\s+${name}\\b`);
const TOP_LEVEL_BINDING = (name: string): RegExp =>
  new RegExp(`(?:^|\\n)\\s*(?:export\\s+)?(?:async\\s+)?(?:const|let|var|function)\\s+${name}\\b`);
const IDENTIFIER = /\b([A-Za-z_$][\w$]*)\b/g;
const MAX_DECLARATION_SCAN = 200_000;

function declarationBody(content: string, pattern: RegExp): { body: string; head: string } | undefined {
  if (content.length > MAX_DECLARATION_SCAN) return undefined;
  const scan = stripCommentsOnly(content);
  const match = pattern.exec(scan);
  if (match?.index === undefined) return undefined;
  const from = match.index;
  let depth = 0;
  for (let i = from; i < scan.length && i < from + 600; i += 1) {
    const ch = scan[i];
    if (ch === '(') depth += 1;
    else if (ch === ')') depth -= 1;
    else if (ch === ';' && depth === 0) return { body: '', head: content.slice(from, i) };
    else if (ch === '{' && depth === 0) {
      const close = balancedBlockEnd(scan, i);
      return close === undefined
        ? undefined
        : { body: content.slice(i + 1, close), head: content.slice(from, i) };
    }
  }
  return undefined;
}

export function guardBodies(content: string, exportName: string): string[] {
  const direct = declarationBody(content, EXPORTED_BINDING(exportName));
  if (direct === undefined) return [];
  if (direct.body !== '') return [direct.body];

  const bodies: string[] = [];
  IDENTIFIER.lastIndex = 0;
  const seen = new Set<string>([exportName]);
  for (let m = IDENTIFIER.exec(direct.head); m !== null; m = IDENTIFIER.exec(direct.head)) {
    const name = m[1];
    if (name === undefined || seen.has(name)) continue;
    seen.add(name);
    const referenced = declarationBody(content, TOP_LEVEL_BINDING(name));
    if (referenced !== undefined && referenced.body !== '') bodies.push(referenced.body);
  }
  return bodies;
}

function controlsProvenBy(lookup: GuardLookup, filePath: string, text: string): CascadeControl[] {
  const index = buildIndex(lookup);
  const key = `${filePath} ${text.length} ${text.slice(0, 400)}`;
  const memo = index.guards.get(key);
  if (memo !== undefined) return memo;

  const controls = new Set<CascadeControl>();
  const inline = classifyGuardBody(text);
  if (inline.blocks.role || isStrongAdminText(text)) controls.add('admin');
  if (inline.blocks.identity) controls.add('auth');
  if (inline.blocks.rate) controls.add('rateLimit');

  if (!controls.has('admin') && (resolvesToRoleCheck(lookup, filePath, text) ||
    resolvesToStrongAdminHelper(lookup, filePath, text))) controls.add('admin');
  if (!controls.has('auth') && resolvesToRejection(lookup, filePath, text)) controls.add('auth');
  if (!controls.has('rateLimit') && resolvesToRateLimit(lookup, filePath, text)) controls.add('rateLimit');

  if (controls.has('admin')) controls.add('auth');
  const out = [...controls];
  index.guards.set(key, out);
  return out;
}

const PATHNAME_LITERAL = /\bpathname\s*(?:\.\s*(?:startsWith|includes|match)\s*\(\s*|===?\s*)['"`]([^'"`]+)['"`]/g;

const ROUTE_ID_LITERAL =
  /\broute\s*(?:\?\.|\.)\s*id\s*(?:\.\s*(?:startsWith|includes|match)\s*\(\s*|===?\s*)['"`]([^'"`]+)['"`]/g;

const ROUTE_ID_EXPR = /\broute\s*(?:\?\.|\.)\s*id\b/;

const CONDITION_CALL = /\b([A-Za-z_$][\w$]*)\s*\(([^()]{0,200})\)/g;

const FIRST_PARAMETER = /^\s*(?:async\s+)?(?:function\s*[A-Za-z_$][\w$]*\s*)?\(?\s*([A-Za-z_$][\w$]*)/;

const namedSubjectLiteral = (name: string): RegExp =>
  new RegExp(
    `\\b${name}\\s*(?:\\.\\s*(?:startsWith|includes|match)\\s*\\(\\s*|===?\\s*)['"\`]([^'"\`]+)['"\`]`,
    'g',
  );
const ARRAY_PATH_LITERAL = /\[[^\]]{0,600}?\]/g;
const PATH_STRING = /['"`](\/[A-Za-z0-9_\-./[\]]{0,120})['"`]/g;

interface ScopePrefix {
  subject: 'pathname' | 'routeId';
  value: string;
}

interface GuardScope {
  prefixes: ScopePrefix[] | undefined;
  exempt: string[];
}

function literalsIn(text: string, pattern: RegExp): string[] {
  const out: string[] = [];
  pattern.lastIndex = 0;
  for (let match = pattern.exec(text); match !== null; match = pattern.exec(text)) {
    const literal = match[1];
    if (literal !== undefined && literal.startsWith('/')) out.push(literal);
  }
  return out;
}

const PATHNAME_TEST = /\bpathname\b/;
const DECLARATION_INITIALISER = (name: string): RegExp =>
  new RegExp(`(?:^|[\\n;{])\\s*(?:export\\s+)?(?:const|let|var)\\s+${name}\\s*(?::[^=\\n]{0,120})?=`);

function pathTestedPrefixes(
  condition: string,
  bodyText: string,
  moduleText: string,
): string[] | undefined {
  const collected: string[] = [];
  let found = false;
  const seen = new Set<string>();
  IDENTIFIER.lastIndex = 0;
  for (let m = IDENTIFIER.exec(condition); m !== null; m = IDENTIFIER.exec(condition)) {
    const name = m[1];
    if (name === undefined || seen.has(name)) continue;
    seen.add(name);
    const before = condition.slice(0, m.index).replace(/\s+$/, '');
    if (before.endsWith('!')) continue;
    for (const source of [bodyText, stripCommentsOnly(moduleText)]) {
      const at = DECLARATION_INITIALISER(name).exec(source);
      if (at?.index === undefined) continue;
      const from = at.index + at[0].length;
      const initialiser = source.slice(from, Math.min(source.length, from + MAX_INITIALISER_CHARS))
        .split(/;\s*\n/)[0] ?? '';
      if (!PATHNAME_TEST.test(initialiser)) break;
      found = true;
      collected.push(...literalsIn(initialiser, PATHNAME_LITERAL));
      break;
    }
  }
  return found ? collected : undefined;
}

const MAX_INITIALISER_CHARS = 1_200;

function routeIdTestedPrefixes(
  condition: string,
  bodyText: string,
  moduleText: string,
): string[] | undefined {
  const collected: string[] = [];
  let found = false;
  const seen = new Set<string>();
  CONDITION_CALL.lastIndex = 0;
  for (let m = CONDITION_CALL.exec(condition); m !== null; m = CONDITION_CALL.exec(condition)) {
    const name = m[1];
    const args = m[2] ?? '';
    if (name === undefined || seen.has(name)) continue;
    if (!ROUTE_ID_EXPR.test(args)) continue;
    seen.add(name);
    for (const source of [bodyText, stripCommentsOnly(moduleText)]) {
      const at = DECLARATION_INITIALISER(name).exec(source);
      if (at?.index === undefined) continue;
      const from = at.index + at[0].length;
      const initialiser = source.slice(from, Math.min(source.length, from + MAX_INITIALISER_CHARS))
        .split(/;\s*\n/)[0] ?? '';
      found = true;
      const parameter = FIRST_PARAMETER.exec(initialiser)?.[1];
      if (parameter !== undefined) {
        collected.push(...literalsIn(initialiser, namedSubjectLiteral(parameter)));
      }
      break;
    }
  }
  return found ? collected : undefined;
}

function pathScopeOf(
  condition: string,
  rawCondition: string,
  bodyText: string,
  moduleText: string,
): ScopePrefix[] | undefined {
  const direct = literalsIn(rawCondition, PATHNAME_LITERAL);
  if (direct.length > 0) return direct.map((value) => ({ subject: 'pathname' as const, value }));

  const directRouteId = literalsIn(rawCondition, ROUTE_ID_LITERAL);
  if (directRouteId.length > 0) {
    return directRouteId.map((value) => ({ subject: 'routeId' as const, value }));
  }

  const indirectPath = pathTestedPrefixes(condition, bodyText, moduleText);
  const indirectRouteId = routeIdTestedPrefixes(condition, bodyText, moduleText);
  if (indirectPath === undefined && indirectRouteId === undefined) return undefined;
  return [
    ...(indirectPath ?? []).map((value) => ({ subject: 'pathname' as const, value })),
    ...(indirectRouteId ?? []).map((value) => ({ subject: 'routeId' as const, value })),
  ];
}

function hookGuardScope(guardBodyText: string, moduleText: string): GuardScope {
  const code = blankNestedFunctions(stripComments(guardBodyText));
  const withStrings = stripCommentsOnly(guardBodyText);
  let prefixes: ScopePrefix[] | undefined = [];
  let sawPathTest = false;
  for (const item of conditionals(code)) {
    const identityGuard = (IDENTITY_SUBJECT.test(item.condition) || ROLE_SUBJECT.test(item.condition)) &&
      FAILED_TEST.test(item.condition);
    const guards = (identityGuard || COUNTER_OVER_LIMIT.test(item.condition)) &&
      HOOK_BLOCKS.test(item.consequent);
    if (!guards) continue;
    const raw = withStrings.slice(item.conditionIndex, item.conditionIndex + item.condition.length);
    const scoped = pathScopeOf(item.condition, raw, withStrings, moduleText);
    if (scoped === undefined) { prefixes = undefined; break; }
    sawPathTest = true;
    prefixes?.push(...scoped);
  }
  if (prefixes !== undefined && prefixes.length === 0 && !sawPathTest) {
    return { prefixes: undefined, exempt: [] };
  }

  const exemptSource = stripCommentsOnly(moduleText);
  const exempt: string[] = [];
  ARRAY_PATH_LITERAL.lastIndex = 0;
  for (let array = ARRAY_PATH_LITERAL.exec(exemptSource); array !== null;
    array = ARRAY_PATH_LITERAL.exec(exemptSource)) {
    exempt.push(...literalsIn(array[0], PATH_STRING));
  }
  return { prefixes, exempt };
}

const HOOK_BLOCKS = /\bthrow\b|\bredirect\s*\(|\berror\s*\(\s*(?:401|403)\b|\bstatus\s*:\s*(?:401|403)\b|\bnew\s+Response\s*\([^)]*40[13]/;

function underPrefix(routePath: string, prefix: string): boolean {
  const trimmed = prefix.replace(/\/$/, '');
  return routePath === trimmed || routePath === prefix || routePath.startsWith(trimmed + '/');
}

function prefixCovers(routePath: string, routeId: string | undefined, prefix: ScopePrefix): boolean {
  if (prefix.subject === 'pathname') return underPrefix(routePath, prefix.value);
  return routeId !== undefined && underPrefix(routeId, prefix.value);
}

function pathCovered(
  routePath: string,
  routeId: string | undefined,
  prefixes: ScopePrefix[] | undefined,
): boolean {
  if (prefixes === undefined) return true;
  return prefixes.some((prefix) => prefixCovers(routePath, routeId, prefix));
}

function scopeCovers(routePath: string, routeId: string | undefined, scope: GuardScope): boolean {
  if (!pathCovered(routePath, routeId, scope.prefixes)) return false;
  return !scope.exempt.some((prefix) => underPrefix(routePath, prefix));
}

function ancestorDirectories(dir: string): string[] {
  const segments = dir.split('/').filter((segment) => segment !== '');
  const out: string[] = [''];
  let running = '';
  for (const segment of segments) {
    running = running === '' ? segment : `${running}/${segment}`;
    out.push(running);
  }
  return out;
}

interface HookGuardRegion {
  text: string;
  clauses: ScopePrefix[][];
  exempt: string[];
}

function hookGuardRegions(guardBodyText: string, moduleText: string): HookGuardRegion[] {
  const code = blankNestedFunctions(stripComments(guardBodyText));
  const withStrings = stripCommentsOnly(guardBodyText);
  const all = conditionals(code);
  const regions: HookGuardRegion[] = [];

  for (const gate of all) {
    if (gate.depth === 0 && gate.consequent === '') continue;
    const chain = [gate, ...all.filter((outer) =>
      outer !== gate &&
      outer.consequentIndex <= gate.conditionIndex &&
      gate.conditionIndex < outer.consequentIndex + outer.consequent.length)];
    const clauses: ScopePrefix[][] = [];
    let readable = true;
    for (const link of chain) {
      const raw = withStrings.slice(link.conditionIndex, link.conditionIndex + link.condition.length);
      const scoped = pathScopeOf(link.condition, raw, withStrings, moduleText);
      if (scoped === undefined) { readable = false; break; }
      clauses.push(scoped);
    }
    if (!readable || clauses.every((clause) => clause.length === 0)) continue;
    regions.push({ text: gate.consequent, clauses, exempt: [] });
  }
  return regions;
}

export function cascadingGuardsForRoute(lookup: GuardLookup, query: CascadeQuery): CascadingGuard[] {
  const role = routeRole(query);
  const found: CascadingGuard[] = [];
  const index = buildIndex(lookup);

  if (query.framework === 'sveltekit') {
    const routeId = svelteKitRouteId(query.filePath);
    for (const hook of index.svelteHooks) {
      const bodies = guardBodies(hook.content, 'handle');
      if (bodies.length === 0) continue;
      if (scopeCovers(query.routePath, routeId, hookGuardScope(bodies.join('\n'), hook.content))) {
        for (const body of bodies) {
          for (const control of controlsProvenBy(lookup, hook.path, body)) {
            found.push({ control, via: 'sveltekit_hook', filePath: hook.path, line: 1 });
          }
        }
      }
      for (const body of bodies) {
        for (const region of hookGuardRegions(body, hook.content)) {
          if (!region.clauses.every((clause) =>
            scopeCovers(query.routePath, routeId, { prefixes: clause, exempt: region.exempt }))) continue;
          for (const control of controlsProvenBy(lookup, hook.path, region.text)) {
            found.push({ control, via: 'sveltekit_hook', filePath: hook.path, line: 1 });
          }
        }
      }
    }

    if (role === 'load') {
      const dirs = new Set(ancestorDirectories(directoryOf(query.filePath)));
      for (const layout of index.svelteLayouts) {
        if (layout.entry.path === query.filePath) continue;
        if (!dirs.has(layout.dir)) continue;
        for (const body of guardBodies(layout.entry.content, 'load')) {
          for (const control of controlsProvenBy(lookup, layout.entry.path, body)) {
            found.push({ control, via: 'sveltekit_layout', filePath: layout.entry.path, line: 1 });
          }
        }
      }
    }
    return found;
  }

  if (query.framework === 'nextjs_app' || query.framework === 'nextjs_pages') {
    for (const middleware of index.nextMiddleware) {
      const bodies = guardBodies(middleware.content, 'middleware');
      if (bodies.length === 0) bodies.push(...guardBodies(middleware.content, 'default'));
      if (!bodies.some((body) => controlsProvenBy(lookup, middleware.path, body).includes('admin'))) continue;
      if (!nextMiddlewareCovers(lookup, middleware.path, query.routePath)) continue;
      found.push({ control: 'admin', via: 'next_middleware', filePath: middleware.path, line: 1 });
      found.push({ control: 'auth', via: 'next_middleware', filePath: middleware.path, line: 1 });
    }
    return found;
  }

  return found;
}

export function cascadingGuardsForFile(lookup: GuardLookup, filePath: string): CascadingGuard[] {
  const index = buildIndex(lookup);
  const entry = lookup.fileMap.entries.find((candidate) => candidate.path === filePath);
  if (entry === undefined) return [];
  if (USE_SERVER_DIRECTIVE.test(entry.content)) return [];
  if (!NEXT_PAGE_FILE.test(filePath) && !NEXT_LAYOUT_FILE.test(filePath)) return [];

  const dirs = new Set(ancestorDirectories(directoryOf(filePath)));
  const found: CascadingGuard[] = [];
  for (const layout of index.nextLayouts) {
    if (layout.entry.path === filePath) continue;
    if (!dirs.has(layout.dir)) continue;
    if (USE_SERVER_DIRECTIVE.test(layout.entry.content)) continue;
    for (const body of guardBodies(layout.entry.content, 'default')) {
      for (const control of controlsProvenBy(lookup, layout.entry.path, body)) {
        found.push({ control, via: 'next_layout', filePath: layout.entry.path, line: 1 });
      }
    }
  }
  return found;
}

function nextMiddlewareCovers(lookup: GuardLookup, filePath: string, routePath: string): boolean {
  const { projectMap } = lookup;
  const coverage = (projectMap.middlewareCoverage ?? []).find((item) => item.filePath === filePath);
  const matchers = projectMap.middlewareMatchers.filter((matcher) => matcher.filePath === filePath);
  const test = (pattern: string): boolean => {
    try {
      return new RegExp(pattern).test(routePath);
    } catch {
      return false;
    }
  };
  const protectedPatterns = coverage?.protectedPatterns ?? [];
  if (protectedPatterns.length > 0) {
    if (!protectedPatterns.some(test)) return false;
  } else if (matchers.length > 0) {
    if (!matchers.some((matcher) => test(matcher.pattern))) return false;
  }
  return !(coverage?.exemptPatterns ?? []).some(test);
}

const APP_USE = /\bapp\s*\.\s*use\s*\(/g;

export function expressUseGuards(
  lookup: GuardLookup,
  filePath: string,
  routeLine: number,
  routePath: string,
): CascadingGuard[] {
  const entry = lookup.fileMap.entries.find((candidate) => candidate.path === filePath);
  if (entry === undefined) return [];
  const content = entry.content;
  const found: CascadingGuard[] = [];
  APP_USE.lastIndex = 0;
  for (let match = APP_USE.exec(content); match !== null; match = APP_USE.exec(content)) {
    const line = lineNumberAt(content, match.index);
    if (line >= routeLine) continue;
    const args = balancedArguments(content, match.index + match[0].length - 1);
    if (args === undefined) continue;
    const mountPrefix = /^\s*['"`]([^'"`]*)['"`]\s*,/.exec(args)?.[1];
    if (mountPrefix !== undefined &&
      !pathCovered(routePath, undefined, [{ subject: 'pathname', value: mountPrefix }])) continue;
    for (const token of identifierArguments(args)) {
      const resolved = resolveMiddleware(token, filePath, importBindings(lookup, filePath),
        (path) => lookup.fileMap.entries.find((candidate) => candidate.path === path)?.content);
      if (resolved === undefined) continue;
      if (resolved.effects.admin) found.push({ control: 'admin', via: 'express_use', filePath, line });
      if (resolved.effects.admin || resolved.effects.auth) {
        found.push({ control: 'auth', via: 'express_use', filePath, line });
      }
      if (resolved.effects.rateLimit) found.push({ control: 'rateLimit', via: 'express_use', filePath, line });
    }
    for (const control of controlsProvenBy(lookup, filePath, args)) {
      found.push({ control, via: 'express_use', filePath, line });
    }
  }
  return found;
}

function balancedBlockEnd(scan: string, open: number, max = 40_000): number | undefined {
  let depth = 0;
  let quote: string | undefined;
  let escaped = false;
  for (let i = open; i < scan.length && i < open + max; i += 1) {
    const ch = scan[i] ?? '';
    if (quote !== undefined) {
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === quote) quote = undefined;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; continue; }
    if (ch === '{') depth += 1;
    else if (ch === '}') {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return undefined;
}

function balancedBlock(content: string, open: number, max = 40_000): string | undefined {
  const close = balancedBlockEnd(stripCommentsOnly(content), open, max);
  return close === undefined ? undefined : content.slice(open + 1, close);
}

function identifierArguments(args: string): string[] {
  return [...args.matchAll(/(?:^|,)\s*([A-Za-z_$][\w$.]*)\s*(?=,|$)/g)]
    .map((match) => match[1])
    .filter((token): token is string => token !== undefined);
}

function importBindings(lookup: GuardLookup, filePath: string): Map<string, string> {
  const map = new Map<string, string>();
  const imports = lookup.projectMap.imports.find((entry) => entry.filePath === filePath);
  if (imports === undefined) return map;
  for (const ref of imports.imports) {
    if (ref.resolvedPath === undefined) continue;
    for (const binding of ref.bindings ?? []) map.set(binding, ref.resolvedPath);
  }
  return map;
}

function balancedArguments(content: string, open: number, max = 2_000): string | undefined {
  let depth = 0;
  let quote: string | undefined;
  let escaped = false;
  for (let i = open; i < content.length && i < open + max; i += 1) {
    const ch = content[i] ?? '';
    if (quote !== undefined) {
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === quote) quote = undefined;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; continue; }
    if (ch === '(' || ch === '[' || ch === '{') depth += 1;
    else if (ch === ')' || ch === ']' || ch === '}') {
      depth -= 1;
      if (depth === 0) return content.slice(open + 1, i);
    }
  }
  return undefined;
}

export function cascadingControlProven(
  lookup: GuardLookup,
  query: CascadeQuery,
  control: CascadeControl,
): boolean {
  if (cascadingGuardsForRoute(lookup, query).some((guard) => guard.control === control)) return true;
  return expressUseGuards(lookup, query.filePath, query.line, query.routePath)
    .some((guard) => guard.control === control);
}
