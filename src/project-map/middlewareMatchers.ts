import type { FileMapEntry, MiddlewareCoverage, MiddlewareMatcher, ProjectMap } from '../shared/types.js';

const CONFIG_MATCHER_KEY = /export\s+const\s+config\s*=\s*\{[\s\S]{0,500}?matcher\s*:\s*/;
const STRING_LITERAL = /['"`]([^'"`]+)['"`]/g;

const MIDDLEWARE_ENTRYPOINT_BASENAME = /^(?:middleware|proxy)\.(?:ts|tsx|js|jsx|mjs|cjs)$/;

export function isNextMiddlewareEntrypoint(filePath: string): boolean {
  const segments = filePath.split('/').filter((segment) => segment !== '');
  const base = segments[segments.length - 1];
  if (base === undefined || !MIDDLEWARE_ENTRYPOINT_BASENAME.test(base)) return false;
  const parent = segments[segments.length - 2];
  return parent === undefined || parent === 'src';
}

export function extractMiddlewareMatchers(entry: FileMapEntry): MiddlewareMatcher[] {
  if (!entry.isLikelyMiddleware) return [];
  const key = CONFIG_MATCHER_KEY.exec(entry.content);
  if (key === null) return [];
  const value = readValueLiteral(entry.content, key.index + key[0].length);
  if (value === undefined) return [];
  return stringLiteralsIn(value).map((source) => ({
    filePath: entry.path,
    source,
    pattern: compileMatcherPattern(source),
  }));
}

function readValueLiteral(content: string, from: number): string | undefined {
  let index = from;
  while (index < content.length && /\s/.test(content[index] ?? '')) index += 1;
  const opener = content[index];
  if (opener === undefined) return undefined;
  if (opener === "'" || opener === '"' || opener === '`') {
    const end = content.indexOf(opener, index + 1);
    return end === -1 ? undefined : content.slice(index, end + 1);
  }
  if (opener !== '[') return undefined;
  let depth = 0;
  let quote: string | undefined;
  for (let cursor = index; cursor < content.length; cursor += 1) {
    const char = content[cursor] ?? '';
    if (quote !== undefined) {
      if (char === '\\') { cursor += 1; continue; }
      if (char === quote) quote = undefined;
      continue;
    }
    if (char === "'" || char === '"' || char === '`') { quote = char; continue; }
    if (char === '[') depth += 1;
    if (char === ']') {
      depth -= 1;
      if (depth === 0) return content.slice(index, cursor + 1);
    }
  }
  return undefined;
}

function stringLiteralsIn(literal: string): string[] {
  const out: string[] = [];
  STRING_LITERAL.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = STRING_LITERAL.exec(literal)) !== null) {
    if (match[1] !== undefined) out.push(match[1]);
  }
  return out;
}

export function extractMiddlewareCoverage(entry: FileMapEntry): MiddlewareCoverage | undefined {
  if (!entry.isLikelyMiddleware) return undefined;
  const content = entry.content;
  const exemptPatterns: string[] = [];
  for (const listName of ['publicRoutes', 'ignoredRoutes']) {
    const key = new RegExp(`\\b${listName}\\s*:\\s*`).exec(content);
    if (key === null) continue;
    const value = readValueLiteral(content, key.index + key[0].length);
    if (value === undefined) continue;
    for (const source of stringLiteralsIn(value)) exemptPatterns.push(compileMatcherPattern(source));
  }

  for (const source of codeLevelExemptPaths(content)) {
    exemptPatterns.push(compileMatcherPattern(source));
  }

  const protectedPatterns: string[] = [];
  if (/\bclerkMiddleware\s*\(/.test(content) && /\.\s*protect\s*\(/.test(content)) {
    const key = /\bcreateRouteMatcher\s*\(\s*/.exec(content);
    if (key !== null) {
      const value = readValueLiteral(content, key.index + key[0].length);
      if (value !== undefined) {
        for (const source of stringLiteralsIn(value)) protectedPatterns.push(compileMatcherPattern(source));
      }
    }
  }

  return {
    filePath: entry.path,
    entrypoint: isNextMiddlewareEntrypoint(entry.path),
    exemptPatterns: [...new Set(exemptPatterns)].sort(),
    protectedPatterns: [...new Set(protectedPatterns)].sort(),
  };
}

const PASS_THROUGH_RETURN = /\breturn\s+(?:NextResponse|Response)\s*\.\s*next\s*\(\s*\)/;
const PATHNAME_PREFIX_TEST = /\bpathname\s*\.\s*startsWith\s*\(\s*['"`]([^'"`]+)['"`]/g;
const PATHNAME_EQUALS_TEST = /\bpathname\s*===?\s*['"`]([^'"`]+)['"`]/g;
const EXEMPT_LOOKBACK_LINES = 3;

function codeLevelExemptPaths(content: string): string[] {
  const lines = content.split('\n');
  const found: string[] = [];
  for (let index = 0; index < lines.length; index += 1) {
    if (!PASS_THROUGH_RETURN.test(lines[index] ?? '')) continue;
    const window = lines.slice(Math.max(0, index - EXEMPT_LOOKBACK_LINES), index + 1).join('\n');
    for (const [pattern, suffix] of [[PATHNAME_PREFIX_TEST, '/(.*)'], [PATHNAME_EQUALS_TEST, '']] as [RegExp, string][]) {
      pattern.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = pattern.exec(window)) !== null) {
        const literal = match[1];
        if (literal === undefined || !literal.startsWith('/')) continue;
        found.push(literal);
        if (suffix !== '') found.push(`${literal.replace(/\/$/, '')}${suffix}`);
      }
    }
  }
  return found;
}

export function compileMatcherPattern(source: string): string {
  let pattern = '';
  let index = 0;
  while (index < source.length) {
    const char = source[index] ?? '';
    if (char === ':') {
      let end = index + 1;
      while (end < source.length && /[A-Za-z0-9_]/.test(source[end] ?? '')) end += 1;
      const modifier = source[end];
      if (modifier === '*') {
        pattern = pattern.replace(/\/$/, '');
        pattern += '(?:/[^?]*)?';
        index = end + 1;
      } else if (modifier === '+') {
        pattern += '[^/]+(?:/[^?]*)?';
        index = end + 1;
      } else {
        pattern += '[^/]+';
        index = end;
      }
      continue;
    }
    if (char === '(' ) {
      let depth = 0;
      let end = index;
      do {
        const current = source[end] ?? '';
        if (current === '(') depth += 1;
        if (current === ')') depth -= 1;
        end += 1;
      } while (end < source.length && depth > 0);
      pattern += source.slice(index, end);
      index = end;
      continue;
    }
    pattern += /[.*+?^${}|[\]\\]/.test(char) ? `\\${char}` : char;
    index += 1;
  }
  return `^${pattern}$`;
}

export function isRouteCoveredByMiddleware(projectMap: ProjectMap, routePath: string): boolean {
  if (projectMap.middlewareFiles.length === 0) return false;
  if (projectMap.middlewareMatchers.length === 0) return true;
  return projectMap.middlewareMatchers.some((matcher) => {
    try {
      return new RegExp(matcher.pattern).test(routePath);
    } catch {
      return false;
    }
  });
}

export function middlewareFilesWithAuthGuard(projectMap: ProjectMap): Set<string> {
  const middlewareFiles = new Set(projectMap.middlewareFiles);
  const guarded = new Set<string>();
  for (const signal of projectMap.authSignals) {
    if (!signal.protective || !signal.checked) continue;
    if (middlewareFiles.has(signal.filePath)) guarded.add(signal.filePath);
  }
  return guarded;
}

export function isRouteProtectedByMiddleware(projectMap: ProjectMap, routePath: string): boolean {
  const guardedFiles = middlewareFilesWithAuthGuard(projectMap);
  if (guardedFiles.size === 0) return false;

  const coverage = new Map((projectMap.middlewareCoverage ?? []).map((item) => [item.filePath, item]));
  const hasEntrypoint = (projectMap.middlewareCoverage ?? []).some((item) => item.entrypoint);

  for (const filePath of guardedFiles) {
    const info = coverage.get(filePath);
    const isEntrypoint = info?.entrypoint === true;
    if (hasEntrypoint && !isEntrypoint) continue;

    const protectedPatterns = info?.protectedPatterns ?? [];
    const matchers = projectMap.middlewareMatchers.filter((matcher) => matcher.filePath === filePath);
    if (protectedPatterns.length > 0) {
      if (!protectedPatterns.some((pattern) => matches(pattern, routePath))) continue;
    } else if (matchers.length > 0) {
      if (!matchers.some((matcher) => matches(matcher.pattern, routePath))) continue;
    } else if (!isEntrypoint) {
      continue;
    }

    if ((info?.exemptPatterns ?? []).some((pattern) => matches(pattern, routePath))) continue;
    return true;
  }
  return false;
}

function matches(pattern: string, routePath: string): boolean {
  try {
    return new RegExp(pattern).test(routePath);
  } catch {
    return false;
  }
}

export function deriveFrontendRoute(filePath: string): string | undefined {
  const appMatch = /(^|\/)app\/(.*?)(?:\/)?(page|layout)\.(tsx|jsx|ts|js)$/.exec(filePath);
  if (appMatch !== null) {
    const segments = (appMatch[2] ?? '')
      .split('/')
      .filter((segment) => segment !== '' && !/^\(.*\)$/.test(segment));
    return `/${segments.join('/')}`;
  }
  const pagesMatch = /(^|\/)pages\/(.+)\.(tsx|jsx|ts|js)$/.exec(filePath);
  if (pagesMatch !== null && !(pagesMatch[2] ?? '').startsWith('api/')) {
    const route = (pagesMatch[2] ?? '').replace(/\/index$/, '').replace(/^index$/, '');
    return `/${route}`;
  }
  return undefined;
}
