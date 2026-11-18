import { enclosingFunctionScopeRange } from './handlerScope.js';
import { parseBuilderEq, parseEqChain, parseObjectFilter, type FilterPair } from './ownership.js';
import { analyzeTaint } from './taint.js';
import type { FileMap, FileMapEntry, ProjectMap, RuleContext } from './types.js';

export interface ResolutionContext {
  readonly fileMap: FileMap;
  readonly projectMap: Pick<ProjectMap, 'imports'>;
}

const TERMINAL_VERIFICATION =
  /\bjwtVerify\s*\(|\bcompactVerify\s*\(|\bjwtDecrypt\s*\(|\bcreateRemoteJWKSet\s*\(|\bjwt\s*\.\s*verify\s*\(|\bverifyIdToken\s*\(|\bverifySessionCookie\s*\(|\bgetServerSession\s*\(|\bauth\s*\(\s*\)|\bgetAuth\s*\(\s*_?req(?:uest)?\b|\.\s*auth\s*\.\s*getUser\s*\(|\bgetIronSession\s*\(|\bunsealData\s*\(|\.\s*isAuthenticated\s*\(|\bpassport\s*\.\s*authenticate\s*\(/;

const MAX_RESOLUTION_DEPTH = 4;
const MAX_BODY = 8_000;

const verifierCache = new WeakMap<RuleContext, Map<string, boolean>>();

function cacheFor(context: RuleContext): Map<string, boolean> {
  let cache = verifierCache.get(context);
  if (cache === undefined) {
    cache = new Map();
    verifierCache.set(context, cache);
  }
  return cache;
}

export function entryFor(context: ResolutionContext, filePath: string): FileMapEntry | undefined {
  return context.fileMap.entries.find((candidate) => candidate.path === filePath);
}

function blockFrom(content: string, fromIndex: number): string | undefined {
  const open = content.indexOf('{', fromIndex);
  if (open === -1) return undefined;
  let depth = 0;
  for (let i = open; i < content.length && i < open + MAX_BODY; i += 1) {
    const ch = content[i];
    if (ch === '{') depth += 1;
    else if (ch === '}') {
      depth -= 1;
      if (depth === 0) return content.slice(open, i + 1);
    }
  }
  return undefined;
}

export function namedFunctionBody(content: string, name: string): string | undefined {
  const n = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const patterns = [
    new RegExp(`(?:export\\s+)?(?:default\\s+)?(?:async\\s+)?function\\s+${n}\\s*\\(`),
    new RegExp(
      `(?:export\\s+)?(?:const|let|var)\\s+${n}\\s*(?::[^=\\n]{0,160})?=\\s*(?:async\\s+)?function\\b`,
    ),
    new RegExp(
      `(?:export\\s+)?(?:const|let|var)\\s+${n}\\s*(?::[^=\\n]{0,160})?=\\s*(?:async\\s*)?` +
        `(?:\\([^)]*\\)|[A-Za-z_$][\\w$]*)\\s*(?::[^=>\\n]{0,160})?=>`,
    ),
  ];
  for (const pattern of patterns) {
    const match = pattern.exec(content);
    if (match?.index === undefined) continue;
    const body = blockFrom(content, match.index + match[0].length);
    if (body !== undefined) return body;
  }
  return undefined;
}

export function importedFrom(context: ResolutionContext, filePath: string, name: string): string | undefined {
  const fileImports = context.projectMap.imports.find((item) => item.filePath === filePath);
  if (fileImports === undefined) return undefined;
  for (const ref of fileImports.imports) {
    if (ref.resolvedPath === undefined) continue;
    if (ref.bindings?.includes(name) === true) return ref.resolvedPath;
  }
  const reExport = new RegExp(
    `export\\s*\\{[^}]*\\b${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b[^}]*\\}\\s*from\\s*['"]([^'"]+)['"]`,
  );
  const entry = entryFor(context, filePath);
  const source = entry === undefined ? null : reExport.exec(entry.content);
  if (source?.[1] === undefined) return undefined;
  return fileImports.imports.find((ref) => ref.source === source[1])?.resolvedPath;
}

export function resolvesToVerification(
  context: RuleContext,
  filePath: string,
  name: string,
  requireImported = true,
  depth = 0,
  visited: Set<string> = new Set(),
): boolean {
  if (depth > MAX_RESOLUTION_DEPTH) return false;
  const key = `${filePath}::${name}`;
  if (visited.has(key)) return false;
  visited.add(key);
  const cache = cacheFor(context);
  const cached = cache.get(key);
  if (cached !== undefined) return cached;

  const definedIn = importedFrom(context, filePath, name);
  const searchPaths = requireImported
    ? definedIn === undefined
      ? []
      : [definedIn]
    : [...(definedIn === undefined ? [] : [definedIn]), filePath];

  let verified = false;
  for (const path of searchPaths) {
    const entry = entryFor(context, path);
    if (entry === undefined) continue;
    const body = namedFunctionBody(entry.content, name);
    if (body === undefined) {
      const onward = path === filePath ? undefined : importedFrom(context, path, name);
      if (onward !== undefined && resolvesToVerification(context, path, name, true, depth + 1, visited)) {
        verified = true;
        break;
      }
      continue;
    }
    if (verificationOnReturnPath(context, path, body, depth, visited)) {
      verified = true;
      break;
    }
  }

  cache.set(key, verified);
  return verified;
}

function verificationOnReturnPath(
  context: RuleContext,
  path: string,
  body: string,
  depth: number,
  visited: Set<string>,
): boolean {
  const returned: string[] = [];
  for (const match of body.matchAll(/\breturn\s+([^;\n]{1,300})/g)) {
    const expr = match[1];
    if (expr !== undefined) returned.push(expr.trim());
  }
  if (returned.length === 0) return false;

  const isVerifyingExpression = (expr: string): boolean => {
    if (TERMINAL_VERIFICATION.test(expr)) return true;
    const call = /^(?:await\s+)?([A-Za-z_$][\w$]*)\s*\(/.exec(expr.trim());
    if (call?.[1] === undefined) return false;
    return resolvesToVerification(context, path, call[1], false, depth + 1, visited);
  };

  const verifiedLocals = new Set<string>();
  for (const match of body.matchAll(
    /\b(?:const|let|var)\s+(\{[^{}=]*\}|[A-Za-z_$][\w$]*)\s*(?::[^=\n]{0,160})?=\s*([^\n;]{1,300})/g,
  )) {
    const target = match[1];
    const init = match[2];
    if (target === undefined || init === undefined) continue;
    if (!isVerifyingExpression(init)) continue;
    for (const name of boundNames(target)) verifiedLocals.add(name);
  }

  return returned.some((expr) => {
    if (isVerifyingExpression(expr)) return true;
    const lead = /^([A-Za-z_$][\w$]*)/.exec(expr);
    return lead?.[1] !== undefined && verifiedLocals.has(lead[1]);
  });
}

export function earlyExitOnFalsy(scope: string, name: string): boolean {
  const n = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(
    `if\\s*\\([^;{]{0,240}?(?:!\\s*${n}(?![\\w$.?[])|\\b${n}\\s*===?\\s*(?:null|undefined)\\b)` +
      `[^;{]{0,240}?\\)\\s*(?:\\{[^}]{0,240}?)?\\b(?:return|throw|redirect|notFound|unauthorized|forbidden)\\b`,
  ).test(scope);
}

const GUARD_BINDING =
  /\b(?:const|let|var)\s+(\{[^{}=]*\}|[A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?([A-Za-z_$][\w$]*)\s*\(/g;

const ALIAS_BINDING =
  /\b(?:const|let|var)\s+(\{[^{}=]*\}|[A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)((?:\s*[?.]\s*[A-Za-z_$][\w$]*)*)\s*[;\n]/g;

function boundNames(target: string): string[] {
  const trimmed = target.trim();
  if (!trimmed.startsWith('{')) return [trimmed];
  const names: string[] = [];
  for (const part of trimmed.slice(1, -1).split(',')) {
    const token = part.trim();
    if (token === '') continue;
    const renamed = /^[A-Za-z_$][\w$]*\s*:\s*([A-Za-z_$][\w$]*)$/.exec(token);
    const plain = /^([A-Za-z_$][\w$]*)$/.exec(token);
    const name = renamed?.[1] ?? plain?.[1];
    if (name !== undefined && !names.includes(name)) names.push(name);
  }
  return names;
}

export function verifiedSessionIdentities(
  context: RuleContext,
  filePath: string,
  scope: string,
): Set<string> {
  const identities = new Set<string>();
  GUARD_BINDING.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = GUARD_BINDING.exec(scope)) !== null) {
    const target = match[1];
    const helper = match[2];
    if (target === undefined || helper === undefined) continue;
    const names = boundNames(target);
    if (names.length === 0) continue;
    if (!names.some((name) => earlyExitOnFalsy(scope, name))) continue;
    if (!resolvesToVerification(context, filePath, helper)) continue;
    for (const name of names) identities.add(name);
  }
  if (identities.size === 0) return identities;

  for (let pass = 0; pass < 3; pass += 1) {
    const before = identities.size;
    ALIAS_BINDING.lastIndex = 0;
    while ((match = ALIAS_BINDING.exec(scope)) !== null) {
      const target = match[1];
      const base = match[2];
      if (target === undefined || base === undefined) continue;
      if (!identities.has(base)) continue;
      for (const name of boundNames(target)) identities.add(name);
    }
    if (identities.size === before) break;
  }

  const taint = analyzeTaint(scope);
  for (const name of [...identities]) {
    if (taint.get(name) === 'user') identities.delete(name);
  }
  return identities;
}

export function verifiedSessionIdentitiesAt(
  context: RuleContext,
  filePath: string,
  content: string,
  offset: number,
): Set<string> {
  const { start, end } = enclosingFunctionScopeRange(content, offset);
  return verifiedSessionIdentities(context, filePath, content.slice(start, end));
}

function filterRegions(text: string): string[] {
  const regions: string[] = [];
  for (const match of text.matchAll(/\bwhere\s*:/g)) {
    const region = blockFrom(text, match.index + match[0].length);
    if (region !== undefined) regions.push(region);
  }
  for (const match of text.matchAll(/\.\s*(?:where|eq|match|filter)\s*\(/g)) {
    const region = parenFrom(text, match.index + match[0].length - 1);
    if (region !== undefined) regions.push(`${match[0]}${region.slice(1)}`);
  }
  return regions;
}

function parenFrom(text: string, openIndex: number): string | undefined {
  let depth = 0;
  for (let i = openIndex; i < text.length && i < openIndex + 1_200; i += 1) {
    const ch = text[i];
    if (ch === '(') depth += 1;
    else if (ch === ')') {
      depth -= 1;
      if (depth === 0) return text.slice(openIndex, i + 1);
    }
  }
  return undefined;
}

function pairsOf(region: string): FilterPair[] {
  return [...parseObjectFilter(region), ...parseEqChain(region), ...parseBuilderEq(region)];
}

function bindsIdentity(pairs: readonly FilterPair[], identities: ReadonlySet<string>): boolean {
  return pairs.some((pair) => {
    const lead = /^([A-Za-z_$][\w$]*)/.exec(pair.value.trim().replace(/^await\s+/, ''));
    return lead?.[1] !== undefined && identities.has(lead[1]);
  });
}

export function selectionBoundToIdentity(
  text: string,
  identities: ReadonlySet<string>,
  fallbackToWholeText = false,
): boolean {
  if (identities.size === 0) return false;
  const regions = filterRegions(text);
  if (regions.length === 0) {
    return fallbackToWholeText ? bindsIdentity(pairsOf(text), identities) : false;
  }
  return regions.some((region) => bindsIdentity(pairsOf(region), identities));
}

export function statementFrom(text: string, index: number, max = 2_000): string {
  let depth = 0;
  let quote: string | undefined;
  let escaped = false;
  for (let i = index; i < text.length && i < index + max; i += 1) {
    const ch = text[i] ?? '';
    if (quote !== undefined) {
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === quote) quote = undefined;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; continue; }
    if (ch === '(' || ch === '{' || ch === '[') depth += 1;
    else if (ch === ')' || ch === '}' || ch === ']') {
      depth -= 1;
      if (depth < 0) return text.slice(index, i);
    } else if (ch === ';' && depth === 0) return text.slice(index, i);
  }
  return text.slice(index, Math.min(text.length, index + max));
}
