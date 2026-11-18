import { referencesUserInput } from './userInput.js';

export type TaintKind = 'user' | 'trusted' | 'unknown';


export interface Scope {
  readonly start: number;
  readonly end: number;
}

const CONTROL_HEAD = new Set(['if', 'for', 'while', 'switch', 'catch', 'with', 'do', 'await']);

const TYPE_CHAR = /[\w$.<>[\]|&,'"\s]/;

const LOOKBACK_LIMIT = 4000;
const TYPE_LOOKBACK_LIMIT = 200;

function skipBackWhitespace(masked: readonly string[], from: number): number {
  let index = from;
  while (index >= 0 && /\s/.test(masked[index] ?? '')) index -= 1;
  return index;
}

function matchingOpenParen(masked: readonly string[], closeIndex: number): number {
  let depth = 0;
  const floor = Math.max(0, closeIndex - LOOKBACK_LIMIT);
  for (let index = closeIndex; index >= floor; index -= 1) {
    const char = masked[index];
    if (char === ')') depth += 1;
    else if (char === '(') {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

function wordBefore(masked: readonly string[], openIndex: number): string {
  let index = skipBackWhitespace(masked, openIndex - 1);
  const end = index + 1;
  while (index >= 0 && /[\w$]/.test(masked[index] ?? '')) index -= 1;
  return masked.slice(index + 1, end).join('');
}

function opensFunctionBody(masked: readonly string[], braceIndex: number): boolean {
  let index = skipBackWhitespace(masked, braceIndex - 1);
  if (index < 0) return false;

  if (masked[index] === '>' && masked[index - 1] === '=') return true;

  if (masked[index] !== ')') {
    const floor = Math.max(0, index - TYPE_LOOKBACK_LIMIT);
    let scan = index;
    while (scan >= floor && TYPE_CHAR.test(masked[scan] ?? '')) scan -= 1;
    if (scan < 0 || masked[scan] !== ':') return false;
    index = skipBackWhitespace(masked, scan - 1);
    if (index < 0 || masked[index] !== ')') return false;
  }

  const open = matchingOpenParen(masked, index);
  if (open === -1) return false;
  return !CONTROL_HEAD.has(wordBefore(masked, open));
}

function scanFunctionScopes(content: string): Scope[] | undefined {
  const length = content.length;
  const masked = new Array<string>(length).fill(' ');
  const frames: Array<{ kind: 'brace'; start: number } | { kind: 'sub' }> = [];
  const scopes: Scope[] = [];
  const modes: Array<'code' | 'template'> = ['code'];
  let lastCode = '';
  let index = 0;

  const isRegexStart = (): boolean => {
    if (lastCode === '') return true;
    if ('(,=:[!&|?{};+-*%^~<>'.includes(lastCode)) return true;
    let scan = skipBackWhitespace(masked, index - 1);
    const end = scan + 1;
    while (scan >= 0 && /[\w$]/.test(masked[scan] ?? '')) scan -= 1;
    const word = masked.slice(scan + 1, end).join('');
    return /^(?:return|typeof|instanceof|in|of|new|delete|void|throw|case|do|else|yield|await)$/.test(word);
  };

  while (index < length) {
    const mode = modes[modes.length - 1];
    const char = content[index] ?? '';

    if (mode === 'template') {
      if (char === '\\') { index += 2; continue; }
      if (char === '`') { modes.pop(); index += 1; continue; }
      if (char === '$' && content[index + 1] === '{') {
        frames.push({ kind: 'sub' });
        modes.push('code');
        index += 2;
        continue;
      }
      if (char === '\n') masked[index] = '\n';
      index += 1;
      continue;
    }

    const next = content[index + 1];
    if (char === '/' && next === '/') {
      while (index < length && content[index] !== '\n') index += 1;
      continue;
    }
    if (char === '/' && next === '*') {
      index += 2;
      while (index < length && !(content[index] === '*' && content[index + 1] === '/')) {
        if (content[index] === '\n') masked[index] = '\n';
        index += 1;
      }
      index = Math.min(length, index + 2);
      continue;
    }
    if (char === '"' || char === "'") {
      const quote = char;
      index += 1;
      while (index < length) {
        if (content[index] === '\\') { index += 2; continue; }
        if (content[index] === quote) { index += 1; break; }
        if (content[index] === '\n') { masked[index] = '\n'; }
        index += 1;
      }
      lastCode = quote;
      continue;
    }
    if (char === '`') {
      modes.push('template');
      lastCode = '`';
      index += 1;
      continue;
    }
    if (char === '/' && isRegexStart()) {
      index += 1;
      let inClass = false;
      while (index < length) {
        const regexChar = content[index];
        if (regexChar === '\\') { index += 2; continue; }
        if (regexChar === '\n') break;
        if (regexChar === '[') inClass = true;
        else if (regexChar === ']') inClass = false;
        else if (regexChar === '/' && !inClass) { index += 1; break; }
        index += 1;
      }
      lastCode = '/';
      continue;
    }
    if (char === '{') {
      masked[index] = '{';
      frames.push({ kind: 'brace', start: index });
      lastCode = '{';
      index += 1;
      continue;
    }
    if (char === '}') {
      const frame = frames.pop();
      if (frame === undefined) return undefined;
      if (frame.kind === 'sub') {
        modes.pop();
        index += 1;
        continue;
      }
      masked[index] = '}';
      if (opensFunctionBody(masked, frame.start)) {
        scopes.push({ start: frame.start, end: index + 1 });
      }
      lastCode = '}';
      index += 1;
      continue;
    }
    masked[index] = char;
    if (!/\s/.test(char)) lastCode = char;
    index += 1;
  }

  if (frames.length > 0) return undefined;
  return scopes;
}

function innermostScope(scopes: readonly Scope[], at: number): Scope | undefined {
  let low = 0;
  let high = scopes.length - 1;
  let candidate = -1;
  while (low <= high) {
    const mid = (low + high) >> 1;
    const scope = scopes[mid];
    if (scope !== undefined && scope.start <= at) {
      candidate = mid;
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }
  for (let index = candidate; index >= 0; index -= 1) {
    const scope = scopes[index];
    if (scope !== undefined && at < scope.end) return scope;
  }
  return undefined;
}

interface Binding {
  readonly kind: TaintKind;
  readonly scope: Scope;
  readonly at: number;
}

export class TaintMap {
  private readonly byName = new Map<string, Binding[]>();

  add(name: string, kind: TaintKind, scope: Scope, at: number): void {
    const list = this.byName.get(name);
    if (list === undefined) this.byName.set(name, [{ kind, scope, at }]);
    else list.push({ kind, scope, at });
  }

  kindAt(name: string, at?: number): TaintKind | undefined {
    const list = this.byName.get(name);
    if (list === undefined || list.length === 0) return undefined;
    if (at === undefined) return list[list.length - 1]?.kind;
    let best: Binding | undefined;
    for (const binding of list) {
      if (at < binding.scope.start || at >= binding.scope.end) continue;
      if (best === undefined) { best = binding; continue; }
      if (binding.scope.start > best.scope.start) best = binding;
      else if (binding.scope.start === best.scope.start && binding.at >= best.at) best = binding;
    }
    return best?.kind;
  }

  get(name: string): TaintKind | undefined {
    return this.kindAt(name, undefined);
  }

  userNamesAt(at?: number): string[] {
    const names: string[] = [];
    for (const name of this.byName.keys()) {
      if (this.kindAt(name, at) === 'user') names.push(name);
    }
    return names;
  }

  get size(): number {
    return this.byName.size;
  }
}


const TRUSTED_SOURCE =
  /\bsession\s*[?.]|\breq\.session\b|\brequest\.session\b|\bres\.locals\.user\b|\blocals\.user\b|\bctx\.state\.user\b|\bgetServerSession\s*\(\s*\)|\bgetSession\s*\(\s*\)|\bgetUser\s*\(\s*\)|\bcurrentUser\b|\bauth\s*\(\s*\)|\bverifyIdToken\s*\(|\bjwt\.verify\s*\(|\bverifyToken\s*\(|\bdecodedToken\b|\bverifiedUser\b/;

const CLIENT_IDENTITY_SOURCE =
  /\buse(?:Auth|User|Session|AuthContext|CurrentUser|SupabaseAuth|Clerk)\w*\s*\(|\bauth\s*\.\s*(?:getUser|getSession|currentUser)\b|\bsupabase\s*\.\s*auth\s*\.\s*(?:getUser|getSession)\s*\(|\bgetAuth\s*\(\s*\)\s*\.\s*currentUser\b|\buseAuthenticatedUser\s*\(/;

const SESSION_IDENTITY_SOURCE =
  /\bgetAuth\s*\(\s*_?req(?:uest)?\s*(?:as\s+[\w.<>[\]]+\s*)?\)/;

function stripAwait(expr: string): string {
  return expr.trim().replace(/^await\s+/, '');
}

export function classifyExpression(
  expr: string,
  map: TaintMap = new TaintMap(),
  at?: number,
): TaintKind {
  const e = stripAwait(expr);

  const leading = /^([A-Za-z_$][\w$]*)/.exec(e);
  const bound = leading?.[1] === undefined ? undefined : map.kindAt(leading[1], at);
  if (leading !== null && leading[1] !== undefined && bound !== undefined) {
    const accessor = e.slice(leading[1].length);
    if (accessor === '' || /^\s*[?.[]/.test(accessor)) {
      const base = bound;
      const isCall = accessor.includes('(');
      if (!isCall || base === 'user') return base;
    }
  }

  const user = referencesUserInput(e);
  const trusted =
    TRUSTED_SOURCE.test(e) || CLIENT_IDENTITY_SOURCE.test(e) || SESSION_IDENTITY_SOURCE.test(e);
  if (trusted && !user) return 'trusted';
  if (user) return 'user';
  if (trusted) return 'trusted';
  return 'unknown';
}

const DECLARATION =
  /\b(?:const|let|var)\s+(\{(?:[^{}=]|\{[^{}=]*\})*\}|\[[^\]=]*\]|[A-Za-z_$][\w$]*)\s*=\s*([^\n;]+)/g;

function splitTopLevel(inner: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let start = 0;
  for (let index = 0; index < inner.length; index += 1) {
    const char = inner[index];
    if (char === '{' || char === '[') depth += 1;
    else if (char === '}' || char === ']') depth -= 1;
    else if (char === ',' && depth === 0) {
      parts.push(inner.slice(start, index));
      start = index + 1;
    }
  }
  parts.push(inner.slice(start));
  return parts;
}

function destructuredNames(target: string): string[] {
  const inner = target.slice(1, -1);
  const names: string[] = [];
  for (const rawPart of splitTopLevel(inner)) {
    const part = rawPart.trim();
    if (part === '' || part.startsWith('...')) continue;
    const nested = /^[A-Za-z_$][\w$]*\s*:\s*([{[][\s\S]*[}\]])$/.exec(part);
    if (nested !== null && nested[1] !== undefined) {
      names.push(...destructuredNames(nested[1]));
      continue;
    }
    const aliased = /^[A-Za-z_$][\w$]*\s*:\s*([A-Za-z_$][\w$]*)/.exec(part);
    if (aliased !== null && aliased[1] !== undefined) {
      names.push(aliased[1]);
      continue;
    }
    const bare = /^([A-Za-z_$][\w$]*)/.exec(part);
    if (bare !== null && bare[1] !== undefined) names.push(bare[1]);
  }
  return names;
}

export function analyzeTaint(content: string): TaintMap {
  const map = new TaintMap();
  const fileScope: Scope = { start: 0, end: content.length };
  const functionScopes = (scanFunctionScopes(content) ?? []).sort((a, b) => a.start - b.start);

  DECLARATION.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = DECLARATION.exec(content)) !== null) {
    const target = match[1];
    const expr = match[2];
    if (target === undefined || expr === undefined) continue;
    const at = match.index;
    const scope = innermostScope(functionScopes, at) ?? fileScope;
    const kind = classifyExpression(expr, map, at);
    if (target.startsWith('{') || target.startsWith('[')) {
      for (const name of destructuredNames(target)) map.add(name, kind, scope, at);
    } else {
      map.add(target, kind, scope, at);
    }
  }
  return map;
}

export function isUserControlled(expr: string, map: TaintMap, at?: number): boolean {
  return classifyExpression(expr, map, at) === 'user';
}

export function isTrustedIdentity(expr: string, map: TaintMap, at?: number): boolean {
  return classifyExpression(expr, map, at) === 'trusted';
}

export function usesUserInput(text: string, map: TaintMap, at?: number): boolean {
  if (referencesUserInput(text)) return true;
  for (const name of map.userNamesAt(at)) {
    const re = new RegExp(`\\b${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`);
    if (re.test(text)) return true;
  }
  return false;
}
