import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash } from 'node:crypto';
import { MAX_MATCHES_PER_FIND, PUBLIC_ENV_PREFIXES } from './constants.js';

export function toPosixPath(value: string): string {
  return value.split('\\').join('/');
}

export function sha1Hex(value: string): string {
  return createHash('sha1').update(value).digest('hex');
}

// Includes the evidence, so two findings on one line never collapse.
export function buildFindingId(
  ruleId: string,
  filePath: string,
  lineStart: number,
  evidence: string,
): string {
  return `f_${sha1Hex(`${ruleId}:${filePath}:${lineStart}:${evidence}`).slice(0, 12)}`;
}

export interface LineIndex {
  content: string;
  offsets: number[];
}

const lineIndexStore = new AsyncLocalStorage<Map<string, LineIndex>>();

export function runWithLineIndexCache<T>(fn: () => T): T {
  return lineIndexStore.run(new Map<string, LineIndex>(), fn);
}

export function runWithLineIndexCacheAsync<T>(fn: () => Promise<T>): Promise<T> {
  return lineIndexStore.run(new Map<string, LineIndex>(), fn);
}

// Caps regex matches examined per scan, separate from the findings cap.
export interface MatchBudget {
  remaining: number;
  truncated: boolean;
}

const matchBudgetStore = new AsyncLocalStorage<MatchBudget>();

export function runWithMatchBudget<T>(budget: MatchBudget, fn: () => T): T {
  return matchBudgetStore.run(budget, fn);
}

export function currentMatchBudget(): MatchBudget | undefined {
  return matchBudgetStore.getStore();
}

function computeLineIndex(content: string): LineIndex {
  const offsets = [0];
  for (let i = 0; i < content.length; i += 1) {
    if (content.charCodeAt(i) === 10) offsets.push(i + 1);
  }
  return { content, offsets };
}

export function buildLineIndex(content: string): LineIndex {
  const cache = lineIndexStore.getStore();
  if (cache === undefined) return computeLineIndex(content);
  const cached = cache.get(content);
  if (cached !== undefined) return cached;
  const index = computeLineIndex(content);
  cache.set(content, index);
  return index;
}

function lineFromIndex(indexData: LineIndex, charIndex: number): number {
  const { offsets } = indexData;
  let lo = 0;
  let hi = offsets.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if ((offsets[mid] ?? 0) <= charIndex) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

export function lineNumberAt(content: string, index: number): number {
  return lineFromIndex(buildLineIndex(content), index);
}

const MAX_SNIPPET_LENGTH = 200;

function snippetFromIndex(indexData: LineIndex, line: number): string {
  const { content, offsets } = indexData;
  const start = offsets[line - 1];
  if (start === undefined) return '';
  const end = offsets[line] ?? content.length + 1;
  const raw = content.slice(start, end > start ? end - 1 : end);
  const text = raw.replace(/\r$/, '').trim();
  return text.length > MAX_SNIPPET_LENGTH ? `${text.slice(0, MAX_SNIPPET_LENGTH)}…` : text;
}

export function lineAt(content: string, line: number): string {
  return snippetFromIndex(buildLineIndex(content), line);
}

// Rejects matches inside a string opened earlier on the same line.
export function isInsideStringLiteral(content: string, index: number): boolean {
  const lineStart = content.lastIndexOf('\n', index - 1) + 1;
  let openQuote: string | undefined;
  for (let i = lineStart; i < index; i += 1) {
    const ch = content[i];
    if (ch === '\\') {
      i += 1;
      continue;
    }
    if (openQuote === undefined) {
      if (ch === '"' || ch === "'" || ch === '`') openQuote = ch;
      else if (ch === '/' && content[i + 1] === '/') return false;
    } else if (ch === openQuote) {
      openQuote = undefined;
    }
  }
  return openQuote !== undefined;
}

export interface PatternMatch {
  matchText: string;
  index: number;
  line: number;
  snippet: string;
  groups: (string | undefined)[];
}

export interface FindMatchesOptions {
  maxMatches?: number;
}

export function findMatches(
  content: string,
  pattern: RegExp,
  options: FindMatchesOptions = {},
): PatternMatch[] {
  if (!pattern.global) {
    throw new Error(`findMatches requires a global regex, got: ${pattern}`);
  }
  const perFindCap = options.maxMatches ?? MAX_MATCHES_PER_FIND;
  const budget = matchBudgetStore.getStore();
  const budgetCap = budget !== undefined ? Math.max(0, budget.remaining) : Number.POSITIVE_INFINITY;
  const cap = Math.min(perFindCap, budgetCap);
  if (cap <= 0) {
    if (budget !== undefined) budget.truncated = true;
    return [];
  }
  const lineIndex = buildLineIndex(content);
  const matches: PatternMatch[] = [];
  pattern.lastIndex = 0;
  let match: RegExpExecArray | null;
  let stoppedAtCap = false;
  while ((match = pattern.exec(content)) !== null) {
    const line = lineFromIndex(lineIndex, match.index);
    matches.push({
      matchText: match[0],
      index: match.index,
      line,
      snippet: snippetFromIndex(lineIndex, line),
      groups: match.slice(1),
    });
    if (match.index === pattern.lastIndex) pattern.lastIndex += 1;
    if (matches.length >= cap) {
      stoppedAtCap = true;
      break;
    }
  }
  if (budget !== undefined) budget.remaining = Math.max(0, budget.remaining - matches.length);
  if (stoppedAtCap) {
    const hasMore = pattern.exec(content) !== null;
    if (hasMore && budget !== undefined) budget.truncated = true;
  }
  return matches;
}

export function redactSecret(value: string): string {
  if (value.length <= 10) return `${value.slice(0, 3)}…[redacted]`;
  return `${value.slice(0, 6)}…[redacted]…${value.slice(-3)}`;
}

const PLACEHOLDER_TOKEN =
  /(?<![A-Za-z0-9])(?:your|examples?|changeme|change[_-]me|placeholder|dummy|samples?|todo|x{4,})(?![A-Za-z0-9])/i;

const PLACEHOLDER_STRUCTURE = /<[^>]*>|\$\{/;

export function isPlaceholderValue(value: string): boolean {
  return PLACEHOLDER_TOKEN.test(value) || PLACEHOLDER_STRUCTURE.test(value);
}

export function decodeJwtPayload(token: string): Record<string, unknown> | undefined {
  const parts = token.split('.');
  if (parts.length !== 3 || parts[1] === undefined) return undefined;
  try {
    const json = Buffer.from(parts[1], 'base64url').toString('utf8');
    const parsed: unknown = JSON.parse(json);
    if (parsed !== null && typeof parsed === 'object') {
      return parsed as Record<string, unknown>;
    }
    return undefined;
  } catch {
    return undefined;
  }
}

export function isPublicEnvName(name: string): boolean {
  return PUBLIC_ENV_PREFIXES.some((prefix) => name.startsWith(prefix));
}

export function basename(filePath: string): string {
  const posix = toPosixPath(filePath);
  const idx = posix.lastIndexOf('/');
  return idx === -1 ? posix : posix.slice(idx + 1);
}

export function extensionOf(filePath: string): string {
  const name = basename(filePath);
  const idx = name.lastIndexOf('.');
  if (idx <= 0) return '';
  return name.slice(idx).toLowerCase();
}
