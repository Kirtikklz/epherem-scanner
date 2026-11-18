import { isFunctionBrace, stripCommentsAndStrings } from './source.js';

const SERVER_FN_FACTORY = /\bcreateServerFn\s*\(/g;
const HANDLER_MEMBER = '.handler';

export interface LineRange {
  startLine: number;
  endLine: number;
}

function lineStarts(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i += 1) {
    if (text[i] === '\n') starts.push(i + 1);
  }
  return starts;
}

function lineOf(starts: readonly number[], index: number): number {
  let low = 0;
  let high = starts.length - 1;
  while (low < high) {
    const mid = (low + high + 1) >> 1;
    if ((starts[mid] ?? 0) <= index) low = mid;
    else high = mid - 1;
  }
  return low + 1;
}

function matching(stripped: string, open: number, openChar: string, closeChar: string): number {
  let depth = 0;
  for (let i = open; i < stripped.length; i += 1) {
    const c = stripped[i];
    if (c === openChar) depth += 1;
    else if (c === closeChar) {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function callbackBody(stripped: string, paren: number): { start: number; end: number } | undefined {
  const callEnd = matching(stripped, paren, '(', ')');
  if (callEnd === -1) return undefined;
  for (let i = paren + 1; i < callEnd; i += 1) {
    if (stripped[i] !== '{') continue;
    if (!isFunctionBrace(stripped, i)) {
      const close = matching(stripped, i, '{', '}');
      if (close === -1 || close >= callEnd) return undefined;
      i = close;
      continue;
    }
    const close = matching(stripped, i, '{', '}');
    if (close === -1 || close > callEnd) return undefined;
    return { start: i, end: close };
  }
  return undefined;
}

function handlerBodyRange(
  stripped: string,
  from: number,
  limit: number,
): { start: number; end: number } | undefined {
  let depth = 1;
  for (let i = from; i < limit; i += 1) {
    const c = stripped[i];
    if (c === '(' || c === '[' || c === '{') {
      depth += 1;
      continue;
    }
    if (c === ')' || c === ']' || c === '}') {
      depth -= 1;
      continue;
    }
    if (depth > 0) continue;
    if (c === ';') return undefined;
    if (c === '\n') {
      let j = i + 1;
      while (j < limit && /\s/.test(stripped[j] ?? '')) j += 1;
      if (stripped[j] !== '.') return undefined;
      i = j - 1;
      continue;
    }
    if (c !== '.') continue;
    if (!stripped.startsWith(HANDLER_MEMBER, i)) continue;
    let j = i + HANDLER_MEMBER.length;
    while (j < limit && /\s/.test(stripped[j] ?? '')) j += 1;
    if (stripped[j] !== '(') continue;
    return callbackBody(stripped, j);
  }
  return undefined;
}

export function serverFunctionHandlerLineRanges(content: string): LineRange[] {
  if (!content.includes('createServerFn')) return [];
  const stripped = stripCommentsAndStrings(content);
  const starts = lineStarts(stripped);
  const factoryAt: number[] = [];
  SERVER_FN_FACTORY.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = SERVER_FN_FACTORY.exec(stripped)) !== null) {
    factoryAt.push(match.index + match[0].length);
  }
  const ranges: LineRange[] = [];
  for (let n = 0; n < factoryAt.length; n += 1) {
    const body = handlerBodyRange(stripped, factoryAt[n] ?? 0, factoryAt[n + 1] ?? stripped.length);
    if (body === undefined) continue;
    ranges.push({ startLine: lineOf(starts, body.start), endLine: lineOf(starts, body.end) });
  }
  return ranges;
}

export function isInsideServerFunctionHandler(content: string, line: number): boolean {
  return serverFunctionHandlerLineRanges(content).some(
    (range) => line >= range.startLine && line <= range.endLine,
  );
}
