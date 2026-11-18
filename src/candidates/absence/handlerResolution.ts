import { isInsideComment } from '../textUtils.js';

export interface HandlerLocation {
  filePath: string;
  line: number;
  endLine: number;
  kind: 'inline' | 'named';
}

const MAX_BODY_CHARS = 60_000;

const MAX_HEAD_CHARS = 600;

export function isInlineHandlerText(argText: string): boolean {
  return /^\s*(?:async\b|function\b|\(|[A-Za-z_$][\w$]*\s*=>)/.test(argText);
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function opensRegexLiteral(content: string, index: number): boolean {
  let i = index - 1;
  while (i >= 0 && (content[i] === ' ' || content[i] === '\t')) i -= 1;
  if (i < 0) return true;
  const prev = content[i] ?? '';
  if ('(,=:[!&|?{};+-*%<>~^\n'.includes(prev)) return true;
  const word = /(?:^|[^\w$])(return|typeof|case|in|of|do|else|throw|await|yield|void|delete)$/.exec(content.slice(Math.max(0, i - 8), i + 1));
  return word !== null;
}

function skipRegexLiteral(content: string, from: number): number {
  let i = from + 1;
  let inClass = false;
  while (i < content.length) {
    const ch = content[i];
    if (ch === '\\') {
      i += 2;
      continue;
    }
    if (ch === '\n') return i;
    if (inClass) {
      if (ch === ']') inClass = false;
    } else if (ch === '[') {
      inClass = true;
    } else if (ch === '/') {
      return i + 1;
    }
    i += 1;
  }
  return content.length;
}

function skipLiteral(content: string, i: number, limit: number): number {
  const ch = content[i] ?? '';
  if (ch === '"' || ch === "'") return skipQuoted(content, i, ch);
  if (ch === '`') return skipTemplate(content, i, limit);
  if (ch === '/' && content[i + 1] === '/') {
    const nl = content.indexOf('\n', i);
    return nl === -1 ? limit : nl + 1;
  }
  if (ch === '/' && content[i + 1] === '*') {
    const close = content.indexOf('*/', i + 2);
    return close === -1 ? limit : close + 2;
  }
  if (ch === '/' && opensRegexLiteral(content, i)) return skipRegexLiteral(content, i);
  return i;
}

export function matchClose(content: string, from: number, bound: number): number {
  const pairs: Record<string, string> = { '{': '}', '(': ')', '[': ']' };
  const stack: string[] = [];
  const limit = Math.min(content.length, from + bound);
  let i = from;
  while (i < limit) {
    const ch = content[i] ?? '';
    const skipped = skipLiteral(content, i, limit);
    if (skipped !== i) {
      i = skipped;
      continue;
    }
    if (ch === '{' || ch === '(' || ch === '[') {
      stack.push(pairs[ch] ?? '');
    } else if (ch === '}' || ch === ')' || ch === ']') {
      const expected = stack.pop();
      if (expected !== ch) return -1;
      if (stack.length === 0) return i;
    }
    i += 1;
  }
  return -1;
}

function skipQuoted(content: string, from: number, quote: string): number {
  let i = from + 1;
  while (i < content.length) {
    const ch = content[i];
    if (ch === '\\') {
      i += 2;
      continue;
    }
    if (ch === quote || ch === '\n') return i + 1;
    i += 1;
  }
  return content.length;
}

function skipTemplate(content: string, from: number, limit: number): number {
  let i = from + 1;
  while (i < limit) {
    const ch = content[i];
    if (ch === '\\') {
      i += 2;
      continue;
    }
    if (ch === '`') return i + 1;
    if (ch === '$' && content[i + 1] === '{') {
      const close = matchClose(content, i + 1, limit - i);
      if (close === -1) return limit;
      i = close + 1;
      continue;
    }
    i += 1;
  }
  return limit;
}

function skipSpace(content: string, from: number): number {
  let i = from;
  while (i < content.length && /\s/.test(content[i] ?? '')) i += 1;
  return i;
}

function bodyStartFromHead(content: string, headStart: number): { index: number; expressionArrow: boolean } | undefined {
  let i = skipSpace(content, headStart);
  const limit = Math.min(content.length, headStart + MAX_HEAD_CHARS);
  if (content[i] === '(') {
    const close = matchClose(content, i, MAX_HEAD_CHARS);
    if (close === -1) return undefined;
    i = skipSpace(content, close + 1);
  } else {
    const single = /^[A-Za-z_$][\w$]*/.exec(content.slice(i, limit));
    if (single === null) return undefined;
    i = skipSpace(content, i + single[0].length);
  }
  if (content[i] === ':') {
    let depth = 0;
    let j = i + 1;
    for (; j < limit; j += 1) {
      const ch = content[j] ?? '';
      if (ch === '<' || ch === '(' || ch === '[' || ch === '{') {
        if (ch === '{' && depth === 0) break;
        depth += 1;
      } else if (ch === '>' || ch === ')' || ch === ']' || ch === '}') {
        depth -= 1;
      } else if (ch === '=' && content[j + 1] === '>' && depth === 0) {
        break;
      }
    }
    i = skipSpace(content, j);
  }
  if (content[i] === '{') return { index: i, expressionArrow: false };
  if (content[i] === '=' && content[i + 1] === '>') {
    const afterArrow = skipSpace(content, i + 2);
    if (content[afterArrow] === '{') return { index: afterArrow, expressionArrow: false };
    return { index: i, expressionArrow: true };
  }
  return undefined;
}

function functionEnd(content: string, headStart: number): number {
  const body = bodyStartFromHead(content, headStart);
  if (body === undefined) return -1;
  if (!body.expressionArrow) return matchClose(content, body.index, MAX_BODY_CHARS);
  let depth = 0;
  let i = body.index + 2;
  const limit = Math.min(content.length, i + MAX_BODY_CHARS);
  while (i < limit) {
    const ch = content[i] ?? '';
    const skipped = skipLiteral(content, i, limit);
    if (skipped !== i) {
      i = skipped;
      continue;
    }
    if (ch === '(' || ch === '[' || ch === '{') depth += 1;
    else if (ch === ')' || ch === ']' || ch === '}') {
      if (depth === 0) return i - 1;
      depth -= 1;
    } else if ((ch === ';' || ch === '\n') && depth === 0) return i;
    i += 1;
  }
  return -1;
}

function functionHeadOfValue(content: string, valueStart: number): number {
  let i = skipSpace(content, valueStart);
  const slice = content.slice(i, i + MAX_HEAD_CHARS);
  const wrapped = /^([A-Za-z_$][\w$.]*)\s*\(\s*(?=async\b|function\b|\(|[A-Za-z_$][\w$]*\s*=>)/.exec(slice);
  if (wrapped !== null && !/^(?:new|require|import)$/.test(wrapped[1] ?? '')) {
    i = skipSpace(content, i + wrapped[0].length);
  }
  const head = /^(?:async\s+)?(?:function\s*\*?\s*[A-Za-z_$]?[\w$]*\s*)?(?=\(|[A-Za-z_$][\w$]*\s*=>)/.exec(content.slice(i, i + MAX_HEAD_CHARS));
  if (head === null) return -1;
  return i + head[0].length;
}

interface Definition {
  start: number;
  headStart: number;
  valueStart: number;
}

function definitionsOf(content: string, name: string): Definition[][] {
  const n = escapeRegExp(name);
  const collect = (re: RegExp, headFromMatch: boolean): Definition[] => {
    const out: Definition[] = [];
    for (let m = re.exec(content); m !== null; m = re.exec(content)) {
      const start = m.index + (m[1]?.length ?? 0);
      if (isInsideComment(content, start)) continue;
      const after = m.index + m[0].length;
      out.push(
        headFromMatch
          ? { start, headStart: after - 1, valueStart: -1 }
          : { start, headStart: -1, valueStart: after },
      );
      if (out.length > 4) break;
    }
    return out;
  };
  const shapes: Array<[RegExp, boolean]> = [
    [new RegExp(`(^|[^\\w$.])(?:module\\s*\\.\\s*)?exports\\s*\\.\\s*${n}\\s*=(?!=)`, 'g'), false],
    [new RegExp(`(^|[^\\w$.])this\\s*\\.\\s*${n}\\s*=(?!=)`, 'g'), false],
    [new RegExp(`(^|[^\\w$.])(?:const|let|var)\\s+${n}\\s*=(?!=)`, 'g'), false],
    [new RegExp(`(^|[^\\w$.])function\\s*\\*?\\s*${n}\\s*\\(`, 'g'), true],
    [new RegExp(`(^|[{,\\s])${n}\\s*:\\s*(?=async\\b|function\\b|\\()`, 'g'), false],
    [new RegExp(`(^|[{,;\\s])(?:(?:async|static|public|private|protected|override)\\s+)*${n}\\s*\\(`, 'g'), true],
  ];
  return shapes.map(([re, headFromMatch]) => collect(re, headFromMatch));
}

export function findFunctionSpan(content: string, name: string): { start: number; end: number } | undefined {
  if (!/^[A-Za-z_$][\w$]*$/.test(name)) return undefined;
  const byShape = definitionsOf(content, name);
  for (let shape = 0; shape < byShape.length; shape += 1) {
    const defs = byShape[shape] ?? [];
    if (defs.length === 0) continue;
    const candidates =
      shape === byShape.length - 1
        ? defs.filter((d) => {
            const body = bodyStartFromHead(content, d.headStart);
            return body !== undefined && !body.expressionArrow;
          })
        : defs;
    if (candidates.length === 0) continue;
    if (candidates.length > 1) return undefined;
    const def = candidates[0];
    if (def === undefined) return undefined;
    const headStart = def.headStart >= 0 ? def.headStart : functionHeadOfValue(content, def.valueStart);
    if (headStart < 0) return undefined;
    const end = functionEnd(content, headStart);
    if (end < 0) return undefined;
    return { start: def.start, end };
  }
  return undefined;
}

function lineOf(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i += 1) if (content[i] === '\n') line += 1;
  return line;
}

export interface ResolveHandlerInput {
  token: string | undefined;
  inline: boolean;
  filePath: string;
  line: number;
  endLine: number;
  bindings: ReadonlyMap<string, string>;
  contentOf: (path: string) => string | undefined;
}

export function resolveHandler(input: ResolveHandlerInput): HandlerLocation | undefined {
  if (input.inline) {
    return { filePath: input.filePath, line: input.line, endLine: input.endLine, kind: 'inline' };
  }
  const token = input.token;
  if (token === undefined) return undefined;
  const parts = token.split('.');
  const head = parts[0] ?? '';
  const name = parts[parts.length - 1] ?? '';
  if (head === '' || name === '') return undefined;
  const targetFile = input.bindings.get(head) ?? input.filePath;
  const content = input.contentOf(targetFile);
  if (content === undefined) return undefined;
  const span = findFunctionSpan(content, name);
  if (span === undefined) return undefined;
  return { filePath: targetFile, line: lineOf(content, span.start), endLine: lineOf(content, span.end), kind: 'named' };
}
