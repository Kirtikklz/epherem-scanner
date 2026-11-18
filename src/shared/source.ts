export function stripCommentsAndStrings(source: string): string {
  const out = source.split('');
  const n = source.length;
  let i = 0;
  const blank = (from: number, to: number): void => {
    for (let k = from; k < to && k < n; k += 1) {
      if (out[k] !== '\n' && out[k] !== '\r') out[k] = ' ';
    }
  };
  while (i < n) {
    const c = source[i];
    const next = source[i + 1];
    if (c === '/' && next === '/') {
      let j = i + 2;
      while (j < n && source[j] !== '\n') j += 1;
      blank(i, j);
      i = j;
      continue;
    }
    if (c === '/' && next === '*') {
      let j = i + 2;
      while (j < n && !(source[j] === '*' && source[j + 1] === '/')) j += 1;
      j = Math.min(n, j + 2);
      blank(i, j);
      i = j;
      continue;
    }
    if (c === '#') {
      let j = i + 1;
      while (j < n && source[j] !== '\n') j += 1;
      blank(i, j);
      i = j;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      const quote = c;
      let j = i + 1;
      while (j < n) {
        if (source[j] === '\\') {
          j += 2;
          continue;
        }
        if (source[j] === quote) {
          j += 1;
          break;
        }
        j += 1;
      }
      blank(i + 1, Math.max(i + 1, j - 1));
      i = j;
      continue;
    }
    i += 1;
  }
  return out.join('');
}

export const HASH_COMMENT_EXTENSIONS: ReadonlySet<string> = new Set([
  '.py', '.rb', '.yaml', '.yml', '.toml', '.env',
]);

export function usesHashComments(extension: string, label?: string): boolean {
  return HASH_COMMENT_EXTENSIONS.has(extension) || label === 'env';
}

export function stripCommentsOnly(source: string, hashComments = false): string {
  return stripComments(source, hashComments ? HASH_SYNTAX : C_STYLE_SYNTAX);
}

export interface CommentSyntax {
  hash: boolean;
  cStyle: boolean;
  html: boolean;
}

const HASH_SYNTAX: CommentSyntax = { hash: true, cStyle: false, html: false };
const C_STYLE_SYNTAX: CommentSyntax = { hash: false, cStyle: true, html: false };
const MARKUP_SYNTAX: CommentSyntax = { hash: false, cStyle: false, html: true };

const MARKUP_EXTENSIONS: ReadonlySet<string> = new Set([
  '.html', '.htm', '.erb', '.ejs', '.hbs', '.handlebars', '.njk', '.nunjucks', '.mustache', '.vue', '.svelte',
]);

export function commentSyntaxFor(extension: string, label?: string): CommentSyntax {
  if (usesHashComments(extension, label)) return HASH_SYNTAX;
  if (MARKUP_EXTENSIONS.has(extension)) return MARKUP_SYNTAX;
  return C_STYLE_SYNTAX;
}

let lastStripped: { source: string; hash: boolean; cStyle: boolean; html: boolean; out: string } | undefined;
export function stripComments(source: string, syntax: CommentSyntax): string {
  const last = lastStripped;
  if (last !== undefined && last.source === source && last.hash === syntax.hash && last.cStyle === syntax.cStyle && last.html === syntax.html) return last.out;
  const out = stripCommentsOnce(source, syntax);
  lastStripped = { source, hash: syntax.hash, cStyle: syntax.cStyle, html: syntax.html, out };
  return out;
}

function stripCommentsOnce(source: string, syntax: CommentSyntax): string {
  const { hash: hashComments, cStyle, html } = syntax;
  const out = source.split('');
  const n = source.length;
  let i = 0;
  const blank = (from: number, to: number): void => {
    for (let k = from; k < to && k < n; k += 1) {
      if (out[k] !== '\n' && out[k] !== '\r') out[k] = ' ';
    }
  };
  while (i < n) {
    const c = source[i];
    const next = source[i + 1];
    if (html && c === '<' && source.startsWith('<!--', i)) {
      const close = source.indexOf('-->', i + 4);
      if (close !== -1) {
        const j = close + 3;
        blank(i, j);
        i = j;
        continue;
      }
    }
    if (cStyle && c === '/' && next === '/') {
      let j = i + 2;
      while (j < n && source[j] !== '\n') j += 1;
      blank(i, j);
      i = j;
      continue;
    }
    if (cStyle && c === '/' && next === '*') {
      let j = i + 2;
      while (j < n && !(source[j] === '*' && source[j + 1] === '/')) j += 1;
      j = Math.min(n, j + 2);
      blank(i, j);
      i = j;
      continue;
    }
    if (hashComments && c === '#') {
      let j = i + 1;
      while (j < n && source[j] !== '\n') j += 1;
      blank(i, j);
      i = j;
      continue;
    }
    if ((cStyle || hashComments) && (c === '"' || c === "'" || c === '`')) {
      const quote = c;
      let j = i + 1;
      while (j < n) {
        if (source[j] === '\\') {
          j += 2;
          continue;
        }
        if (source[j] === quote) {
          j += 1;
          break;
        }
        j += 1;
      }
      i = j;
      continue;
    }
    i += 1;
  }
  return out.join('');
}

export interface BlockRange {
  start: number;
  end: number;
}

export function topLevelBlockRanges(stripped: string): BlockRange[] {
  const ranges: BlockRange[] = [];
  let depth = 0;
  let start = -1;
  for (let i = 0; i < stripped.length; i += 1) {
    const c = stripped[i];
    if (c === '{') {
      if (depth === 0) start = i;
      depth += 1;
    } else if (c === '}') {
      if (depth > 0) {
        depth -= 1;
        if (depth === 0 && start >= 0) {
          ranges.push({ start, end: i });
          start = -1;
        }
      }
    }
  }
  return ranges;
}

export function enclosingTopLevelBlock(stripped: string, index: number): BlockRange | undefined {
  for (const range of topLevelBlockRanges(stripped)) {
    if (index >= range.start && index <= range.end) return range;
    if (range.start > index) break;
  }
  return undefined;
}

interface RawBlock {
  start: number;
  end: number;
}
function allBlocks(stripped: string): RawBlock[] {
  const stack: number[] = [];
  const out: RawBlock[] = [];
  for (let i = 0; i < stripped.length; i += 1) {
    const c = stripped[i];
    if (c === '{') stack.push(i);
    else if (c === '}') {
      const start = stack.pop();
      if (start !== undefined) out.push({ start, end: i });
    }
  }
  return out;
}

const CONTROL_FLOW_KEYWORDS = new Set(['if', 'for', 'while', 'switch', 'catch']);

export function isFunctionBrace(stripped: string, bracePos: number): boolean {
  let j = bracePos - 1;
  while (j >= 0 && /\s/.test(stripped[j] ?? '')) j -= 1;
  if (j < 0) return false;
  if (stripped[j] === '>' && stripped[j - 1] === '=') return true;
  if (stripped[j] === ')') {
    let depth = 0;
    let k = j;
    for (; k >= 0; k -= 1) {
      if (stripped[k] === ')') depth += 1;
      else if (stripped[k] === '(') {
        depth -= 1;
        if (depth === 0) break;
      }
    }
    let m = k - 1;
    while (m >= 0 && /\s/.test(stripped[m] ?? '')) m -= 1;
    const end = m;
    while (m >= 0 && /[\w$]/.test(stripped[m] ?? '')) m -= 1;
    const word = stripped.slice(m + 1, end + 1);
    return !CONTROL_FLOW_KEYWORDS.has(word);
  }
  return false;
}

export function enclosingFunctionBlock(stripped: string, index: number): BlockRange | undefined {
  let best: BlockRange | undefined;
  for (const block of allBlocks(stripped)) {
    if (index < block.start || index > block.end) continue;
    if (!isFunctionBrace(stripped, block.start)) continue;
    if (best === undefined || block.start > best.start) best = { start: block.start, end: block.end };
  }
  return best;
}
