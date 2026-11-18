import { maskPython } from './pythonGuards.js';

export interface PyScope {
  defLine: number;
  endLine: number;
  indent: number;
  name: string;
  params: string[];
}

const DEF = /^(\s*)(?:async\s+)?def\s+(\w+)\s*\(/;

export const indentOf = (text: string): number => /^\s*/.exec(text)![0].length;

const maskedCache = new Map<string, string[]>();
export function maskedLines(content: string): string[] {
  let lines = maskedCache.get(content);
  if (lines === undefined) {
    lines = maskPython(content).split('\n');
    if (maskedCache.size > 64) maskedCache.clear();
    maskedCache.set(content, lines);
  }
  return lines;
}

function paramsOf(lines: string[], defLine: number): { params: string[]; headerEnd: number } {
  let depth = 0;
  let text = '';
  let started = false;
  for (let l = defLine; l <= lines.length; l += 1) {
    const line = lines[l - 1] ?? '';
    for (const c of line) {
      if (c === '(' || c === '[' || c === '{') { depth += 1; if (depth === 1 && c === '(' && !started) { started = true; continue; } }
      if (c === ')' || c === ']' || c === '}') {
        depth -= 1;
        if (depth === 0 && started) return { params: splitParams(text), headerEnd: l };
      }
      if (started && depth >= 1) text += c;
    }
    text += '\n';
  }
  return { params: splitParams(text), headerEnd: defLine };
}

function splitParams(text: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let current = '';
  for (const c of text) {
    if (c === '(' || c === '[' || c === '{') depth += 1;
    if (c === ')' || c === ']' || c === '}') depth -= 1;
    if (c === ',' && depth === 0) { out.push(current); current = ''; continue; }
    current += c;
  }
  out.push(current);
  return out.map((p) => /^\s*\**\s*(\w+)/.exec(p)?.[1]).filter((p): p is string => p !== undefined && p !== 'self' && p !== 'cls');
}

export function scopeOfDef(lines: string[], defLine: number): PyScope | undefined {
  const m = DEF.exec(lines[defLine - 1] ?? '');
  if (m === null) return undefined;
  const indent = m[1]!.length;
  const { params, headerEnd } = paramsOf(lines, defLine);
  let endLine = headerEnd;
  for (let l = headerEnd + 1; l <= lines.length; l += 1) {
    const text = lines[l - 1] ?? '';
    if (text.trim() === '') continue;
    if (indentOf(text) <= indent) break;
    endLine = l;
  }
  return { defLine, endLine, indent, name: m[2]!, params };
}

export function enclosingDef(lines: string[], line: number): PyScope | undefined {
  let minIndent = indentOf(lines[line - 1] ?? '');
  for (let l = line; l >= 1; l -= 1) {
    const text = lines[l - 1] ?? '';
    if (text.trim() === '') continue;
    const indent = indentOf(text);
    if (l !== line && indent >= minIndent) continue;
    if (DEF.test(text) && (l === line ? false : indent < minIndent)) {
      const scope = scopeOfDef(lines, l);
      if (scope !== undefined && scope.endLine >= line) return scope;
    }
    minIndent = Math.min(minIndent, indent);
    if (indent === 0 && l !== line) return undefined;
  }
  return undefined;
}

export function defsNamed(lines: string[], name: string): PyScope[] {
  const out: PyScope[] = [];
  lines.forEach((text, i) => {
    const m = DEF.exec(text);
    if (m !== null && m[2] === name) {
      const scope = scopeOfDef(lines, i + 1);
      if (scope !== undefined) out.push(scope);
    }
  });
  return out;
}

export function blockOf(lines: string[], line: number): { start: number; end: number } {
  const header = lines[line - 1] ?? '';
  const indent = indentOf(header);
  if (/:\s*\S/.test(header.replace(/\[[^\]]*\]|\{[^}]*\}|lambda[^:]*:/g, ''))) {
    const after = header.slice(header.lastIndexOf(':') + 1);
    if (after.trim() !== '') return { start: line, end: line };
  }
  let end = line;
  let l = line;
  while (l <= lines.length && !/:\s*$/.test(lines[l - 1] ?? '')) l += 1;
  for (let k = l + 1; k <= lines.length; k += 1) {
    const text = lines[k - 1] ?? '';
    if (text.trim() === '') continue;
    if (indentOf(text) <= indent) break;
    end = k;
  }
  return { start: Math.min(l + 1, end), end };
}


const proseCache = new Map<string, [number, number][]>();
function proseRanges(content: string): [number, number][] {
  const cached = proseCache.get(content);
  if (cached !== undefined) return cached;
  const ranges: [number, number][] = [];
  let depth = 0;
  let lineHasCode = false;
  let i = 0;
  while (i < content.length) {
    const c = content[i]!;
    if (c === '\n') { if (depth === 0 && content[i - 1] !== '\\') lineHasCode = false; i += 1; continue; }
    if (c === '#') {
      const end = content.indexOf('\n', i);
      ranges.push([i, end < 0 ? content.length : end]);
      i = end < 0 ? content.length : end;
      continue;
    }
    if (c === '"' || c === "'") {
      let p = i;
      while (p > 0 && /[rRbBuUfF]/.test(content[p - 1]!) && !/\w/.test(content[p - 2] ?? ' ')) p -= 1;
      const statement = depth === 0 && !lineHasCode;
      const quote = content.startsWith(c.repeat(3), i) ? c.repeat(3) : c;
      let j = i + quote.length;
      while (j < content.length && !content.startsWith(quote, j)) {
        if (quote.length === 1 && content[j] === '\n') break;
        if (content[j] === '\\') j += 1;
        j += 1;
      }
      const end = Math.min(content.length, j + (content.startsWith(quote, j) ? quote.length : 0));
      const rest = content.slice(end, (content.indexOf('\n', end) + 1 || content.length + 1) - 1);
      if (statement && /^\s*(?:#.*)?$/.test(rest)) ranges.push([p, end]);
      lineHasCode = true;
      i = end;
      continue;
    }
    if (c === '(' || c === '[' || c === '{') depth += 1;
    if ((c === ')' || c === ']' || c === '}') && depth > 0) depth -= 1;
    if (!/\s/.test(c) && !/[rRbBuUfF]/.test(c)) lineHasCode = true;
    else if (/[rRbBuUfF]/.test(c) && !/['"]/.test(content[i + 1] ?? '') && !/[rRbBuUfF]/.test(content[i + 1] ?? '')) lineHasCode = true;
    i += 1;
  }
  if (proseCache.size > 64) proseCache.clear();
  proseCache.set(content, ranges);
  return ranges;
}

export function inPythonProse(content: string, index: number): boolean {
  return proseRanges(content).some(([start, end]) => index >= start && index < end);
}
