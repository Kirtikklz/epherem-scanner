import type { FileMapEntry } from './types.js';
import { indentOf, maskedLines, scopeOfDef } from './pythonScope.js';

export type RaiserIndex = Map<string, RaiserFacts[]>;
export interface RaiserFacts { literalOnly: Map<string, boolean>; reraises: boolean; mentions?: Set<string> }

const RAISE = /^\s*raise\s+((?:[A-Za-z_]\w*\.)*[A-Za-z_]\w*)\s*(\(\s*(f?r?['"]|\))?)?/;
const BARE_RAISE = /^\s*raise\s*(?:$|#)/;
const QUIET_BUILTINS = new Set(['str', 'len', 'bool', 'isinstance', 'dict', 'list', 'tuple', 'set', 'range', 'enumerate', 'print', 'repr', 'type', 'super']);
const NOT_A_CALL = new Set(['if', 'elif', 'while', 'for', 'return', 'not', 'and', 'or', 'in', 'is', 'with', 'assert', 'await', 'yield', 'lambda', 'del', 'raise', 'print']);
const BROAD = new Set(['Exception', 'BaseException']);

function raisesIn(lines: string[], from: number, to: number): { literalOnly: Map<string, boolean>; reraises: boolean } {
  const literalOnly = new Map<string, boolean>();
  let reraises = false;
  for (let l = from; l <= to; l += 1) {
    const text = lines[l - 1] ?? '';
    if (BARE_RAISE.test(text)) { reraises = true; continue; }
    const m = RAISE.exec(text);
    if (m === null) continue;
    const cls = m[1]!.split('.').pop()!;
    const written = (m[3] !== undefined && m[3] !== ')')
      || (m[2] !== undefined && m[3] === undefined && writtenOnLinesBelow(lines, l, m.index + m[0].length, to));
    literalOnly.set(cls, (literalOnly.get(cls) ?? true) && written);
  }
  return { literalOnly, reraises };
}

function writtenOnLinesBelow(lines: string[], line: number, from: number, to: number): boolean {
  let text = (lines[line - 1] ?? '').slice(from);
  if (text.trim() !== '') return false;
  let depth = 1;
  let inside = '';
  for (let l = line + 1; l <= Math.min(to, line + 20); l += 1) {
    text = lines[l - 1] ?? '';
    for (const c of text) {
      if (c === '(' || c === '[' || c === '{') depth += 1;
      if (c === ')' || c === ']' || c === '}') depth -= 1;
      if (depth === 0) break;
      inside += c;
    }
    if (depth === 0) {
      const rest = inside.replace(/[rRbBuUfF]{0,2}(?:"[^"\n]*"|'[^'\n]*')/g, '');
      return rest !== inside && /^[\s,]*$/.test(rest);
    }
    inside += '\n';
  }
  return false;
}

const indexCache = new WeakMap<FileMapEntry[], RaiserIndex>();
export function pythonRaiserIndex(entries: FileMapEntry[]): RaiserIndex {
  const cached = indexCache.get(entries);
  if (cached !== undefined) return cached;
  const index: RaiserIndex = new Map();
  for (const entry of entries) {
    if (entry.extension !== '.py') continue;
    const lines = maskedLines(entry.content ?? '');
    lines.forEach((text, i) => {
      if (!/^\s*(?:async\s+)?def\s/.test(text)) return;
      const scope = scopeOfDef(lines, i + 1);
      if (scope === undefined) return;
      const list = index.get(scope.name) ?? [];
      const mentions = new Set<string>();
      for (let l = scope.defLine + 1; l <= scope.endLine; l += 1) for (const w of (lines[l - 1] ?? '').matchAll(/[A-Za-z_]\w*/g)) mentions.add(w[0]);
      list.push({ ...raisesIn(lines, scope.defLine + 1, scope.endLine), mentions });
      index.set(scope.name, list);
    });
  }
  indexCache.set(entries, index);
  return index;
}

export function pythonOwnRaiseOnly(content: string, index: number, name: string, raisers: RaiserIndex): boolean {
  const lines = maskedLines(content);
  const line = content.slice(0, index).split('\n').length;
  let exceptLine = 0;
  let classes: string[] = [];
  for (let l = line; l >= 1 && l > line - 200; l -= 1) {
    const m = new RegExp(`^\\s*except\\s+\\(?([^:]+?)\\)?\\s+as\\s+${name}\\s*:`).exec(lines[l - 1] ?? '');
    if (m !== null) { exceptLine = l; classes = m[1]!.split(',').map((c) => c.trim().split('.').pop() ?? '').filter(Boolean); break; }
  }
  if (exceptLine === 0 || classes.length === 0 || classes.some((c) => BROAD.has(c) || !/^[A-Za-z_]\w*$/.test(c))) return false;
  const exceptIndent = indentOf(lines[exceptLine - 1] ?? '');
  let tryLine = 0;
  let bodyEnd = 0;
  for (let l = exceptLine - 1; l >= 1; l -= 1) {
    const text = lines[l - 1] ?? '';
    if (text.trim() === '' || indentOf(text) > exceptIndent) continue;
    if (indentOf(text) < exceptIndent) return false;
    if (/^\s*except\b/.test(text)) continue;
    if (/^\s*try\s*:\s*$/.test(text)) { tryLine = l; break; }
    return false;
  }
  if (tryLine === 0) return false;
  for (let l = tryLine + 1; l <= exceptLine; l += 1) {
    const text = lines[l - 1] ?? '';
    if (text.trim() !== '' && indentOf(text) <= exceptIndent) { bodyEnd = l - 1; break; }
  }
  if (bodyEnd <= tryLine) return false;
  const own = raisesIn(lines, tryLine + 1, bodyEnd);
  if (own.reraises) return false;
  let written = classes.some((c) => own.literalOnly.get(c) === true);
  if (classes.some((c) => own.literalOnly.get(c) === false)) return false;
  for (let l = tryLine + 1; l <= bodyEnd; l += 1) {
    const text = lines[l - 1] ?? '';
    for (const call of text.matchAll(/(?<![\w.])((?:[A-Za-z_]\w*\s*\.\s*)*([A-Za-z_]\w*))\s*\(/g)) {
      const callee = call[2]!;
      if (NOT_A_CALL.has(callee) && !call[1]!.includes('.')) continue;
      if (/\b(?:def|class)\s+$/.test(text.slice(0, call.index))) continue;
      if (!call[1]!.includes('.') && QUIET_BUILTINS.has(callee)) continue;
      const defs = raisers.get(callee);
      if (defs === undefined || defs.length === 0) return false;
      for (const def of defs) {
        if (def.reraises) return false;
        for (const c of classes) {
          const literal = def.literalOnly.get(c);
          if (literal === false) return false;
          if (literal === true) written = true;
        }
      }
      if (!quietBeneath(callee, classes, raisers)) return false;
    }
  }
  return written;
}

function quietBeneath(start: string, classes: string[], raisers: RaiserIndex): boolean {
  const seen = new Set<string>([start]);
  const queue = [start];
  while (queue.length > 0) {
    const name = queue.shift()!;
    for (const def of raisers.get(name) ?? []) {
      for (const mention of def.mentions ?? []) {
        if (seen.has(mention) || !raisers.has(mention)) continue;
        if (seen.size >= 200) return false;
        seen.add(mention);
        queue.push(mention);
        for (const below of raisers.get(mention)!) {
          if (below.reraises) return false;
          if (classes.some((c) => below.literalOnly.get(c) === false)) return false;
        }
      }
    }
  }
  return true;
}
