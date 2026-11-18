import type { FileMapEntry } from './types.js';
import { blockOf, defsNamed, enclosingDef, indentOf, maskedLines, scopeOfDef, type PyScope } from './pythonScope.js';

export interface UploadFacts {
  stored: boolean;
  typeChecked: boolean;
  sizeChecked: boolean;
}

const MAX_HELPER_DEPTH = 2;
const REQUEST_FILES = /request\s*\.\s*(?:files|FILES)\b(?:\s*\[[^\]\n]*\]|\s*\.\s*(?:get|getlist|values)\s*\([^)\n]*\))?/.source;
const NOT_STORING_CALLS = new Set(['len', 'bool', 'isinstance', 'print', 'str', 'repr', 'getattr', 'hasattr', 'type', 'id', 'secure_filename']);
const REFUSES = /^\s*(?:return\b|raise\b|abort\s*\(|continue\b|break\b)/;
const PARSER_CALL = /(?<![\w.])(?:json\s*\.\s*loads?|yaml\s*\.\s*(?:safe_)?load|csv\s*\.\s*(?:reader|DictReader)|len|hashlib\s*\.\s*\w+)\s*\(/;
const IN_MEMORY_CALLEE = /^(?:json\.loads?|yaml\.(?:safe_)?load|csv\.(?:reader|DictReader)|len|hashlib\.\w+|(?:io\.)?(?:StringIO|BytesIO)|[\w.]+\.decode)$/;
const METADATA = 'filename|content_type|mimetype|mimetype_params|content_length|size|headers|name|tell\\s*\\(\\s*\\)';

function withoutInert(text: string, file: string): string {
  let out = text.replace(new RegExp(`(?:${file})\\s*\\.\\s*(?:${METADATA})(?!\\w)`, 'g'), '_');
  for (let guard = 0; guard < 20; guard += 1) {
    const m = PARSER_CALL.exec(out);
    if (m === null) break;
    const open = m.index + m[0].length - 1;
    const end = open + callArguments(out, open).length + 2;
    out = `${out.slice(0, m.index)}_${out.slice(end)}`;
  }
  return out;
}

const escape = (name: string): string => name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const wordsOf = (names: Iterable<string>): string => [...names].map(escape).join('|');

function bodyLines(lines: string[], scope: PyScope): number[] {
  const out: number[] = [];
  let skipUntil = 0;
  for (let l = scope.defLine + 1; l <= scope.endLine; l += 1) {
    if (l <= skipUntil) continue;
    const text = lines[l - 1] ?? '';
    if (/^\s*(?:async\s+)?def\s/.test(text)) {
      const nestedIndent = indentOf(text);
      let k = l + 1;
      while (k <= scope.endLine && ((lines[k - 1] ?? '').trim() === '' || indentOf(lines[k - 1] ?? '') > nestedIndent)) k += 1;
      skipUntil = k - 1;
      continue;
    }
    out.push(l);
  }
  return out;
}

function callArguments(text: string, open: number): string {
  let depth = 0;
  for (let i = open; i < text.length; i += 1) {
    if (text[i] === '(' || text[i] === '[' || text[i] === '{') depth += 1;
    if (text[i] === ')' || text[i] === ']' || text[i] === '}') { depth -= 1; if (depth === 0) return text.slice(open + 1, i); }
  }
  return text.slice(open + 1);
}

function splitTop(text: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let current = '';
  for (const c of text) {
    if (c === '(' || c === '[' || c === '{') depth += 1;
    if (c === ')' || c === ']' || c === '}') depth -= 1;
    if (c === ',' && depth === 0) { out.push(current); current = ''; continue; }
    current += c;
  }
  if (current.trim() !== '') out.push(current);
  return out;
}

function withContinuation(lines: string[], l: number, text: string, endLine: number): string {
  let out = text;
  const open = (s: string): number => [...s].reduce((depth, c) => depth + ('([{'.includes(c) ? 1 : ')]}'.includes(c) ? -1 : 0), 0);
  let depth = open(out);
  for (let k = l + 1; k <= endLine && (depth > 0 || /\\\s*$/.test(out)); k += 1) {
    const next = lines[k - 1] ?? '';
    out = `${out.replace(/\\\s*$/, '')} ${next.trim()}`;
    depth += open(next);
  }
  return out;
}

function literalCollection(text: string): boolean {
  const body = /^(?:(?:frozenset|set|tuple|list)\s*\(\s*([[{(][^]*[\]})])\s*\)|([[{(][^]*[\]})]))$/.exec(text.trim());
  if (body === null) return false;
  const inner = (body[1] ?? body[2]!).slice(1, -1);
  return /^[\s\w"',:.\-[\]{}]*$/.test(inner) && !/\b(?:for|if|lambda|in|not|and|or)\b/.test(inner);
}
const CLOSER: Record<string, string> = { '[': ']', '{': '}', '(': ')' };
function fixedCollection(lines: string[], scope: PyScope, text: string, at: number): boolean {
  if (/^[[{(]/.test(text.slice(at))) return literalCollection(`${text[at]!}${callArguments(text, at)}${CLOSER[text[at]!]!}`);
  const name = /^([A-Za-z_]\w*)(?:\s*\.\s*(?:items|values|keys)\s*\(\s*\))?(?![\w.])/.exec(text.slice(at))?.[1];
  if (name === undefined) return false;
  const bindings: string[] = [];
  const binding = new RegExp(`^(\\s*)${escape(name)}\\s*(?::[^=]+)?=(?!=)\\s*(.+)$`);
  lines.forEach((line, i) => {
    const m = binding.exec(line);
    if (m === null) return;
    if (m[1]!.length > 0 && !(i + 1 > scope.defLine && i + 1 <= scope.endLine)) return;
    bindings.push(withContinuation(lines, i + 1, m[2]!, lines.length));
  });
  return bindings.length > 0 && bindings.every(literalCollection);
}

function bodySniffs(lines: string[], scope: PyScope, param: string): boolean {
  const drawn = new Set<string>();
  for (const l of bodyLines(lines, scope)) {
    const text = lines[l - 1] ?? '';
    const loop = /^\s*for\s+([\w\s,]+?)\s+in\s+([A-Za-z_]\w*)(?:\s*\.\s*(?:items|values|keys)\s*\(\s*\))?\s*:/.exec(text);
    if (loop !== null && fixedCollection(lines, scope, text, text.indexOf(loop[2]!, text.indexOf(' in ') + 4))) loop[1]!.split(',').map((v) => v.trim()).filter(Boolean).forEach((v) => drawn.add(v));
  }
  if (drawn.size === 0) return false;
  const P = escape(param);
  const D = wordsOf(drawn);
  return bodyLines(lines, scope).some((l) => new RegExp(`\\b${P}\\s*\\.\\s*startswith\\s*\\(\\s*(?:${D})\\s*\\)|\\b${P}\\s*\\[[^\\]]*\\]\\s*==\\s*(?:${D})\\b`).test(lines[l - 1] ?? ''));
}

function bodyTestsMembership(lines: string[], scope: PyScope, strict = false): boolean {
  const params = new Set(scope.params);
  for (const l of bodyLines(lines, scope)) {
    const text = lines[l - 1] ?? '';
    if (/^\s*for\b/.test(text)) continue;
    if (!/^\s*(?:return|if|elif|assert)\b|=/.test(text)) continue;
    if (strict && (!/^\s*return\b/.test(text) || /\bnot\b/.test(text))) continue;
    for (const m of text.matchAll(/\bin\s+([A-Za-z_][\w.]*|[[{(])/g)) {
      if (/\bfor\s+[\w\s,]+$/.test(text.slice(0, m.index))) continue;
      const right = m[1]!;
      if (params.has(right.split('.')[0]!)) continue;
      if (strict && !fixedCollection(lines, scope, text, m.index + m[0].length - m[1]!.length)) continue;
      return true;
    }
  }
  return false;
}

function flatten(text: string): string {
  let depth = 0;
  let out = '';
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i]!;
    if (')]}'.includes(c)) depth -= 1;
    out += depth > 0 ? ' ' : c;
    if ('([{'.includes(c)) depth += 1;
  }
  return out;
}

function andOnAMiss(values: (boolean | undefined)[]): boolean | undefined {
  return values.includes(false) ? false : values.includes(undefined) ? undefined : true;
}
function orOnAMiss(values: (boolean | undefined)[]): boolean | undefined {
  return values.includes(true) ? true : values.includes(undefined) ? undefined : false;
}

function conditionOnAMiss(text: string, part: (p: string) => boolean | undefined): boolean | undefined {
  const t = text.trim();
  const flat = flatten(t);
  for (const [word, combine] of [['or', orOnAMiss], ['and', andOnAMiss]] as const) {
    const at = [...flat.matchAll(new RegExp(`(?<![\\w.])${word}(?![\\w.])`, 'g'))].map((m) => m.index);
    if (at.length === 0) continue;
    const pieces = [...at, t.length].map((end, i) => t.slice(i === 0 ? 0 : at[i - 1]! + word.length, end));
    return combine(pieces.map((p) => conditionOnAMiss(p, part)));
  }
  if (/^not(?![\w.])/.test(t)) {
    const inner = conditionOnAMiss(t.slice(3), part);
    return inner === undefined ? undefined : !inner;
  }
  if (t.startsWith('(') && callArguments(t, 0).length + 2 === t.length) return conditionOnAMiss(t.slice(1, -1), part);
  if (/(?<![\w.])(?:if|else|lambda)(?![\w.])/.test(flat)) return undefined;
  return part(t);
}

interface ScopeOptions { strict: boolean; content?: Set<string> }
function scopeFacts(
  entry: FileMapEntry,
  lines: string[],
  scope: PyScope,
  seeds: Set<string>,
  withRequest: boolean,
  depth: number,
  options: ScopeOptions = { strict: false },
): UploadFacts {
  const strict = options.strict;
  const facts: UploadFacts = { stored: false, typeChecked: false, sizeChecked: false };
  const body = bodyLines(lines, scope);
  const fileVars = new Set(seeds);
  const fileExpr = (): string => [withRequest ? REQUEST_FILES : '', fileVars.size > 0 ? `\\b(?:${wordsOf(fileVars)})\\b` : ''].filter(Boolean).join('|') || '(?!)';

  for (let pass = 0; pass < 4; pass += 1) {
    const before = fileVars.size;
    const expr = new RegExp(`^(?:await\\s+)?(?:${fileExpr()})\\s*(?:$|or\\b|\\[)`);
    for (const l of body) {
      const text = (lines[l - 1] ?? '').trim();
      const assign = /^(\w+)\s*(?::\s*[\w.[\], ]+)?=\s*(.+)$/.exec(text);
      if (assign !== null && !/^[=]/.test(assign[2]!) && expr.test(assign[2]!.trim())) fileVars.add(assign[1]!);
      const loop = /^(?:async\s+)?for\s+(\w+)\s+in\s+(.+):/.exec(text);
      if (loop !== null && new RegExp(fileExpr()).test(loop[2]!)) fileVars.add(loop[1]!);
    }
    if (fileVars.size === before) break;
  }
  if (!withRequest && fileVars.size === 0 && (options.content?.size ?? 0) === 0) return facts;
  const FILE = fileExpr();

  const nameVars = new Set<string>();
  const sizeVars = new Set<string>();
  const contentVars = new Set<string>(options.content);
  const tempVars = new Set<string>();
  const carriedVars = new Set<string>(options.content);
  const carriedExpr = (): string => [FILE, carriedVars.size > 0 ? `\\b(?:${wordsOf(carriedVars)})\\b` : ''].filter(Boolean).join('|');
  for (let pass = 0; pass < 4; pass += 1) {
    const before = nameVars.size + sizeVars.size + contentVars.size + tempVars.size + carriedVars.size;
    for (const l of body) {
      const text = (lines[l - 1] ?? '').trim();
      const withTemp = /^with\s+.*\btempfile\s*\.\s*\w+\s*\(.*\bas\s+(\w+)\s*:/.exec(text);
      if (withTemp !== null) tempVars.add(withTemp[1]!);
      const assign = /^([\w, ]+?)\s*=\s*(.+)$/.exec(text);
      if (assign === null || /^[=]/.test(assign[2]!)) continue;
      const targets = assign[1]!.split(',').map((t) => t.trim()).filter(Boolean);
      const rhs = assign[2]!;
      const mentions = (set: Set<string>): boolean => set.size > 0 && new RegExp(`\\b(?:${wordsOf(set)})\\b`).test(rhs);
      if (new RegExp(`(?:${FILE})\\s*\\.\\s*filename\\b`).test(rhs) || mentions(nameVars)) targets.forEach((t) => nameVars.add(t));
      if (new RegExp(`(?:${FILE})\\s*\\.\\s*(?:read|stream)\\b`).test(rhs)) targets.forEach((t) => contentVars.add(t));
    }
    for (const l of body) {
      const loop = new RegExp(`^(?:async\\s+)?for\\s+(\\w+)\\s+in\\s+(?:${FILE})\\s*\\.\\s*(?:chunks|stream|read)\\b`).exec((lines[l - 1] ?? '').trim());
      if (loop !== null) contentVars.add(loop[1]!);
    }
    for (const l of body) {
      const text = (lines[l - 1] ?? '').trim();
      const CARRIED = carriedExpr();
      const carries = (rhs: string): boolean => new RegExp(CARRIED).test(withoutInert(rhs, CARRIED));
      const assign = /^([\w, ]+?)\s*(?::\s*[\w.[\], ]+)?[+|]?=\s*(.+)$/.exec(text);
      if (assign !== null && !/^[=]/.test(assign[2]!) && carries(assign[2]!)) assign[1]!.split(',').map((t) => t.trim()).filter(Boolean).forEach((t) => carriedVars.add(t));
      const loop = /^(?:async\s+)?for\s+([\w, ]+?)\s+in\s+(.+):/.exec(text);
      if (loop !== null && carries(loop[2]!)) loop[1]!.split(',').map((t) => t.trim()).filter(Boolean).forEach((t) => carriedVars.add(t));
      for (const bound of text.matchAll(/(?:^(?:async\s+)?with\s+|,\s*)([^,]+?)\s+as\s+(\w+)/g)) {
        if (/^(?:async\s+)?with\b/.test(text) && carries(bound[1]!)) carriedVars.add(bound[2]!);
      }
    }
    for (const l of body) {
      const text = (lines[l - 1] ?? '').trim();
      const assign = /^([\w, ]+?)\s*=\s*(.+)$/.exec(text);
      if (assign === null || /^[=]/.test(assign[2]!)) continue;
      const targets = assign[1]!.split(',').map((t) => t.trim()).filter(Boolean);
      const rhs = assign[2]!;
      const mentions = (set: Set<string>): boolean => set.size > 0 && new RegExp(`\\b(?:${wordsOf(set)})\\b`).test(rhs);
      if (new RegExp(`(?:${FILE})\\s*\\.\\s*(?:tell\\s*\\(|content_length\\b|size\\b)`).test(rhs)
        || /\blen\s*\(/.test(rhs) && (new RegExp(FILE).test(rhs) || mentions(contentVars))) targets.forEach((t) => sizeVars.add(t));
      if (/\btempfile\s*\.\s*\w+\s*\(/.test(rhs) || mentions(tempVars)) targets.forEach((t) => tempVars.add(t));
    }
    if (nameVars.size + sizeVars.size + contentVars.size + tempVars.size + carriedVars.size === before) break;
  }
  const NAME = [`(?:${FILE})\\s*\\.\\s*filename\\b`, nameVars.size > 0 ? `\\b(?:${wordsOf(nameVars)})\\b` : ''].filter(Boolean).join('|');
  const lookupVars = new Set<string>();
  const LOOKUP_KEY = strict ? `${NAME}|(?:${FILE})\\s*\\.\\s*(?:content_type|mimetype)\\b` : NAME;
  for (const l of body) {
    const text = (lines[l - 1] ?? '').trim();
    const lookup = new RegExp(`^(\\w+)\\s*=\\s*([A-Za-z_][\\w.]*)\\s*\\.\\s*get\\s*\\(\\s*(?:${LOOKUP_KEY})`).exec(text);
    if (lookup !== null && !fileVars.has(lookup[1]!) && (!strict || fixedCollection(lines, scope, lookup[2]!, 0))) lookupVars.add(lookup[1]!);
  }

  const storeLines: number[] = [];
  const helperChecks: { line: number; typed: boolean; sized: boolean }[] = [];
  for (const l of body) {
    const text = lines[l - 1] ?? '';
    const save = new RegExp(`(?:${FILE})\\s*\\.\\s*save\\s*\\(`).exec(text);
    if (save !== null) {
      const target = callArguments(text, save.index + save[0].length - 1);
      const temp = tempVars.size > 0 && new RegExp(`\\b(?:${wordsOf(tempVars)})\\b`).test(target);
      if (!temp) { facts.stored = true; storeLines.push(l); }
    }
    if (new RegExp(`\\bcopyfileobj\\s*\\(\\s*(?:${FILE})|\\.\\s*write\\s*\\(\\s*(?:${FILE})\\s*\\.\\s*(?:read|stream)`).test(text)) { facts.stored = true; storeLines.push(l); }
    const written = contentVars.size > 0 ? new RegExp(`(\\w+)\\s*\\.\\s*write\\s*\\(\\s*(?:${wordsOf(contentVars)})\\b`).exec(text) : null;
    if (written !== null && !tempVars.has(written[1]!)) { facts.stored = true; storeLines.push(l); }
    if (new RegExp(`^\\s*return\\s+(?:${FILE})\\s*$|^\\s*[\\w.]+\\.\\w+\\s*=\\s*(?:${FILE})\\s*$`).test(text)) { facts.stored = true; storeLines.push(l); }
    const CARRIED = carriedExpr();
    const kept = /^\s*return\s+(.+)$/.exec(text)
      ?? /^\s*(?!return\b)(\w+)(?:\s*\.\s*\w+|\[.*\])+\s*(?::[^=]+)?(?:[-+*/|&@%^]|\/\/|\*\*|<<|>>)?=(?!=)\s*(.+)$/.exec(text);
    if (kept !== null) {
      const rhs = withContinuation(lines, l, kept[2] ?? kept[1]!, scope.endLine);
      const base = kept[2] === undefined ? undefined : kept[1]!;
      if ((base === undefined || !tempVars.has(base)) && new RegExp(CARRIED).test(withoutInert(rhs, CARRIED))) { facts.stored = true; storeLines.push(l); }
    }
    for (const call of text.matchAll(/([A-Za-z_][\w.]*)\s*\(/g)) {
      const open = call.index + call[0].length - 1;
      const args = splitTop(callArguments(text, open));
      if (tempVars.size > 0 && args.some((arg) => new RegExp(`\\b(?:${wordsOf(tempVars)})\\b`).test(arg))
        && (/^(?:shutil\s*\.\s*(?:copy\w*|move)|os\s*\.\s*(?:rename|replace|link))$/.test(call[1]!) || defsNamed(lines, call[1]!).length > 0)) {
        facts.stored = true;
        storeLines.push(l);
      }
      const position = args.findIndex((arg) => new RegExp(`^\\s*(?:\\w+\\s*=\\s*)?(?:\\*\\s*)?(?:${FILE})\\s*$`).test(arg));
      if (position < 0) {
        const carried = args.findIndex((arg) => new RegExp(CARRIED).test(withoutInert(arg.replace(/^\s*\w+\s*=(?!=)/, ''), CARRIED)));
        if (carried < 0) continue;
        const callee = call[1]!;
        if (NOT_STORING_CALLS.has(callee) || IN_MEMORY_CALLEE.test(callee) || /^(?:log|logger|logging)\b/.test(callee)) continue;
        if (tempVars.size > 0 && new RegExp(`^(?:${wordsOf(tempVars)})\\.write\\w*$`).test(callee)) continue;
        const helper = depth < MAX_HELPER_DEPTH && !callee.includes('.') ? defsNamed(lines, callee).at(0) : undefined;
        const bare = /^\s*(?:(\w+)\s*=\s*)?\w+\s*$/.exec(args[carried]!);
        const param = bare === null ? undefined : bare[1] ?? helper?.params[carried];
        if (helper === undefined || param === undefined || scopeFacts(entry, lines, helper, new Set([param]), false, depth + 1, { strict }).stored) { facts.stored = true; storeLines.push(l); }
        continue;
      }
      const callee = call[1]!;
      if (NOT_STORING_CALLS.has(callee) || /^(?:log|logger|logging)\b/.test(callee)) continue;
      const helper = depth < MAX_HELPER_DEPTH && !callee.includes('.') ? defsNamed(lines, callee).at(0) : undefined;
      if (helper === undefined) { facts.stored = true; storeLines.push(l); continue; }
      const keyword = /^\s*(\w+)\s*=/.exec(args[position]!)?.[1];
      const param = keyword ?? helper.params[position];
      if (param === undefined) { facts.stored = true; storeLines.push(l); continue; }
      const inner = scopeFacts(entry, lines, helper, new Set([param]), false, depth + 1, { strict });
      if (inner.stored) { facts.stored = true; storeLines.push(l); }
      if (strict) { helperChecks.push({ line: l, typed: inner.typeChecked, sized: inner.sizeChecked }); continue; }
      facts.typeChecked ||= inner.typeChecked;
      facts.sizeChecked ||= inner.sizeChecked;
    }
  }
  const beforeAnyStore = (l: number): boolean => !strict || storeLines.every((s) => s >= l);
  for (const check of helperChecks) {
    if (!beforeAnyStore(check.line)) continue;
    facts.typeChecked ||= check.typed;
    facts.sizeChecked ||= check.sized;
  }

  const governs = (l: number): boolean => {
    const block = blockOf(lines, l);
    if (block.start === l) return REFUSES.test((lines[l - 1] ?? '').slice((lines[l - 1] ?? '').lastIndexOf(':') + 1));
    if (storeLines.some((s) => s >= block.start && s <= block.end)) return true;
    const blockIndent = indentOf(lines[block.start - 1] ?? '');
    for (let k = block.start; k <= block.end; k += 1) {
      const text = lines[k - 1] ?? '';
      if (text.trim() !== '' && indentOf(text) === blockIndent && REFUSES.test(text)) return true;
    }
    return false;
  };
  const role = (l: number): 'refuses' | 'holds' | undefined => {
    const block = blockOf(lines, l);
    if (block.start === l) return REFUSES.test((lines[l - 1] ?? '').slice((lines[l - 1] ?? '').lastIndexOf(':') + 1)) ? 'refuses' : undefined;
    if (storeLines.some((s) => s >= block.start && s <= block.end)) return 'holds';
    const blockIndent = indentOf(lines[block.start - 1] ?? '');
    for (let k = block.start; k <= block.end; k += 1) {
      const text = lines[k - 1] ?? '';
      if (text.trim() !== '' && indentOf(text) === blockIndent && REFUSES.test(text)) return 'refuses';
    }
    return undefined;
  };
  const typeVars = new Set<string>();
  if (strict) {
    for (const l of body) {
      const assign = /^(\w+)\s*=\s*(.+)$/.exec((lines[l - 1] ?? '').trim());
      if (assign !== null && !/^[=]/.test(assign[2]!) && new RegExp(`(?:${FILE})\\s*\\.\\s*(?:content_type|mimetype)\\b`).test(assign[2]!)) typeVars.add(assign[1]!);
    }
  }
  const TYPE = [NAME, strict ? `(?:${FILE})\\s*\\.\\s*(?:content_type|mimetype)\\b` : '', typeVars.size > 0 ? `\\b(?:${wordsOf(typeVars)})\\b` : ''].filter(Boolean).join('|');
  const sniffVars = new Set<string>();
  if (strict && contentVars.size > 0) {
    for (const l of body) {
      const call = /^(\w+)\s*=\s*(?:await\s+)?([A-Za-z_]\w*)\s*\((.*)\)\s*$/.exec((lines[l - 1] ?? '').trim());
      if (call === null) continue;
      const position = splitTop(call[3]!).findIndex((arg) => new RegExp(`^\\s*(?:\\w+\\s*=\\s*)?(?:${wordsOf(contentVars)})\\s*$`).test(arg));
      const helper = position < 0 ? undefined : defsNamed(lines, call[2]!).at(0);
      const param = helper?.params[position];
      if (helper !== undefined && param !== undefined && bodySniffs(lines, helper, param)) sniffVars.add(call[1]!);
    }
  }
  const SIZE = [
    sizeVars.size > 0 ? `\\b(?:${wordsOf(sizeVars)})\\b` : '',
    `(?:${FILE})\\s*\\.\\s*(?:content_length|size)\\b`,
    `\\blen\\s*\\(\\s*(?:(?:${FILE})|${contentVars.size > 0 ? `\\b(?:${wordsOf(contentVars)})\\b` : '(?!)'})`,
  ].filter(Boolean).join('|');
  const typeOnAMiss = (sniffed: boolean) => (part: string): boolean | undefined => {
    const flat = flatten(part);
    const KIND = wordsOf([...lookupVars, ...(sniffed ? sniffVars : [])]);
    const membership = /(?<![\w.])(not\s+)?in(?![\w.])/.exec(flat);
    if (membership !== null) {
      const left = part.slice(0, membership.index).trim();
      const right = part.slice(membership.index + membership[0].length).trim();
      if (!/^(?:[A-Za-z_]\w*(?:\s*\.\s*(?:items|values|keys)\s*\(\s*\))?|[[{(][^]*[\]})])$/.test(right)) return undefined;
      if (/^[[{(]/.test(right) && callArguments(right, 0).length + 2 !== right.length) return undefined;
      if (!fixedCollection(lines, scope, right, 0)) return undefined;
      const tested = new RegExp(TYPE).test(left) && !new RegExp(`^(?:${TYPE})$`).test(right);
      if (!tested && !new RegExp(`^(?:${KIND})$`).test(left)) return undefined;
      return membership[1] !== undefined;
    }
    if (new RegExp(`^(?:${NAME})(?:\\s*\\.\\s*lower\\s*\\(\\s*\\))?\\s*\\.\\s*endswith\\s*\\(\\s*(?:"[^"]*"|'[^']*'|\\(\\s*(?:(?:"[^"]*"|'[^']*')\\s*,?\\s*)+\\))\\s*\\)$`).test(part)) return false;
    const call = /^([A-Za-z_]\w*)\s*\(/.exec(part);
    if (call !== null && callArguments(part, call[0].length - 1).length + call[0].length + 1 === part.length) {
      const args = callArguments(part, call[0].length - 1);
      const helper = new RegExp(TYPE).test(args) || new RegExp(`^\\s*(?:${FILE})\\s*$`).test(args) ? defsNamed(lines, call[1]!).at(0) : undefined;
      return helper !== undefined && bodyTestsMembership(lines, helper, true) ? false : undefined;
    }
    const kind = new RegExp(`^(?:${KIND})(?:\\s+is(\\s+not)?\\s+None)?$`).exec(part);
    if (kind === null) return undefined;
    return /\bis\s+None$/.test(part);
  };
  const sizeOnAMiss = (part: string): boolean | undefined => {
    const flat = flatten(part);
    const operators = [...flat.matchAll(/(?<![<>=!-])(?:<=|>=|==|!=|<|>)(?![<>=])/g)];
    if (operators.length === 0) return undefined;
    const sides = [...operators.map((o, i) => part.slice(i === 0 ? 0 : operators[i - 1]!.index + operators[i - 1]![0].length, o.index)), part.slice(operators.at(-1)!.index + operators.at(-1)![0].length)];
    const big = new RegExp(SIZE);
    return andOnAMiss(operators.map((o, i) => {
      const [left, right] = [big.test(sides[i]!), big.test(sides[i + 1]!)];
      if (left === right || o[0] === '==' || o[0] === '!=') return undefined;
      return left === o[0].startsWith('>');
    }));
  };
  for (const l of body) {
    const text = lines[l - 1] ?? '';
    if (!/^\s*(?:if|elif)\b/.test(text)) continue;
    if (!beforeAnyStore(l)) continue;
    const condition = text.replace(/:\s*[^:]*$/, '');
    if (strict) {
      const how = role(l);
      if (how === undefined) continue;
      const test = condition.replace(/^\s*(?:if|elif)\b/, '');
      if (conditionOnAMiss(test, typeOnAMiss(how === 'refuses')) === (how === 'refuses')) facts.typeChecked = true;
      if (conditionOnAMiss(test, sizeOnAMiss) === (how === 'refuses')) facts.sizeChecked = true;
      continue;
    }
    let typed = false;
    for (const m of condition.matchAll(/\bin\s+([A-Za-z_][\w.]*|[[{(])/g)) {
      const left = condition.slice(0, m.index).split(/\b(?:and|or)\b/).pop() ?? '';
      if (/\bfor\b/.test(left)) continue;
      if (new RegExp(NAME).test(left) && !new RegExp(`^(?:${NAME})$`).test(m[1]!)) typed = true;
    }
    if (lookupVars.size > 0 && new RegExp(`\\b(?:${wordsOf(lookupVars)})\\b`).test(condition)) typed = true;
    for (const call of condition.matchAll(/([A-Za-z_]\w*)\s*\(/g)) {
      const args = callArguments(condition, call.index + call[0].length - 1);
      if (!new RegExp(NAME).test(args) && !new RegExp(`^\\s*(?:${FILE})\\s*$`).test(args)) continue;
      const helper = defsNamed(lines, call[1]!).at(0);
      if (helper !== undefined && bodyTestsMembership(lines, helper)) typed = true;
    }
    if (typed && governs(l)) facts.typeChecked = true;
    const sized = /[<>]/.test(condition) && new RegExp(SIZE).test(condition);
    if (sized && governs(l)) facts.sizeChecked = true;
  }
  return facts;
}

const factsCache = new WeakMap<FileMapEntry, Map<number, UploadFacts>>();

export function pythonUploadFacts(entry: FileMapEntry, line: number): UploadFacts | undefined {
  const lines = maskedLines(entry.content ?? '');
  const scope = enclosingDef(lines, line);
  if (scope === undefined) return undefined;
  let byScope = factsCache.get(entry);
  if (byScope === undefined) { byScope = new Map(); factsCache.set(entry, byScope); }
  const cached = byScope.get(scope.defLine);
  if (cached !== undefined) return cached;
  const facts = scopeFacts(entry, lines, scope, new Set(), true, 0);
  byScope.set(scope.defLine, facts);
  return facts;
}

export interface FastapiUpload { name: string; line: number; defLine: number; facts: UploadFacts; inMemory: boolean }

const ROUTE_DECORATOR = /^\s*@\s*[A-Za-z_][\w.]*\s*\.\s*(?:get|post|put|patch|delete|api_route|route)\s*\(/;
const FASTAPI_IMPORT = /^\s*(?:from|import)\s+(?:fastapi|starlette)\b/m;

function decoratorAbove(lines: string[], below: number): number | undefined {
  let depth = 0;
  for (let k = below - 1; k >= 0; k -= 1) {
    const text = lines[k] ?? '';
    for (const c of text) depth += '([{'.includes(c) ? 1 : ')]}'.includes(c) ? -1 : 0;
    if (depth >= 0) return /^\s*@/.test(text) ? k : undefined;
  }
  return undefined;
}

function uploadParameters(lines: string[], defLine: number): { params: { name: string; line: number; bytes: boolean }[]; headerEnd: number } {
  const out: { name: string; line: number; bytes: boolean }[] = [];
  let depth = 0;
  let started = false;
  let current = '';
  let currentLine = defLine;
  const close = (): void => {
    const m = /^\s*(\w+)([^]*)$/.exec(current);
    if (m !== null && m[1] !== 'self' && m[1] !== 'cls') {
      const rest = m[2]!;
      const upload = /\bUploadFile\b/.test(rest);
      if (upload || /\bFile\s*\(/.test(rest)) out.push({ name: m[1]!, line: currentLine, bytes: !upload && /\bbytes\b/.test(rest) });
    }
    current = '';
  };
  for (let l = defLine; l <= lines.length; l += 1) {
    for (const c of lines[l - 1] ?? '') {
      if (!started) { if (c === '(') { started = true; depth = 1; } continue; }
      if (c === '(' || c === '[' || c === '{') depth += 1;
      if (c === ')' || c === ']' || c === '}') { depth -= 1; if (depth === 0) { close(); return { params: out, headerEnd: l }; } }
      if (c === ',' && depth === 1) { close(); continue; }
      if (current.trim() === '' && /\S/.test(c)) currentLine = l;
      current += c;
    }
    current += '\n';
  }
  return { params: out, headerEnd: defLine };
}

function provedInMemory(lines: string[], scope: PyScope, headerEnd: number, name: string, bytes: boolean): boolean {
  let text = lines.slice(headerEnd, scope.endLine).join('\n');
  const U = `\\b${escape(name)}\\b`;
  const READ = `(?:await\\s+)?${U}\\s*\\.\\s*(?:file\\s*\\.\\s*)?read\\s*\\(\\s*\\)`;
  const DECODE = '(?:\\s*\\.\\s*decode\\s*\\([^()\\n]*\\))?';
  const content = new Set<string>(bytes ? [name] : []);
  for (let pass = 0; pass < 4; pass += 1) {
    const before = content.size;
    const source = [bytes ? '' : READ, content.size > 0 ? `\\b(?:${wordsOf(content)})\\b` : ''].filter(Boolean).join('|');
    for (const m of text.matchAll(new RegExp(`^[ \\t]*(\\w+)[ \\t]*=[ \\t]*(?:${source})${DECODE}[ \\t]*$`, 'gm'))) content.add(m[1]!);
    if (content.size === before) break;
  }
  const ARG = [bytes ? '' : READ, content.size > 0 ? `\\b(?:${wordsOf(content)})\\b` : ''].filter(Boolean).join('|');
  const locals = wordsOf([...content].filter((c) => c !== name)) || '(?!)';
  text = text.replace(new RegExp(`^[ \\t]*(?:${locals})[ \\t]*=[ \\t]*(?:${ARG})${DECODE}[ \\t]*$`, 'gm'), '_');
  let parsed = 0;
  const parse = (pattern: RegExp): void => { text = text.replace(pattern, () => { parsed += 1; return '_'; }); };
  parse(new RegExp(`(?<![\\w.])(?:json\\s*\\.\\s*loads|yaml\\s*\\.\\s*safe_load)\\s*\\(\\s*(?:${ARG})${DECODE}\\s*\\)`, 'g'));
  text = text.replace(new RegExp(`(?<![\\w.])len\\s*\\(\\s*(?:${ARG})\\s*\\)`, 'g'), '_');
  parse(new RegExp(`(?<![\\w.])csv\\s*\\.\\s*(?:reader|DictReader)\\s*\\(\\s*(?:io\\s*\\.\\s*)?StringIO\\s*\\(\\s*(?:${ARG})\\s*\\.\\s*decode\\s*\\([^()\\n]*\\)\\s*\\)\\s*(?:,[^()\\n]*)?\\)`, 'g'));
  if (!bytes) parse(new RegExp(`(?<![\\w.])json\\s*\\.\\s*load\\s*\\(\\s*${U}\\s*\\.\\s*file\\s*\\)`, 'g'));
  if (parsed === 0) return false;
  if (!bytes) {
    text = text.replace(new RegExp(`${U}\\s*\\.\\s*(?:filename|content_type|size|headers)\\b(?!\\s*[(=])`, 'g'), '_');
    text = text.replace(new RegExp(`^[ \\t]*(?:await\\s+)?${U}\\s*\\.\\s*(?:close|seek)\\s*\\([^()\\n]*\\)[ \\t]*$`, 'gm'), '_');
  }
  const left = [U, content.size > 0 ? `\\b(?:${wordsOf(content)})\\b` : ''].filter(Boolean).join('|');
  return !new RegExp(left).test(text);
}

export function pythonUploadDefLine(entry: FileMapEntry, line: number): number | undefined {
  return enclosingDef(maskedLines(entry.content ?? ''), line)?.defLine;
}

const fastapiCache = new WeakMap<FileMapEntry, FastapiUpload[]>();
export function fastapiUploads(entry: FileMapEntry): FastapiUpload[] {
  const cached = fastapiCache.get(entry);
  if (cached !== undefined) return cached;
  const out: FastapiUpload[] = [];
  const content = entry.content ?? '';
  if (entry.extension === '.py' && FASTAPI_IMPORT.test(content) && /\bUploadFile\b|\bFile\s*\(/.test(content)) {
    const lines = maskedLines(content);
    lines.forEach((text, i) => {
      if (!/^\s*(?:async\s+)?def\s+\w+\s*\(/.test(text)) return;
      let routed = false;
      for (let at = decoratorAbove(lines, i); at !== undefined; at = decoratorAbove(lines, at)) {
        if (ROUTE_DECORATOR.test(lines[at] ?? '')) routed = true;
      }
      if (!routed) return;
      const scope = scopeOfDef(lines, i + 1);
      if (scope === undefined) return;
      const { params, headerEnd } = uploadParameters(lines, i + 1);
      for (const param of params) {
        const facts = scopeFacts(entry, lines, { ...scope, defLine: headerEnd }, param.bytes ? new Set() : new Set([param.name]), false, 0, { strict: true, content: param.bytes ? new Set([param.name]) : undefined });
        out.push({ name: param.name, line: param.line, defLine: i + 1, facts, inMemory: provedInMemory(lines, scope, headerEnd, param.name, param.bytes) });
      }
    });
  }
  fastapiCache.set(entry, out);
  return out;
}

export function pythonNameIsStoredRecord(entry: FileMapEntry, line: number, name: string): boolean {
  const lines = maskedLines(entry.content ?? '');
  const scope = enclosingDef(lines, line);
  if (scope === undefined || scope.params.includes(name)) return false;
  const bindings: string[] = [];
  for (const l of bodyLines(lines, scope)) {
    const text = (lines[l - 1] ?? '').trim();
    const assign = new RegExp(`^${escape(name)}\\s*(?::[^=]+)?=\\s*(.+)$`).exec(text);
    if (assign !== null && !assign[1]!.startsWith('=')) bindings.push(assign[1]!);
    const loop = new RegExp(`^(?:async\\s+)?for\\s+(?:\\w+\\s*,\\s*)*${escape(name)}(?:\\s*,\\s*\\w+)*\\s+in\\s+(.+):`).exec(text);
    if (loop !== null) bindings.push(loop[1]!);
    const asBinding = new RegExp(`^(?:async\\s+)?with\\s+(.+)\\bas\\s+${escape(name)}\\b`).exec(text);
    if (asBinding !== null) bindings.push(asBinding[1]!);
  }
  if (bindings.length === 0) return false;
  return bindings.every((rhs) => !/\brequest\b|\bfiles\b|\bFILES\b|\bUploadFile\b|\bform\b/.test(rhs) && !scope.params.some((p) => new RegExp(`\\b${escape(p)}\\b`).test(rhs)));
}

const capCache = new WeakMap<FileMapEntry[], boolean>();
export function flaskBodyCapSet(entries: FileMapEntry[]): boolean {
  const cached = capCache.get(entries);
  if (cached !== undefined) return cached;
  const set = entries.some((entry) => {
    if (entry.extension !== '.py') return false;
    const content = entry.content ?? '';
    if (!content.includes('MAX_CONTENT_LENGTH')) return false;
    const lines = maskedLines(content);
    const sourceLines = content.split('\n');
    return sourceLines.some((text, i) => {
      const code = lines[i] ?? '';
      if (code.trim() === '' || /^\s*#/.test(text)) return false;
      return /^\s*MAX_CONTENT_LENGTH\s*(?::[^=]+)?=\s*[^=\s]/.test(code)
        || /\[\s*['"]MAX_CONTENT_LENGTH['"]\s*\]\s*=\s*[^=\s]/.test(text) && /\]\s*=\s*[^=\s]/.test(code)
        || /\bMAX_CONTENT_LENGTH\s*=\s*[^=\s]/.test(code) && /\b(?:update|dict|Flask|from_mapping)\s*\(/.test(code);
    });
  });
  capCache.set(entries, set);
  return set;
}
