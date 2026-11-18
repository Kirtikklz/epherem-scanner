import type { RuleContext } from './types.js';
import { blockOf, defsNamed, enclosingDef, indentOf, maskedLines, type PyScope } from './pythonScope.js';

const RAISING_VERIFY = /\bconstruct_event\s*\(|\bverify_header\s*\(|\bWebhook\s*\([^)\n]*\)\s*\.\s*verify\s*\(/;
const COMPARE = /\bcompare_digest\s*\(/;
const HMAC_NEW = /\bhmac\s*\.\s*new\s*\(/;
const EQUALITY = /[!=]=/;
const DIGEST_CALL = /\b(?:hex)?digest\s*\(/;
const LITERAL = /^(?:None|True|False|-?\d[\w.]*|[rRbBuUfF]{0,2}(['"])[^'"\n]*\1|\[\s*\]|\{\s*\}|\(\s*\)|)$/;
const BODY_READ = /\brequest\s*\.\s*(?:get_json|get_data|json|data|body)\b/;
const IF_HEADER = /^\s*(?:if|elif)\b/;
const REFUSES = /^\s*(?:raise\b|return\b|abort\s*\()|\babort\s*\(/;
const WRITE = /\.\s*(?:save|create|add|commit|delete|update|bulk_create|insert|insert_one|execute)\s*\(|\binsert\s+into\b|(?<![.\w])\w*(?:create|update|insert|delete|fulfil|grant|activate|provision|send|charge|subscription|payment|invoice|record|save|process|handle|apply|credit|refund)\w*\s*\(/i;
const MAX_HELPER_DEPTH = 2;

interface PyFileLines { path: string; lines: string[] }

function bodyLines(lines: string[], scope: PyScope): number[] {
  const out: number[] = [];
  for (let l = scope.defLine + 1; l <= scope.endLine; l += 1) out.push(l);
  return out;
}

function blockRefuses(lines: string[], header: number): boolean {
  const { start, end } = blockOf(lines, header);
  for (let l = start; l <= end; l += 1) {
    const text = l === header ? (lines[l - 1] ?? '').slice((lines[l - 1] ?? '').lastIndexOf(':') + 1) : (lines[l - 1] ?? '');
    if (REFUSES.test(text)) return true;
  }
  return false;
}

function digestNames(lines: string[], scope: PyScope | undefined): Set<string> {
  const seen = new Map<string, boolean>();
  if (scope === undefined) return new Set();
  for (const l of bodyLines(lines, scope)) {
    const m = /^\s*([A-Za-z_]\w*)\s*(?::[^=\n]+)?=(?!=)(.*)$/.exec(lines[l - 1] ?? '');
    if (m === null) continue;
    const mac = HMAC_NEW.test(m[2]!) || DIGEST_CALL.test(m[2]!);
    seen.set(m[1]!, (seen.get(m[1]!) ?? true) && mac);
  }
  return new Set([...seen].filter(([, mac]) => mac).map(([name]) => name));
}

function digestEquality(lines: string[], line: number): boolean {
  const text = lines[line - 1] ?? '';
  const digests = digestNames(lines, enclosingDef(lines, line));
  const isDigest = (side: string): boolean => DIGEST_CALL.test(side)
    || digests.has(/^([A-Za-z_]\w*)(?:\s*\.\s*\w+\s*\(\s*\))*$/.exec(side)?.[1] ?? '');
  const condition = text.replace(IF_HEADER, '').slice(0, Math.max(0, text.replace(IF_HEADER, '').lastIndexOf(':')));
  for (const part of condition.split(/\band\b|\bor\b/)) {
    const m = /^(.*?)[!=]=(.*)$/.exec(part);
    if (m === null) continue;
    const [left, right] = [m[1]!, m[2]!].map((side) => side.trim().replace(/^not\s+/, '').replace(/^\(+|\)+$/g, '').trim());
    if ((isDigest(left!) && !LITERAL.test(right!)) || (isDigest(right!) && !LITERAL.test(left!))) return true;
  }
  return false;
}

function decidingCompare(lines: string[], line: number): boolean {
  const text = lines[line - 1] ?? '';
  if (!IF_HEADER.test(text)) return false;
  const compares = COMPARE.test(text) || (EQUALITY.test(text) && digestEquality(lines, line));
  return compares && blockRefuses(lines, line);
}

function exceptsRefuse(lines: string[], tryLine: number, endLine: number): boolean {
  const indent = indentOf(lines[tryLine - 1] ?? '');
  for (let l = tryLine + 1; l <= endLine; l += 1) {
    const text = lines[l - 1] ?? '';
    if (text.trim() === '' || indentOf(text) > indent) continue;
    if (indentOf(text) < indent) break;
    if (/^\s*except\b/.test(text)) {
      if (!blockRefuses(lines, l)) return false;
    } else if (/^\s*finally\s*:/.test(text)) {
      const { start, end } = blockOf(lines, l);
      for (let k = start; k <= end; k += 1) if (/^\s*return\b/.test(lines[k - 1] ?? '')) return false;
    } else if (!/^\s*else\s*:/.test(text)) break;
  }
  return true;
}

function swallowed(lines: string[], scope: PyScope, line: number): boolean {
  let indent = indentOf(lines[line - 1] ?? '');
  for (let l = line - 1; l > scope.defLine; l -= 1) {
    const text = lines[l - 1] ?? '';
    if (text.trim() === '' || indentOf(text) >= indent) continue;
    indent = indentOf(text);
    if (/^\s*try\s*:/.test(text) && !exceptsRefuse(lines, l, scope.endLine)) return true;
  }
  return false;
}

type Verdict = 'refuses' | 'returns' | 'none';

function helperVerdict(files: readonly PyFileLines[], name: string, depth: number): Verdict {
  const defs = files.flatMap((file) => defsNamed(file.lines, name).map((scope) => ({ file, scope })));
  if (defs.length === 0) return 'none';
  let all: Verdict | undefined;
  for (const { file, scope } of defs) {
    const verdict = scopeVerdict(files, file.lines, scope, depth + 1);
    if (verdict === 'none') return 'none';
    all = all === 'returns' || verdict === 'returns' ? 'returns' : 'refuses';
  }
  return all ?? 'none';
}

function scopeVerdict(files: readonly PyFileLines[], lines: string[], scope: PyScope, depth: number): Verdict {
  const body = bodyLines(lines, scope);
  const hmacUsed = body.some((l) => HMAC_NEW.test(lines[l - 1] ?? '') || COMPARE.test(lines[l - 1] ?? ''));
  for (const l of body) {
    const text = lines[l - 1] ?? '';
    if (swallowed(lines, scope, l)) continue;
    if (RAISING_VERIFY.test(text)) return 'refuses';
    if (hmacUsed && decidingCompare(lines, l)) return 'refuses';
  }
  for (const l of body) {
    const text = lines[l - 1] ?? '';
    if (/^\s*return\b/.test(text) && COMPARE.test(text)) return 'returns';
  }
  if (depth >= MAX_HELPER_DEPTH) return 'none';
  for (const l of body) {
    const verdict = callVerdict(files, lines, l, depth);
    if (verdict !== 'none') return verdict;
  }
  return 'none';
}

function callVerdict(files: readonly PyFileLines[], lines: string[], line: number, depth: number): Verdict {
  const text = lines[line - 1] ?? '';
  for (const call of text.matchAll(/(?<![\w.])([A-Za-z_]\w*)\s*\(/g)) {
    const name = call[1]!;
    if (/^(?:if|elif|while|return|not|and|or|print|len|str|int|bytes|dict|list|set|tuple|isinstance|getattr|super)$/.test(name)) continue;
    const verdict = helperVerdict(files, name, depth);
    if (verdict === 'refuses') return 'refuses';
    if (verdict === 'returns' && IF_HEADER.test(text) && new RegExp(String.raw`\bnot\s+(?:await\s+)?${name}\s*\(`).test(text) && blockRefuses(lines, line)) return 'refuses';
  }
  return 'none';
}

function feedsDigest(lines: string[], scope: PyScope, text: string): boolean {
  const receiver = /(?<![\w.])([A-Za-z_]\w*)\s*\.\s*update\s*\(/.exec(text)?.[1];
  if (receiver === undefined || WRITE.test(text.replace(/[A-Za-z_]\w*\s*\.\s*update\s*\(/, ''))) return false;
  const bound = new RegExp(String.raw`^\s*${receiver}\s*=\s*(?:hmac\s*\.\s*new|hashlib\s*\.\s*\w+)\s*\(`);
  return bodyLines(lines, scope).some((l) => bound.test(lines[l - 1] ?? ''));
}

const filesCache = new WeakMap<object, PyFileLines[]>();

function pythonFiles(context: RuleContext): PyFileLines[] {
  let files = filesCache.get(context.fileMap);
  if (files === undefined) {
    files = context.fileMap.entries
      .filter((entry) => entry.extension === '.py')
      .map((entry) => ({ path: entry.path, lines: maskedLines(entry.content ?? '') }));
    filesCache.set(context.fileMap, files);
  }
  return files;
}

export function pythonWebhookVerified(context: RuleContext, content: string, line: number): boolean {
  const lines = maskedLines(content);
  const scope = enclosingDef(lines, line);
  if (scope === undefined) return false;
  const files = pythonFiles(context);
  const hmacUsed = bodyLines(lines, scope).some((l) => HMAC_NEW.test(lines[l - 1] ?? '') || COMPARE.test(lines[l - 1] ?? ''));
  const bodies = bodyNames(lines, scope);
  for (const l of bodyLines(lines, scope)) {
    const text = lines[l - 1] ?? '';
    const verified = RAISING_VERIFY.test(text)
      || (hmacUsed && decidingCompare(lines, l))
      || callVerdict(files, lines, l, 0) === 'refuses';
    if (verified && !swallowed(lines, scope, l)) return true;
    if (WRITE.test(text) && !feedsDigest(lines, scope, text)) return false;
    if (givenTheBody(lines, scope, l, bodies)) return false;
  }
  return false;
}

function bodyNames(lines: string[], scope: PyScope): Set<string> {
  const names = new Set<string>();
  for (const l of bodyLines(lines, scope)) {
    const m = /^\s*([A-Za-z_]\w*)\s*(?::[^=\n]+)?=(?!=)(.*)$/.exec(lines[l - 1] ?? '');
    if (m === null || HMAC_NEW.test(m[2]!) || DIGEST_CALL.test(m[2]!) || /\bhashlib\s*\./.test(m[2]!)) continue;
    if (BODY_READ.test(m[2]!) || [...names].some((name) => new RegExp(String.raw`(?<![\w.])${name}\b`).test(m[2]!))) names.add(m[1]!);
  }
  return names;
}

const CHECK_CALL = /(?:^|\.)\s*(?:construct_event|verify_header|compare_digest)$|^\s*hmac\s*\.\s*new$|^\s*hashlib\s*\.\s*\w+$|^\s*json\s*\.\s*loads$/;

function givenTheBody(lines: string[], scope: PyScope, line: number, bodies: Set<string>): boolean {
  const text = lines[line - 1] ?? '';
  let statement = text;
  for (let l = line + 1, depth = parenDepth(text); depth > 0 && l <= scope.endLine; l += 1) {
    statement += `\n${lines[l - 1] ?? ''}`;
    depth += parenDepth(lines[l - 1] ?? '');
  }
  const givesBody = (args: string): boolean => BODY_READ.test(args)
    || [...bodies].some((name) => new RegExp(String.raw`(?<![\w.])${name}\b`).test(args));
  let checkUntil = -1;
  for (const call of statement.matchAll(/((?:[A-Za-z_]\w*\s*\.\s*)*[A-Za-z_]\w*)\s*\(/g)) {
    const open = call.index! + call[0].length - 1;
    const close = closingParen(statement, open);
    const callee = call[1]!;
    if (/^(?:if|elif|while|not|and|or|in|is|return|await|assert|yield|lambda|for|with)$/.test(callee)) continue;
    const check = CHECK_CALL.test(callee) || (/(?:^|\.)\s*update$/.test(callee) && feedsDigest(lines, scope, text));
    if (check) { checkUntil = Math.max(checkUntil, close); continue; }
    if (call.index! < checkUntil) continue;
    if (givesBody(statement.slice(open + 1, close))) return true;
  }
  return false;
}

function parenDepth(text: string): number {
  let depth = 0;
  for (const c of text) { if (c === '(') depth += 1; else if (c === ')') depth -= 1; }
  return depth;
}

function closingParen(text: string, open: number): number {
  let depth = 0;
  for (let i = open; i < text.length; i += 1) {
    if (text[i] === '(') depth += 1;
    else if (text[i] === ')') { depth -= 1; if (depth === 0) return i; }
  }
  return text.length;
}
