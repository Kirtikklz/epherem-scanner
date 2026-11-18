import { maskPython } from './pythonGuards.js';
import { indentOf, scopeOfDef, type PyScope } from './pythonScope.js';

const SOURCE_CHAIN = /^(?:self\.)?(?:flask\.)?request\.(?:args|form|files|values|json|get_json|GET|POST|data|query_params)(?:\.|$)/;

const SOURCE_ANYWHERE = /(?<![\w.])(?:self\s*\.\s*)?(?:flask\s*\.\s*)?request\s*\.\s*(?:args|form|files|values|json|get_json|GET|POST|data|query_params)\b/;

const PASSES_ON = new Set([
  'str', 'text', 'sqlalchemy.text', 'sa.text',
  'os.path.normpath', 'os.path.abspath', 'os.path.realpath',
  'os.path.expanduser', 'os.fspath', 'Path', 'pathlib.Path', 'PurePath', 'PurePosixPath', 'urljoin', 'urllib.parse.urljoin',
]);

const JOINING_METHODS = new Set(['format', 'join']);

const ROUTE_DECORATOR = /^\s*@\s*\w+(?:\s*\.\s*\w+)*\s*\.\s*(?:get|post|put|patch|delete|options|head|api_route)\s*\(/;

const IMPORTS_FASTAPI = /^\s*(?:from\s+fastapi\b|import\s+fastapi\b)/m;

const FRAMEWORK_OBJECT = /^(?:Request|Response|WebSocket|HTTPConnection|BackgroundTasks|Session|AsyncSession)$/;

const CONVERTED_TYPE = /^(?:int|float|bool|UUID|uuid\.UUID|datetime|date|time|datetime\.datetime|datetime\.date|Decimal|PositiveInt|NonNegativeInt|StrictInt|StrictBool)$/;

const KEYWORDS = new Set(['if', 'else', 'elif', 'for', 'in', 'not', 'and', 'or', 'is', 'None', 'True', 'False', 'await', 'lambda', 'return', 'yield', 'async', 'from', 'as']);

function defAround(lines: string[], line: number): PyScope | undefined {
  const indent = indentOf(lines[line - 1] ?? '');
  for (let l = line - 1; l >= 1; l -= 1) {
    const text = lines[l - 1] ?? '';
    if (!DEF_LINE.test(text) || indentOf(text) >= indent) continue;
    const scope = scopeOfDef(lines, l);
    if (scope !== undefined && scope.endLine >= line) return scope;
  }
  return undefined;
}

const DEF_LINE = /^\s*(?:async\s+)?def\s+\w+\s*\(/;

interface Masked {
  masked: string;
  lines: string[];
  starts: number[];
}

const maskedSaved = new Map<string, Masked>();
function masking(content: string): Masked {
  let m = maskedSaved.get(content);
  if (m === undefined) {
    const masked = maskPython(content);
    const lines = masked.split('\n');
    const starts: number[] = [];
    let at = 0;
    for (const line of lines) { starts.push(at); at += line.length + 1; }
    m = { masked, lines, starts };
    if (maskedSaved.size > 32) maskedSaved.clear();
    maskedSaved.set(content, m);
  }
  return m;
}

function lineOf(m: Masked, index: number): number {
  let low = 0;
  let high = m.starts.length - 1;
  while (low < high) {
    const mid = (low + high + 1) >> 1;
    if (m.starts[mid]! <= index) low = mid; else high = mid - 1;
  }
  return low + 1;
}

function stringEnd(text: string, i: number): number {
  const c = text[i]!;
  const quote = text.startsWith(c.repeat(3), i) ? c.repeat(3) : c;
  let j = i + quote.length;
  while (j < text.length && !text.startsWith(quote, j)) {
    if (quote.length === 1 && text[j] === '\n') return j;
    if (text[j] === '\\') j += 1;
    j += 1;
  }
  return Math.min(text.length, j + quote.length);
}

function fStringFields(body: string): string[] {
  const out: string[] = [];
  let i = 0;
  while (i < body.length) {
    if (body.startsWith('{{', i)) { i += 2; continue; }
    if (body[i] !== '{') { i += 1; continue; }
    let depth = 1;
    let j = i + 1;
    let cut = -1;
    while (j < body.length && depth > 0) {
      const c = body[j]!;
      if (c === '"' || c === "'") { j = stringEnd(body, j); continue; }
      if (c === '{' || c === '(' || c === '[') depth += 1;
      else if (c === '}' || c === ')' || c === ']') { depth -= 1; if (depth === 0) break; }
      else if (depth === 1 && cut < 0 && (c === '!' || c === ':') && body[j + 1] !== '=') cut = j;
      j += 1;
    }
    out.push(body.slice(i + 1, cut >= 0 ? cut : j));
    i = j + 1;
  }
  return out;
}

interface Frame { opaque: boolean; close: string; cond: boolean }

function expressionFollowed(text: string, followed: ReadonlySet<string>, depth = 0): boolean {
  if (depth > 4) return false;
  const code = maskPython(text);
  const stack: Frame[] = [{ opaque: false, close: '', cond: false }];
  const top = (): Frame => stack[stack.length - 1]!;
  const opaque = (): boolean => stack.some((f) => f.opaque || f.cond);
  let prev = '';
  let i = 0;
  while (i < code.length) {
    const c = code[i]!;
    if (/\s/.test(c)) { i += 1; continue; }
    if (c === '"' || c === "'") {
      let p = i;
      while (p > 0 && /[rRbBuUfF]/.test(code[p - 1]!)) p -= 1;
      const prefix = p > 0 && /\w/.test(code[p - 1]!) ? '' : code.slice(p, i);
      const end = stringEnd(text, i);
      if (/[fF]/.test(prefix) && !opaque()) {
        const quoteLength = text.startsWith(c.repeat(3), i) ? 3 : 1;
        const body = text.slice(i + quoteLength, Math.max(i + quoteLength, end - quoteLength));
        for (const field of fStringFields(body)) if (expressionFollowed(field, followed, depth + 1)) return true;
      }
      prev = 'str';
      i = end;
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      let j = i;
      while (j < code.length && /\w/.test(code[j]!)) j += 1;
      const word = code.slice(i, j);
      if (/^[rRbBuUfF]{1,2}$/.test(word) && (code[j] === '"' || code[j] === "'")) { i = j; continue; }
      const afterDot = /\.\s*$/.test(code.slice(Math.max(0, i - 8), i));
      if (afterDot) {
        const call = /^\s*\(/.exec(code.slice(j));
        if (call !== null) {
          stack.push({ opaque: !JOINING_METHODS.has(word), close: ')', cond: false });
          i = j + call[0].length;
          prev = 'op';
          continue;
        }
        i = j;
        prev = 'id';
        continue;
      }
      if (word === 'if') { if (prev !== '' && prev !== 'op') top().cond = true; i = j; prev = 'op'; continue; }
      if (word === 'else') { top().cond = false; i = j; prev = 'op'; continue; }
      if (word === 'lambda') return false;
      if (KEYWORDS.has(word)) { i = j; prev = 'op'; continue; }
      if (/^\s*=(?!=)/.test(code.slice(j)) && top().close === ')') { i = j; prev = 'op'; continue; }
      let chain = word;
      let k = j;
      for (;;) {
        const m = /^\s*\.\s*([A-Za-z_]\w*)/.exec(code.slice(k));
        if (m === null) break;
        chain += `.${m[1]}`;
        k += m[0].length;
      }
      const reads = !opaque() && (SOURCE_CHAIN.test(chain) || followed.has(word));
      const call = /^\s*\(/.exec(code.slice(k));
      if (call !== null) {
        const dotted = chain.includes('.');
        const receiver = dotted ? chain.slice(0, chain.lastIndexOf('.')) : '';
        const method = dotted ? chain.slice(chain.lastIndexOf('.') + 1) : '';
        if (SOURCE_CHAIN.test(chain) && !opaque()) return true;
        if (dotted && !opaque() && (followed.has(word) || SOURCE_CHAIN.test(`${receiver}.`) || SOURCE_CHAIN.test(receiver))) return true;
        const passes = PASSES_ON.has(chain) || (dotted && JOINING_METHODS.has(method));
        stack.push({ opaque: !passes, close: ')', cond: false });
        i = k + call[0].length;
        prev = 'op';
        continue;
      }
      if (reads) return true;
      i = k;
      prev = 'id';
      continue;
    }
    if (c === '(' || c === '[' || c === '{') {
      const close = c === '(' ? ')' : c === '[' ? ']' : '}';
      const index = (c === '[' || c === '(') && (prev === 'id' || prev === 'close' || prev === 'str');
      stack.push({ opaque: index, close, cond: false });
      i += 1;
      prev = 'op';
      continue;
    }
    if (c === ')' || c === ']' || c === '}') {
      if (stack.length > 1) stack.pop();
      i += 1;
      prev = 'close';
      continue;
    }
    if (c === ',' ) { top().cond = false; }
    i += 1;
    prev = 'op';
  }
  return false;
}

interface Param { name: string; annotation: string; fallback: string; star: boolean }

function paramsAt(masked: string, open: number): { params: Param[]; close: number } {
  let depth = 0;
  let current = '';
  const parts: string[] = [];
  let close = -1;
  for (let i = open; i < masked.length; i += 1) {
    const c = masked[i]!;
    if (c === '(' || c === '[' || c === '{') { depth += 1; if (depth === 1 && c === '(') continue; }
    if (c === ')' || c === ']' || c === '}') { depth -= 1; if (depth === 0) { close = i; break; } }
    if (c === ',' && depth === 1) { parts.push(current); current = ''; continue; }
    current += c;
  }
  parts.push(current);
  const params: Param[] = [];
  for (const part of parts) {
    const m = /^\s*(\*{0,2})\s*([A-Za-z_]\w*)\s*(?::([^=]*))?(?:=([\s\S]*))?$/.exec(part);
    if (m === null) continue;
    params.push({ name: m[2]!, annotation: (m[3] ?? '').trim(), fallback: (m[4] ?? '').trim(), star: m[1] !== '' });
  }
  return { params, close };
}

const aliasSaved = new Map<string, Set<string>>();
function dependencyAliases(masked: string): Set<string> {
  let names = aliasSaved.get(masked);
  if (names === undefined) {
    names = new Set();
    for (const m of masked.matchAll(/^(\w+)\s*(?::[^=\n]*)?=\s*Annotated\s*\[([^\n]*(?:\n[ \t]+[^\n]*)*)/gm)) {
      if (/\b(?:Depends|Security)\s*\(/.test(m[2] ?? '')) names.add(m[1]!);
    }
    if (aliasSaved.size > 32) aliasSaved.clear();
    aliasSaved.set(masked, names);
  }
  return names;
}

function baseType(annotation: string): string {
  let a = annotation.trim();
  for (let n = 0; n < 4; n += 1) {
    const wrapped = /^(?:typing\.)?(?:Optional|Annotated)\s*\[([\s\S]*)\]$/.exec(a);
    if (wrapped === null) break;
    a = (wrapped[1] ?? '').split(',')[0]!.trim();
  }
  return a.replace(/\s*\|\s*None$/, '').replace(/^None\s*\|\s*/, '').trim();
}

const projectAliasSaved = new WeakMap<object, Set<string>>();
export function pythonDependencyAliases(entries: readonly { extension: string; content: string }[]): ReadonlySet<string> {
  let names = projectAliasSaved.get(entries);
  if (names === undefined) {
    names = new Set();
    for (const entry of entries) {
      if (entry.extension !== '.py' || !entry.content.includes('Annotated')) continue;
      for (const n of dependencyAliases(masking(entry.content).masked)) names.add(n);
    }
    projectAliasSaved.set(entries, names);
  }
  return names;
}

export interface FollowOptions {
  head?: boolean;
  aliases?: ReadonlySet<string>;
}

function routeParameters(content: string, m: Masked, defLine: number, defIndent: number, projectAliases: ReadonlySet<string> = new Set()): string[] {
  if (!IMPORTS_FASTAPI.test(content)) return [];
  let routed = false;
  for (let l = defLine - 1; l >= 1 && l >= defLine - 20; l -= 1) {
    const text = m.lines[l - 1] ?? '';
    if (text.trim() === '') break;
    if (indentOf(text) < defIndent) break;
    if (indentOf(text) === defIndent && !text.trim().startsWith('@') && !/^\s*[)\]]/.test(text)) break;
    if (ROUTE_DECORATOR.test(text)) { routed = true; break; }
  }
  if (!routed) return [];
  const open = m.masked.indexOf('(', m.starts[defLine - 1]!);
  if (open < 0) return [];
  const aliases = new Set([...dependencyAliases(m.masked), ...projectAliases]);
  const out: string[] = [];
  for (const p of paramsAt(m.masked, open).params) {
    if (p.star || p.name === 'self' || p.name === 'cls') continue;
    if (/\b(?:Depends|Security)\s*\(/.test(`${p.annotation} ${p.fallback}`)) continue;
    const base = baseType(p.annotation);
    if (FRAMEWORK_OBJECT.test(base) || CONVERTED_TYPE.test(base)) continue;
    if ([...aliases].some((alias) => new RegExp(`\\b${alias}\\b`).test(p.annotation))) continue;
    out.push(p.name);
  }
  return out;
}

function topLevelAssignments(stmt: string): number[] {
  const out: number[] = [];
  let depth = 0;
  for (let i = 0; i < stmt.length; i += 1) {
    const c = stmt[i]!;
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === ']' || c === '}') depth -= 1;
    else if (c === '=' && depth === 0 && stmt[i + 1] !== '=' && !/[=<>!:+\-*/%|&^@]/.test(stmt[i - 1] ?? '')) out.push(i);
  }
  return out;
}

function targetNames(target: string): string[] | undefined {
  let t = target.trim();
  const colon = t.indexOf(':');
  if (colon >= 0 && !t.slice(0, colon).includes('[')) t = t.slice(0, colon).trim();
  t = t.replace(/^[([]|[)\]]$/g, '').trim();
  const names: string[] = [];
  for (const piece of t.split(',')) {
    const p = piece.trim().replace(/^\*/, '');
    if (p === '') continue;
    if (!/^[A-Za-z_]\w*$/.test(p)) return undefined;
    names.push(p);
  }
  return names;
}

interface Statement { start: number; end: number; line: number; indent: number }

function headerEndLine(m: Masked, defLine: number): number {
  const open = m.masked.indexOf('(', m.starts[defLine - 1]!);
  const close = open < 0 ? -1 : paramsAt(m.masked, open).close;
  return close < 0 ? defLine : lineOf(m, close);
}

function statementsOf(m: Masked, from: number, to: number): Statement[] {
  const out: Statement[] = [];
  let l = from;
  while (l <= to) {
    const first = m.lines[l - 1] ?? '';
    if (first.trim() === '') { l += 1; continue; }
    let depth = 0;
    let last = l;
    for (let k = l; k <= m.lines.length; k += 1) {
      const text = m.lines[k - 1] ?? '';
      for (const c of text) {
        if (c === '(' || c === '[' || c === '{') depth += 1;
        else if (c === ')' || c === ']' || c === '}') depth -= 1;
      }
      last = k;
      if (depth <= 0 && !/\\\s*$/.test(text)) break;
    }
    const start = m.starts[l - 1]!;
    const end = m.starts[last - 1]! + (m.lines[last - 1] ?? '').length;
    out.push({ start, end, line: l, indent: indentOf(first) });
    l = last + 1;
  }
  return out;
}

function followedNamesBefore(content: string, m: Masked, defLine: number, endLine: number, defIndent: number, beforeLine: number, opts: FollowOptions = {}): Set<string> {
  const followed = new Set(routeParameters(content, m, defLine, defIndent, opts.aliases));
  const carried = (from: number, to: number): boolean => {
    const text = content.slice(from, to);
    const head = opts.head === true ? urlHead(text) : text;
    return head !== null && expressionFollowed(head, followed);
  };
  const headerEnd = headerEndLine(m, defLine);
  const statements = statementsOf(m, headerEnd + 1, Math.min(endLine, beforeLine - 1));
  const bodyIndent = statements[0]?.indent ?? defIndent + 4;
  let skipDeeperThan = -1;
  for (const s of statements) {
    if (s.line >= beforeLine) break;
    if (skipDeeperThan >= 0) {
      if (s.indent > skipDeeperThan) continue;
      skipDeeperThan = -1;
    }
    const stmt = m.masked.slice(s.start, s.end);
    const body = stmt.trim();
    if (/^(?:async\s+)?def\b|^class\b/.test(body)) { skipDeeperThan = s.indent; continue; }
    const loop = /^(\s*)(?:async\s+)?for\s+([\s\S]+?)\s+in\s+([\s\S]+):\s*$/.exec(stmt);
    if (loop !== null) {
      const iterStart = s.start + stmt.indexOf(loop[3]!, loop[1]!.length + 4 + loop[2]!.length);
      const names = targetNames(loop[2]!);
      if (names !== undefined && expressionFollowed(content.slice(iterStart, iterStart + loop[3]!.length), followed)) names.forEach((n) => followed.add(n));
      continue;
    }
    if (/^(?:if|elif|else|while|with|try|except|finally|return|yield|raise|assert|del|import|from|global|nonlocal|pass|break|continue|@)\b/.test(body)) continue;
    const augmented = /^(\s*)([A-Za-z_]\w*)\s*(?:\+|-|\*|\/|\/\/|%|\||&|\^|@|\*\*|<<|>>)=(?!=)/.exec(stmt);
    if (augmented !== null) {
      const rhsStart = s.start + augmented[0].length;
      if (opts.head !== true && expressionFollowed(content.slice(rhsStart, s.end), followed)) followed.add(augmented[2]!);
      continue;
    }
    const eqs = topLevelAssignments(stmt);
    if (eqs.length === 0) continue;
    const lastEq = eqs[eqs.length - 1]!;
    const choice = /^\s*([A-Za-z_]\w*)\s+if\s+\1\s+in\s+([A-Za-z_]\w*)(?:\.\w+)*\s+else\s+/.exec(stmt.slice(lastEq + 1));
    const allowList = choice !== null && !followed.has(choice[2]!);
    const rhsFrom = s.start + lastEq + 1 + (allowList ? choice![0].length : 0);
    const carries = carried(rhsFrom, s.end);
    let from = 0;
    for (const eq of eqs) {
      const names = targetNames(stmt.slice(from, eq));
      from = eq + 1;
      if (names === undefined) continue;
      for (const n of names) {
        if (carries) followed.add(n);
        else if (s.indent === bodyIndent) followed.delete(n);
      }
    }
  }
  return followed;
}

export function pythonValueReaches(content: string, start: number, end: number, opts: FollowOptions = {}): boolean {
  if (end <= start) return false;
  const text = opts.head === true ? urlHead(content.slice(start, end)) : content.slice(start, end);
  if (text === null) return false;
  const m = masking(content);
  const line = lineOf(m, start);
  const scope = defAround(m.lines, line);
  if (scope === undefined) return expressionFollowed(text, new Set());
  let stmtLine = line;
  const statements = statementsOf(m, headerEndLine(m, scope.defLine) + 1, line);
  for (const s of statements) if (m.starts[s.line - 1]! <= start) stmtLine = s.line;
  const followed = followedNamesBefore(content, m, scope.defLine, scope.endLine, scope.indent, stmtLine, opts);
  if (!expressionFollowed(text, followed)) return false;
  return !governedByUnreadCheck(m, statements, stmtLine, scope.endLine, followed);
}

const NOT_A_CHECK = new Set(['len', 'bool', 'str', 'int', 'float', 'isinstance', 'issubclass', 'hasattr', 'getattr', 'callable', 'type', 'any', 'all', 'list', 'set', 'dict', 'tuple', 'print', 'repr', 'sorted', 'min', 'max', 'sum', 'abs', 'round', 'id', 'hash', 'iter', 'enumerate', 'zip', 'range', 'map', 'filter', 'open', 'super']);

function governedByUnreadCheck(m: Masked, statements: Statement[], sinkLine: number, endLine: number, followed: ReadonlySet<string>): boolean {
  for (const s of statements) {
    if (s.line >= sinkLine) break;
    const stmt = m.masked.slice(s.start, s.end);
    const head = /^\s*(?:if|elif|while)\b([\s\S]*?):(?=\s*(?:$|\S))/.exec(stmt);
    if (head === null) continue;
    let unread = false;
    for (const call of head[1]!.matchAll(/(?<![\w.])([A-Za-z_]\w*)\s*\(/g)) {
      if (NOT_A_CHECK.has(call[1]!) || KEYWORDS.has(call[1]!)) continue;
      const args = head[1]!.slice(call.index! + call[0].length);
      const names = args.match(/[A-Za-z_]\w*/g) ?? [];
      if (names.some((n) => followed.has(n)) || SOURCE_ANYWHERE.test(args)) { unread = true; break; }
    }
    if (!unread) continue;
    const oneLine = stmt.slice(head[0].length).trim() !== '';
    let blockEnd = s.line;
    if (!oneLine) {
      for (let l = s.line + 1; l <= endLine; l += 1) {
        const t = m.lines[l - 1] ?? '';
        if (t.trim() === '') continue;
        if (indentOf(t) <= s.indent) break;
        blockEnd = l;
      }
    }
    if (sinkLine > s.line && sinkLine <= blockEnd) return true;
    const block = oneLine ? [stmt.slice(head[0].length)] : m.lines.slice(s.line, blockEnd);
    if (block.some((t) => REFUSAL_LINE.test(t))) return true;
  }
  return false;
}

function fixedLiteralHead(text: string): boolean {
  if (/^https?:\/\/[A-Za-z0-9.-]+(?::\d+)?\//.test(text)) return true;
  return /^\/[^/\\\t\r\n]/.test(text) && !/^\/(?:%2f|%5c)/i.test(text);
}

function urlHead(text: string): string | null {
  const t = text.trim();
  if (pythonHasBranches(t)) return t;
  const literal = /^([rRbBuUfF]{0,2})(["'])/.exec(t);
  if (literal !== null) {
    const at = literal[1]!.length;
    const quote = t.startsWith(literal[2]!.repeat(3), at) ? literal[2]!.repeat(3) : literal[2]!;
    const end = stringEnd(t, at);
    const body = t.slice(at + quote.length, Math.max(at + quote.length, end - quote.length));
    const rest = t.slice(end).trim();
    if (!/[fF]/.test(literal[1]!)) {
      if (fixedLiteralHead(body)) return null;
      if (rest === '') return null;
      return rest.startsWith('+') ? rest.slice(1) : t;
    }
    const field = /^\{([^{}]*)\}\//.exec(body);
    if (field !== null) return field[1]!;
    if (fixedLiteralHead(body.split('{')[0]!)) return null;
    const host = /^https?:\/\/([^/]*)\//.exec(body);
    if (host !== null) {
      const fields = fStringFields(host[1]!);
      return fields.length === 0 ? null : fields.join(' + ');
    }
    return t;
  }
  const concat = /^([A-Za-z_][\w.]*(?:\s*\([^()]*\))?(?:\.\w+)*)\s*\+\s*[rRuU]?["']\//.exec(t);
  if (concat !== null) return concat[1]!;
  return t;
}

export function pythonHasBranches(text: string): boolean {
  const code = maskPython(text);
  let depth = 0;
  let flat = '';
  for (const c of code) {
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === ']' || c === '}') depth -= 1;
    else if (depth === 0) flat += c;
  }
  return /\b(?:if|else|or|and|lambda)\b/.test(flat);
}

export function pythonUrlHeadFixed(text: string): boolean {
  return urlHead(text) === null;
}

const REFUSAL_LINE = /^\s*(?:raise\b|return\b|abort\s*\()/;

export function pythonCheckActsBefore(
  content: string,
  sinkIndex: number,
  test: (condition: string) => boolean,
  rebinds: readonly string[] = [],
): boolean {
  const m = masking(content);
  const line = lineOf(m, sinkIndex);
  const scope = defAround(m.lines, line);
  if (scope === undefined) return false;
  for (const s of statementsOf(m, headerEndLine(m, scope.defLine) + 1, line - 1)) {
    if (s.line >= line) break;
    const stmt = m.masked.slice(s.start, s.end);
    const head = /^\s*(?:if|elif)\b([\s\S]*?):(?=\s*(?:$|\S))/.exec(stmt);
    if (head === null || !test(head[1]!)) continue;
    const after = stmt.slice(head[0].length);
    const bodyLines: string[] = [];
    if (after.trim() !== '') bodyLines.push(after);
    else {
      for (let l = s.line + 1; l <= scope.endLine; l += 1) {
        const text = m.lines[l - 1] ?? '';
        if (text.trim() === '') continue;
        if (indentOf(text) <= s.indent) break;
        bodyLines.push(text);
      }
    }
    for (const text of bodyLines) {
      if (REFUSAL_LINE.test(text)) return true;
      for (const name of rebinds) if (new RegExp(`^\\s*${name}\\s*=\\s*[rRbBuU]?["']`).test(text)) return true;
    }
  }
  return false;
}

export function pythonCallBindings(content: string, index: number, callee: RegExp): { name: string; args: string }[] {
  const span = pythonFunctionSpan(content, index);
  if (span === undefined) return [];
  const m = masking(content);
  const body = m.masked.slice(span.from, Math.min(span.to, index));
  const out: { name: string; args: string }[] = [];
  const re = new RegExp(String.raw`(?<![\w.])([A-Za-z_]\w*)\s*=\s*(?:${callee.source})\s*\(`, 'g');
  for (const b of body.matchAll(re)) {
    const open = span.from + b.index! + b[0].length - 1;
    const args = pythonCallArguments(content, open);
    out.push({ name: b[1]!, args: args.map((a) => content.slice(a.start, a.end)).join(',') });
  }
  return out;
}

export function pythonIdentifiers(text: string): Set<string> {
  return new Set(maskPython(text).match(/[A-Za-z_]\w*/g) ?? []);
}

export function pythonFunctionSpan(content: string, index: number): { from: number; to: number } | undefined {
  const m = masking(content);
  const scope = defAround(m.lines, lineOf(m, index));
  if (scope === undefined) return undefined;
  const from = m.starts[scope.defLine - 1]!;
  const to = m.starts[scope.endLine - 1]! + (m.lines[scope.endLine - 1] ?? '').length;
  return { from, to };
}

const gateSaved = new Map<string, boolean>();
export function pythonFileHasSources(content: string): boolean {
  let answer = gateSaved.get(content);
  if (answer === undefined) {
    const m = masking(content);
    answer = SOURCE_ANYWHERE.test(m.masked);
    if (!answer && IMPORTS_FASTAPI.test(content)) {
      m.lines.forEach((text, i) => {
        if (answer) return;
        const def = /^(\s*)(?:async\s+)?def\s+\w+\s*\(/.exec(text);
        if (def !== null && routeParameters(content, m, i + 1, def[1]!.length).length > 0) answer = true;
      });
    }
    if (gateSaved.size > 32) gateSaved.clear();
    gateSaved.set(content, answer);
  }
  return answer;
}

export interface PyArgument { start: number; end: number; keyword?: string }

export function pythonCallArguments(content: string, open: number): PyArgument[] {
  const m = masking(content);
  const out: PyArgument[] = [];
  let depth = 0;
  let begin = open + 1;
  const push = (to: number): void => {
    const slice = m.masked.slice(begin, to);
    if (slice.trim() === '') return;
    const leftPad = slice.length - slice.trimStart().length;
    const kw = /^\s*([A-Za-z_]\w*)\s*=(?!=)\s*/.exec(slice);
    const s = begin + (kw === null ? leftPad : kw[0].length);
    out.push({ start: s, end: begin + slice.trimEnd().length, ...(kw === null ? {} : { keyword: kw[1]! }) });
  };
  for (let i = open; i < m.masked.length; i += 1) {
    const c = m.masked[i]!;
    if (c === '(' || c === '[' || c === '{') { depth += 1; continue; }
    if (c === ')' || c === ']' || c === '}') { depth -= 1; if (depth === 0) { push(i); break; } continue; }
    if (c === ',' && depth === 1) { push(i); begin = i + 1; }
  }
  return out;
}

export function pythonMasked(content: string): string {
  return masking(content).masked;
}

interface ProofScope { content: string; m: Masked; bodyFrom: number; to: number; index: number; statements: Statement[]; params: Set<string>; caught: Set<string> }

function proofScope(content: string, index: number): ProofScope | undefined {
  const m = masking(content);
  const scope = defAround(m.lines, lineOf(m, index));
  if (scope === undefined) return undefined;
  const headerEnd = headerEndLine(m, scope.defLine);
  const from = m.starts[scope.defLine - 1]!;
  const to = m.starts[scope.endLine - 1]! + (m.lines[scope.endLine - 1] ?? '').length;
  const bodyFrom = headerEnd < m.lines.length ? m.starts[headerEnd]! : to;
  const span = m.masked.slice(from, to);
  const params = new Set<string>();
  for (const d of span.matchAll(/\bdef\s+\w+\s*\(/g)) {
    for (const p of paramsAt(m.masked, from + d.index! + d[0].length - 1).params) params.add(p.name);
  }
  for (const l of span.matchAll(/\blambda\b([^:\n]*):/g)) for (const n of l[1]!.match(/[A-Za-z_]\w*/g) ?? []) params.add(n);
  const caught = new Set<string>();
  for (const c of span.matchAll(/\bexcept\b[^:\n]*?\bas\s+([A-Za-z_]\w*)/g)) caught.add(c[1]!);
  return { content, m, bodyFrom, to, index, statements: statementsOf(m, headerEnd + 1, scope.endLine), params, caught };
}

const BINDING_KEYWORD_LINE = (n: string): RegExp => new RegExp(`^[ \\t]*(?:global|nonlocal|import|from|case)\\b[^\\n]*(?<![\\w.])${n}\\b`, 'm');

function plainBindings(ps: ProofScope, name: string): { at: number; from: number; to: number }[] | undefined {
  const word = new RegExp(`(?<![\\w.])${name}\\b`);
  if (ps.params.has(name)) return undefined;
  const body = ps.m.masked.slice(ps.bodyFrom, ps.to);
  for (const f of body.matchAll(/\bfor\s+([^\n]+?)\s+in\b/g)) if (word.test(f[1]!)) return undefined;
  for (const a of body.matchAll(/\bas\s+\(?\s*([A-Za-z_][\w \t,]*)/g)) if (word.test(a[1]!)) return undefined;
  if (new RegExp(`(?<![\\w.])${name}\\s*:=`).test(body) || BINDING_KEYWORD_LINE(name).test(body)) return undefined;
  const out: { at: number; from: number; to: number }[] = [];
  for (const s of ps.statements) {
    const stmt = ps.m.masked.slice(s.start, s.end);
    if (!word.test(stmt)) continue;
    if (new RegExp(`(?<![\\w.])${name}\\s*(?:\\+|-|\\*|\\/|\\/\\/|%|\\||&|\\^|@|\\*\\*|<<|>>)=`).test(stmt)) return undefined;
    const eqs = topLevelAssignments(stmt);
    let from = 0;
    for (const eq of eqs) {
      const target = stmt.slice(from, eq);
      from = eq + 1;
      if (!word.test(target.replace(/\[[^\]]*\]/g, ''))) continue;
      const names = targetNames(target);
      if (names === undefined || names.length !== 1 || /[,*]/.test(target)) return undefined;
      out.push({ at: s.start, from: s.start + eqs[eqs.length - 1]! + 1, to: s.end });
    }
  }
  return out;
}

function nameProved(ps: ProofScope, name: string, depth: number): boolean {
  if (depth > 6 || KEYWORDS.has(name)) return false;
  const bindings = plainBindings(ps, name);
  if (bindings === undefined || !bindings.some((b) => b.at < ps.index)) return false;
  return bindings.every((b) => expressionProved(ps, ps.content.slice(b.from, b.to), ps.m.masked.slice(b.from, b.to), depth + 1, true));
}

function exceptionAlias(ps: ProofScope, name: string, depth = 0): boolean {
  if (ps.caught.has(name)) return true;
  if (depth > 6) return false;
  for (const s of ps.statements) {
    const alias = new RegExp(`^\\s*${name}\\s*(?::[^=\\n]*)?=\\s*([A-Za-z_]\\w*)\\s*$`).exec(ps.m.masked.slice(s.start, s.end));
    if (alias !== null && exceptionAlias(ps, alias[1]!, depth + 1)) return true;
  }
  return false;
}

function closeOf(code: string, open: number): number {
  let depth = 0;
  for (let i = open; i < code.length; i += 1) {
    const c = code[i]!;
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === ']' || c === '}') { depth -= 1; if (depth === 0) return i; }
  }
  return -1;
}

function topLevelCuts(code: string, chars: string): number[] {
  const out: number[] = [];
  let depth = 0;
  for (let i = 0; i < code.length; i += 1) {
    const c = code[i]!;
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === ']' || c === '}') depth -= 1;
    else if (depth === 0 && chars.includes(c) && code[i + 1] !== '=') out.push(i);
  }
  return out;
}

function piecesProved(ps: ProofScope, text: string, code: string, cuts: number[], depth: number, emptyOk: boolean): boolean {
  let from = 0;
  for (const cut of [...cuts, code.length]) {
    const piece = code.slice(from, cut);
    if (piece.trim() === '') { if (!emptyOk) return false; }
    else if (!expressionProved(ps, text.slice(from, cut), piece, depth, false)) return false;
    from = cut + 1;
  }
  return true;
}

function argumentsProved(ps: ProofScope, text: string, code: string, depth: number): boolean {
  let from = 0;
  for (const cut of [...topLevelCuts(code, ','), code.length]) {
    const piece = code.slice(from, cut);
    if (piece.trim() !== '') {
      if (/^\s*\*/.test(piece)) return false;
      const kw = /^\s*[A-Za-z_]\w*\s*=(?!=)/.exec(piece);
      const skip = kw === null ? 0 : kw[0].length;
      if (!expressionProved(ps, text.slice(from + skip, cut), piece.slice(skip), depth, false)) return false;
    }
    from = cut + 1;
  }
  return true;
}

const REQUEST_ROOT = /^(?:self\s*\.\s*)?(?:flask\s*\.\s*)?request\s*\.\s*(args|form|files|values|json|get_json|GET|POST|data|query_params)\b/;
const REQUEST_METHODS = new Set(['get', 'getlist', 'get_json']);

function tailEnd(ps: ProofScope, text: string, code: string, at: number, last: string | undefined, depth: number): number {
  let i = at;
  for (;;) {
    while (i < code.length && /\s/.test(code[i]!)) i += 1;
    const dot = /^\.\s*([A-Za-z_]\w*)/.exec(code.slice(i));
    if (dot !== null) { if (last !== undefined) last = dot[1]!; i += dot[0].length; continue; }
    if (code[i] === '[' || code[i] === '(') {
      const call = code[i] === '(';
      if (call && (last === undefined || !REQUEST_METHODS.has(last))) return -1;
      const close = closeOf(code, i);
      if (close < 0) return -1;
      const inner = code.slice(i + 1, close);
      const innerText = text.slice(i + 1, close);
      if (!(call ? argumentsProved(ps, innerText, inner, depth) : expressionProved(ps, innerText, inner, depth, false))) return -1;
      if (call) last = '';
      i = close + 1;
      continue;
    }
    return i;
  }
}

function expressionProved(ps: ProofScope, rawText: string, rawCode: string, depth: number, whole: boolean): boolean {
  if (depth > 8) return false;
  const code0 = rawCode.replace(/\\\n/g, '  ');
  let a = 0;
  let b = code0.length;
  while (a < b && /\s/.test(code0[a]!)) a += 1;
  while (b > a && /\s/.test(code0[b - 1]!)) b -= 1;
  if (a >= b) return false;
  const text = rawText.slice(a, b);
  const code = code0.slice(a, b);
  const cuts = topLevelCuts(code, '+%');
  if (cuts.length > 0) return piecesProved(ps, text, code, cuts, depth + 1, false);
  if (code[0] === '(' && closeOf(code, 0) === code.length - 1) {
    const inner = code.slice(1, -1);
    if (inner.trim() === '') return true;
    return piecesProved(ps, text.slice(1, -1), inner, topLevelCuts(inner, ','), depth + 1, true);
  }
  if (/^(?:\d[\w.]*|\.\d\w*|None|True|False)$/.test(code)) return true;
  if (/^[rRbBuUfF]{0,2}["']/.test(code)) {
    let i = 0;
    for (;;) {
      const lit = /^([rRbBuUfF]{0,2})(["'])/.exec(code.slice(i));
      if (lit === null) break;
      const q = i + lit[1]!.length;
      const end = stringEnd(text, q);
      if (/[fF]/.test(lit[1]!)) {
        const ql = text.startsWith(lit[2]!.repeat(3), q) ? 3 : 1;
        for (const field of fStringFields(text.slice(q + ql, Math.max(q + ql, end - ql)))) {
          if (!expressionProved(ps, field, maskPython(field), depth + 1, false)) return false;
        }
      }
      i = end;
      while (i < code.length && /\s/.test(code[i]!)) i += 1;
    }
    if (i >= code.length) return true;
    const format = /^\.\s*format\s*\(/.exec(code.slice(i));
    if (format === null) return false;
    const open = i + format[0].length - 1;
    const close = closeOf(code, open);
    if (close !== code.length - 1) return false;
    return argumentsProved(ps, text.slice(open + 1, close), code.slice(open + 1, close), depth + 1);
  }
  const request = REQUEST_ROOT.exec(code);
  if (request !== null) return tailEnd(ps, text, code, request[0].length, request[1]!, depth + 1) === code.length;
  const root = /^[A-Za-z_]\w*/.exec(code);
  if (root === null || KEYWORDS.has(root[0])) return false;
  if (root[0].length === code.length) return !whole && nameProved(ps, root[0], depth + 1);
  if (exceptionAlias(ps, root[0])) return false;
  return tailEnd(ps, text, code, root[0].length, undefined, depth + 1) === code.length;
}

export function pythonNameProved(content: string, index: number, name: string): boolean {
  const ps = proofScope(content, index);
  return ps !== undefined && /^[A-Za-z_]\w*$/.test(name) && nameProved(ps, name, 0);
}

export function pythonReadsOnlyProved(content: string, index: number, text: string): boolean {
  const ps = proofScope(content, index);
  if (ps === undefined) return false;
  if (/(?:^|[^\w])[rRbBuU]?[fF][rRbB]?["']/.test(text)) return false;
  const masked = maskPython(text);
  const code = masked.split('');
  for (const r of masked.matchAll(new RegExp(`(?<![\\w.])${REQUEST_ROOT.source.slice(1)}`, 'g'))) {
    const end = tailEnd(ps, text.slice(r.index), masked.slice(r.index), r[0].length, r[1]!, 1);
    for (let i = r.index; i < r.index + end; i += 1) code[i] = ' ';
  }
  const rest = code.join('');
  if (/[\w)\]]\s*\(/.test(rest)) return false;
  for (const id of rest.matchAll(/(?<![\w.])([A-Za-z_]\w*)\b(?!\s*=(?!=))(?!["'])/g)) {
    const name = id[1]!;
    if (/^(?:None|True|False|and|or|not|in|is|if|else)$/.test(name)) continue;
    if (!nameProved(ps, name, 0)) return false;
  }
  return true;
}

const QUERY_READ_INLINE = /^(?:flask\s*\.\s*)?request\s*\.\s*(?:args|GET|query_params)\s*(?:\.\s*get\s*\(\s*(?:"[^"\n]*"|'[^'\n]*')\s*(?:,\s*(?:"[^"\n]*"|'[^'\n]*'|None)\s*)?\)|\[\s*(?:"[^"\n]*"|'[^'\n]*')\s*\])$/;
const QUERY_READ_ANYWHERE = /(?<![\w.])(?:flask\s*\.\s*)?request\s*\.\s*(?:args|GET|query_params)\b/;
const STRING_ANNOTATION = /^(?:str|Optional\s*\[\s*str\s*\]|str\s*\|\s*None|None\s*\|\s*str)$/;

function orFallback(masked: string): { left: string; right: string } | undefined {
  let depth = 0;
  const cuts: number[] = [];
  for (let i = 0; i < masked.length; i += 1) {
    const c = masked[i]!;
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === ']' || c === '}') depth -= 1;
    else if (depth === 0 && /\s/.test(c)) {
      const word = /^\s(or|and|if|else|not|for|lambda)\s/.exec(masked.slice(i));
      if (word !== null) {
        if (word[1] !== 'or') return undefined;
        cuts.push(i);
      }
    }
  }
  if (cuts.length === 0) return { left: masked.trim(), right: '' };
  if (cuts.length > 1) return undefined;
  return { left: masked.slice(0, cuts[0]).trim(), right: masked.slice(cuts[0]! + 4).trim() };
}

function inlineQueryRead(text: string): boolean {
  const parts = orFallback(text);
  if (parts === undefined || !QUERY_READ_INLINE.test(parts.left)) return false;
  return !SOURCE_ANYWHERE.test(parts.right);
}

export function pythonRedirectStraightFromQuery(content: string, start: number, end: number, opts: FollowOptions = {}): boolean {
  if (end <= start) return false;
  const m = masking(content);
  const parts = orFallback(m.masked.slice(start, end));
  if (parts === undefined || SOURCE_ANYWHERE.test(parts.right)) return false;
  const line = lineOf(m, start);
  const scope = defAround(m.lines, line);
  if (scope === undefined) return false;
  const headerEnd = headerEndLine(m, scope.defLine);
  const bodyFrom = m.starts[headerEnd]!;
  const bodyTo = m.starts[scope.endLine - 1]! + (m.lines[scope.endLine - 1] ?? '').length;
  const statements = statementsOf(m, headerEnd + 1, scope.endLine);
  const sinkStmt = statements.filter((s) => s.start <= start).pop();
  if (sinkStmt === undefined) return false;

  if (QUERY_READ_INLINE.test(parts.left)) {
    for (const s of statements) {
      if (s.start >= sinkStmt.start) break;
      const stmt = m.masked.slice(s.start, s.end);
      if (/^\s*(?:if|elif|while|assert)\b/.test(stmt) && QUERY_READ_ANYWHERE.test(stmt)) return false;
    }
    return true;
  }

  const name = /^[A-Za-z_]\w*$/.exec(parts.left)?.[0];
  if (name === undefined || KEYWORDS.has(name) || name === 'self') return false;
  const mention = new RegExp(String.raw`(?<![\w.])${name}\b`, 'g');
  const others: number[] = [];
  for (const hit of m.masked.slice(bodyFrom, bodyTo).matchAll(mention)) {
    const at = bodyFrom + hit.index;
    if (at >= start && at < end) continue;
    others.push(at);
  }

  if (others.length === 0) {
    if (!routeParameters(content, m, scope.defLine, scope.indent, opts.aliases).includes(name)) return false;
    const open = m.masked.indexOf('(', m.starts[scope.defLine - 1]!);
    const param = paramsAt(m.masked, open).params.find((p) => p.name === name);
    if (param === undefined) return false;
    const annotation = param.annotation.replace(/^Annotated\s*\[\s*([\s\S]*?)\s*,\s*Query\s*\([\s\S]*\)\s*\]$/, '$1');
    if (annotation !== '' && !STRING_ANNOTATION.test(annotation)) return false;
    if (param.fallback !== '' && !/^(?:None|"[^"\n]*"|'[^'\n]*'|Query\s*\([\s\S]*\))$/.test(param.fallback)) return false;
    const raw = content.split('\n');
    const named = new RegExp(String.raw`\{${name}[:}]`);
    for (let l = scope.defLine - 1; l >= 1 && l >= scope.defLine - 20; l -= 1) {
      const text = m.lines[l - 1] ?? '';
      if (text.trim() !== '' && indentOf(text) <= scope.indent && !/^\s*@/.test(text) && !/^\s*[)\]]/.test(text)) break;
      if (named.test(raw[l - 1] ?? '')) return false;
    }
    return true;
  }

  if (others.length !== 1) return false;
  const binding = statements.find((s) => s.start <= others[0]! && others[0]! < s.end);
  if (binding === undefined || binding.indent !== sinkStmt.indent || binding.start >= sinkStmt.start) return false;
  if (statements.some((s) => s.start > binding.start && s.start < sinkStmt.start && s.indent < sinkStmt.indent)) return false;
  const stmt = m.masked.slice(binding.start, binding.end);
  const eqs = topLevelAssignments(stmt);
  if (eqs.length !== 1 || stmt.slice(0, eqs[0]).trim() !== name) return false;
  return inlineQueryRead(stmt.slice(eqs[0]! + 1).trim());
}
