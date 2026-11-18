import type { ApiRoute, FileMapEntry, RuleContext } from './types.js';
import { maskPython, pythonCallerParameters, pythonHandlerSpan, pythonReading, pythonRouteGuard } from './pythonGuards.js';
import { enclosingDef, indentOf, maskedLines } from './pythonScope.js';
import { readPythonTree, type PyNode, type PyTree } from './pythonParser.js';
import { bindingsOf, functionAt, isPlainLiteral, parameterNames } from './pythonBindings.js';

export interface PythonDeleteSite {
  index: number;
  line: number;
  owned: boolean;
}

type Bounds = { start: number; end: number };

function closing(code: string, open: number): number | undefined {
  let depth = 0;
  for (let i = open; i < code.length; i += 1) {
    const c = code[i];
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === ']' || c === '}') { depth -= 1; if (depth === 0) return i; }
  }
  return undefined;
}

function opening(code: string, close: number): number | undefined {
  let depth = 0;
  for (let i = close; i >= 0; i -= 1) {
    const c = code[i];
    if (c === ')' || c === ']' || c === '}') depth += 1;
    else if (c === '(' || c === '[' || c === '{') { depth -= 1; if (depth === 0) return i; }
  }
  return undefined;
}

function chainStart(code: string, dot: number): number {
  let i = dot - 1;
  for (;;) {
    while (i >= 0 && /[ \t\r\n\\]/.test(code[i]!)) i -= 1;
    if (i < 0) return 0;
    const c = code[i]!;
    if (c === ')' || c === ']') {
      const open = opening(code, i);
      if (open === undefined) return i + 1;
      i = open - 1;
      let j = i;
      while (j >= 0 && /\w/.test(code[j]!)) j -= 1;
      if (j < i) i = j;
      else return open;
    } else if (/\w/.test(c)) {
      while (i >= 0 && /\w/.test(code[i]!)) i -= 1;
    } else {
      return i + 1;
    }
    let k = i;
    while (k >= 0 && /[ \t\r\n\\]/.test(code[k]!)) k -= 1;
    if (k >= 0 && code[k] === '.') { i = k - 1; continue; }
    return i + 1;
  }
}

function chainCalls(code: string, from: number, to: number): Array<{ name: string; open: number; close: number }> {
  const out: Array<{ name: string; open: number; close: number }> = [];
  const CALL = /([A-Za-z_]\w*)\s*\(/g;
  CALL.lastIndex = from;
  let m: RegExpExecArray | null;
  while ((m = CALL.exec(code)) !== null && m.index < to) {
    const open = m.index + m[0].length - 1;
    const close = closing(code, open);
    if (close === undefined || close > to) break;
    out.push({ name: m[1]!, open, close });
    if (/^(?:execute|scalars?)$/.test(m[1]!)) {
      const first = topParts(code, open + 1, close)[0];
      if (first !== undefined) out.push(...chainCalls(code, first.start, first.end));
    }
    CALL.lastIndex = close + 1;
  }
  return out;
}

const FILTER_CALLS = new Set(['filter', 'filter_by', 'where', 'get', 'get_or_404', 'eq', 'get_object_or_404', 'get_list_or_404']);

function chainEnd(code: string, from: number): number {
  let end = from;
  for (;;) {
    const next = /^\s*\.\s*[A-Za-z_]\w*\s*\(/.exec(code.slice(end, end + 400));
    if (next === null) return end;
    const c = closing(code, end + next[0].length - 1);
    if (c === undefined) return end;
    end = c + 1;
  }
}

function topParts(code: string, from: number, to: number): Bounds[] {
  const out: Bounds[] = [];
  let depth = 0;
  let begin = from;
  for (let i = from; i < to; i += 1) {
    const c = code[i];
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === ']' || c === '}') depth -= 1;
    else if (c === ',' && depth === 0) { out.push({ start: begin, end: i }); begin = i + 1; }
  }
  out.push({ start: begin, end: to });
  return out.filter((part) => code.slice(part.start, part.end).trim() !== '');
}

function splitEquals(code: string, from: number, to: number): [string, string] | undefined {
  let depth = 0;
  for (let i = from; i < to - 1; i += 1) {
    const c = code[i];
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === ']' || c === '}') depth -= 1;
    else if (depth === 0 && c === '=' && code[i + 1] === '=' && code[i - 1] !== '!' && code[i - 1] !== '=' && code[i + 2] !== '=') {
      return [code.slice(from, i).trim(), code.slice(i + 2, to).trim()];
    }
  }
  return undefined;
}

const COLUMN = /^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$/;
const ACCESSOR = /(?:\s*\.\s*[A-Za-z_]\w*|\s*\[\s*(?:["'][^"'\n]*["']|\d+)\s*\])*/.source;
const LITERAL = /^(?:[rRbBuU]{0,2}(?:"[^"\n]*"|'[^'\n]*')|-?\d+(?:\.\d+)?|True|False|None)$/;
const REQUEST_VALUE = /^request\s*\.\s*(?:json|form|args|values|data|POST|GET|get_json\s*\(\s*\)|view_args|query_params|path_params)\b/;
const CONVERSION = /^(?:int|str|float|UUID|uuid\.UUID)\s*\(([\s\S]*)\)$/;

interface CallerContext {
  params: Set<string>;
  flaskLoginCurrentUser: boolean;
  gNames: Set<string>;
  gClient: Set<string>;
  aliases: Set<string>;
  client: Set<string>;
}

function isCaller(expression: string, caller: CallerContext): boolean {
  const text = expression.trim();
  if (new RegExp(`^(?:self\\s*\\.\\s*)?request\\s*\\.\\s*user${ACCESSOR}$`).test(text)) return true;
  if (caller.flaskLoginCurrentUser && new RegExp(`^current_user${ACCESSOR}$`).test(text)) return true;
  const g = new RegExp(`^g\\s*\\.\\s*([A-Za-z_]\\w*)${ACCESSOR}$`).exec(text);
  if (g !== null && caller.gNames.has(g[1]!)) return true;
  const head = new RegExp(`^([A-Za-z_]\\w*)${ACCESSOR}$`).exec(text);
  if (head !== null && (caller.params.has(head[1]!) || caller.aliases.has(head[1]!))) return true;
  return false;
}

function isClientValue(expression: string, caller: CallerContext): boolean {
  const text = expression.trim();
  const conversion = CONVERSION.exec(text);
  if (conversion !== null) return isClientValue(conversion[1]!.split(',')[0] ?? '', caller);
  if (REQUEST_VALUE.test(text)) return true;
  const g = new RegExp(`^g\\s*\\.\\s*([A-Za-z_]\\w*)${ACCESSOR}$`).exec(text);
  if (g !== null && caller.gClient.has(g[1]!)) return true;
  const head = new RegExp(`^([A-Za-z_]\\w*)${ACCESSOR}$`).exec(text);
  return head !== null && caller.client.has(head[1]!);
}

type ValueKind = 'owned' | 'client' | 'constant' | 'unknown';

function valueKind(expression: string, caller: CallerContext): ValueKind {
  const text = expression.trim();
  if (isCaller(text, caller)) return 'owned';
  if (LITERAL.test(text)) return 'constant';
  if (isClientValue(text, caller)) return 'client';
  return 'unknown';
}

type Verdict = 'owned' | 'client' | 'unknown';

function combine(kinds: ValueKind[]): Verdict {
  if (kinds.includes('owned')) return 'owned';
  if (kinds.includes('unknown') || !kinds.includes('client')) return 'unknown';
  return 'client';
}

function argumentKinds(code: string, open: number, close: number, name: string, caller: CallerContext): ValueKind[] {
  const parts = topParts(code, open + 1, close);
  if (name === 'eq') {
    const value = parts[1];
    return parts.length === 2 && value !== undefined ? [valueKind(code.slice(value.start, value.end), caller)] : ['unknown'];
  }
  const kinds: ValueKind[] = [];
  parts.forEach((part, i) => {
    const text = code.slice(part.start, part.end);
    if (i === 0 && /^(?:get|get_or_404|get_object_or_404|get_list_or_404)$/.test(name) && parts.length > 1 && /^\s*[A-Z]\w*(?:\.[A-Z]\w*)*\s*$/.test(text)) return;
    const keyword = /^\s*([A-Za-z_]\w*)\s*=(?!=)/.exec(text);
    if (keyword !== null) { kinds.push(valueKind(text.slice(keyword[0].length), caller)); return; }
    const sides = splitEquals(code, part.start, part.end);
    if (sides !== undefined) {
      const [left, right] = sides;
      if (COLUMN.test(left) && !COLUMN.test(right)) kinds.push(valueKind(right, caller));
      else if (COLUMN.test(right) && !COLUMN.test(left)) kinds.push(valueKind(left, caller));
      else if (COLUMN.test(left) && COLUMN.test(right)) kinds.push(isCaller(right, caller) || isCaller(left, caller) ? 'owned' : isClientValue(right, caller) || isClientValue(left, caller) ? 'client' : 'unknown');
      else kinds.push('unknown');
      return;
    }
    const conj = /^\s*(?:[\w.]+\.)?and_\s*\(/.exec(text);
    if (conj !== null) {
      const innerOpen = part.start + text.indexOf('(', conj.index);
      const innerClose = closing(code, innerOpen);
      if (innerClose !== undefined && innerClose < part.end) { kinds.push(...argumentKinds(code, innerOpen, innerClose, 'and_', caller)); return; }
    }
    if (/^(?:get|get_or_404)$/.test(name)) { kinds.push(valueKind(text, caller)); return; }
    kinds.push('unknown');
  });
  return kinds;
}

const PLAIN_CALLS = new Set([
  'query', 'select', 'delete', 'table', 'from_', 'execute', 'scalar', 'scalars', 'all', 'first', 'one', 'one_or_none',
  'first_or_404', 'one_or_404', 'scalar_one', 'scalar_one_or_none', 'order_by', 'limit', 'select_related',
  'prefetch_related', 'only', 'defer', 'distinct', 'with_for_update', 'options', 'unique',
]);

const NO_PAYLOAD: ReadonlySet<string> = new Set();
const UPDATE_PAYLOAD: ReadonlySet<string> = new Set(['update', 'values', 'returning']);

function chainVerdict(code: string, from: number, to: number, caller: CallerContext, payload: ReadonlySet<string> = NO_PAYLOAD): Verdict {
  const kinds: ValueKind[] = [];
  for (const call of chainCalls(code, from, to)) {
    if (payload.has(call.name)) continue;
    if (FILTER_CALLS.has(call.name)) kinds.push(...argumentKinds(code, call.open, call.close, call.name, caller));
    else if (!PLAIN_CALLS.has(call.name)) kinds.push('unknown');
  }
  return combine(kinds);
}

function isFetch(text: string): boolean {
  const t = text.trim().replace(/^await\s+/, '').replace(/^\(\s*/, '');
  return /^get_object_or_404\s*\(/.test(t)
    || /^[A-Za-z_]\w*\s*\.\s*(?:objects|query)\s*\./.test(t)
    || /^(?:[A-Za-z_]\w*\s*\.\s*)*(?:db|session|\w+_session)\s*\.\s*(?:query\s*\(|get\s*\(|get_or_404\s*\(|execute\s*\(\s*select\s*\(|scalars?\s*\(\s*select\s*\()/.test(t);
}


interface Statement { line: number; target: string; value: Bounds }

function assignmentsIn(code: string, lines: string[], lineStarts: number[], from: number, beforeLine: number): Statement[] {
  const out: Statement[] = [];
  for (let l = from; l < beforeLine; l += 1) {
    const text = lines[l - 1] ?? '';
    const m = /^(\s*)([A-Za-z_]\w*)\s*(?::[^=\n]+)?=(?!=)\s*/.exec(text);
    if (m === null) continue;
    const start = lineStarts[l - 1]! + m[0].length;
    let depth = 0;
    let i = start;
    for (; i < code.length; i += 1) {
      const c = code[i];
      if (c === '(' || c === '[' || c === '{') depth += 1;
      else if (c === ')' || c === ']' || c === '}') depth -= 1;
      else if (c === '\n' && depth <= 0 && code[i - 1] !== '\\') break;
    }
    out.push({ line: l, target: m[2]!, value: { start, end: i } });
  }
  return out;
}

function boundOtherwise(lines: string[], from: number, beforeLine: number, name: string): boolean {
  const n = name.replace(/\W/g, '');
  const other = new RegExp(`^\\s*for\\b[^:]*\\b${n}\\b[^:]*\\bin\\b|\\bas\\s+\\(?[\\w\\s,]*\\b${n}\\b|^\\s*[\\w\\s,()]*,\\s*${n}\\s*(?:,[\\w\\s,()]*)?=(?!=)|^\\s*${n}\\s*,[\\w\\s,()]*=(?!=)|^\\s*${n}\\s*(?:[-+*/%&|^@]|//|<<|>>|\\*\\*)=|\\b${n}\\s*:=|^\\s*(?:global|nonlocal)\\b[^\\n]*\\b${n}\\b|^\\s*del\\b[^\\n]*\\b${n}\\b`);
  for (let l = from; l < beforeLine; l += 1) if (other.test(lines[l - 1] ?? '')) return true;
  return false;
}

type CheckVerdict = 'owned' | 'unread' | 'none';

const COMPARISON = /^\s*\(?\s*([\s\S]+?)\s*(!=|==|\bis\s+not\b|\bnot\s+in\b|\bis\b|\bin\b)\s*([\s\S]+?)\s*\)?\s*$/;

function conditionVerdict(condition: string, obj: string, caller: CallerContext, mismatch: boolean, refuses: boolean): CheckVerdict {
  const mentions = new RegExp(`(?<![\\w.])${obj}\\b`);
  let verdict: CheckVerdict = 'none';
  for (const part of condition.split(mismatch ? /\s+or\s+/ : /\s+and\s+/)) {
    if (!mentions.test(part)) continue;
    if (new RegExp(`^\\s*(?:not\\s+${obj}|${obj}\\s+is\\s+(?:not\\s+)?None|${obj})\\s*$`).test(part)) continue;
    const cmp = COMPARISON.exec(part);
    const ofObj = (side: string): boolean => new RegExp(`^${obj}\\s*\\.\\s*[A-Za-z_]\\w*${ACCESSOR}$`).test(side.trim());
    if (cmp === null || (!ofObj(cmp[1]!) && !ofObj(cmp[3]!))) { verdict = 'unread'; continue; }
    const other = ofObj(cmp[1]!) ? cmp[3]! : cmp[1]!;
    const kind = valueKind(other, caller);
    const differs = /^(?:!=|is\s+not|not\s+in)$/.test(cmp[2]!.replace(/\s+/g, ' '));
    if (kind === 'owned' && differs === mismatch && (refuses || !mismatch)) return 'owned';
    if (kind === 'owned' || kind === 'unknown') verdict = 'unread';
  }
  return verdict;
}

function refusesTheOwner(tree: PyTree | undefined, line: number, obj: string, caller: CallerContext): boolean {
  if (tree === undefined) return false;
  const statement = tree.find((n) => n.type === 'if_statement' && n.line === line)[0];
  let condition = statement?.child('condition');
  while (condition?.type === 'parenthesized_expression') condition = condition.namedChildren[0];
  if (condition?.type !== 'comparison_operator') return false;
  const operands = condition.namedChildren;
  const operators = condition.childrenOf('operators');
  if (operands.length !== 2 || operators.length !== 1 || operators[0]!.text !== '==') return false;
  const ofObj = (n: PyNode): boolean => n.type === 'attribute' && n.child('object')?.type === 'identifier' && n.child('object')!.text === obj;
  const [left, right] = operands as [PyNode, PyNode];
  return (ofObj(left) && isCaller(right.text, caller)) || (ofObj(right) && isCaller(left.text, caller));
}

function objectChecks(lines: string[], handler: { bodyIndent: number; bodyLine: number }, deleteLine: number, obj: string, caller: CallerContext, tree?: PyTree): CheckVerdict {
  const REFUSE = /^\s*(?:raise\b|abort\s*\(|return\b[^\n]*(?:\b40[134]\b|Forbidden|NotFound|PermissionDenied|Http404))/;
  const EXIT = /^\s*(?:raise\b|abort\s*\(|return\b)/;
  let verdict: CheckVerdict = 'none';
  const merge = (next: CheckVerdict): boolean => {
    if (next === 'owned') return true;
    if (next === 'unread') verdict = 'unread';
    return false;
  };
  for (let l = handler.bodyLine; l < deleteLine; l += 1) {
    const text = lines[l - 1] ?? '';
    if (indentOf(text) !== handler.bodyIndent) continue;
    const head = /^\s*if\s+([\s\S]+?)\s*:\s*(.*)$/.exec(text);
    if (head === null) continue;
    const block: string[] = [];
    if (head[2]!.trim() !== '') block.push(head[2]!);
    else {
      let blockIndent = -1;
      for (let n = l + 1; n < deleteLine; n += 1) {
        const next = lines[n - 1] ?? '';
        if (next.trim() === '') continue;
        if (indentOf(next) <= handler.bodyIndent) break;
        if (blockIndent < 0) blockIndent = indentOf(next);
        if (indentOf(next) === blockIndent) block.push(next);
      }
    }
    if (!block.some((statement) => EXIT.test(statement))) continue;
    if (block.some((statement) => REFUSE.test(statement)) && refusesTheOwner(tree, l, obj, caller)) continue;
    if (merge(conditionVerdict(head[1]!, obj, caller, true, block.some((statement) => REFUSE.test(statement))))) return 'owned';
  }
  let indent = indentOf(lines[deleteLine - 1] ?? '');
  for (let l = deleteLine - 1; l >= handler.bodyLine && indent > handler.bodyIndent; l -= 1) {
    const text = lines[l - 1] ?? '';
    if (text.trim() === '' || indentOf(text) >= indent) continue;
    indent = indentOf(text);
    const head = /^\s*(?:if|elif)\s+([\s\S]+?)\s*:\s*$/.exec(text);
    if (head !== null) {
      if (merge(conditionVerdict(head[1]!, obj, caller, false, false))) return 'owned';
    } else if (/^\s*else\s*:/.test(text) && new RegExp(`(?<![\\w.])${obj}\\b`).test(lines.slice(handler.bodyLine - 1, l - 1).join('\n'))) {
      verdict = 'unread';
    }
  }
  return verdict;
}

function owns(verdict: Verdict): boolean | undefined {
  return verdict === 'owned' ? true : verdict === 'client' ? false : undefined;
}

function clientParameters(lines: string[], defLine: number, bodyLine: number): Set<string> {
  const names = new Set<string>();
  const header = lines.slice(defLine - 1, bodyLine - 1).join('\n');
  const open = header.indexOf('(');
  const close = open < 0 ? undefined : closing(header, open);
  if (close === undefined) return names;
  for (const part of topParts(header, open + 1, close)) {
    const text = header.slice(part.start, part.end);
    const name = /^\s*([A-Za-z_]\w*)\b/.exec(text)?.[1];
    if (name === undefined || /^(?:self|cls|request|req)$/.test(name)) continue;
    if (/\b(?:Depends|Security)\s*\(/.test(text)) continue;
    names.add(name);
  }
  return names;
}

interface Handler { routes: ApiRoute[]; defLine: number; endLine: number; bodyIndent: number; bodyLine: number }

function bodyLineOf(lines: string[], defLine: number): number {
  let depth = 0;
  for (let l = defLine; l <= lines.length; l += 1) {
    for (const c of lines[l - 1] ?? '') {
      if (c === '(' || c === '[' || c === '{') depth += 1;
      else if (c === ')' || c === ']' || c === '}') depth -= 1;
    }
    if (depth <= 0 && /:\s*(?:\S.*)?$/.test(lines[l - 1] ?? '')) return l + 1;
  }
  return defLine + 1;
}

function handlerAt(context: RuleContext, entry: FileMapEntry, line: number): Handler | undefined {
  const lines = maskedLines(entry.content);
  const def = enclosingDef(lines, line);
  if (def === undefined) return undefined;
  const routes = context.projectMap.apiRoutes.filter((route) => {
    if (route.filePath !== entry.path) return false;
    const span = pythonHandlerSpan(context, route);
    return span !== undefined && span.startLine <= def.defLine && def.endLine <= span.endLine && span.startLine <= line && line <= span.endLine;
  });
  if (routes.length === 0) return undefined;
  const bodyLine = bodyLineOf(lines, def.defLine);
  let bodyIndent = -1;
  for (let l = bodyLine; l <= def.endLine; l += 1) {
    const text = lines[l - 1] ?? '';
    if (text.trim() === '') continue;
    bodyIndent = indentOf(text);
    break;
  }
  return { routes, defLine: def.defLine, endLine: def.endLine, bodyIndent, bodyLine };
}

type Origin = 'safe' | 'request' | 'unknown';

interface OriginEnv { library: (name: string) => string | undefined }

const REQUEST_PARTS = new Set(['json', 'form', 'args', 'values', 'data', 'headers', 'cookies', 'view_args', 'files']);
const ROW_CALLS = new Set(['get', 'filter_by', 'first', 'one', 'one_or_none', 'first_or_404', 'get_or_404']);

function allOrigins(origins: Origin[]): Origin {
  if (origins.length > 0 && origins.every((o) => o === 'safe')) return 'safe';
  if (origins.length > 0 && origins.every((o) => o === 'request')) return 'request';
  return 'unknown';
}

function callValues(call: PyNode): PyNode[] | undefined {
  const args = call.child('arguments');
  if (args === undefined || args.type !== 'argument_list') return undefined;
  const out: PyNode[] = [];
  for (const arg of args.namedChildren) {
    if (arg.type === 'list_splat' || arg.type === 'dictionary_splat') return undefined;
    out.push(arg.type === 'keyword_argument' ? arg.child('value')! : arg);
  }
  return out;
}

function keyword(call: PyNode, name: string): PyNode | undefined {
  return call.child('arguments')?.namedChildren.find((a) => a.type === 'keyword_argument' && a.child('name')?.text === name)?.child('value');
}

function verifiedDecode(call: PyNode, env: OriginEnv): boolean {
  const fn = call.child('function');
  if (fn === undefined || env.library(fn.text.replace(/\s+/g, '')) !== 'jwt:decode') return false;
  const positional = call.child('arguments')?.namedChildren.filter((a) => a.type !== 'keyword_argument' && a.type !== 'comment') ?? [];
  if (keyword(call, 'options') !== undefined || keyword(call, 'verify') !== undefined) return false;
  if (positional.some((a) => a.type === 'list_splat' || a.type === 'dictionary_splat')) return false;
  const key = positional[1] ?? keyword(call, 'key');
  if (key === undefined || key.type === 'none' || (key.type === 'string' && /^[rbuRBU]*(['"])\1$/.test(key.text))) return false;
  const algorithms = keyword(call, 'algorithms');
  return algorithms !== undefined && algorithms.type === 'list' && !/['"]none['"]/i.test(algorithms.text);
}

function originOf(node: PyNode | undefined, fn: PyNode | undefined, env: OriginEnv, depth: number): Origin {
  if (node === undefined || depth > 8) return 'unknown';
  const next = (n: PyNode | undefined): Origin => originOf(n, fn, env, depth + 1);
  if (isPlainLiteral(node)) return 'safe';
  switch (node.type) {
    case 'parenthesized_expression':
      return next(node.namedChildren[0]);
    case 'identifier': {
      const name = node.text;
      if (fn !== undefined) {
        if (parameterNames(fn).includes(name)) return 'unknown';
        const bindings = bindingsOf(fn, name);
        if (bindings.length > 0) {
          return allOrigins(bindings.map((b) => next(b.value)));
        }
      }
      if (name === 'current_user' && env.library(name) === 'flask_login:current_user') return 'safe';
      if (name === 'session' && env.library(name) === 'flask:session') return 'safe';
      return 'unknown';
    }
    case 'attribute':
    case 'subscript': {
      const base = node.child(node.type === 'attribute' ? 'object' : 'value');
      if (node.type === 'attribute' && base?.type === 'identifier' && base.text === 'request' && env.library('request') === 'flask:request') {
        return REQUEST_PARTS.has(node.child('attribute')?.text ?? '') ? 'request' : 'unknown';
      }
      return next(base);
    }
    case 'call': {
      const callee = node.child('function');
      if (callee === undefined) return 'unknown';
      if (verifiedDecode(node, env)) return 'safe';
      if (callee.type === 'identifier' && /^(?:int|str|UUID)$/.test(callee.text)) {
        const values = callValues(node);
        return values !== undefined && values.length === 1 ? next(values[0]) : 'unknown';
      }
      if (callee.type !== 'attribute') return 'unknown';
      const method = callee.child('attribute')?.text ?? '';
      const receiver = callee.child('object');
      if (method === 'get_json' && receiver?.type === 'identifier' && receiver.text === 'request' && env.library('request') === 'flask:request') return 'request';
      const row = rowLookup(node);
      if (row !== undefined) return allOrigins(row.map((v) => next(v)));
      if (method === 'get') {
        const values = callValues(node);
        if (values === undefined || values.length === 0 || values.length > 2 || !values.every((v) => isPlainLiteral(v))) return 'unknown';
        return next(receiver);
      }
      return 'unknown';
    }
    default:
      return 'unknown';
  }
}

function rowLookup(call: PyNode): PyNode[] | undefined {
  const values: PyNode[] = [];
  let current: PyNode | undefined = call;
  while (current?.type === 'call') {
    const callee: PyNode | undefined = current.child('function');
    if (callee?.type !== 'attribute' || !ROW_CALLS.has(callee.child('attribute')?.text ?? '')) return undefined;
    const args = callValues(current);
    if (args === undefined) return undefined;
    const receiver: PyNode | undefined = callee.child('object');
    const root = receiver?.text.replace(/\s+/g, '') ?? '';
    if (/^[A-Z]\w*\.(?:query|objects)$/.test(root)) return [...values, ...args];
    if (/^(?:db\.session|session|db)$/.test(root) && callee.child('attribute')?.text === 'get') {
      if (args[0]?.type !== 'identifier' || !/^[A-Z]/.test(args[0].text)) return undefined;
      return [...values, ...args.slice(1)];
    }
    values.push(...args);
    current = receiver;
  }
  return undefined;
}

function gFactsOf(context: RuleContext): { caller: Set<string>; client: Set<string> } {
  const cached = gCache.get(context.fileMap);
  if (cached !== undefined) return cached;
  const origins = new Map<string, Origin[]>();
  const unread = new Set<string>();
  let anySetattr = false;
  for (const entry of context.fileMap.entries) {
    if (entry.extension !== '.py') continue;
    const code = maskPython(entry.content);
    if (/\bsetattr\s*\(\s*g\s*,/.test(code) || /\bflask\s*\.\s*g\b/.test(code)) anySetattr = true;
    const mentioned = [...code.matchAll(/(?<![\w.])g\s*\.\s*([A-Za-z_]\w*)/g)].map((m) => m[1]!);
    if (mentioned.length === 0) continue;
    const read = readPythonTree(entry);
    const flaskG = libraryImport(context, entry.path, 'g') === 'flask:g';
    if (read.tree === undefined || !flaskG) { for (const name of mentioned) unread.add(name); continue; }
    const env: OriginEnv = { library: (name) => libraryImport(context, entry.path, name) };
    for (const target of read.tree.find((n) => n.type === 'attribute' && n.child('object')?.text === 'g' && n.child('object')?.type === 'identifier')) {
      const name = target.child('attribute')?.text ?? '';
      const parent = target.parent;
      const plain = parent?.type === 'assignment' && target.field === 'left';
      const written = plain || ['augmented_assignment', 'pattern_list', 'tuple_pattern', 'list_pattern', 'for_statement', 'as_pattern_target', 'delete_statement'].includes(parent?.type ?? '');
      if (!written) continue;
      if (!plain) { unread.add(name); continue; }
      const fn = functionAt(read.tree, target.line);
      origins.set(name, [...(origins.get(name) ?? []), originOf(parent!.child('right'), fn, env, 0)]);
    }
  }
  const facts = { caller: new Set<string>(), client: new Set<string>() };
  if (!anySetattr) {
    for (const [name, list] of origins) {
      if (unread.has(name)) continue;
      const origin = allOrigins(list);
      if (origin === 'safe') facts.caller.add(name);
      else if (origin === 'request') facts.client.add(name);
    }
  }
  gCache.set(context.fileMap, facts);
  return facts;
}
const gCache = new WeakMap<object, { caller: Set<string>; client: Set<string> }>();

function libraryImport(context: RuleContext, filePath: string, name: string): string | undefined {
  const proj = pythonReading.project(context);
  const symbol = pythonReading.resolveSymbol(proj, filePath, name);
  return symbol?.kind === 'library' ? `${symbol.module}:${symbol.name}` : undefined;
}

export function pythonOrmDeletes(context: RuleContext, entry: FileMapEntry): PythonDeleteSite[] {
  return pythonOrmWrites(context, entry, 'delete');
}

export function pythonOrmUpdates(context: RuleContext, entry: FileMapEntry): PythonDeleteSite[] {
  return pythonOrmWrites(context, entry, 'update');
}

const FIELD_WRITE = /^[ \t]*([A-Za-z_]\w*)[ \t]*\.[ \t]*[A-Za-z_]\w*(?:[ \t]*\.[ \t]*[A-Za-z_]\w*|[ \t]*\[[^\]\n]*\])*[ \t]*(?:[-+*/%&|^@]|\/\/|<<|>>|\*\*)?=(?!=)/gm;
const SETATTR_WRITE = /(?<![\w.])setattr\s*\(\s*([A-Za-z_]\w*)\s*,/g;
const SESSION_COMMIT = /(?<![\w.])(?:[A-Za-z_]\w*\s*\.\s*)*(?:db|session|\w+_session)\s*\.\s*commit\s*\(/;
const UPDATE_QUERY = /^[A-Za-z_]\w*\.query\.|^(?:[A-Za-z_]\w*\.)*(?:db|session|\w+_session)\.query\(|^[A-Za-z_]\w*\.objects\.|\.(?:table|from_)\(/;

function pythonOrmWrites(context: RuleContext, entry: FileMapEntry, kind: 'delete' | 'update'): PythonDeleteSite[] {
  if (entry.extension !== '.py' || !(kind === 'delete' ? /\bdelete\b/ : /\b(?:update|commit|save)\b/).test(entry.content)) return [];
  const code = maskPython(entry.content);
  const lines = code.split('\n');
  const lineStarts = [0];
  for (let i = 0; i < code.length; i += 1) if (code.charCodeAt(i) === 10) lineStarts.push(i + 1);
  const lineOf = (index: number): number => {
    let lo = 0;
    let hi = lineStarts.length - 1;
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (lineStarts[mid]! <= index) lo = mid; else hi = mid - 1; }
    return lo + 1;
  };
  const flaskLogin = libraryImport(context, entry.path, 'current_user') === 'flask_login:current_user';
  const flaskG = libraryImport(context, entry.path, 'g') === 'flask:g';
  const coreDelete = kind === 'delete' && /^sqlalchemy(?:\.\w+)*:delete$/.test(libraryImport(context, entry.path, 'delete') ?? '');
  const coreUpdate = kind === 'update' && /^sqlalchemy(?:\.\w+)*:update$/.test(libraryImport(context, entry.path, 'update') ?? '');
  const tree = readPythonTree(entry).tree;

  interface Candidate { index: number; judge: (caller: CallerContext, handler: Handler) => boolean | undefined; report?: (handler: Handler) => number | undefined }
  const candidates: Candidate[] = [];

  const objectOwned = (obj: string, at: number, caller: CallerContext, handler: Handler): boolean | undefined => {
    const line = lineOf(at);
    if (boundOtherwise(lines, handler.bodyLine, line, obj)) return undefined;
    const fetches = assignmentsIn(code, lines, lineStarts, handler.bodyLine, line).filter((s) => s.target === obj);
    if (fetches.length === 0) return undefined;
    if (!fetches.every((s) => isFetch(code.slice(s.value.start, s.value.end)))) return undefined;
    const verdicts = fetches.map((s) => chainVerdict(code, s.value.start, s.value.end, caller));
    if (verdicts.includes('unknown')) return undefined;
    if (verdicts.every((v) => v === 'owned')) return true;
    const checked = objectChecks(lines, handler, line, obj, caller, tree);
    return checked === 'owned' ? true : checked === 'unread' ? undefined : false;
  };

  for (const m of kind === 'delete' ? code.matchAll(/\.\s*delete\s*\(/g) : []) {
    const dot = m.index!;
    const open = dot + m[0].length - 1;
    const close = closing(code, open);
    if (close === undefined) continue;
    const args = code.slice(open + 1, close).trim();
    const start = chainStart(code, dot);
    const receiver = code.slice(start, dot).replace(/\s+/g, '');
    const word = dot + m[0].indexOf('delete');
    if (args === '') {
      if (/^[A-Za-z_]\w*$/.test(receiver)) {
        candidates.push({ index: word, judge: (caller, handler) => objectOwned(receiver, word, caller, handler) });
        continue;
      }
      const django = /^[A-Za-z_]\w*\.objects\./.test(receiver) || /^get_object_or_404\(/.test(receiver);
      const legacy = /^[A-Za-z_]\w*\.query\./.test(receiver) || /^(?:[A-Za-z_]\w*\.)*(?:db|session|\w+_session)\.query\(/.test(receiver);
      const supabase = /\.(?:table|from_)\(/.test(receiver);
      if (!django && !legacy && !supabase) continue;
      const last = chainEnd(code, close + 1);
      candidates.push({ index: word, judge: (caller) => owns(chainVerdict(code, start, last, caller)) });
      continue;
    }
    if (/^(?:await)?(?:[A-Za-z_]\w*\.)*(?:db|session|\w+_session)$/.test(receiver) && /^[A-Za-z_]\w*$/.test(args)) {
      candidates.push({ index: word, judge: (caller, handler) => objectOwned(args, word, caller, handler) });
    }
  }
  if (coreDelete) {
    for (const m of code.matchAll(/(?<![\w.])delete\s*\(/g)) {
      const open = m.index! + m[0].length - 1;
      const close = closing(code, open);
      if (close === undefined) continue;
      const end = chainEnd(code, close + 1);
      candidates.push({ index: m.index!, judge: (caller) => owns(chainVerdict(code, close + 1, end, caller)) });
    }
  }

  for (const m of kind === 'update' ? code.matchAll(/\.\s*update\s*\(/g) : []) {
    const dot = m.index!;
    const open = dot + m[0].length - 1;
    const close = closing(code, open);
    if (close === undefined) continue;
    const start = chainStart(code, dot);
    const receiver = code.slice(start, dot).replace(/\s+/g, '');
    const at = dot + m[0].indexOf('update');
    if (/^[A-Za-z_]\w*$/.test(receiver)) {
      candidates.push({ index: at, judge: (caller, handler) => objectOwned(receiver, at, caller, handler) });
      continue;
    }
    if (!UPDATE_QUERY.test(receiver)) continue;
    const tail = chainEnd(code, close + 1);
    candidates.push({ index: at, judge: (caller) => owns(chainVerdict(code, start, tail, caller, UPDATE_PAYLOAD)) });
  }
  if (coreUpdate) {
    for (const m of code.matchAll(/(?<![\w.])update\s*\(/g)) {
      const open = m.index! + m[0].length - 1;
      const close = closing(code, open);
      if (close === undefined) continue;
      const rest = chainEnd(code, close + 1);
      candidates.push({ index: m.index!, judge: (caller) => owns(chainVerdict(code, close + 1, rest, caller, UPDATE_PAYLOAD)) });
    }
  }
  if (kind === 'update') {
    const bound = new Set(assignmentsIn(code, lines, lineStarts, 1, lines.length + 1).map((s) => s.target));
    const writes = [...code.matchAll(FIELD_WRITE), ...code.matchAll(SETATTR_WRITE)];
    for (const w of writes) {
      const obj = w[1]!;
      if (!bound.has(obj)) continue;
      const at = w.index! + w[0].indexOf(obj);
      const writeLine = lineOf(at);
      const persisted = (handler: Handler): number | undefined => {
        const save = new RegExp(`(?<![\\w.])${obj}\\s*\\.\\s*save\\s*\\(`);
        for (let l = writeLine; l <= handler.endLine; l += 1) {
          const text = lines[l - 1] ?? '';
          if (SESSION_COMMIT.test(text) || save.test(text)) return lineStarts[l - 1]!;
        }
        return undefined;
      };
      candidates.push({
        index: at,
        judge: (caller, handler) => {
          const persist = persisted(handler);
          return persist === undefined ? undefined : objectOwned(obj, persist, caller, handler);
        },
        report: (handler) => assignmentsIn(code, lines, lineStarts, handler.bodyLine, writeLine).filter((s) => s.target === obj).at(-1)?.line,
      });
    }
  }

  const out: PythonDeleteSite[] = [];
  for (const candidate of candidates) {
    const line = lineOf(candidate.index);
    const handler = handlerAt(context, entry, line);
    if (handler === undefined) continue;
    const levels = handler.routes.map((route) => pythonRouteGuard(context, route, line)?.level);
    if (levels.some((level) => level === undefined) || levels.every((level) => level === 'admin')) continue;
    const fn = tree === undefined ? undefined : functionAt(tree, handler.defLine);
    const parsed = fn !== undefined && fn.line === handler.defLine ? fn : undefined;
    const rebound = (name: string): boolean => parsed === undefined || bindingsOf(parsed, name).length > 0;
    const params = new Set<string>();
    for (const route of handler.routes) for (const name of pythonCallerParameters(context, route)) params.add(name);
    const g = flaskG ? gFactsOf(context) : { caller: new Set<string>(), client: new Set<string>() };
    const caller: CallerContext = {
      params: new Set([...params].filter((name) => !rebound(name))),
      flaskLoginCurrentUser: flaskLogin && (parsed === undefined || bindingsOf(parsed, 'current_user').length === 0),
      gNames: g.caller,
      gClient: g.client,
      aliases: new Set(),
      client: new Set([...clientParameters(lines, handler.defLine, handler.bodyLine)].filter((name) => !params.has(name))),
    };
    const assigned = assignmentsIn(code, lines, lineStarts, handler.bodyLine, line);
    for (const target of new Set(assigned.map((s) => s.target))) {
      const values = assigned.filter((s) => s.target === target);
      if (parsed === undefined) continue;
      if (!bindingsOf(parsed, target).every((b) => b.value !== undefined && isCaller(b.value.text, caller))) continue;
      if (!boundOtherwise(lines, handler.bodyLine, line, target) && values.every((s) => isCaller(code.slice(s.value.start, s.value.end), caller))) {
        caller.aliases.add(target);
      }
    }
    for (const target of new Set(assigned.map((s) => s.target))) {
      const values = assigned.filter((s) => s.target === target);
      if (!caller.aliases.has(target) && !boundOtherwise(lines, handler.bodyLine, line, target) && values.every((s) => isClientValue(code.slice(s.value.start, s.value.end), caller))) {
        caller.client.add(target);
      }
    }
    for (const target of new Set(assigned.map((s) => s.target))) {
      const fetches = assigned.filter((s) => s.target === target && isFetch(code.slice(s.value.start, s.value.end)));
      if (fetches.length === 0 || objectChecks(lines, handler, line, target, caller, tree) === 'none') continue;
      for (const s of fetches) {
        for (const word of code.slice(s.value.start, s.value.end).match(/[A-Za-z_]\w*/g) ?? []) caller.client.delete(word);
      }
    }
    const owned = candidate.judge(caller, handler);
    if (owned === undefined) continue;
    out.push({ index: candidate.index, line: candidate.report?.(handler) ?? line, owned });
  }
  return out;
}
