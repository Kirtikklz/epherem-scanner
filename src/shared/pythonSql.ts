import { enclosingDef, maskedLines } from './pythonScope.js';

const IDENT = /^[A-Za-z_]\w*$/;

function splitTop(text: string, separator: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let quote = '';
  let start = 0;
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i]!;
    if (quote !== '') {
      if (c === '\\') { i += 1; continue; }
      if (text.startsWith(quote, i)) { i += quote.length - 1; quote = ''; }
      continue;
    }
    if (c === '"' || c === "'") { quote = text.startsWith(c.repeat(3), i) ? c.repeat(3) : c; i += quote.length - 1; continue; }
    if (c === '(' || c === '[' || c === '{') depth += 1;
    if (c === ')' || c === ']' || c === '}') depth -= 1;
    if (depth === 0 && text.startsWith(separator, i)) {
      const word = /^\w/.test(separator);
      if (!word || (!/\w/.test(text[i - 1] ?? ' ') && !/\w/.test(text[i + separator.length] ?? ' '))) {
        parts.push(text.slice(start, i));
        start = i + separator.length;
        i += separator.length - 1;
      }
    }
  }
  parts.push(text.slice(start));
  return parts;
}

function stripParens(text: string): string {
  let t = text.trim();
  while (t.startsWith('(') && t.endsWith(')') && balanced(t.slice(1, -1))) t = t.slice(1, -1).trim();
  return t;
}

function balanced(text: string): boolean {
  let depth = 0;
  let quote = '';
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i]!;
    if (quote !== '') { if (c === '\\') i += 1; else if (c === quote) quote = ''; continue; }
    if (c === '"' || c === "'") { quote = c; continue; }
    if (c === '(' || c === '[' || c === '{') depth += 1;
    if (c === ')' || c === ']' || c === '}') { depth -= 1; if (depth < 0) return false; }
  }
  return depth === 0 && quote === '';
}

function interpolations(body: string): string[] | undefined {
  const out: string[] = [];
  for (let i = 0; i < body.length; i += 1) {
    if (body[i] === '{' && body[i + 1] === '{') { i += 1; continue; }
    if (body[i] !== '{') continue;
    let depth = 1;
    let j = i + 1;
    while (j < body.length && depth > 0) { if (body[j] === '{') depth += 1; if (body[j] === '}') depth -= 1; j += 1; }
    if (depth !== 0) return undefined;
    out.push(body.slice(i + 1, j - 1).replace(/![rsa]$|:[^:{}]*$/, ''));
    i = j - 1;
  }
  return out;
}

const STRING = /^([rRbBuUfF]{0,2})("""|'''|"|')([\s\S]*)\2$/;

interface Env { statements: string[]; module: string[]; clock?: boolean; params?: Set<string> }

const CLOCK_READING = /^(?:time\s*\.\s*(?:time|monotonic)\s*\(\s*\)|(?:datetime\s*\.\s*)?datetime\s*\.\s*(?:now|utcnow)\s*\(\s*(?:(?:tz\s*=\s*)?(?:(?:datetime\s*\.\s*)?timezone\s*\.\s*utc|UTC))?\s*\)|timezone\s*\.\s*now\s*\(\s*\))(?:\s*\.\s*(?:timestamp|isoformat)\s*\(\s*\))?$/;

function constantBuilt(expression: string, env: Env, seen: Set<string>, depth: number): boolean {
  if (depth > 10) return false;
  const text = stripParens(expression);
  if (text === '') return false;
  if (env.clock === true) {
    if (/^-?\d+(?:\.\d+)?$/.test(text)) return true;
    if (CLOCK_READING.test(text)) return true;
    for (const op of ['-', '*', '//', '/']) {
      const parts = splitTop(text, op);
      if (parts.length > 1) return parts.every((part) => constantBuilt(part, env, seen, depth + 1));
    }
    const delta = /^(?:datetime\s*\.\s*)?timedelta\s*\(([\s\S]*)\)$/.exec(text);
    if (delta !== null) {
      return splitTop(delta[1]!, ',').filter((a) => a.trim() !== '').every((a) => {
        const kw = /^\s*\w+\s*=(?!=)([\s\S]+)$/.exec(a);
        return kw !== null && constantBuilt(kw[1]!, env, seen, depth + 1);
      });
    }
    const cast = /^(?:int|float|round)\s*\(([\s\S]*)\)$/.exec(text);
    if (cast !== null) return constantBuilt(cast[1]!, env, seen, depth + 1);
  }
  const conditional = splitTop(text, ' if ');
  if (conditional.length === 2) {
    const tail = splitTop(conditional[1]!, ' else ');
    return tail.length === 2 && constantBuilt(conditional[0]!, env, seen, depth + 1) && constantBuilt(tail[1]!, env, seen, depth + 1);
  }
  const sum = splitTop(text, '+');
  if (sum.length > 1) return sum.every((part) => constantBuilt(part, env, seen, depth + 1));
  const literal = STRING.exec(text);
  if (literal !== null && !literal[3]!.replace(/\\./g, '').includes(literal[2]!)) {
    if (!/[fF]/.test(literal[1]!)) return true;
    const parts = interpolations(literal[3]!);
    return parts !== undefined && parts.every((part) => constantBuilt(part, env, seen, depth + 1));
  }
  if (/^-?\d+(?:\.\d+)?$/.test(text)) return true;
  const join = /^([rRuU]?(?:"[^"\\]*"|'[^'\\]*'))\s*\.\s*join\s*\(([\s\S]*)\)$/.exec(text);
  if (join !== null) {
    const inner = join[2]!.trim();
    const generator = /^([\s\S]+?)\s+for\s+(\w+)\s+in\s+([\s\S]+)$/.exec(stripParens(inner));
    if (generator !== null) {
      const iter = generator[3]!.trim();
      if (!/^[[(]\s*(?:(?:"[^"\\]*"|'[^'\\]*')\s*,?\s*)+[\])]$/.test(iter)) return false;
      const loopEnv: Env = { ...env, statements: [...env.statements, `${generator[2]} = ""`] };
      return constantBuilt(generator[1]!, loopEnv, seen, depth + 1);
    }
    return listBuilt(inner, env, seen, depth + 1);
  }
  if (IDENT.test(text)) return nameBuilt(text, env, seen, depth + 1);
  return false;
}

function listBuilt(expression: string, env: Env, seen: Set<string>, depth: number): boolean {
  const text = stripParens(expression);
  if (/^[[(][\s\S]*[\])]$/.test(text)) {
    const inner = text.slice(1, -1).trim();
    return inner === '' || splitTop(inner, ',').filter((p) => p.trim() !== '').every((part) => constantBuilt(part, env, seen, depth + 1));
  }
  if (!IDENT.test(text)) return false;
  return nameBuilt(text, env, seen, depth + 1, true);
}

function nameBuilt(name: string, env: Env, seen: Set<string>, depth: number, asList = false): boolean {
  if (seen.has(name)) return true;
  if (env.clock === true) {
    if (env.params?.has(name) === true) return false;
    const word = new RegExp(`\\b${name}\\b`);
    const plain = new RegExp(`^\\s*${name}\\s*(?::[^=]+)?$`);
    for (const statement of env.statements) {
      const s = statement.trim();
      if (!word.test(s)) continue;
      if (new RegExp(`\\bas\\s+${name}\\b|\\b${name}\\s*:=|^(?:global|nonlocal|import|from)\\b`).test(s)) return false;
      const lhs = /^([^=]*?)(?<![=!<>])=(?!=)/.exec(s);
      if (lhs !== null && word.test(lhs[1]!) && !plain.test(lhs[1]!)) return false;
    }
  }
  const next = new Set(seen).add(name);
  const assigned: string[] = [];
  const added: string[] = [];
  for (const statement of env.statements) {
    const s = statement.trim();
    const tuple = /^([\w\s,]+?)\s*=\s*(?!=)([\s\S]+)$/.exec(s);
    if (tuple !== null && tuple[1]!.includes(',')) {
      const targets = tuple[1]!.split(',').map((t) => t.trim());
      const index = targets.indexOf(name);
      if (index >= 0) {
        const values = splitTop(tuple[2]!, ',');
        if (values.length !== targets.length) return false;
        assigned.push(values[index]!);
      }
      continue;
    }
    const m = new RegExp(`^${name}\\s*(?::[^=]+)?(\\+?=)(?!=)\\s*([\\s\\S]+)$`).exec(s);
    if (m !== null) { (m[1] === '+=' ? added : assigned).push(m[2]!); continue; }
    const call = new RegExp(`^${name}\\s*\\.\\s*(append|extend|insert)\\s*\\(([\\s\\S]*)\\)$`).exec(s);
    if (call !== null) {
      if (call[1] === 'append') added.push(`[${call[2]}]`);
      else if (call[1] === 'extend') added.push(call[2]!);
      else added.push(`[${splitTop(call[2]!, ',').slice(1).join(',')}]`);
      continue;
    }
    if (new RegExp(`^${name}\\s*(?:\\[|\\.\\s*(?!join\\b)\\w+\\s*\\()`).test(s) || new RegExp(`^for\\s+(?:[\\w\\s,]*\\b)?${name}\\b[\\w\\s,]*\\bin\\b`).test(s)) {
      return false;
    }
  }
  if (assigned.length === 0) {
    if (!/^[A-Z][A-Z0-9_]*$/.test(name)) return false;
    const writes = env.module.filter((line) => new RegExp(`^${name}\\s*=(?!=)`).test(line.trim()));
    return writes.length === 1 && constantBuilt(writes[0]!.trim().replace(new RegExp(`^${name}\\s*=\\s*`), ''), env, next, depth + 1);
  }
  const values = assigned.every((value) => asList || /^\s*[[(]/.test(value) ? listBuilt(value, env, next, depth + 1) || constantBuilt(value, env, next, depth + 1) : constantBuilt(value, env, next, depth + 1));
  return values && added.every((value) => listBuilt(value, env, next, depth + 1) || constantBuilt(value, env, next, depth + 1));
}

function statementsOf(content: string, line: number): Env | undefined {
  const masked = maskedLines(content);
  const source = content.split('\n');
  const scope = enclosingDef(masked, line);
  if (scope === undefined) return undefined;
  const statements: string[] = [];
  let current = '';
  let depth = 0;
  for (let l = scope.defLine + 1; l <= scope.endLine; l += 1) {
    const m = masked[l - 1] ?? '';
    const r = source[l - 1] ?? '';
    let start = 0;
    for (let i = 0; i < m.length; i += 1) {
      const c = m[i]!;
      if (c === '(' || c === '[' || c === '{') depth += 1;
      if (c === ')' || c === ']' || c === '}') depth -= 1;
      if (c === ';' && depth === 0) { statements.push(current + r.slice(start, i)); current = ''; start = i + 1; }
    }
    let hash = -1;
    for (let i = start; i < r.length; i += 1) if (r[i] === '#' && m.slice(i).trim() === '') { hash = i; break; }
    const piece = hash >= 0 ? r.slice(start, hash) : r.slice(start);
    current += piece;
    if (depth > 0 || /\\\s*$/.test(piece)) { current += '\n'; continue; }
    statements.push(current);
    current = '';
  }
  if (current.trim() !== '') statements.push(current);
  const module = source
    .map((text, i) => { const m = masked[i] ?? ''; const hash = [...text].findIndex((c, j) => c === '#' && m.slice(j).trim() === ''); return hash >= 0 ? text.slice(0, hash) : text; })
    .filter((text) => /^[A-Z][A-Z0-9_]*\s*=/.test(text));
  return { statements, module };
}

function callArguments(content: string, open: number): string[] | undefined {
  let depth = 0;
  let quote = '';
  let close = -1;
  for (let i = open; i < content.length && i - open < 4000; i += 1) {
    const c = content[i]!;
    if (quote !== '') { if (c === '\\') { i += 1; continue; } if (content.startsWith(quote, i)) { i += quote.length - 1; quote = ''; } continue; }
    if (c === '"' || c === "'") { quote = content.startsWith(c.repeat(3), i) ? c.repeat(3) : c; i += quote.length - 1; continue; }
    if (c === '(' || c === '[' || c === '{') depth += 1;
    if (c === ')' || c === ']' || c === '}') { depth -= 1; if (depth === 0) { close = i; break; } }
  }
  if (close < 0) return undefined;
  return splitTop(content.slice(open + 1, close), ',').filter((a) => a.trim() !== '');
}

function defParameters(masked: string[], defLine: number): Set<string> {
  const header = masked.slice(defLine - 1, defLine + 30).join('\n');
  const open = header.indexOf('(');
  const names = new Set<string>();
  if (open < 0) return names;
  let depth = 0;
  let close = -1;
  for (let i = open; i < header.length; i += 1) {
    if (header[i] === '(' || header[i] === '[' || header[i] === '{') depth += 1;
    if (header[i] === ')' || header[i] === ']' || header[i] === '}') { depth -= 1; if (depth === 0) { close = i; break; } }
  }
  for (const part of splitTop(header.slice(open + 1, close < 0 ? undefined : close), ',')) {
    const name = /^\s*\*{0,2}\s*([A-Za-z_]\w*)/.exec(part)?.[1];
    if (name !== undefined) names.add(name);
  }
  return names;
}

export function pythonSqlTakesNothingFromOutside(content: string, index: number): boolean {
  const masked = maskedLines(content).join('\n');
  let q = index - 1;
  while (q >= 0 && masked[q] !== '"' && masked[q] !== "'") q -= 1;
  if (q < 0) return false;
  while (q > 0 && masked[q - 1] === masked[q]) q -= 1;
  let p = q - 1;
  while (p >= 0 && /[rRbBuUfF]/.test(masked[p]!)) p -= 1;
  while (p >= 0 && /\s/.test(masked[p]!)) p -= 1;
  if (p < 0 || !/\.\s*execute(?:many)?\s*\($/.test(masked.slice(Math.max(0, p - 40), p + 1))) return false;
  const args = callArguments(content, p);
  if (args === undefined || args.length !== 2) return false;
  const line = content.slice(0, index).split('\n').length;
  const env = statementsOf(content, line);
  if (env === undefined) return false;
  const query = args[0]!.trim().replace(/(["'])\s+([rRbBuUfF]{0,2}["'])/g, '$1 + $2');
  if (!constantBuilt(query, env, new Set(), 0)) return false;
  const sequence = /^(?:\(([\s\S]*)\)|\[([\s\S]*)\])$/.exec(args[1]!.trim());
  const inner = sequence?.[1] ?? sequence?.[2];
  if (inner === undefined) return false;
  const items = splitTop(inner, ',').filter((v) => v.trim() !== '');
  const lines = maskedLines(content);
  const scope = enclosingDef(lines, line)!;
  const clock: Env = { ...env, clock: true, params: defParameters(lines, scope.defLine) };
  if (!items.every((item) => constantBuilt(item, clock, new Set(), 0))) return false;
  return items.some((item) => readsClock(item, clock, new Set()));
}

function readsClock(expression: string, env: Env, seen: Set<string>): boolean {
  const text = stripParens(expression);
  if (CLOCK_READING.test(text)) return true;
  const conditional = splitTop(text, ' if ');
  if (conditional.length === 2) {
    const tail = splitTop(conditional[1]!, ' else ');
    return tail.length === 2 && readsClock(conditional[0]!, env, seen) && readsClock(tail[1]!, env, seen);
  }
  for (const op of ['+', '-', '*', '//', '/']) {
    const parts = splitTop(text, op);
    if (parts.length > 1) return parts.some((part) => readsClock(part, env, seen));
  }
  const call = /^(?:(?:datetime\s*\.\s*)?timedelta|int|float|round)\s*\(([\s\S]*)\)$/.exec(text);
  if (call !== null) return splitTop(call[1]!, ',').some((a) => readsClock(a.replace(/^\s*\w+\s*=(?!=)/, ''), env, seen));
  if (!IDENT.test(text)) return false;
  if (seen.has(text)) return true;
  const values = env.statements
    .map((s) => new RegExp(`^${text}\\s*(?::[^=]+)?=(?!=)\\s*([\\s\\S]+)$`).exec(s.trim())?.[1])
    .filter((v): v is string => v !== undefined);
  const next = new Set(seen).add(text);
  return values.length > 0 && values.every((v) => readsClock(v, env, next));
}

export function pythonSqlFromConstantFragments(content: string, index: number): boolean {
  const open = content.indexOf('(', index);
  if (open < 0) return false;
  const args = callArguments(content, open);
  if (args === undefined || args.length < 2) return false;
  const line = content.slice(0, index).split('\n').length;
  const env = statementsOf(content, line);
  if (env === undefined) return false;
  const query = args[0]!.trim().replace(/(["'])\s+([rRbBuUfF]{0,2}["'])/g, '$1 + $2');
  return constantBuilt(query, env, new Set(), 0);
}
