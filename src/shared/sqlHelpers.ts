import path from 'node:path';
import type { FileMapEntry } from './types.js';
import { stripCommentsAndStrings } from './source.js';
import { pythonMasked } from './pythonFlow.js';

export interface SqlHelper {
  name: string;
  filePath: string;
  method: boolean;
}

const JS_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);
const IDENT = String.raw`[A-Za-z_$][\w$]*`;
const RESERVED = new Set(['if', 'for', 'while', 'switch', 'catch', 'function', 'return', 'require', 'import', 'super', 'constructor']);

function jsDatabaseCallOf(param: string): RegExp {
  return new RegExp(
    String.raw`\b(?:conn|connection|con|db|database|pool|client|knex|sequelize|sqlite|sql|mysql|pg|cnx)\s*\.\s*(?:query|execute|run|all|get|each|exec|prepare|raw)\s*\(\s*${param}\s*[,)]`,
  );
}

function braceBlock(code: string, open: number, limit = 4000): string | undefined {
  if (code[open] !== '{') return undefined;
  let depth = 0;
  const end = Math.min(code.length, open + limit);
  for (let i = open; i < end; i += 1) {
    const c = code[i];
    if (c === '{') depth += 1;
    else if (c === '}') {
      depth -= 1;
      if (depth === 0) return code.slice(open, i + 1);
    }
  }
  return undefined;
}

const JS_FUNCTION_VALUE =
  String.raw`(?:async\s+)?(?:function\s*(?:${IDENT})?\s*\(\s*(${IDENT})\b[^)]*\)\s*(?=\{)|\(\s*(${IDENT})\b[^)]*\)\s*=>|(${IDENT})\s*=>)`;

const JS_DEFINITIONS: readonly RegExp[] = [
  new RegExp(String.raw`\b(?:async\s+)?function\s+(${IDENT})\s*\(\s*(${IDENT})\b[^)]*\)\s*(?=\{)`, 'g'),
  new RegExp(String.raw`\b(?:const|let|var)\s+(${IDENT})\s*=\s*${JS_FUNCTION_VALUE}`, 'g'),
  new RegExp(String.raw`\b(?:module\.)?exports\.(${IDENT})\s*=\s*${JS_FUNCTION_VALUE}`, 'g'),
  new RegExp(String.raw`(?:^|[{,])\s*(${IDENT})\s*:\s*${JS_FUNCTION_VALUE}`, 'gm'),
];

function jsBodyAfter(code: string, from: number): string {
  const brace = /^\s*\{/.exec(code.slice(from, from + 40));
  if (brace !== null) return braceBlock(code, from + brace[0].length - 1) ?? '';
  return code.slice(from, from + 600).split(/;\s*(?:\n|$)|\n\s*\n/)[0] ?? '';
}

function jsHelpersIn(entry: FileMapEntry): SqlHelper[] {
  const code = stripCommentsAndStrings(entry.content);
  const out: SqlHelper[] = [];
  for (const pattern of JS_DEFINITIONS) {
    for (const m of code.matchAll(pattern)) {
      const name = m[1];
      const param = m[2] ?? m[3] ?? m[4];
      if (name === undefined || param === undefined || m.index === undefined || RESERVED.has(name)) continue;
      const body = jsBodyAfter(code, m.index + m[0].length);
      if (jsDatabaseCallOf(param.replace(/[$]/g, '\\$&')).test(body)) out.push({ name, filePath: entry.path, method: false });
    }
  }
  return out;
}

const PY_DEFINITION = /^([ \t]*)def\s+([A-Za-z_]\w*)\s*\(\s*(self\s*,\s*)?([A-Za-z_]\w*)\s*[,)=:]/gm;

function pythonHelpersIn(entry: FileMapEntry): SqlHelper[] {
  const masked = pythonMasked(entry.content);
  const lines = masked.split('\n');
  const out: SqlHelper[] = [];
  for (const m of masked.matchAll(PY_DEFINITION)) {
    if (m.index === undefined) continue;
    const indent = (m[1] ?? '').replace(/\t/g, '    ').length;
    const name = m[2] ?? '';
    const param = m[4] ?? '';
    if (param === 'self') continue;
    const startLine = masked.slice(0, m.index).split('\n').length;
    const body: string[] = [];
    for (let i = startLine; i < lines.length && body.length < 80; i += 1) {
      const line = lines[i] ?? '';
      if (line.trim() === '') continue;
      if (line.replace(/\t/g, '    ').search(/\S/) <= indent) break;
      body.push(line);
    }
    const sink = new RegExp(String.raw`(?:\.\s*(?:execute|executemany)\s*\(\s*(?:text\s*\(\s*)?|\bread_sql(?:_query)?\s*\(\s*)${param}\s*[,)]`);
    if (sink.test(body.join('\n'))) out.push({ name, filePath: entry.path, method: m[3] !== undefined });
  }
  return out;
}

const projectSaved = new WeakMap<readonly FileMapEntry[], { js: SqlHelper[]; py: SqlHelper[] }>();

export function projectSqlHelpers(entries: readonly FileMapEntry[]): { js: SqlHelper[]; py: SqlHelper[] } {
  const saved = projectSaved.get(entries);
  if (saved !== undefined) return saved;
  const js: SqlHelper[] = [];
  const py: SqlHelper[] = [];
  for (const entry of entries) {
    if (JS_EXTENSIONS.has(entry.extension)) js.push(...jsHelpersIn(entry));
    else if (entry.extension === '.py') py.push(...pythonHelpersIn(entry));
  }
  const result = { js, py };
  projectSaved.set(entries, result);
  return result;
}

function moduleStem(filePath: string): string[] {
  const posix = filePath.replace(/\\/g, '/');
  const stem = path.posix.basename(posix).replace(/\.[^.]+$/, '');
  return stem === 'index' || stem === '__init__' ? [stem, path.posix.basename(path.posix.dirname(posix))] : [stem];
}

const escape = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export function jsHelperCalls(entry: FileMapEntry, helpers: readonly SqlHelper[]): number[] {
  if (helpers.length === 0) return [];
  const code = stripCommentsAndStrings(entry.content);
  const out = new Set<number>();
  const relative = [...entry.content.matchAll(/(?:\brequire\s*\(\s*|\bfrom\s+|\bimport\s+)['"](\.{1,2}\/[^'"]+)['"]/g)];
  for (const helper of helpers) {
    const name = escape(helper.name);
    const local = helper.filePath === entry.path;
    const stems = moduleStem(helper.filePath);
    const fromItsModule = relative.filter((r) => stems.includes(moduleStem(r[1] ?? '')[0] ?? ''));
    let bare = local;
    const receivers: string[] = [];
    for (const r of fromItsModule) {
      const at = r.index ?? 0;
      const statementStart = Math.max(entry.content.lastIndexOf('\n', at) + 1, entry.content.lastIndexOf(';', at) + 1);
      const statement = entry.content.slice(statementStart, at + r[0].length + 2);
      if (new RegExp(String.raw`\{[^}]*\b${name}\b[^}]*\}`).test(statement)) bare = true;
      const binding = /(?:\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\b|\bimport\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\b)/.exec(statement);
      const receiver = binding?.[1] ?? binding?.[2];
      if (receiver !== undefined) receivers.push(receiver);
    }
    const shapes: RegExp[] = [];
    if (bare) shapes.push(new RegExp(String.raw`(?<![\w$.])${name}\s*\(`, 'g'));
    for (const receiver of receivers) shapes.push(new RegExp(String.raw`(?<![\w$.])${escape(receiver)}\s*\.\s*${name}\s*\(`, 'g'));
    for (const shape of shapes) {
      for (const m of code.matchAll(shape)) {
        if (m.index === undefined) continue;
        const before = code.slice(Math.max(0, m.index - 12), m.index);
        if (/\bfunction\s*$/.test(before)) continue;
        out.add(m.index + m[0].search(new RegExp(String.raw`${name}\s*\($`)));
      }
    }
  }
  return [...out].sort((a, b) => a - b);
}

export function pythonHelperCalls(entry: FileMapEntry, helpers: readonly SqlHelper[]): number[] {
  if (helpers.length === 0) return [];
  const masked = pythonMasked(entry.content);
  const out = new Set<number>();
  for (const helper of helpers) {
    const name = escape(helper.name);
    const local = helper.filePath === entry.path;
    const stem = escape(moduleStem(helper.filePath)[0] ?? '');
    const shapes: RegExp[] = [];
    if (helper.method) {
      if (local) shapes.push(new RegExp(String.raw`\bself\s*\.\s*${name}\s*\(`, 'g'));
    } else {
      const imported = new RegExp(String.raw`^\s*from\s+(?:[\w.]*\.)?${stem}\s+import\s+(?:\*|\(?[^\n]*\b${name}\b)`, 'm').test(masked);
      if (local || imported) shapes.push(new RegExp(String.raw`(?<![\w.])${name}\s*\(`, 'g'));
      if (new RegExp(String.raw`^\s*(?:import\s+(?:[\w.]*\.)?${stem}\b|from\s+[\w.]+\s+import\s+[^\n]*\b${stem}\b)`, 'm').test(masked)) {
        shapes.push(new RegExp(String.raw`(?<![\w.])${stem}\s*\.\s*${name}\s*\(`, 'g'));
      }
    }
    for (const shape of shapes) {
      for (const m of masked.matchAll(shape)) {
        if (m.index === undefined) continue;
        if (/\bdef\s+$/.test(masked.slice(Math.max(0, m.index - 8), m.index))) continue;
        out.add(m.index + m[0].search(new RegExp(String.raw`${name}\s*\($`)));
      }
    }
  }
  return [...out].sort((a, b) => a - b);
}
