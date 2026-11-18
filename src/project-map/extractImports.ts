import type { FileImports, FileMapEntry, ImportRef } from '../shared/types.js';
import { findMatches } from '../shared/utils.js';

const JS_IMPORT_PATTERN = /import\s+(?:[\w${}\s,*]+\s+from\s+)?['"]([^'"]+)['"]/g;
const JS_REQUIRE_PATTERN = /require\(\s*['"]([^'"]+)['"]\s*\)/g;
const JS_DYNAMIC_IMPORT_PATTERN = /import\(\s*['"]([^'"]+)['"]\s*\)/g;
const JS_EXPORT_FROM_PATTERN = /export\s+(?:\*(?:\s+as\s+[\w$]+)?|\{[^}]*\})\s+from\s+['"]([^'"]+)['"]/g;
const PY_IMPORT_PATTERN = /^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))/gm;

const ESM_IMPORT_CLAUSE_PATTERN = /import\s+([^;'"]+?)\s+from\s+['"]([^'"]+)['"]/g;
const CJS_REQUIRE_BINDING_PATTERN =
  /(?:const|let|var)\s+(\{[^}]*\}|[A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)/g;

const JS_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);

export function parseImportBindings(clause: string): string[] {
  const names: string[] = [];
  const add = (name: string | undefined): void => {
    if (name === undefined) return;
    const trimmed = name.trim();
    if (trimmed !== '' && !names.includes(trimmed)) names.push(trimmed);
  };

  const rest = clause.trim();

  const namespace = /^\*\s+as\s+([A-Za-z_$][\w$]*)/.exec(rest);
  if (namespace !== null) {
    add(namespace[1]);
    return names;
  }

  const braceStart = rest.indexOf('{');
  const head = braceStart === -1 ? rest : rest.slice(0, braceStart);
  for (const part of head.split(',')) {
    const token = part.trim();
    if (token === '' || token === '*') continue;
    const ident = /^([A-Za-z_$][\w$]*)$/.exec(token);
    if (ident !== null) add(ident[1]);
  }

  if (braceStart !== -1) {
    const braceEnd = rest.indexOf('}', braceStart);
    const inner = rest.slice(braceStart + 1, braceEnd === -1 ? rest.length : braceEnd);
    for (const part of inner.split(',')) {
      const token = part.trim();
      if (token === '') continue;
      const aliased = /^[A-Za-z_$][\w$]*\s+as\s+([A-Za-z_$][\w$]*)$/.exec(token);
      const renamed = /^[A-Za-z_$][\w$]*\s*:\s*([A-Za-z_$][\w$]*)$/.exec(token);
      const plain = /^([A-Za-z_$][\w$]*)$/.exec(token);
      if (aliased !== null) add(aliased[1]);
      else if (renamed !== null) add(renamed[1]);
      else if (plain !== null) add(plain[1]);
    }
  }

  return names;
}

function collectBindings(content: string): Map<string, string[]> {
  const byKey = new Map<string, string[]>();
  const record = (pattern: RegExp): void => {
    for (const match of findMatches(content, pattern)) {
      const clause = match.groups[0];
      const source = match.groups[1];
      if (clause === undefined || source === undefined) continue;
      const bindings = parseImportBindings(clause);
      if (bindings.length === 0) continue;
      const key = `${match.line} ${source}`;
      const existing = byKey.get(key);
      if (existing === undefined) {
        byKey.set(key, bindings);
      } else {
        for (const name of bindings) if (!existing.includes(name)) existing.push(name);
      }
    }
  };
  record(new RegExp(ESM_IMPORT_CLAUSE_PATTERN.source, 'g'));
  record(new RegExp(CJS_REQUIRE_BINDING_PATTERN.source, 'g'));
  return byKey;
}

export function extractFileImports(entry: FileMapEntry): FileImports {
  const imports: ImportRef[] = [];

  if (JS_EXTENSIONS.has(entry.extension)) {
    for (const pattern of [JS_IMPORT_PATTERN, JS_REQUIRE_PATTERN, JS_DYNAMIC_IMPORT_PATTERN, JS_EXPORT_FROM_PATTERN]) {
      for (const match of findMatches(entry.content, pattern)) {
        const source = match.groups[0];
        if (source !== undefined) imports.push({ source, line: match.line });
      }
    }

    const bindingIndex = collectBindings(entry.content);
    if (bindingIndex.size > 0) {
      for (const ref of imports) {
        const bindings = bindingIndex.get(`${ref.line} ${ref.source}`);
        if (bindings !== undefined && bindings.length > 0) ref.bindings = [...bindings];
      }
    }
  } else if (entry.extension === '.py') {
    for (const match of findMatches(entry.content, PY_IMPORT_PATTERN)) {
      const source = match.groups[0] ?? match.groups[1];
      if (source !== undefined) imports.push({ source, line: match.line });
    }
  }

  imports.sort((a, b) => a.line - b.line || a.source.localeCompare(b.source));
  return { filePath: entry.path, imports };
}
