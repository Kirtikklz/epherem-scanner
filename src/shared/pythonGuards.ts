import type { ApiRoute, FileMap, FileMapEntry, GuardLookup } from './types.js';

export type PythonGuardLevel = 'auth' | 'admin';

export interface PythonGuardProof {
  level: PythonGuardLevel;
  via: string;
}

interface PyDef {
  name: string;
  indent: number;
  defLine: number;
  endLine: number;
  bodyLine: number;
  signature: string;
  decorators: Array<{ line: number; text: string }>;
}

interface PyFile {
  entry: FileMapEntry;
  code: string;
  codeLines: string[];
  lines: string[];
  lineStarts: number[];
  defs: PyDef[];
}

const fileCache = new WeakMap<FileMapEntry, PyFile>();

export function maskPython(content: string): string {
  const out = content.split('');
  let i = 0;
  while (i < content.length) {
    const c = content[i];
    if (c === '#') {
      while (i < content.length && content[i] !== '\n') { out[i] = ' '; i += 1; }
      continue;
    }
    if (c === '"' || c === "'") {
      const quote = content.startsWith(c.repeat(3), i) ? c.repeat(3) : c;
      let j = i + quote.length;
      while (j < content.length && !content.startsWith(quote, j)) {
        if (quote.length === 1 && content[j] === '\n') break;
        if (content[j] === '\\') { if (content[j] !== '\n') out[j] = ' '; j += 1; }
        if (j < content.length && content[j] !== '\n') out[j] = ' ';
        j += 1;
      }
      i = j + (content.startsWith(quote, j) ? quote.length : 0);
      continue;
    }
    i += 1;
  }
  return out.join('');
}

function indentOf(line: string): number {
  let n = 0;
  while (n < line.length && (line[n] === ' ' || line[n] === '\t')) n += 1;
  return n;
}

function closingBracket(code: string, open: number): number | undefined {
  let depth = 0;
  for (let i = open; i < code.length; i += 1) {
    const c = code[i];
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === ']' || c === '}') {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return undefined;
}

function lineOfIndex(lineStarts: number[], index: number): number {
  let lo = 0;
  let hi = lineStarts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if ((lineStarts[mid] ?? 0) <= index) lo = mid; else hi = mid - 1;
  }
  return lo + 1;
}

function readPyFile(entry: FileMapEntry): PyFile {
  const cached = fileCache.get(entry);
  if (cached !== undefined) return cached;
  const code = maskPython(entry.content);
  const lines = entry.content.split('\n');
  const codeLines = code.split('\n');
  const lineStarts = [0];
  for (let i = 0; i < code.length; i += 1) if (code.charCodeAt(i) === 10) lineStarts.push(i + 1);
  const defs: PyDef[] = [];
  const DEF = /^([ \t]*)(?:async[ \t]+)?def[ \t]+(\w+)[ \t]*\(/gm;
  let match: RegExpExecArray | null;
  while ((match = DEF.exec(code)) !== null) {
    const indent = (match[1] ?? '').length;
    const open = match.index + match[0].length - 1;
    const close = closingBracket(code, open);
    if (close === undefined) continue;
    const defLine = lineOfIndex(lineStarts, match.index);
    const headerEndLine = lineOfIndex(lineStarts, close);
    const headerRest = (codeLines[headerEndLine - 1] ?? '').slice(close - (lineStarts[headerEndLine - 1] ?? 0) + 1);
    const colon = headerRest.indexOf(':');
    let endLine = headerEndLine;
    if (colon >= 0 && headerRest.slice(colon + 1).trim() === '') {
      for (let l = headerEndLine + 1; l <= codeLines.length; l += 1) {
        const text = codeLines[l - 1] ?? '';
        if (text.trim() === '') continue;
        if (indentOf(text) <= indent) break;
        endLine = l;
      }
    }
    const decorators: Array<{ line: number; text: string }> = [];
    let next = defLine;
    for (let l = defLine - 1; l >= 1; l -= 1) {
      const text = codeLines[l - 1] ?? '';
      if (text.trim() === '') break;
      const ind = indentOf(text);
      if (ind === indent && text.trim().startsWith('@')) {
        decorators.unshift({ line: l, text: lines.slice(l - 1, next - 1).join('\n') });
        next = l;
        continue;
      }
      if (ind > indent || /^[)\]}]/.test(text.trim())) continue;
      break;
    }
    defs.push({ name: match[2] ?? '', indent, defLine, endLine, bodyLine: headerEndLine + 1, signature: code.slice(open + 1, close), decorators });
  }
  const file: PyFile = { entry, code, codeLines, lines, lineStarts, defs };
  fileCache.set(entry, file);
  return file;
}

function originalLines(file: PyFile, from: number, to: number): string {
  return file.lines.slice(from - 1, to).join('\n');
}

function splitTopLevel(text: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i];
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === ']' || c === '}') depth -= 1;
    else if (c === ',' && depth === 0) { parts.push(text.slice(start, i)); start = i + 1; }
  }
  parts.push(text.slice(start));
  return parts.map((part) => part.trim()).filter((part) => part !== '');
}

function keywordArgument(args: string, name: string): string | undefined {
  for (const part of splitTopLevel(args)) {
    const m = new RegExp(`^${name}\\s*=(?!=)\\s*([\\s\\S]*)$`).exec(part);
    if (m !== null) return (m[1] ?? '').trim();
  }
  return undefined;
}

interface Project {
  byPath: Map<string, FileMapEntry>;
  pyPaths: string[];
  symbolCache: Map<string, ResolvedSymbol | undefined>;
  levelCache: Map<string, PythonGuardLevel | undefined | 'pending'>;
  includes?: IncludeCall[];
  gates?: Gate[];
  djangoDefault?: { level: PythonGuardLevel | undefined; found: boolean };
  loginMiddleware?: boolean;
}

const projectCache = new WeakMap<FileMap, Project>();

function project(source: Pick<GuardLookup, 'fileMap'>): Project {
  const cached = projectCache.get(source.fileMap);
  if (cached !== undefined) return cached;
  const byPath = new Map<string, FileMapEntry>();
  for (const entry of source.fileMap.entries) if (entry.extension === '.py') byPath.set(entry.path, entry);
  const built: Project = {
    byPath,
    pyPaths: [...byPath.keys()].sort(),
    symbolCache: new Map(),
    levelCache: new Map(),
  };
  projectCache.set(source.fileMap, built);
  return built;
}

function dirOf(path: string): string {
  const i = path.lastIndexOf('/');
  return i < 0 ? '' : path.slice(0, i);
}

function joinPath(dir: string, rest: string): string {
  return dir === '' ? rest : `${dir}/${rest}`;
}

function resolveModule(proj: Project, fromFile: string, spec: string): string | undefined {
  const dots = /^\.*/.exec(spec)?.[0].length ?? 0;
  const rest = spec.slice(dots).split('.').filter(Boolean).join('/');
  if (dots > 0) {
    let base = dirOf(fromFile);
    for (let d = 1; d < dots; d += 1) base = dirOf(base);
    const candidates = rest === ''
      ? [joinPath(base, '__init__.py')]
      : [joinPath(base, `${rest}.py`), joinPath(base, `${rest}/__init__.py`)];
    return candidates.find((candidate) => proj.byPath.has(candidate));
  }
  if (rest === '') return undefined;
  const matches = proj.pyPaths.filter((path) =>
    path === `${rest}.py` || path.endsWith(`/${rest}.py`) ||
    path === `${rest}/__init__.py` || path.endsWith(`/${rest}/__init__.py`));
  if (matches.length === 0) return undefined;
  const from = dirOf(fromFile);
  const shared = (path: string): number => {
    let n = 0;
    while (n < path.length && n < from.length && path[n] === from[n]) n += 1;
    return n;
  };
  return [...matches].sort((a, b) => shared(b) - shared(a) || a.localeCompare(b))[0];
}

type Binding = { module: string } | { module: string; name: string };

function importBinding(file: PyFile, name: string): Binding | undefined {
  const code = file.code;
  const FROM = /^[ \t]*from[ \t]+(\.*[\w.]*)[ \t]+import[ \t]+(\([^)]*\)|[^\n]*)/gm;
  let m: RegExpExecArray | null;
  while ((m = FROM.exec(code)) !== null) {
    const spec = m[1] ?? '';
    const list = (m[2] ?? '').replace(/[()\\]/g, ' ');
    for (const item of list.split(',')) {
      const parts = item.trim().split(/\s+as\s+/);
      const imported = (parts[0] ?? '').trim();
      const bound = (parts[1] ?? imported).trim();
      if (bound === name && imported !== '' && imported !== '*') return { module: spec, name: imported };
    }
  }
  const IMPORT = /^[ \t]*import[ \t]+([^\n]+)/gm;
  while ((m = IMPORT.exec(code)) !== null) {
    for (const item of (m[1] ?? '').split(',')) {
      const parts = item.trim().split(/\s+as\s+/);
      const dotted = (parts[0] ?? '').trim();
      if (parts[1] !== undefined && parts[1].trim() === name) return { module: dotted };
      if (parts[1] === undefined && dotted.split('.')[0] === name) return { module: name };
    }
  }
  return undefined;
}

type ResolvedSymbol =
  | { kind: 'def'; file: string; def: PyDef }
  | { kind: 'assign'; file: string; line: number; value: string }
  | { kind: 'class'; file: string; line: number; endLine: number; header: string }
  | { kind: 'module'; file: string }
  | { kind: 'library'; module: string; name: string };

function moduleAssignment(file: PyFile, name: string): { line: number; value: string } | undefined {
  const ASSIGN = new RegExp(`^(?:type[ \\t]+)?${name}[ \\t]*(?::[^=\\n]+)?=(?!=)[ \\t]*`, 'gm');
  let m: RegExpExecArray | null;
  let found: { line: number; value: string } | undefined;
  while ((m = ASSIGN.exec(file.code)) !== null) {
    const start = m.index + m[0].length;
    found = { line: lineOfIndex(file.lineStarts, m.index), value: statementFrom(file, start) };
  }
  return found;
}

function statementFrom(file: PyFile, start: number): string {
  let depth = 0;
  let i = start;
  for (; i < file.code.length; i += 1) {
    const c = file.code[i];
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === ']' || c === '}') depth -= 1;
    else if (c === '\n' && depth <= 0 && file.code[i - 1] !== '\\') break;
  }
  return file.entry.content.slice(start, i);
}

const MAX_RESOLVE_DEPTH = 6;

function resolveSymbol(proj: Project, filePath: string, dotted: string, depth = 0): ResolvedSymbol | undefined {
  const key = `${filePath}\u0000${dotted}`;
  if (proj.symbolCache.has(key)) return proj.symbolCache.get(key);
  proj.symbolCache.set(key, undefined);
  const result = resolveSymbolUncached(proj, filePath, dotted, depth);
  proj.symbolCache.set(key, result);
  return result;
}

function resolveSymbolUncached(proj: Project, filePath: string, dotted: string, depth: number): ResolvedSymbol | undefined {
  if (depth > MAX_RESOLVE_DEPTH) return undefined;
  const entry = proj.byPath.get(filePath);
  if (entry === undefined) return undefined;
  const file = readPyFile(entry);
  const [head, ...restParts] = dotted.split('.');
  if (head === undefined || head === '') return undefined;
  const rest = restParts.join('.');
  if (rest === '') {
    const def = file.defs.find((candidate) => candidate.indent === 0 && candidate.name === head);
    if (def !== undefined) return { kind: 'def', file: filePath, def };
    const classMatch = new RegExp(`^class[ \\t]+${head}\\b[^\\n]*`, 'm').exec(file.code);
    if (classMatch !== null) {
      const line = lineOfIndex(file.lineStarts, classMatch.index);
      let endLine = line;
      for (let l = line + 1; l <= file.codeLines.length; l += 1) {
        const text = file.codeLines[l - 1] ?? '';
        if (text.trim() === '') continue;
        if (indentOf(text) === 0) break;
        endLine = l;
      }
      return { kind: 'class', file: filePath, line, endLine, header: file.lines[line - 1] ?? '' };
    }
    const assignment = moduleAssignment(file, head);
    if (assignment !== undefined) return { kind: 'assign', file: filePath, ...assignment };
  }
  const binding = importBinding(file, head);
  if (binding === undefined) return undefined;
  if (!('name' in binding)) {
    const target = resolveModule(proj, filePath, binding.module);
    if (target === undefined) return { kind: 'library', module: binding.module, name: rest };
    return rest === '' ? { kind: 'module', file: target } : resolveSymbol(proj, target, rest, depth + 1);
  }
  const asSubmodule = resolveModule(proj, filePath, `${binding.module}${binding.module.endsWith('.') ? '' : '.'}${binding.name}`);
  if (asSubmodule !== undefined) {
    return rest === '' ? { kind: 'module', file: asSubmodule } : resolveSymbol(proj, asSubmodule, rest, depth + 1);
  }
  const moduleFile = resolveModule(proj, filePath, binding.module);
  if (moduleFile === undefined) return { kind: 'library', module: binding.module, name: rest === '' ? binding.name : `${binding.name}.${rest}` };
  return resolveSymbol(proj, moduleFile, rest === '' ? binding.name : `${binding.name}.${rest}`, depth + 1);
}

const CALLER_STATE =
  /\b(?:current_user|request\.user|g\.user|session|logged_in|is_authenticated|is_anonymous|user|users?_id|username|token|api_key|apikey|auth\w*|credentials?|principal|identity|role|roles|is_admin|is_staff|is_superuser|member|membership)\b/i;
const PRIVILEGE =
  /\b(?:is_admin|is_staff|is_superuser|is_owner|admin\w*|superuser\w*|role|roles|min_role|has_role|has_perm\w*|permissions?|scopes?|ROLE_\w+)\b/i;

const STATUS_401_403 = /(?:^|[^\w.])(?:401|403)\b|\bHTTP_40[13]_\w+|\bHTTPStatus\.(?:UNAUTHORIZED|FORBIDDEN)\b|\bstatus\.HTTP_40[13]\w*/;

interface Refusal {
  line: number;
  conditions: string[];
  anonymous: boolean;
}

function governingConditions(file: PyFile, fromLine: number, line: number): string[] {
  const conditions: string[] = [];
  let indent = indentOf(file.codeLines[line - 1] ?? '');
  for (let l = line - 1; l >= fromLine && indent > 0; l -= 1) {
    const text = file.codeLines[l - 1] ?? '';
    if (text.trim() === '') continue;
    const ind = indentOf(text);
    if (ind >= indent) continue;
    indent = ind;
    const header = /^\s*(?:if|elif|while)\b([\s\S]*?):?\s*$/.exec(text);
    if (header !== null) {
      conditions.unshift(originalLines(file, l, l + 3).split(':')[0] ?? text);
    } else if (/^\s*else\s*:/.test(text)) {
      conditions.unshift('<else>');
    }
  }
  return conditions;
}

function refusalsIn(proj: Project | undefined, file: PyFile, from: number, to: number): Refusal[] {
  const refusals: Refusal[] = [];
  for (let l = from; l <= to; l += 1) {
    const code = file.codeLines[l - 1] ?? '';
    const trimmed = code.trim();
    if (trimmed === '') continue;
    const statement = originalLines(file, l, Math.min(to, l + 6));
    let refuses = false;
    let needsCallerCondition = false;
    if (/\braise\s+(?:[\w.]+\.)?HTTPException\s*\(/.test(code)) {
      const open = file.lineStarts[l - 1]! + code.indexOf('(', code.search(/HTTPException/));
      const close = closingBracket(file.code, open);
      const args = close === undefined ? statement : file.code.slice(open, close);
      refuses = STATUS_401_403.test(args);
    } else if (/\braise\s+(?:[\w.]+\.)?(?:Unauthorized|Forbidden|PermissionDenied|NotAuthenticated|AuthenticationFailed|HTTPUnauthorized|HTTPForbidden)\b/.test(code)) {
      refuses = true;
    } else if (/\babort\s*\(/.test(code)) {
      refuses = STATUS_401_403.test(code.slice(code.search(/\babort\s*\(/)));
    } else if (/\b(?:login_manager|current_app\.login_manager)\.unauthorized\s*\(/.test(code)) {
      refuses = true;
    } else if (/^\s*raise\s+(\w+)\s*$/.test(code)) {
      const name = /^\s*raise\s+(\w+)/.exec(code)?.[1] ?? '';
      refuses = boundToAuthException(file, name, from, to);
    } else if (/^\s*return\b/.test(code)) {
      const returned = statementFrom(file, file.lineStarts[l - 1]! + code.search(/return/) + 6);
      if (/,\s*(?:401|403|HTTPStatus\.(?:UNAUTHORIZED|FORBIDDEN)|status\.HTTP_40[13]\w*)\s*(?:,[^,]*)?\s*$/.test(returned) ||
          /\bstatus(?:_code)?\s*=\s*(?:401|403|HTTPStatus\.(?:UNAUTHORIZED|FORBIDDEN)|status\.HTTP_40[13]\w*)/.test(returned)) {
        refuses = true;
      } else if (/^\s*(?:redirect|RedirectResponse|HttpResponseRedirect|redirect_to_login)\s*\(/.test(returned)) {
        refuses = true;
        needsCallerCondition = true;
      }
    }
    if (!refuses) continue;
    const conditions = governingConditions(file, from, l);
    if (needsCallerCondition && !conditions.some((condition) => CALLER_STATE.test(condition))) continue;
    if (swallowedByExcept(file, from, l)) continue;
    if (conditions.some((condition) => testsClientSuppliedValue(file, l, condition))) continue;
    refusals.push({ line: l, conditions, anonymous: !onlyWithCredential(proj, file, from, l) });
  }
  return refusals;
}

const REQUEST_READ =
  /^(?:(?:[\w.]*\.)?(?:headers|cookies|args|query_params|form|values|GET|POST|COOKIES|META)\s*(?:\.get\s*\(|\[)|(?:(?:flask|request|req)\.)?session\s*(?:\.get\s*\(|\[)|[\w.]*\.authorization\b|getattr\s*\([\s\S]*,\s*None\s*\)\s*$)/;

const OMITTABLE_DEFAULT = /^(?:None|(?:[\w.]+\.)?(?:Header|Cookie|Query|Body|Form)\s*\(\s*(?:None\b|[\s\S]*\bdefault\s*=\s*None\b))/;
const OPTIONAL_ANNOTATION = /\bOptional\s*\[|\|\s*None\b|\bNone\s*\||\bUnion\s*\[[^\]]*\bNone\b/;

function omittableParameters(proj: Project | undefined, file: PyFile, def: PyDef): string[] {
  const names: string[] = [];
  for (const parameter of splitTopLevel(def.signature)) {
    const m = /^(\w+)\s*(?::\s*([^=]+?))?\s*(?:=(?!=)\s*([\s\S]+))?$/.exec(parameter);
    if (m === null) continue;
    const annotation = m[2] ?? '';
    const value = (m[3] ?? '').trim();
    if (OMITTABLE_DEFAULT.test(value) || OPTIONAL_ANNOTATION.test(annotation)) { names.push(m[1] ?? ''); continue; }
    const scheme = /^(?:[\w.]+\.)?(?:Depends|Security)\s*\(\s*([A-Za-z_][\w.]*)/.exec(value)?.[1];
    if (scheme !== undefined && proj !== undefined) {
      const symbol = resolveSymbol(proj, file.entry.path, scheme);
      if (symbol?.kind === 'assign' && SECURITY_SCHEME.test(symbol.value) && /\bauto_error\s*=\s*False\b/.test(symbol.value)) names.push(m[1] ?? '');
    }
  }
  return names;
}

function presenceSubjects(proj: Project | undefined, file: PyFile, line: number): Set<string> {
  const names = new Set<string>();
  for (const def of file.defs) {
    if (def.defLine >= line || def.endLine < line) continue;
    const origins = defOrigins(proj, file, def);
    for (const name of origins.parameters) names.add(name);
    for (const read of origins.reads) if (read.line < line) names.add(read.name);
  }
  return names;
}

const originCache = new WeakMap<PyDef, { parameters: string[]; reads: Array<{ line: number; name: string }> }>();

function defOrigins(proj: Project | undefined, file: PyFile, def: PyDef): { parameters: string[]; reads: Array<{ line: number; name: string }> } {
  const cached = originCache.get(def);
  if (cached !== undefined) return cached;
  const reads: Array<{ line: number; name: string }> = [];
  for (let l = def.defLine + 1; l <= def.endLine; l += 1) {
    const code = file.codeLines[l - 1] ?? '';
    const assign = /^\s*([A-Za-z_]\w*)\s*(?::[^=\n]+)?=(?!=)\s*/.exec(code);
    if (assign === null) continue;
    const value = statementFrom(file, file.lineStarts[l - 1]! + assign[0].length).trim();
    if (isBareRequestRead(value)) reads.push({ line: l, name: assign[1] ?? '' });
  }
  const origins = { parameters: omittableParameters(proj, file, def), reads };
  originCache.set(def, origins);
  return origins;
}

function isBareRequestRead(text: string): boolean {
  return REQUEST_READ.test(text) && !/==|!=|<|>|\bin\b|\bis\b/.test(maskPython(text));
}

function isPresenceSubject(text: string, subjects: ReadonlySet<string>): boolean {
  const t = unwrapParens(text.trim());
  if (isBareRequestRead(t)) return true;
  const base = /^([A-Za-z_]\w*)(?:\s*\.get\(\s*['"][^'"]+['"][^)]*\)|\s*\[\s*['"][^'"]+['"]\s*\])?$/.exec(t)?.[1];
  if (base !== undefined && subjects.has(base)) return true;
  return isCredentialReference(t);
}

const CREDENTIAL_NAME =
  /(?:token|creds?|credentials?|api_?key|authorization|auth|auth_?header|bearer|jwt|cookie|session_?id|user|user_?id|uid|principal|identity)$/i;

function isCredentialReference(text: string): boolean {
  const m = /^([A-Za-z_][\w.]*)(?:\s*\.get\(\s*['"]([^'"]+)['"][^)]*\)|\s*\[\s*['"]([^'"]+)['"]\s*\])?$/.exec(text.trim());
  if (m === null) return false;
  const key = m[2] ?? m[3];
  const name = key !== undefined ? key.replace(/-/g, '_') : (m[1] ?? '').split('.').pop() ?? '';
  return CREDENTIAL_NAME.test(name);
}

function splitBoolean(condition: string, operator: 'and' | 'or'): string[] {
  const parts: string[] = [];
  let depth = 0;
  let start = 0;
  const word = new RegExp(`^\\s${operator}\\s`);
  for (let i = 0; i < condition.length; i += 1) {
    const c = condition[i];
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === ']' || c === '}') depth -= 1;
    else if (depth === 0 && word.test(condition.slice(i, i + operator.length + 2))) {
      parts.push(condition.slice(start, i));
      start = i + operator.length + 1;
    }
  }
  parts.push(condition.slice(start));
  return parts.map((part) => unwrapParens(part.trim())).filter((part) => part !== '');
}

function unwrapParens(text: string): string {
  let t = text.trim();
  while (t.startsWith('(') && closingBracket(t, 0) === t.length - 1) t = t.slice(1, -1).trim();
  return t;
}

function conditionText(header: string): string {
  return header.replace(/^\s*(?:if|elif|while)\b/, '').replace(/:\s*$/, '').trim();
}

function testsPresence(condition: string, subjects: ReadonlySet<string>): boolean {
  const disjuncts = splitBoolean(condition, 'or');
  if (disjuncts.length > 1) return disjuncts.every((disjunct) => testsPresence(disjunct, subjects));
  return splitBoolean(condition, 'and').some((atom) => {
    if (/^not\s/.test(atom)) {
      const rest = unwrapParens(atom.replace(/^not\s+/, ''));
      return /\.is_anonymous(?:\s*\(\s*\))?$/.test(rest);
    }
    if (/\.is_authenticated(?:\s*\(\s*\))?$/.test(atom)) return true;
    if (/^['"][^'"]+['"]\s+in\s+session$/.test(atom)) return true;
    const notNone = /^([\s\S]+?)\s*(?:is\s+not|!=)\s*None$/.exec(atom);
    if (notNone !== null) return isPresenceSubject(notNone[1] ?? '', subjects);
    return isPresenceSubject(atom, subjects);
  });
}

function testsMissing(condition: string, subjects: ReadonlySet<string>): boolean {
  const disjuncts = splitBoolean(condition, 'or');
  if (disjuncts.length > 1) return disjuncts.some((disjunct) => testsMissing(disjunct, subjects));
  const conjuncts = splitBoolean(condition, 'and');
  return conjuncts.length > 0 && conjuncts.every((atom) => {
    if (/\.is_anonymous(?:\s*\(\s*\))?$/.test(atom) && !/^not\s/.test(atom)) return true;
    if (/^['"][^'"]+['"]\s+not\s+in\s+session$/.test(atom)) return true;
    const none = /^([\s\S]+?)\s*(?:is|==)\s*None$/.exec(atom);
    if (none !== null) return isPresenceSubject(none[1] ?? '', subjects);
    if (!/^not\s/.test(atom)) return false;
    const rest = unwrapParens(atom.replace(/^not\s+/, ''));
    return /\.is_authenticated(?:\s*\(\s*\))?$/.test(rest) || isPresenceSubject(rest, subjects);
  });
}

function onlyWithCredential(proj: Project | undefined, file: PyFile, fromLine: number, line: number): boolean {
  const subjects = presenceSubjects(proj, file, line);
  let indent = indentOf(file.codeLines[line - 1] ?? '');
  for (let l = line - 1; l >= fromLine && indent > 0; l -= 1) {
    const text = file.codeLines[l - 1] ?? '';
    if (text.trim() === '') continue;
    const ind = indentOf(text);
    if (ind >= indent) continue;
    indent = ind;
    const header = /^\s*(if|elif|else)\b/.exec(text)?.[1];
    if (header === undefined) continue;
    if (header !== 'else' && testsPresence(conditionText(originalLines(file, l, l + 3).split(':')[0] ?? text), subjects)) return true;
    if (header === 'if') continue;
    for (let k = l - 1; k >= fromLine; k -= 1) {
      const sibling = file.codeLines[k - 1] ?? '';
      if (sibling.trim() === '' || indentOf(sibling) > ind) continue;
      if (indentOf(sibling) < ind) break;
      const branch = /^\s*(if|elif)\b/.exec(sibling)?.[1];
      if (branch === undefined) break;
      if (testsMissing(conditionText(originalLines(file, k, k + 3).split(':')[0] ?? sibling), subjects)) return true;
      if (branch === 'if') break;
    }
  }
  return false;
}

const BROAD_EXCEPT = /^\s*except\s*(?::|\(?[^:]*\b(?:Exception|BaseException|HTTPException)\b[^:]*:)/;

function swallowedByExcept(file: PyFile, from: number, line: number): boolean {
  let indent = indentOf(file.codeLines[line - 1] ?? '');
  for (let l = line - 1; l >= from && indent > 0; l -= 1) {
    const text = file.codeLines[l - 1] ?? '';
    if (text.trim() === '') continue;
    const ind = indentOf(text);
    if (ind >= indent) continue;
    indent = ind;
    if (!/^\s*try\s*:/.test(text)) continue;
    for (let k = l + 1; k <= file.codeLines.length; k += 1) {
      const clause = file.codeLines[k - 1] ?? '';
      if (clause.trim() === '' || indentOf(clause) > ind) continue;
      if (indentOf(clause) < ind || !/^\s*(?:except|else|finally)\b/.test(clause)) break;
      if (!BROAD_EXCEPT.test(clause)) continue;
      let reraises = false;
      for (let h = k + 1; h <= file.codeLines.length; h += 1) {
        const body = file.codeLines[h - 1] ?? '';
        if (body.trim() === '') continue;
        if (indentOf(body) <= ind) break;
        if (/^\s*raise\b/.test(body)) reraises = true;
      }
      if (!reraises) return true;
    }
  }
  return false;
}

function testsClientSuppliedValue(file: PyFile, line: number, condition: string): boolean {
  if (!/role|admin|staff|superuser|perm|scope|owner|manager|privilege/i.test(condition)) return false;
  const def = [...file.defs].reverse().find((candidate) => candidate.defLine < line && candidate.endLine >= line);
  const names = def === undefined ? [] : splitTopLevel(def.signature)
    .filter((parameter) => /=\s*(?:[\w.]+\.)?(?:Header|Query|Body|Form|Cookie)\s*\(/.test(parameter) ||
      (/^\w+\s*:\s*(?:Optional\[\s*)?(?:str|int|bool|float)\b/.test(parameter) && !/\b(?:Depends|Security)\s*\(/.test(parameter)))
    .map((parameter) => /^\*{0,2}(\w+)/.exec(parameter)?.[1])
    .filter((name): name is string => name !== undefined);
  const sources = [...names, 'request\\.(?:headers|args|form|json|values|cookies|data)', 'request\\.get_json\\(\\)'];
  for (const source of sources) {
    const value = `${source}(?:\\.get\\([^)]*\\)|\\[[^\\]]*\\])?`;
    if (new RegExp(`(?:^|[^\\w.])${value}\\s*(?:==|!=|not\\s+in|in)\\s*['"([{]`).test(condition)) return true;
    if (new RegExp(`['"]\\s*(?:==|!=)\\s*${value}(?![\\w.])`).test(condition)) return true;
  }
  return false;
}

function boundToAuthException(file: PyFile, name: string, from: number, to: number): boolean {
  const pattern = new RegExp(`^\\s*${name}\\s*=\\s*(?:[\\w.]+\\.)?HTTPException\\s*\\(`);
  for (let l = 1; l <= file.codeLines.length; l += 1) {
    const inBlock = l >= from && l <= to;
    const code = file.codeLines[l - 1] ?? '';
    if (!inBlock && indentOf(code) !== 0) continue;
    if (!pattern.test(code)) continue;
    const open = file.lineStarts[l - 1]! + code.indexOf('(', code.search(/HTTPException/));
    const close = closingBracket(file.code, open);
    if (close !== undefined && STATUS_401_403.test(file.code.slice(open, close))) return true;
  }
  return false;
}

function levelOfRefusals(refusals: Refusal[]): PythonGuardLevel | undefined {
  if (!refusals.some((refusal) => refusal.anonymous)) return undefined;
  return refusalLevel(refusals);
}

function refusalLevel(refusals: Refusal[]): PythonGuardLevel | undefined {
  if (refusals.length === 0) return undefined;
  return refusals.some((refusal) =>
    refusal.conditions.length > 0 && refusal.conditions.every((condition) => PRIVILEGE.test(condition))) ? 'admin' : 'auth';
}

function atCallSite(file: PyFile, from: number, line: number, level: PythonGuardLevel | undefined): PythonGuardLevel | undefined {
  if (level !== 'admin') return level;
  return governingConditions(file, from, line).length === 0 ? 'admin' : 'auth';
}

function maxLevel(a: PythonGuardLevel | undefined, b: PythonGuardLevel | undefined): PythonGuardLevel | undefined {
  if (a === 'admin' || b === 'admin') return 'admin';
  return a ?? b;
}

const LIBRARY_DECORATORS: Array<{ module: RegExp; name: RegExp; level: PythonGuardLevel }> = [
  { module: /^flask_login(?:\.utils)?$/, name: /^(?:login_required|fresh_login_required)$/, level: 'auth' },
  { module: /^flask_security(?:\.decorators)?$/, name: /^(?:login_required|auth_required|auth_token_required|http_auth_required)$/, level: 'auth' },
  { module: /^flask_security(?:\.decorators)?$/, name: /^(?:roles_required|roles_accepted|permissions_required|permissions_accepted)$/, level: 'admin' },
  { module: /^flask_jwt_extended$/, name: /^(?:jwt_required|fresh_jwt_required)$/, level: 'auth' },
  { module: /^django\.contrib\.auth\.decorators$/, name: /^login_required$/, level: 'auth' },
  { module: /^django\.contrib\.auth\.decorators$/, name: /^(?:permission_required|user_passes_test)$/, level: 'admin' },
  { module: /^django\.contrib\.admin\.views\.decorators$/, name: /^staff_member_required$/, level: 'admin' },
];

const SECURITY_SCHEME =
  /^\s*(?:[\w.]+\.)?(?:OAuth2PasswordBearer|OAuth2AuthorizationCodeBearer|OAuth2|HTTPBearer|HTTPBasic|HTTPDigest|APIKeyHeader|APIKeyQuery|APIKeyCookie|OpenIdConnect)\s*\(/;
const FLASK_HTTPAUTH = /^\s*(?:[\w.]+\.)?(?:HTTPBasicAuth|HTTPTokenAuth|HTTPDigestAuth|MultiAuth)\s*\(/;

function libraryLevel(symbol: ResolvedSymbol | undefined): PythonGuardLevel | undefined {
  if (symbol?.kind !== 'library') return undefined;
  const name = symbol.name.split('.').pop() ?? '';
  const module = symbol.name.includes('.')
    ? `${symbol.module}.${symbol.name.split('.').slice(0, -1).join('.')}`
    : symbol.module;
  for (const known of LIBRARY_DECORATORS) {
    if (known.module.test(module) && known.name.test(name)) return known.level;
  }
  return undefined;
}

const MAX_GUARD_DEPTH = 4;
const NOT_HELPERS = new Set([
  'if', 'elif', 'while', 'for', 'return', 'not', 'and', 'or', 'print', 'len', 'str', 'int', 'float', 'bool',
  'dict', 'list', 'set', 'tuple', 'isinstance', 'getattr', 'setattr', 'hasattr', 'super', 'range', 'enumerate',
  'zip', 'sorted', 'min', 'max', 'any', 'all', 'type', 'Depends', 'Security', 'HTTPException', 'abort',
  'redirect', 'url_for', 'jsonify', 'flash', 'wraps', 'render_template', 'Header', 'Query', 'Cookie', 'Body',
]);

function defLevel(proj: Project, filePath: string, def: PyDef, depth: number): PythonGuardLevel | undefined {
  const key = `${filePath}\u0000${def.defLine}`;
  const cached = proj.levelCache.get(key);
  if (cached === 'pending') return undefined;
  if (proj.levelCache.has(key)) return cached as PythonGuardLevel | undefined;
  if (depth > MAX_GUARD_DEPTH) return undefined;
  proj.levelCache.set(key, 'pending');
  const entry = proj.byPath.get(filePath);
  let level: PythonGuardLevel | undefined;
  if (entry !== undefined) {
    const file = readPyFile(entry);
    const open = failsOpen(file, def);
    const refusals = open ? [] : refusalsIn(proj, file, def.defLine + 1, def.endLine);
    let bodyLevel = levelOfRefusals(refusals);
    const signature = signatureLevel(proj, filePath, def.signature, depth + 1);
    const checkingCalls: number[] = [];
    if (!open) {
      const CALL = /(?<![\w.])([A-Za-z_][\w.]*)\s*\(/g;
      for (let l = def.defLine + 1; l <= def.endLine; l += 1) {
        const code = file.codeLines[l - 1] ?? '';
        let m: RegExpExecArray | null;
        CALL.lastIndex = 0;
        while ((m = CALL.exec(code)) !== null) {
          const callee = m[1] ?? '';
          if (NOT_HELPERS.has(callee) || callee.startsWith('self.')) continue;
          const helper = atCallSite(file, def.defLine + 1, l, callableLevel(proj, filePath, callee, depth + 1, def));
          if (helper !== undefined && !/^\s*(?:async\s+)?def\s/.test(code)) checkingCalls.push(l);
          bodyLevel = maxLevel(bodyLevel, helper);
        }
      }
    }
    if (bodyLevel !== undefined && completesUnchecked(proj, file, def, refusals, checkingCalls)) bodyLevel = undefined;
    level = maxLevel(bodyLevel, signature);
    if (bodyLevel !== undefined) level = maxLevel(level, refusalLevel(refusals));
  }
  proj.levelCache.set(key, level);
  return level;
}

const MISSING_CREDENTIAL = /\b(?:token|credentials?|api_key|apikey|authorization|auth_header|cookie|session|current_user|user)\b/i;
const CONFIGURATION = /\b(?:settings|config|conf|os\.environ|environ|getenv|app\.config)\b|[A-Z][A-Z0-9]*_(?:ENABLED|DISABLED|REQUIRED)\b|\bis_enabled\b|\bDEBUG\b|\bTESTING\b/;

function failsOpen(file: PyFile, def: PyDef): boolean {
  for (let l = def.defLine + 1; l <= def.endLine; l += 1) {
    const code = file.codeLines[l - 1] ?? '';
    if (!/^\s*return(?:\s+None)?\s*$/.test(code)) continue;
    const conditions = governingConditions(file, def.defLine + 1, l);
    if (conditions.length === 0) continue;
    if (conditions.some((condition) => CONFIGURATION.test(condition))) continue;
    if (conditions.some((condition) => MISSING_CREDENTIAL.test(condition))) return true;
  }
  return false;
}

function parentHeader(file: PyFile, from: number, line: number, indent: number): number | undefined {
  for (let l = line - 1; l >= from; l -= 1) {
    const text = file.codeLines[l - 1] ?? '';
    if (text.trim() === '') continue;
    if (indentOf(text) < indent) return l;
  }
  return undefined;
}

function isConfigurationSwitch(condition: string): boolean {
  const atoms = splitBoolean(condition, 'or').flatMap((part) => splitBoolean(part, 'and'));
  return atoms.length > 0 && atoms.every((atom) => CONFIGURATION.test(atom) && !/\brequest\b/.test(atom));
}

const CONTINUATION_HEADER = /^\s*(?:elif\b|else\s*:|except\b|finally\s*:)/;

function chainHead(file: PyFile, from: number, line: number): number {
  const indent = indentOf(file.codeLines[line - 1] ?? '');
  let head = line;
  while (CONTINUATION_HEADER.test(file.codeLines[head - 1] ?? '')) {
    let k = head - 1;
    while (k >= from && ((file.codeLines[k - 1] ?? '').trim() === '' || indentOf(file.codeLines[k - 1] ?? '') > indent)) k -= 1;
    if (k < from || indentOf(file.codeLines[k - 1] ?? '') !== indent) break;
    head = k;
  }
  return head;
}

function topLevelOnly(text: string): string {
  let depth = 0;
  let out = '';
  for (const c of text) {
    if (c === ')' || c === ']' || c === '}') depth = Math.max(0, depth - 1);
    out += depth > 0 ? ' ' : c;
    if (c === '(' || c === '[' || c === '{') depth += 1;
  }
  return out;
}

function isNegativeAtom(atom: string): boolean {
  const t = topLevelOnly(maskPython(atom)).trim();
  return /^not\b/.test(t) || /(?:\bis\s+|==\s*)None$/.test(t) || /!=/.test(t) || /\snot\s+in\s/.test(t);
}

function firesForEmptyCaller(condition: string): boolean {
  return splitBoolean(condition, 'or').some((disjunct) => {
    const atoms = splitBoolean(disjunct, 'and');
    return atoms.length > 0 && atoms.every(isNegativeAtom);
  });
}

function checkedBefore(
  proj: Project | undefined,
  file: PyFile,
  from: number,
  line: number,
  indent: number,
  refusals: Refusal[],
  checkingCalls: number[],
): boolean {
  let current = line;
  let currentIndent = indent;
  for (;;) {
    const parent = parentHeader(file, from, current, currentIndent);
    const start = parent === undefined ? from : parent + 1;
    const head = chainHead(file, start, current);
    for (const refusal of refusals) {
      if (refusal.line < start || refusal.line >= current || refusal.line >= head) continue;
      const refusalIndent = indentOf(file.codeLines[refusal.line - 1] ?? '');
      if (refusalIndent === currentIndent) return true;
      const branch = parentHeader(file, start, refusal.line, refusalIndent);
      if (branch === undefined || indentOf(file.codeLines[branch - 1] ?? '') !== currentIndent) continue;
      const header = file.codeLines[branch - 1] ?? '';
      if (/^\s*(?:else|except\b[^:]*)\s*:/.test(header)) return true;
      if (/^\s*(?:if|elif)\b/.test(header)) {
        const condition = conditionText(originalLines(file, branch, branch + 3).split(':')[0] ?? header);
        if (!testsPresence(condition, presenceSubjects(proj, file, branch)) && firesForEmptyCaller(condition)) return true;
      }
    }
    for (const call of checkingCalls) {
      if (call >= start && call < current && indentOf(file.codeLines[call - 1] ?? '') === currentIndent) return true;
    }
    if (parent === undefined) return false;
    current = parent;
    currentIndent = indentOf(file.codeLines[parent - 1] ?? '');
  }
}

function requestPathDefs(file: PyFile, def: PyDef): PyDef[] {
  const nested = file.defs.filter((candidate) => candidate.defLine > def.defLine && candidate.endLine <= def.endLine);
  const returned = nested.filter((candidate) => {
    for (let l = def.defLine + 1; l <= def.endLine; l += 1) {
      if (innermostDef(file, l) !== def) continue;
      if (new RegExp(`^\\s*return\\s+${candidate.name}\\s*$`).test(file.codeLines[l - 1] ?? '')) return true;
    }
    return false;
  });
  return returned;
}

function innermostDef(file: PyFile, line: number): PyDef | undefined {
  let found: PyDef | undefined;
  for (const def of file.defs) {
    if (def.defLine < line && def.endLine >= line && (found === undefined || def.defLine > found.defLine)) found = def;
  }
  return found;
}

const ONE_LINE_EXIT = /^\s*(?:if|elif|else|try|except|finally|for|while|with)\b.*:\s*(?:return|yield)\b/;

function completesUnchecked(proj: Project | undefined, file: PyFile, def: PyDef, refusals: Refusal[], checkingCalls: number[]): boolean {
  const refusalLines = new Set(refusals.map((refusal) => refusal.line));
  const handedBack = requestPathDefs(file, def);
  for (const scope of [def, ...handedBack]) {
    const from = scope.bodyLine;
    let bodyIndent: number | undefined;
    let lastTopLevel: number | undefined;
    for (let l = from; l <= scope.endLine; l += 1) {
      const code = file.codeLines[l - 1] ?? '';
      if (code.trim() === '' || innermostDef(file, l) !== scope) continue;
      const indent = indentOf(code);
      if (bodyIndent === undefined && indent > scope.indent) bodyIndent = indent;
      if (indent === bodyIndent) lastTopLevel = l;
      if (!/^\s*(?:return|yield)\b/.test(code) && !ONE_LINE_EXIT.test(code)) continue;
      if (refusalLines.has(l)) continue;
      if (scope === def && handedBack.some((nested) => code.trim() === `return ${nested.name}`)) continue;
      const conditions = governingConditions(file, from, l);
      if (conditions.length > 0 && conditions.every((condition) => condition !== '<else>' && isConfigurationSwitch(conditionText(condition)))) continue;
      if (checkingCalls.includes(l)) continue;
      if (!checkedBefore(proj, file, from, l, indent, refusals, checkingCalls)) return true;
    }
    if (bodyIndent === undefined || lastTopLevel === undefined) continue;
    if (!canFallThrough(file, from, scope.endLine, bodyIndent)) continue;
    if (!checkedBefore(proj, file, from, scope.endLine + 1, bodyIndent, refusals, checkingCalls)) return true;
  }
  return false;
}

function canFallThrough(file: PyFile, start: number, end: number, indent: number): boolean {
  const atIndent: number[] = [];
  for (let l = start; l <= end; l += 1) {
    const text = file.codeLines[l - 1] ?? '';
    if (text.trim() !== '' && indentOf(text) === indent) atIndent.push(l);
  }
  if (atIndent.length === 0) return true;
  let head = atIndent.length - 1;
  while (head > 0 && /^\s*(?:elif\b|else\s*:|except\b|finally\s*:)/.test(file.codeLines[atIndent[head]! - 1] ?? '')) head -= 1;
  const first = file.codeLines[atIndent[head]! - 1] ?? '';
  if (head === atIndent.length - 1 && /^\s*(?:return|raise)\b/.test(first)) return false;
  const isIf = /^\s*if\b/.test(first);
  const isTry = /^\s*try\s*:/.test(first);
  if (!isIf && !isTry) return true;
  const branches = atIndent.slice(head);
  if (isIf && !branches.some((line) => /^\s*else\s*:/.test(file.codeLines[line - 1] ?? ''))) return true;
  if (branches.some((line) => /^\s*finally\s*:/.test(file.codeLines[line - 1] ?? ''))) return true;
  for (let b = 0; b < branches.length; b += 1) {
    const bodyStart = branches[b]! + 1;
    const bodyEnd = (branches[b + 1] ?? end + 1) - 1;
    let bodyIndent: number | undefined;
    for (let l = bodyStart; l <= bodyEnd && bodyIndent === undefined; l += 1) {
      const text = file.codeLines[l - 1] ?? '';
      if (text.trim() !== '') bodyIndent = indentOf(text);
    }
    if (bodyIndent === undefined || bodyIndent <= indent) {
      if (!/:\s*(?:return|raise)\b/.test(file.codeLines[branches[b]! - 1] ?? '')) return true;
      continue;
    }
    if (canFallThrough(file, bodyStart, bodyEnd, bodyIndent)) return true;
  }
  return false;
}

function callableLevel(
  proj: Project,
  filePath: string,
  name: string,
  depth: number,
  enclosing?: PyDef,
): PythonGuardLevel | undefined {
  if (depth > MAX_GUARD_DEPTH) return undefined;
  const entry = proj.byPath.get(filePath);
  if (entry !== undefined && enclosing !== undefined && !name.includes('.')) {
    const file = readPyFile(entry);
    const nested = file.defs.find((candidate) =>
      candidate.name === name && candidate.defLine > enclosing.defLine && candidate.endLine <= enclosing.endLine);
    if (nested !== undefined) return defLevel(proj, filePath, nested, depth);
  }
  const symbol = resolveSymbol(proj, filePath, name);
  if (symbol === undefined) return undefined;
  if (symbol.kind === 'library') return libraryLevel(symbol);
  if (symbol.kind === 'def') return defLevel(proj, symbol.file, symbol.def, depth);
  if (symbol.kind === 'assign') {
    if (SECURITY_SCHEME.test(symbol.value) && !/\bauto_error\s*=\s*False\b/.test(symbol.value)) return 'auth';
    return undefined;
  }
  return undefined;
}

function dependencyLevel(proj: Project, filePath: string, expression: string, depth: number): PythonGuardLevel | undefined {
  const text = expression.trim();
  const call = /^([A-Za-z_][\w.]*)\s*\(([\s\S]*)\)$/.exec(text);
  if (call !== null) {
    const symbol = resolveSymbol(proj, filePath, call[1] ?? '');
    if (symbol?.kind === 'def') {
      const entry = proj.byPath.get(symbol.file);
      if (entry === undefined) return undefined;
      const file = readPyFile(entry);
      const body = file.codeLines.slice(symbol.def.defLine, symbol.def.endLine);
      const returned = body.map((line) => /^\s*return\s+(\w+)\s*$/.exec(line)?.[1]).filter((name): name is string => name !== undefined);
      let level: PythonGuardLevel | undefined;
      for (const name of returned) level = maxLevel(level, callableLevel(proj, symbol.file, name, depth, symbol.def));
      return level;
    }
    return libraryLevel(symbol);
  }
  if (!/^[A-Za-z_][\w.]*$/.test(text)) return undefined;
  return callableLevel(proj, filePath, text, depth);
}

function dependencyExpressions(text: string): string[] {
  const found: string[] = [];
  const DEP = /\b(?:Depends|Security)\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = DEP.exec(text)) !== null) {
    const open = m.index + m[0].length - 1;
    const close = closingBracket(text, open);
    if (close === undefined) continue;
    const args = splitTopLevel(text.slice(open + 1, close));
    const first = args.find((arg) => !/^\w+\s*=(?!=)/.test(arg)) ?? keywordArgument(text.slice(open + 1, close), 'dependency');
    if (first !== undefined && first !== '') found.push(first);
  }
  return found;
}

function signatureLevel(proj: Project, filePath: string, signature: string, depth: number): PythonGuardLevel | undefined {
  if (depth > MAX_GUARD_DEPTH) return undefined;
  let level: PythonGuardLevel | undefined;
  for (const expression of dependencyExpressions(signature)) {
    level = maxLevel(level, dependencyLevel(proj, filePath, expression, depth));
    if (level === 'admin') return level;
  }
  for (const parameter of splitTopLevel(signature)) {
    const annotation = /^\*{0,2}\w+\s*:\s*([A-Za-z_][\w.]*)\s*(?:=|$)/.exec(parameter)?.[1];
    if (annotation === undefined) continue;
    const symbol = resolveSymbol(proj, filePath, annotation);
    if (symbol?.kind !== 'assign' || !/^\s*(?:[\w.]+\.)?Annotated\s*\[/.test(symbol.value)) continue;
    for (const expression of dependencyExpressions(symbol.value)) {
      level = maxLevel(level, dependencyLevel(proj, symbol.file, expression, depth));
    }
  }
  return level;
}

export function pythonCallerParameters(guards: GuardLookup, route: ApiRoute): Set<string> {
  const names = new Set<string>();
  if (route.framework !== 'fastapi') return names;
  const proj = project(guards);
  const entry = proj.byPath.get(route.filePath);
  if (entry === undefined) return names;
  const def = routeDef(readPyFile(entry), route.line);
  if (def === undefined) return names;
  for (const parameter of splitTopLevel(def.signature)) {
    const name = /^\s*(\w+)\b/.exec(parameter)?.[1];
    if (name === undefined) continue;
    let level: PythonGuardLevel | undefined;
    for (const expression of dependencyExpressions(parameter)) level = maxLevel(level, dependencyLevel(proj, route.filePath, expression, 0));
    const annotation = /^\s*\w+\s*:\s*([A-Za-z_][\w.]*)\s*(?:=|$)/.exec(parameter)?.[1];
    if (level === undefined && annotation !== undefined) {
      const symbol = resolveSymbol(proj, route.filePath, annotation);
      if (symbol?.kind === 'assign' && /^\s*(?:[\w.]+\.)?Annotated\s*\[/.test(symbol.value)) {
        for (const expression of dependencyExpressions(symbol.value)) level = maxLevel(level, dependencyLevel(proj, symbol.file, expression, 0));
      }
    }
    if (level !== undefined) names.add(name);
  }
  return names;
}

function dependencyListLevel(proj: Project, filePath: string, value: string, depth: number): PythonGuardLevel | undefined {
  let level: PythonGuardLevel | undefined;
  for (const expression of dependencyExpressions(value)) level = maxLevel(level, dependencyLevel(proj, filePath, expression, depth));
  const withoutCalls = value.replace(/\b(?:Depends|Security)\s*\([^()]*(?:\([^()]*\)[^()]*)*\)/g, '');
  for (const name of withoutCalls.match(/(?<![\w.])[A-Za-z_][\w.]*/g) ?? []) {
    const symbol = resolveSymbol(proj, filePath, name);
    if (symbol?.kind !== 'assign') continue;
    for (const expression of dependencyExpressions(symbol.value)) {
      level = maxLevel(level, dependencyLevel(proj, symbol.file, expression, depth));
    }
  }
  return level;
}

interface IncludeCall {
  file: string;
  parent: string;
  target?: { file: string; name: string };
  dependencies?: string;
  prefix?: string;
}

function includeCalls(proj: Project): IncludeCall[] {
  if (proj.includes !== undefined) return proj.includes;
  const calls: IncludeCall[] = [];
  for (const path of proj.pyPaths) {
    const entry = proj.byPath.get(path);
    if (entry === undefined || !entry.content.includes('include_router')) continue;
    const file = readPyFile(entry);
    const CALL = /([A-Za-z_]\w*)\.include_router\s*\(/g;
    let m: RegExpExecArray | null;
    while ((m = CALL.exec(file.code)) !== null) {
      const open = m.index + m[0].length - 1;
      const close = closingBracket(file.code, open);
      if (close === undefined) continue;
      const args = file.entry.content.slice(open + 1, close);
      const parts = splitTopLevel(args);
      const routerExpr = parts.find((part) => !/^\w+\s*=(?!=)/.test(part)) ?? keywordArgument(args, 'router');
      const call: IncludeCall = { file: path, parent: m[1] ?? '' };
      const dependencies = keywordArgument(args, 'dependencies');
      if (dependencies !== undefined) call.dependencies = dependencies;
      const prefix = keywordArgument(args, 'prefix');
      if (prefix !== undefined) call.prefix = prefix;
      if (routerExpr !== undefined) {
        const target = routerDefinition(proj, path, routerExpr.trim());
        if (target !== undefined) call.target = target;
      }
      calls.push(call);
    }
  }
  proj.includes = calls;
  return calls;
}

function routerDefinition(proj: Project, filePath: string, expression: string): { file: string; name: string } | undefined {
  if (!/^[A-Za-z_][\w.]*$/.test(expression)) return undefined;
  const parts = expression.split('.');
  const last = parts[parts.length - 1] ?? '';
  if (parts.length > 1) {
    const owner = resolveSymbol(proj, filePath, parts.slice(0, -1).join('.'));
    if (owner?.kind === 'module') return { file: owner.file, name: last };
    return undefined;
  }
  const entry = proj.byPath.get(filePath);
  if (entry === undefined) return undefined;
  if (moduleAssignment(readPyFile(entry), last) !== undefined) return { file: filePath, name: last };
  const binding = importBinding(readPyFile(entry), last);
  if (binding === undefined || !('name' in binding)) return undefined;
  const moduleFile = resolveModule(proj, filePath, binding.module);
  return moduleFile === undefined ? undefined : { file: moduleFile, name: binding.name };
}

function mountLevel(proj: Project, filePath: string, name: string, depth: number): PythonGuardLevel | undefined {
  if (depth > MAX_GUARD_DEPTH) return undefined;
  const entry = proj.byPath.get(filePath);
  if (entry === undefined) return undefined;
  const assignment = moduleAssignmentAnyIndent(readPyFile(entry), name);
  let level: PythonGuardLevel | undefined;
  if (assignment !== undefined && /^\s*(?:[\w.]+\.)?(?:APIRouter|FastAPI)\s*\(/.test(assignment)) {
    const open = assignment.indexOf('(');
    const args = assignment.slice(open + 1, assignment.lastIndexOf(')'));
    const dependencies = keywordArgument(args, 'dependencies');
    if (dependencies !== undefined) level = maxLevel(level, dependencyListLevel(proj, filePath, dependencies, depth));
  }
  for (const include of includeCalls(proj)) {
    if (include.target?.file !== filePath || include.target.name !== name) continue;
    let mounted = include.dependencies === undefined
      ? undefined
      : dependencyListLevel(proj, include.file, include.dependencies, depth);
    mounted = maxLevel(mounted, mountLevel(proj, include.file, include.parent, depth + 1));
    if (mounted === undefined) return undefined;
    level = level === undefined ? mounted : maxLevel(level, mounted);
  }
  return level;
}

function moduleAssignmentAnyIndent(file: PyFile, name: string): string | undefined {
  const ASSIGN = new RegExp(`^[ \\t]*${name}[ \\t]*(?::[^=\\n]+)?=(?!=)[ \\t]*`, 'gm');
  const m = ASSIGN.exec(file.code);
  return m === null ? undefined : statementFrom(file, m.index + m[0].length);
}

interface Gate {
  file: string;
  owner: string;
  appWide: boolean;
  publicNames: Set<string>;
  tiers: Map<string, PythonGuardLevel>;
  defaultLevel: PythonGuardLevel | undefined;
}

function gates(proj: Project): Gate[] {
  if (proj.gates !== undefined) return proj.gates;
  const found: Gate[] = [];
  for (const path of proj.pyPaths) {
    const entry = proj.byPath.get(path);
    if (entry === undefined || !/before_(?:app_)?request/.test(entry.content)) continue;
    const file = readPyFile(entry);
    for (const def of file.defs) {
      for (const decorator of def.decorators) {
        const m = /^\s*@([A-Za-z_]\w*)\.(before_request|before_app_request)\s*$/.exec(decorator.text.split('\n')[0] ?? '');
        if (m === null) continue;
        found.push(readGate(proj, file, def, m[1] ?? '', m[2] === 'before_app_request'));
      }
    }
    const CALL = /^[ \t]*([A-Za-z_]\w*)\.(before_request|before_app_request)\s*\(\s*([A-Za-z_]\w*)\s*\)/gm;
    let m: RegExpExecArray | null;
    while ((m = CALL.exec(file.code)) !== null) {
      const def = file.defs.find((candidate) => candidate.name === m![3]);
      if (def !== undefined) found.push(readGate(proj, file, def, m[1] ?? '', m[2] === 'before_app_request'));
    }
  }
  proj.gates = found;
  return found;
}

function literalNames(text: string): string[] {
  return [...text.matchAll(/['"]([^'"\n]+)['"]/g)].map((m) => m[1] ?? '');
}

function readGate(proj: Project, file: PyFile, def: PyDef, owner: string, appWideHook: boolean): Gate {
  const ownerValue = moduleAssignmentAnyIndent(file, owner);
  const appWide = appWideHook || (ownerValue !== undefined && /^\s*(?:[\w.]+\.)?Flask\s*\(/.test(ownerValue));
  const gate: Gate = { file: file.entry.path, owner, appWide, publicNames: new Set(), tiers: new Map(), defaultLevel: undefined };
  const from = def.defLine + 1;
  const to = def.endLine;
  const refusals = refusalsIn(proj, file, from, to);
  if (refusals.length === 0) return gate;

  const collections = new Map<string, string[]>();
  const aliases = new Map<string, string>();
  for (let l = from; l <= to; l += 1) {
    const code = file.codeLines[l - 1] ?? '';
    const assign = /^\s*(\w+)\s*=\s*([{[(]|frozenset\s*\(|set\s*\()/.exec(code);
    if (assign !== null) {
      const start = file.lineStarts[l - 1]! + code.indexOf('=') + 1;
      collections.set(assign[1] ?? '', literalNames(statementFrom(file, start)));
      continue;
    }
    const alias = /^\s*(\w+)\s*=\s*[\w.]*endpoint\w*\s+in\s+(\w+)\s*$/.exec(code);
    if (alias !== null) aliases.set(alias[1] ?? '', alias[2] ?? '');
  }
  const membership = (condition: string): { names: string[]; negated: boolean } | undefined => {
    const direct = /[\w.]*endpoint\w*\s+(not\s+in|in)\s+(\w+|\{[^}]*\}|\([^)]*\)|\[[^\]]*\])/.exec(condition);
    if (direct !== null) {
      const target = direct[2] ?? '';
      const names = /^\w+$/.test(target) ? collections.get(target) ?? moduleCollection(file, target) : literalNames(target);
      if (names !== undefined) return { names, negated: /^not/.test(direct[1] ?? '') };
    }
    for (const [alias, collection] of aliases) {
      const test = new RegExp(`(?:^|[^\\w.])(not\\s+)?${alias}\\b`).exec(condition);
      if (test === null) continue;
      const names = collections.get(collection) ?? moduleCollection(file, collection);
      if (names !== undefined) return { names, negated: test[1] !== undefined };
    }
    return undefined;
  };

  const checked = (line: number, indent: number): boolean => checkedBefore(proj, file, def.bodyLine, line, indent, refusals, []);
  const bodyIndent = (() => {
    for (let l = def.bodyLine; l <= to; l += 1) {
      const text = file.codeLines[l - 1] ?? '';
      if (text.trim() !== '') return indentOf(text);
    }
    return undefined;
  })();
  if (bodyIndent !== undefined && canFallThrough(file, def.bodyLine, to, bodyIndent) && !checked(to + 1, bodyIndent)) return gate;

  for (let l = from; l <= to; l += 1) {
    const code = file.codeLines[l - 1] ?? '';
    if (!/^\s*return(?:\s+None)?\s*$/.test(code)) continue;
    const conditions = governingConditions(file, from, l);
    if (conditions.length === 0) {
      if (!checked(l, indentOf(code))) return gate;
      continue;
    }
    const innermostHeader = (() => {
      const ind = indentOf(code);
      for (let k = l - 1; k >= from; k -= 1) {
        const text = file.codeLines[k - 1] ?? '';
        if (text.trim() !== '' && indentOf(text) < ind) return k;
      }
      return from;
    })();
    const refusedFirst = refusals.filter((refusal) => refusal.line > innermostHeader && refusal.line < l);
    const sets = conditions.map(membership).filter((m): m is { names: string[]; negated: boolean } => m !== undefined);
    if (conditions.includes('<else>')) return gate;
    if (refusedFirst.length > 0) {
      const tier = checked(l, indentOf(code)) ? levelOfRefusals(refusedFirst) : undefined;
      for (const set of sets) {
        if (set.negated) continue;
        for (const name of set.names) {
          if (tier === undefined) gate.publicNames.add(name); else gate.tiers.set(name, tier);
        }
      }
      continue;
    }
    if (sets.some((set) => !set.negated)) {
      for (const set of sets) if (!set.negated) for (const name of set.names) gate.publicNames.add(name);
      continue;
    }
    if (conditions.every((condition) => /request\.method\s*==\s*['"]OPTIONS['"]/.test(condition))) continue;
    if (conditions.every((condition) => CALLER_STATE.test(condition)) && checked(l, indentOf(code))) continue;
    return gate;
  }
  for (const refusal of refusals) {
    for (const condition of refusal.conditions) {
      const set = membership(condition);
      if (set?.negated === true) for (const name of set.names) gate.publicNames.add(name);
    }
  }
  const unnamed = refusals.filter((refusal) => !refusal.conditions.some((condition) => {
    const set = membership(condition);
    return set !== undefined && !set.negated;
  }));
  gate.defaultLevel = levelOfRefusals(unnamed);
  return gate;
}

function moduleCollection(file: PyFile, name: string): string[] | undefined {
  const value = moduleAssignment(file, name)?.value;
  return value === undefined ? undefined : literalNames(value);
}

function blueprintName(file: PyFile, variable: string): string | undefined {
  const value = moduleAssignmentAnyIndent(file, variable);
  if (value === undefined || !/^\s*(?:[\w.]+\.)?Blueprint\s*\(/.test(value)) return undefined;
  return /\(\s*['"]([^'"]+)['"]/.exec(value)?.[1];
}

function gateLevel(proj: Project, file: PyFile, def: PyDef, routeVar: string, decoratorArgs: string): PythonGuardLevel | undefined {
  const endpointArg = /\bendpoint\s*=\s*['"]([^'"]+)['"]/.exec(decoratorArgs)?.[1];
  const bare = endpointArg ?? def.name;
  const bp = blueprintName(file, routeVar);
  const fullName = bp === undefined ? bare : `${bp}.${bare}`;
  let level: PythonGuardLevel | undefined;
  for (const gate of gates(proj)) {
    const applies = gate.appWide || (gate.file === file.entry.path && gate.owner === routeVar);
    if (!applies || gate.defaultLevel === undefined) continue;
    if (gate.publicNames.has(fullName) || gate.publicNames.has(bare)) continue;
    const tier = gate.tiers.get(fullName) ?? gate.tiers.get(bare) ?? gate.defaultLevel;
    level = maxLevel(level, tier);
  }
  return level;
}

function routeDef(file: PyFile, line: number): PyDef | undefined {
  return file.defs.find((def) => def.decorators.some((decorator) => decorator.line === line));
}

export function pythonHandlerSpan(lookup: GuardLookup, route: ApiRoute): { startLine: number; endLine: number } | undefined {
  const entry = project(lookup).byPath.get(route.filePath);
  if (entry === undefined) return undefined;
  if (route.framework === 'django') {
    const handler = djangoHandler(readPyFile(entry), route.line);
    return handler === undefined ? undefined : { startLine: handler.startLine, endLine: handler.endLine };
  }
  const def = routeDef(readPyFile(entry), route.line);
  return def === undefined ? undefined : { startLine: route.line, endLine: def.endLine };
}

function djangoHandler(file: PyFile, line: number): { def?: PyDef; startLine: number; endLine: number } | undefined {
  const def = file.defs.find((candidate) => candidate.defLine === line);
  if (def !== undefined) return { def, startLine: def.decorators[0]?.line ?? def.defLine, endLine: def.endLine };
  const header = file.codeLines[line - 1] ?? '';
  if (!/^\s*class\s+\w+/.test(header)) return undefined;
  const indent = indentOf(header);
  let endLine = line;
  for (let l = line + 1; l <= file.codeLines.length; l += 1) {
    const text = file.codeLines[l - 1] ?? '';
    if (text.trim() === '') continue;
    if (indentOf(text) <= indent) break;
    endLine = l;
  }
  let startLine = line;
  for (let l = line - 1; l >= 1; l -= 1) {
    const text = file.codeLines[l - 1] ?? '';
    if (text.trim() === '') break;
    if (indentOf(text) === indent && text.trim().startsWith('@')) { startLine = l; continue; }
    if (indentOf(text) > indent || /^[)\]}]/.test(text.trim())) continue;
    break;
  }
  return { startLine, endLine };
}

export function pythonRouteGuard(lookup: GuardLookup, route: ApiRoute, beforeLine?: number): PythonGuardProof | undefined {
  if (route.framework === 'django') return djangoRouteGuard(lookup, route, beforeLine);
  if (route.framework !== 'fastapi' && route.framework !== 'flask') return undefined;
  const proj = project(lookup);
  const entry = proj.byPath.get(route.filePath);
  if (entry === undefined) return undefined;
  const file = readPyFile(entry);
  const def = routeDef(file, route.line);
  if (def === undefined) return undefined;
  const routeDecorator = def.decorators.find((decorator) => decorator.line === route.line);
  const decoratorHead = /^\s*@([A-Za-z_]\w*)\./.exec(routeDecorator?.text ?? '');
  const routeVar = decoratorHead?.[1] ?? '';
  const decoratorArgs = (() => {
    const text = routeDecorator?.text ?? '';
    const open = text.indexOf('(');
    return open < 0 ? '' : text.slice(open + 1, text.lastIndexOf(')'));
  })();
  const proofs: PythonGuardProof[] = [];
  const add = (level: PythonGuardLevel | undefined, via: string): void => {
    if (level !== undefined) proofs.push({ level, via });
  };

  if (route.framework === 'fastapi') {
    add(signatureLevel(proj, route.filePath, def.signature, 0), 'route dependency');
    const routeDependencies = keywordArgument(decoratorArgs, 'dependencies');
    if (routeDependencies !== undefined) add(dependencyListLevel(proj, route.filePath, routeDependencies, 0), 'route dependencies=');
    add(mountLevel(proj, route.filePath, routeVar, 0), 'router or app dependencies');
  } else {
    for (const decorator of def.decorators.filter((candidate) => candidate.line > route.line)) {
      const name = /^\s*@([A-Za-z_][\w.]*)/.exec(decorator.text)?.[1];
      if (name === undefined) continue;
      const owner = name.includes('.') ? resolveSymbol(proj, route.filePath, name.split('.').slice(0, -1).join('.')) : undefined;
      if (owner?.kind === 'assign' && FLASK_HTTPAUTH.test(owner.value) && /\.login_required$/.test(name)) {
        add('auth', 'flask-httpauth login_required');
        continue;
      }
      const isCall = /^\s*@[A-Za-z_][\w.]*\s*\(/.test(decorator.text);
      const level = isCall
        ? dependencyLevel(proj, route.filePath, decorator.text.trim().slice(1), 0) ?? callableLevel(proj, route.filePath, name, 0)
        : callableLevel(proj, route.filePath, name, 0);
      add(level, `decorator @${name}`);
    }
    add(gateLevel(proj, file, def, routeVar, decoratorArgs), 'before_request gate');
  }
  add(handlerBodyLevel(proj, file, def, beforeLine), 'handler check');
  if (proofs.length === 0) return undefined;
  return proofs.find((proof) => proof.level === 'admin') ?? proofs[0];
}

function handlerBodyLevel(proj: Project, file: PyFile, def: PyDef, beforeLine: number | undefined): PythonGuardLevel | undefined {
  const last = Math.min(def.endLine, (beforeLine ?? def.endLine + 1) - 1);
  const refusals = refusalsIn(proj, file, def.defLine + 1, last)
    .filter((refusal) => refusal.conditions.some((condition) => CALLER_STATE.test(condition)));
  let level = levelOfRefusals(refusals);
  if (level === 'admin') return level;
  let withCredentialOnly: PythonGuardLevel | undefined;
  const CALL = /(?<![\w.])([A-Za-z_][\w.]*)\s*\(/g;
  for (let l = def.defLine + 1; l <= last; l += 1) {
    const code = file.codeLines[l - 1] ?? '';
    let m: RegExpExecArray | null;
    CALL.lastIndex = 0;
    while ((m = CALL.exec(code)) !== null) {
      const callee = m[1] ?? '';
      if (NOT_HELPERS.has(callee) || callee.startsWith('self.')) continue;
      const open = file.lineStarts[l - 1]! + m.index + m[0].length - 1;
      const close = closingBracket(file.code, open);
      const args = close === undefined ? '' : file.code.slice(open + 1, close);
      if (!CALLER_STATE.test(args) && !/\brequest\b/.test(args)) continue;
      const helper = atCallSite(file, def.defLine + 1, l, callableLevel(proj, file.entry.path, callee, 1));
      if (onlyWithCredential(proj, file, def.defLine + 1, l)) { withCredentialOnly = maxLevel(withCredentialOnly, helper); continue; }
      level = maxLevel(level, helper);
      if (level === 'admin') return level;
    }
  }
  if (level !== undefined) level = maxLevel(level, maxLevel(withCredentialOnly, refusalLevel(refusals)));
  return level;
}

const DJANGO_MIXINS: Array<{ name: RegExp; level: PythonGuardLevel }> = [
  { name: /^(?:LoginRequiredMixin)$/, level: 'auth' },
  { name: /^(?:PermissionRequiredMixin|UserPassesTestMixin)$/, level: 'admin' },
];
const DRF_PERMISSIONS: Record<string, PythonGuardLevel | 'none'> = {
  AllowAny: 'none',
  IsAuthenticated: 'auth',
  IsAuthenticatedOrReadOnly: 'auth',
  IsAdminUser: 'admin',
  DjangoModelPermissions: 'admin',
  DjangoModelPermissionsOrAnonReadOnly: 'admin',
  DjangoObjectPermissions: 'admin',
};

function drfPermissionLevel(proj: Project, filePath: string, list: string): PythonGuardLevel | undefined {
  const names = (list.match(/[A-Za-z_][\w.]*/g) ?? []).filter((name) => name !== 'permissions');
  if (names.length === 0) return undefined;
  let level: PythonGuardLevel | undefined;
  for (const dotted of names) {
    const leaf = dotted.split('.').pop() ?? '';
    const known = DRF_PERMISSIONS[leaf];
    if (known === 'none') continue;
    if (known !== undefined) { level = maxLevel(level, known); continue; }
    const symbol = resolveSymbol(proj, filePath, dotted);
    if (symbol?.kind !== 'class') continue;
    const entry = proj.byPath.get(symbol.file);
    if (entry === undefined) continue;
    const file = readPyFile(entry);
    const method = file.defs.find((def) => def.name === 'has_permission' && def.defLine > symbol.line && def.endLine <= symbol.endLine);
    if (method === undefined) continue;
    const returns = file.codeLines.slice(method.defLine, method.endLine)
      .map((line) => /^\s*return\s+(.+?)\s*$/.exec(line)?.[1])
      .filter((value): value is string => value !== undefined);
    const body = originalLines(file, method.defLine, method.endLine);
    if (returns.length > 0 && returns.some((value) => value !== 'True') && /\brequest\.user\b/.test(body)) {
      level = maxLevel(level, PRIVILEGE.test(body) ? 'admin' : 'auth');
    }
  }
  return level;
}

function drfDefault(proj: Project): PythonGuardLevel | undefined {
  if (proj.djangoDefault !== undefined) return proj.djangoDefault.level;
  let level: PythonGuardLevel | undefined;
  let found = false;
  for (const path of proj.pyPaths) {
    const entry = proj.byPath.get(path);
    if (entry === undefined || !entry.content.includes('DEFAULT_PERMISSION_CLASSES')) continue;
    const file = readPyFile(entry);
    const m = /['"]DEFAULT_PERMISSION_CLASSES['"]\s*:\s*/.exec(file.entry.content);
    if (m === null) continue;
    found = true;
    const value = statementFromBracket(file, m.index + m[0].length);
    level = drfPermissionLevel(proj, path, literalNames(value).join(',') || value);
  }
  proj.djangoDefault = { level, found };
  return level;
}

function statementFromBracket(file: PyFile, start: number): string {
  const open = file.code.slice(start).search(/[[(]/);
  if (open < 0) return '';
  const close = closingBracket(file.code, start + open);
  return close === undefined ? '' : file.entry.content.slice(start + open, close + 1);
}

export function djangoViewGuard(lookup: GuardLookup, filePath: string, line: number): PythonGuardProof | undefined {
  const proj = project(lookup);
  const entry = proj.byPath.get(filePath);
  if (entry === undefined) return undefined;
  const file = readPyFile(entry);
  const classLine = enclosingClassLine(file, line);
  if (classLine !== undefined) {
    const header = originalLines(file, classLine, classLine + 3).split(':')[0] ?? '';
    const bases = /\(([^)]*)\)/.exec(header)?.[1] ?? '';
    for (const base of bases.split(',').map((part) => part.trim().split('.').pop() ?? '')) {
      for (const mixin of DJANGO_MIXINS) {
        if (!mixin.name.test(base)) continue;
        const symbol = resolveSymbol(proj, filePath, base);
        if (symbol?.kind === 'library' && /^django\.contrib\.auth(?:\.mixins)?$/.test(symbol.module)) {
          return { level: mixin.level, via: `mixin ${base}` };
        }
      }
    }
    let classEnd = classLine;
    for (let l = classLine + 1; l <= file.codeLines.length; l += 1) {
      const text = file.codeLines[l - 1] ?? '';
      if (text.trim() === '') continue;
      if (indentOf(text) === 0) break;
      classEnd = l;
    }
    const classBody = file.codeLines.slice(classLine, classEnd).join('\n');
    const permissions = /^[ \t]+permission_classes\s*=\s*/m.exec(classBody);
    if (permissions !== null) {
      const start = (file.lineStarts[classLine] ?? 0) + permissions.index + permissions[0].length;
      const value = statementFrom(file, start);
      const level = drfPermissionLevel(proj, filePath, value);
      return level === undefined ? undefined : { level, via: 'permission_classes' };
    }
    const decoratorLevel = classDecoratorLevel(proj, file, classLine);
    if (decoratorLevel !== undefined) return { level: decoratorLevel, via: 'class decorator' };
    if (/\b(?:APIView|GenericAPIView|ViewSet|ModelViewSet|GenericViewSet|ReadOnlyModelViewSet)\b/.test(bases) ||
        /\b(?:generics|viewsets|mixins)\./.test(bases) || /\w+APIView\b/.test(bases)) {
      const fallback = drfDefault(proj);
      return fallback === undefined ? undefined : { level: fallback, via: 'DEFAULT_PERMISSION_CLASSES' };
    }
    return undefined;
  }
  const def = [...file.defs].reverse().find((candidate) => candidate.defLine <= line && candidate.endLine >= line && candidate.indent === 0);
  if (def === undefined) return undefined;
  let level: PythonGuardLevel | undefined;
  let isApiView = false;
  for (const decorator of def.decorators) {
    const name = /^\s*@([A-Za-z_][\w.]*)/.exec(decorator.text)?.[1] ?? '';
    if (name === 'api_view' || name.endsWith('.api_view')) { isApiView = true; continue; }
    if (name === 'permission_classes' || name.endsWith('.permission_classes')) {
      const value = decorator.text.slice(decorator.text.indexOf('(') + 1, decorator.text.lastIndexOf(')'));
      const listed = drfPermissionLevel(proj, filePath, value);
      if (listed === undefined) return undefined;
      level = maxLevel(level, listed);
      continue;
    }
    const isCall = /^\s*@[A-Za-z_][\w.]*\s*\(/.test(decorator.text);
    level = maxLevel(level, isCall
      ? dependencyLevel(proj, filePath, decorator.text.trim().slice(1), 0) ?? callableLevel(proj, filePath, name, 0)
      : callableLevel(proj, filePath, name, 0));
  }
  if (level === undefined && isApiView) level = drfDefault(proj);
  return level === undefined ? undefined : { level, via: 'view decorator' };
}

function classDecoratorLevel(proj: Project, file: PyFile, classLine: number): PythonGuardLevel | undefined {
  let level: PythonGuardLevel | undefined;
  for (let l = classLine - 1; l >= 1; l -= 1) {
    const text = file.codeLines[l - 1] ?? '';
    if (!text.trim().startsWith('@')) break;
    const original = file.lines[l - 1] ?? '';
    const inner = /^\s*@(?:[\w.]+\.)?method_decorator\s*\(\s*([A-Za-z_][\w.]*)/.exec(original)?.[1];
    if (inner !== undefined) level = maxLevel(level, callableLevel(proj, file.entry.path, inner, 0));
  }
  return level;
}

function djangoRouteGuard(guards: GuardLookup, route: ApiRoute, beforeLine: number | undefined): PythonGuardProof | undefined {
  const proj = project(guards);
  const entry = proj.byPath.get(route.filePath);
  if (entry === undefined) return undefined;
  const file = readPyFile(entry);
  const handler = djangoHandler(file, route.line);
  if (handler === undefined) return undefined;
  const proofs: PythonGuardProof[] = [];
  const view = djangoViewGuard(guards, route.filePath, route.line);
  if (view !== undefined) proofs.push(view);
  if (handler.def !== undefined) {
    const level = handlerBodyLevel(proj, file, handler.def, beforeLine);
    if (level !== undefined) proofs.push({ level, via: 'handler check' });
  }
  if (djangoLoginMiddleware(proj) && plainDjangoView(proj, file, handler.def, route.line) && !loginNotRequired(file, handler.def, route)) {
    proofs.push({ level: 'auth', via: 'LoginRequiredMiddleware' });
  }
  if (proofs.length === 0) return undefined;
  return proofs.find((proof) => proof.level === 'admin') ?? proofs[0];
}

const LOGIN_REQUIRED_MIDDLEWARE = 'django.contrib.auth.middleware.LoginRequiredMiddleware';

function middlewareValueLists(file: PyFile, start: number): boolean {
  const end = start + statementFrom(file, start).length;
  const code = file.code.slice(start, end).replace(/\\\n/g, '  ');
  const original = file.entry.content.slice(start, end);
  const parts: Array<[number, number]> = [];
  let depth = 0;
  let from = 0;
  for (let i = 0; i < code.length; i += 1) {
    const c = code[i];
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === ']' || c === '}') depth -= 1;
    else if (c === '+' && depth === 0) { parts.push([from, i]); from = i + 1; }
  }
  parts.push([from, code.length]);
  let listed = false;
  for (const [a, b] of parts) {
    const piece = code.slice(a, b);
    const trimmed = piece.trim();
    if (/^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$/.test(trimmed)) continue;
    const open = a + piece.indexOf(trimmed.charAt(0));
    if (trimmed === '' || (code[open] !== '[' && code[open] !== '(')) return false;
    const close = closingBracket(code, open);
    if (close === undefined || code.slice(close + 1, b).trim() !== '') return false;
    let level = 0;
    let top = '';
    const commas: number[] = [];
    for (let i = open + 1; i < close; i += 1) {
      const c = code[i] ?? '';
      if (c === '(' || c === '[' || c === '{') level += 1;
      else if (c === ')' || c === ']' || c === '}') level -= 1;
      else if (level === 0 && c === ',') commas.push(i);
      top += level === 0 ? c : ' ';
    }
    if (code[open] === '(' && commas.length === 0 && top.trim() !== '') return false;
    const bounds = [open, ...commas, close];
    for (let k = 0; k + 1 < bounds.length; k += 1) {
      const lo = (bounds[k] ?? 0) + 1;
      const hi = bounds[k + 1] ?? 0;
      const element = code.slice(lo, hi);
      const s = element.trim();
      if (s === '') continue;
      const at = lo + element.indexOf(s.charAt(0));
      const literal = /^[uUrR]?(['"])([^'"\n]*)\1$/.exec(original.slice(at, at + s.length));
      if (literal !== null && literal[2] === LOGIN_REQUIRED_MIDDLEWARE) listed = true;
    }
  }
  return listed;
}

function djangoLoginMiddleware(proj: Project): boolean {
  if (proj.loginMiddleware !== undefined) return proj.loginMiddleware;
  proj.loginMiddleware = false;
  const settings = new Set<string>();
  for (const path of proj.pyPaths) {
    const entry = proj.byPath.get(path);
    if (entry === undefined) continue;
    const file = readPyFile(entry);
    for (const m of entry.content.matchAll(/^ROOT_URLCONF[ \t]*=[ \t]*(['"])([\w.]+)\1/gm)) {
      if (file.code.startsWith('ROOT_URLCONF', m.index ?? 0) && resolveModule(proj, path, m[2] ?? '') !== undefined) settings.add(path);
    }
    for (const m of entry.content.matchAll(/DJANGO_SETTINGS_MODULE['"]?\s*[,=:]\s*(['"])([\w.]+)\1/g)) {
      const target = resolveModule(proj, path, m[2] ?? '');
      if (target !== undefined) settings.add(target);
    }
  }
  if (settings.size === 0) return false;
  const starImports = (file: PyFile): string[] => [...file.code.matchAll(/^from[ \t]+(\.*[\w.]*)[ \t]+import[ \t]+\*/gm)]
    .map((m) => resolveModule(proj, file.entry.path, m[1] ?? ''))
    .filter((target): target is string => target !== undefined);
  for (let round = 0; round < 3; round += 1) {
    for (const path of proj.pyPaths) {
      const entry = proj.byPath.get(path);
      if (entry === undefined || settings.has(path)) continue;
      if (starImports(readPyFile(entry)).some((target) => settings.has(target))) settings.add(path);
    }
  }
  const lists = (path: string, depth: number): boolean => {
    const entry = proj.byPath.get(path);
    if (entry === undefined || depth > 4) return false;
    const file = readPyFile(entry);
    if (/\bMIDDLEWARE\s*(?:\.\s*(?:remove|pop|clear)\s*\(|\[[^\]]*\]\s*=(?!=))|\bdel\s+MIDDLEWARE\b/.test(file.code)) return false;
    const ASSIGN = /^[ \t]*MIDDLEWARE[ \t]*(?::[^=\n]+)?=(?!=)[ \t]*/gm;
    let assigned = false;
    let m: RegExpExecArray | null;
    while ((m = ASSIGN.exec(file.code)) !== null) {
      assigned = true;
      const start = m.index + m[0].length;
      if (!middlewareValueLists(file, start)) return false;
    }
    if (assigned) return true;
    const inherited = starImports(file);
    return inherited.length > 0 && inherited.some((target) => lists(target, depth + 1));
  };
  proj.loginMiddleware = [...settings].every((path) => lists(path, 0));
  return proj.loginMiddleware;
}

const PLAIN_DJANGO_MODULE = /^django\.(?:views(?:\.generic(?:\.\w+)?)?|contrib\.auth\.mixins)$/;

function plainDjangoView(proj: Project, file: PyFile, def: PyDef | undefined, line: number): boolean {
  const classLine = enclosingClassLine(file, line);
  if (classLine === undefined) {
    return def !== undefined && !def.decorators.some((decorator) => /^\s*@(?:[\w.]+\.)?api_view\b/.test(decorator.text));
  }
  return basesArePlainDjango(proj, file.entry.path, file, classLine, 0);
}

function enclosingClassLine(file: PyFile, line: number): number | undefined {
  const own = file.codeLines[line - 1] ?? '';
  if (/^class\s+\w+/.test(own)) return line;
  if (indentOf(own) === 0) return undefined;
  for (let l = line - 1; l >= 1; l -= 1) {
    const text = file.codeLines[l - 1] ?? '';
    if (text.trim() === '' || indentOf(text) > 0 || /^[)\]}]/.test(text.trim())) continue;
    return /^class\s+\w+/.test(text) ? l : undefined;
  }
  return undefined;
}

function basesArePlainDjango(proj: Project, filePath: string, file: PyFile, classLine: number, depth: number): boolean {
  if (depth > 6) return false;
  const header = originalLines(file, classLine, classLine + 3).split(':')[0] ?? '';
  const bases = splitTopLevel(/\(([\s\S]*)\)/.exec(header)?.[1] ?? '').filter((base) => !/^metaclass\s*=/.test(base));
  for (const base of bases) {
    if (base === 'object') continue;
    if (!/^[A-Za-z_][\w.]*$/.test(base)) return false;
    const symbol = resolveSymbol(proj, filePath, base);
    if (symbol?.kind === 'library') {
      if (!PLAIN_DJANGO_MODULE.test(symbol.module)) return false;
      continue;
    }
    if (symbol?.kind !== 'class') return false;
    const owner = proj.byPath.get(symbol.file);
    if (owner === undefined || !basesArePlainDjango(proj, symbol.file, readPyFile(owner), symbol.line, depth + 1)) return false;
  }
  return true;
}

function loginNotRequired(file: PyFile, def: PyDef | undefined, route: ApiRoute): boolean {
  if ((route.wrappedBy ?? []).some((name) => /(?:^|\.)login_not_required$/.test(name))) return true;
  if (def?.decorators.some((decorator) => /\blogin_not_required\b/.test(decorator.text)) === true) return true;
  const classLine = enclosingClassLine(file, route.line);
  if (classLine === undefined) return false;
  const span = djangoHandler(file, classLine);
  return span !== undefined && /\blogin_not_required\b/.test(originalLines(file, span.startLine, span.endLine));
}

export type { PyDef, PyFile, ResolvedSymbol };

export const pythonReading = {
  project,
  readPyFile,
  resolveSymbol,
  resolveModule,
  routerDefinition,
  includeCalls: (proj: Project) => includeCalls(proj),
  moduleAssignmentAnyIndent,
  closingBracket,
  splitTopLevel,
  keywordArgument,
  lineOfIndex,
  statementFrom,
  originalLines,
  djangoHandler,
};
