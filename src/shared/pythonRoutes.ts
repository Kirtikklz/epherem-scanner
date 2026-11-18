import type { ApiRoute, FileMap } from './types.js';
import { pythonReading as R, type PyDef, type PyFile } from './pythonGuards.js';

type Project = ReturnType<typeof R.project>;
type PyKind = 'fastapi' | 'flask';

const MAX_DEPTH = 8;
const HTTP_ORDER = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

function literal(text: string): string | undefined {
  const m = /^[rRuU]?(['"])([^'"\n]*)\1$/.exec(text.trim());
  return m === null ? undefined : m[2];
}

function readFile(proj: Project, path: string): PyFile | undefined {
  const entry = proj.byPath.get(path);
  return entry === undefined ? undefined : R.readPyFile(entry);
}

interface Definition { file: string; name: string; kind: PyKind; value: string; app: boolean }

const BINDING = /^\s*(?:[\w.]+\.)?(APIRouter|FastAPI|Blueprint|Flask)\s*\(/;

function assignments(file: PyFile, name: string): string[] {
  const ASSIGN = new RegExp(`^[ \\t]*${name}[ \\t]*(?::[^=\\n]+)?=(?!=)[ \\t]*`, 'gm');
  const out: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = ASSIGN.exec(file.code)) !== null) out.push(R.statementFrom(file, m.index + m[0].length));
  return out;
}

function definitionOf(proj: Project, filePath: string, name: string, depth = 0): Definition | undefined {
  if (depth > MAX_DEPTH) return undefined;
  const file = readFile(proj, filePath);
  if (file === undefined || !/^[A-Za-z_]\w*$/.test(name)) return undefined;
  const values = assignments(file, name);
  if (values.length > 0) {
    const kinds = new Set(values.map((value) => BINDING.exec(value)?.[1]));
    if (kinds.size !== 1) return undefined;
    const call = [...kinds][0];
    if (call === undefined) return undefined;
    const kind: PyKind = call === 'APIRouter' || call === 'FastAPI' ? 'fastapi' : 'flask';
    return { file: filePath, name, kind, value: values[0] ?? '', app: call === 'FastAPI' || call === 'Flask' };
  }
  const target = R.routerDefinition(proj, filePath, name);
  if (target === undefined || (target.file === filePath && target.name === name)) return undefined;
  return definitionOf(proj, target.file, target.name, depth + 1);
}

function callArguments(value: string): string {
  const open = value.indexOf('(');
  return open < 0 ? '' : value.slice(open + 1, value.lastIndexOf(')'));
}

const DECORATOR = /^[ \t]*@([A-Za-z_]\w*)\.(get|post|put|patch|delete|route|api_route)[ \t]*\(/gm;

function methodList(args: string): string[] | undefined {
  const value = R.keywordArgument(args, 'methods');
  if (value === undefined) return undefined;
  const methods = [...value.matchAll(/['"]([A-Za-z]+)['"]/g)].map((m) => (m[1] ?? '').toUpperCase());
  return methods.length > 0 ? methods : undefined;
}

function decoratorRoutes(proj: Project, routes: ApiRoute[]): { routes: ApiRoute[]; changed: boolean } {
  const out = [...routes];
  let changed = false;
  const at = new Map<string, number>();
  out.forEach((route, i) => { if (route.filePath.endsWith('.py')) at.set(`${route.filePath}\0${route.line}`, i); });
  for (const path of proj.pyPaths) {
    const file = readFile(proj, path);
    if (file === undefined) continue;
    DECORATOR.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = DECORATOR.exec(file.code)) !== null) {
      const receiver = m[1] ?? '';
      const verb = m[2] ?? '';
      const line = R.lineOfIndex(file.lineStarts, m.index + m[0].indexOf('@'));
      const definition = definitionOf(proj, path, receiver);
      const existing = at.get(`${path}\0${line}`);
      if (existing !== undefined) {
        const route = out[existing];
        if (route !== undefined && definition?.kind === 'flask' && route.framework === 'fastapi' && verb !== 'api_route') {
          out[existing] = { ...route, framework: 'flask' };
          changed = true;
        }
        continue;
      }
      if (definition === undefined) continue;
      const open = m.index + m[0].length - 1;
      const close = R.closingBracket(file.code, open);
      if (close === undefined) continue;
      const args = file.entry.content.slice(open + 1, close);
      const routePath = literal(R.splitTopLevel(args)[0] ?? '');
      if (routePath === undefined) continue;
      let methods: string[] | undefined;
      if (verb === 'route') methods = definition.kind === 'flask' ? methodList(args) ?? ['GET'] : undefined;
      else if (verb === 'api_route') methods = definition.kind === 'fastapi' ? methodList(args) ?? ['GET'] : undefined;
      else methods = [verb.toUpperCase()];
      if (methods === undefined) continue;
      out.push({ filePath: path, framework: definition.kind, routePath, methods, line });
      at.set(`${path}\0${line}`, out.length - 1);
      changed = true;
    }
  }
  return { routes: out, changed };
}

interface Mount { file: string; parent: string; target: { file: string; name: string }; prefix?: string }

function objectAt(proj: Project, path: string, expression: string): { file: string; name: string } | undefined {
  const text = expression.trim();
  if (/^[A-Za-z_]\w*$/.test(text)) {
    const definition = definitionOf(proj, path, text);
    if (definition !== undefined) return { file: definition.file, name: definition.name };
  }
  const target = R.routerDefinition(proj, path, text);
  if (target === undefined) return undefined;
  const definition = definitionOf(proj, target.file, target.name);
  return definition === undefined ? target : { file: definition.file, name: definition.name };
}

const mountCache = new WeakMap<Project, { flask: Mount[]; subApps: Array<{ file: string; name: string }> }>();

function mounts(proj: Project): { flask: Mount[]; subApps: Array<{ file: string; name: string }> } {
  const cached = mountCache.get(proj);
  if (cached !== undefined) return cached;
  const flask: Mount[] = [];
  const subApps: Array<{ file: string; name: string }> = [];
  for (const path of proj.pyPaths) {
    const file = readFile(proj, path);
    if (file === undefined || !/register_blueprint|\.mount\s*\(/.test(file.entry.content)) continue;
    const CALL = /([A-Za-z_]\w*)\.(register_blueprint|mount)\s*\(/g;
    let m: RegExpExecArray | null;
    while ((m = CALL.exec(file.code)) !== null) {
      const open = m.index + m[0].length - 1;
      const close = R.closingBracket(file.code, open);
      if (close === undefined) continue;
      const args = file.entry.content.slice(open + 1, close);
      const positional = R.splitTopLevel(args).filter((part) => !/^\w+\s*=(?!=)/.test(part));
      if (m[2] === 'mount') {
        const target = objectAt(proj, path, positional[1] ?? R.keywordArgument(args, 'app') ?? '');
        if (target !== undefined) subApps.push(target);
        continue;
      }
      const target = objectAt(proj, path, positional[0] ?? '');
      if (target === undefined) continue;
      const prefix = R.keywordArgument(args, 'url_prefix');
      flask.push({ file: path, parent: m[1] ?? '', target, ...(prefix !== undefined ? { prefix } : {}) });
    }
  }
  const built = { flask, subApps };
  mountCache.set(proj, built);
  return built;
}

const sameObject = (a: { file: string; name: string }, b: { file: string; name: string }): boolean =>
  a.file === b.file && a.name === b.name;

function prefixValue(proj: Project, filePath: string, text: string): string | undefined {
  const direct = literal(text);
  if (direct !== undefined) return direct;
  const name = text.trim();
  const file = readFile(proj, filePath);
  if (file === undefined || !/^[A-Za-z_]\w*$/.test(name)) return undefined;
  const bindings = file.code.match(new RegExp(`^[ \\t]*${name}[ \\t]*(?::[^=\\n]+)?(?:[-+*/%|&^@]|//|>>|<<|\\*\\*)?=(?!=)`, 'gm')) ?? [];
  const loose = new RegExp(`\\b(?:global|nonlocal|for|as|import)\\b[^\\n]*\\b${name}\\b|\\b${name}\\s*:=`).test(file.code);
  if (bindings.length !== 1 || loose) return undefined;
  const plain = new RegExp(`^${name}[ \\t]*(?::[^=\\n]+)?=(?!=)[ \\t]*`, 'm').exec(file.code);
  return plain === null ? undefined : literal(R.statementFrom(file, plain.index + plain[0].length));
}

function agreed(values: Array<string | undefined>): string | undefined {
  if (values.length === 0 || values.some((value) => value === undefined)) return undefined;
  return new Set(values).size === 1 ? values[0] : undefined;
}

function fastapiPrefix(proj: Project, definition: Definition, depth: number): string | undefined {
  if (depth > MAX_DEPTH) return undefined;
  if (mounts(proj).subApps.some((app) => sameObject(app, definition))) return undefined;
  if (definition.app) return '';
  const ownArg = R.keywordArgument(callArguments(definition.value), 'prefix');
  const own = ownArg === undefined ? '' : prefixValue(proj, definition.file, ownArg);
  if (own === undefined) return undefined;
  const includes = R.includeCalls(proj).filter((call) => {
    if (call.target === undefined) return false;
    const at = definitionOf(proj, call.target.file, call.target.name);
    return sameObject(at ?? call.target, definition);
  });
  return agreed(includes.map((call) => {
    const at = call.prefix === undefined ? '' : prefixValue(proj, call.file, call.prefix);
    const parent = definitionOf(proj, call.file, call.parent);
    if (at === undefined || parent?.kind !== 'fastapi') return undefined;
    const above = fastapiPrefix(proj, parent, depth + 1);
    return above === undefined ? undefined : above + at + own;
  }));
}

function flaskJoin(prefix: string, rule: string): string {
  if (prefix === '') return rule;
  if (rule === '') return prefix;
  return `${prefix.replace(/\/+$/, '')}/${rule.replace(/^\/+/, '')}`;
}

function flaskPrefix(proj: Project, definition: Definition, depth: number): string | undefined {
  if (depth > MAX_DEPTH) return undefined;
  if (definition.app) return mounts(proj).subApps.some((app) => sameObject(app, definition)) ? undefined : '';
  const ownArg = R.keywordArgument(callArguments(definition.value), 'url_prefix');
  const own = ownArg === undefined || ownArg.trim() === 'None' ? '' : prefixValue(proj, definition.file, ownArg);
  if (own === undefined) return undefined;
  const registrations = mounts(proj).flask.filter((mount) => sameObject(mount.target, definition));
  return agreed(registrations.map((mount) => {
    const at = mount.prefix === undefined || mount.prefix.trim() === 'None' ? own : prefixValue(proj, mount.file, mount.prefix);
    const parent = definitionOf(proj, mount.file, mount.parent);
    if (at === undefined || parent?.kind !== 'flask') return undefined;
    const above = flaskPrefix(proj, parent, depth + 1);
    return above === undefined ? undefined : flaskJoin(above, at);
  }));
}

function withPrefixes(proj: Project, routes: ApiRoute[]): { routes: ApiRoute[]; changed: boolean } {
  let changed = false;
  const prefixes = new Map<string, string | undefined>();
  const out = routes.map((route) => {
    if (route.framework !== 'fastapi' && route.framework !== 'flask') return route;
    const file = readFile(proj, route.filePath);
    const receiver = /^\s*@([A-Za-z_]\w*)\./.exec(file?.codeLines[route.line - 1] ?? '')?.[1];
    if (receiver === undefined) return route;
    const key = `${route.framework}\0${route.filePath}\0${receiver}`;
    if (!prefixes.has(key)) {
      const definition = definitionOf(proj, route.filePath, receiver);
      prefixes.set(key, definition === undefined || definition.kind !== route.framework
        ? undefined
        : route.framework === 'fastapi' ? fastapiPrefix(proj, definition, 0) : flaskPrefix(proj, definition, 0));
    }
    const prefix = prefixes.get(key);
    if (prefix === undefined || prefix === '') return route;
    const routePath = route.framework === 'fastapi' ? prefix + route.routePath : flaskJoin(prefix, route.routePath);
    if (routePath === route.routePath) return route;
    changed = true;
    return { ...route, routePath, declaredPath: route.routePath };
  });
  return { routes: out, changed };
}

interface Range { start: number; end: number }

function parts(file: PyFile, range: Range): Range[] {
  const out: Range[] = [];
  let depth = 0;
  let from = range.start;
  const push = (to: number): void => {
    let s = from;
    let e = to;
    while (s < e && /\s/.test(file.code[s] ?? '')) s += 1;
    while (e > s && /\s/.test(file.code[e - 1] ?? '')) e -= 1;
    if (e > s) out.push({ start: s, end: e });
  };
  for (let i = range.start; i < range.end; i += 1) {
    const c = file.code[i];
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === ']' || c === '}') depth -= 1;
    else if (c === ',' && depth === 0) { push(i); from = i + 1; }
  }
  push(range.end);
  return out;
}

const textOf = (file: PyFile, range: Range): string => file.entry.content.slice(range.start, range.end);
const codeOf = (file: PyFile, range: Range): string => file.code.slice(range.start, range.end);

function callIn(file: PyFile, range: Range): { name: string; args: Range } | undefined {
  const m = /^([A-Za-z_][\w.]*)\s*\(/.exec(codeOf(file, range));
  if (m === null) return undefined;
  const open = range.start + m[0].length - 1;
  const close = R.closingBracket(file.code, open);
  if (close !== range.end - 1) return undefined;
  return { name: m[1] ?? '', args: { start: open + 1, end: close } };
}

function keyword(file: PyFile, args: Range[], name: string): Range | undefined {
  for (const arg of args) {
    const m = new RegExp(`^${name}\\s*=(?!=)\\s*`).exec(codeOf(file, arg));
    if (m !== null) return { start: arg.start + m[0].length, end: arg.end };
  }
  return undefined;
}

const positional = (file: PyFile, args: Range[]): Range[] => args.filter((arg) => !/^\w+\s*=(?!=)/.test(codeOf(file, arg)));

interface DjangoWalk {
  proj: Project;
  out: ApiRoute[];
  seen: Set<string>;
}

function addRoute(walk: DjangoWalk, route: ApiRoute): void {
  const key = `${route.filePath}\0${route.line}\0${route.methods.join(',')}`;
  if (walk.seen.has(key)) return;
  walk.seen.add(key);
  walk.out.push(route);
}

function joinDjango(prefix: string, route: string): string {
  return prefix + route.replace(/^\/+/, '');
}

function rootUrlconfs(proj: Project): string[] {
  const roots = new Set<string>();
  for (const path of proj.pyPaths) {
    const file = readFile(proj, path);
    if (file === undefined || !file.entry.content.includes('ROOT_URLCONF')) continue;
    for (const m of file.entry.content.matchAll(/^ROOT_URLCONF[ \t]*=[ \t]*(['"])([\w.]+)\1/gm)) {
      if (!file.code.startsWith('ROOT_URLCONF', m.index ?? 0)) continue;
      const target = R.resolveModule(proj, path, m[2] ?? '');
      if (target !== undefined) roots.add(target);
    }
  }
  return [...roots].sort();
}

function statementEnd(file: PyFile, start: number): number {
  let depth = 0;
  let i = start;
  for (; i < file.code.length; i += 1) {
    const c = file.code[i];
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === ']' || c === '}') depth -= 1;
    else if (c === '\n' && depth <= 0 && file.code[i - 1] !== '\\') break;
  }
  return i;
}

function walkUrlconf(walk: DjangoWalk, path: string, prefix: string, depth: number, stack: string[]): void {
  if (depth > MAX_DEPTH || stack.includes(path)) return;
  const file = readFile(walk.proj, path);
  if (file === undefined) return;
  const next = [...stack, path];
  const ASSIGN = /^urlpatterns[ \t]*(?::[^=\n]+)?\+?=(?!=)[ \t]*/gm;
  let m: RegExpExecArray | null;
  while ((m = ASSIGN.exec(file.code)) !== null) {
    const start = m.index + m[0].length;
    patterns(walk, file, { start, end: statementEnd(file, start) }, prefix, depth, next);
  }
  const EXTEND = /^urlpatterns\.(extend|append)\s*\(/gm;
  while ((m = EXTEND.exec(file.code)) !== null) {
    const open = m.index + m[0].length - 1;
    const close = R.closingBracket(file.code, open);
    if (close === undefined) continue;
    const inner = { start: open + 1, end: close };
    if (m[1] === 'append') entry(walk, file, parts(file, inner)[0] ?? inner, prefix, depth, next);
    else patterns(walk, file, inner, prefix, depth, next);
  }
}

function patterns(walk: DjangoWalk, file: PyFile, range: Range, prefix: string, depth: number, stack: string[]): void {
  if (depth > MAX_DEPTH) return;
  const trimmed = parts(file, range);
  if (trimmed.length !== 1) return;
  const r = trimmed[0]!;
  const code = codeOf(file, r);
  let level = 0;
  const pluses: number[] = [];
  for (let i = r.start; i < r.end; i += 1) {
    const c = file.code[i];
    if (c === '(' || c === '[' || c === '{') level += 1;
    else if (c === ')' || c === ']' || c === '}') level -= 1;
    else if (c === '+' && level === 0) pluses.push(i);
  }
  if (pluses.length > 0) {
    let from = r.start;
    for (const at of [...pluses, r.end]) {
      patterns(walk, file, { start: from, end: at }, prefix, depth + 1, stack);
      from = at + 1;
    }
    return;
  }
  if (code.startsWith('[') || code.startsWith('(')) {
    const close = R.closingBracket(file.code, r.start);
    if (close !== r.end - 1) return;
    for (const item of parts(file, { start: r.start + 1, end: close })) entry(walk, file, item, prefix, depth, stack);
    return;
  }
  const urls = /^([A-Za-z_][\w.]*)\.urls$/.exec(code);
  if (urls !== null) { drfRouter(walk, file, urls[1] ?? '', prefix); return; }
  if (/^[A-Za-z_]\w*$/.test(code)) {
    const ASSIGN = new RegExp(`^${code}[ \\t]*(?::[^=\\n]+)?=(?!=)[ \\t]*`, 'm');
    const m = ASSIGN.exec(file.code);
    if (m !== null && code !== 'urlpatterns') {
      const start = m.index + m[0].length;
      patterns(walk, file, { start, end: statementEnd(file, start) }, prefix, depth + 1, stack);
    }
  }
}

function entry(walk: DjangoWalk, file: PyFile, range: Range, prefix: string, depth: number, stack: string[]): void {
  const call = callIn(file, range);
  if (call === undefined) return;
  const kind = call.name.split('.').pop() ?? '';
  if (kind !== 'path' && kind !== 're_path' && kind !== 'url') return;
  const args = parts(file, call.args);
  const plain = positional(file, args);
  const routeRange = plain[0] ?? keyword(file, args, 'route');
  const viewRange = plain[1] ?? keyword(file, args, 'view');
  if (routeRange === undefined || viewRange === undefined) return;
  let route = literal(textOf(file, routeRange));
  if (route === undefined) return;
  if (kind !== 'path') route = route.replace(/^\^/, '').replace(/\$$/, '');
  view(walk, file, viewRange, joinDjango(prefix, route), [], depth, stack, `/${route.replace(/^\/+/, '')}`);
}

function view(walk: DjangoWalk, file: PyFile, range: Range, path: string, wrappers: string[], depth: number, stack: string[], declared: string): void {
  if (depth > MAX_DEPTH) return;
  const code = codeOf(file, range);
  const call = callIn(file, range);
  if (call !== undefined) {
    const args = parts(file, call.args);
    const leaf = call.name.split('.').pop() ?? '';
    if (leaf === 'include') {
      const first = positional(file, args)[0] ?? keyword(file, args, 'arg');
      if (first !== undefined) include(walk, file, first, path, depth, stack);
      return;
    }
    if (leaf === 'as_view') {
      const owner = call.name.slice(0, -'.as_view'.length);
      const symbol = R.resolveSymbol(walk.proj, file.entry.path, owner);
      if (symbol?.kind !== 'class') return;
      const target = readFile(walk.proj, symbol.file);
      if (target === undefined) return;
      const mapping = positional(file, args)[0];
      const actions = mapping !== undefined && codeOf(file, mapping).startsWith('{')
        ? [...textOf(file, mapping).matchAll(/['"](\w+)['"]\s*:\s*['"](\w+)['"]/g)].map((m) => ({ method: (m[1] ?? '').toUpperCase(), action: m[2] ?? '' }))
        : undefined;
      classRoutes(walk, target, symbol.line, path, declared, wrappers, actions);
      return;
    }
    const inner = positional(file, args)[0];
    if (inner !== undefined) view(walk, file, inner, path, [...wrappers, call.name], depth + 1, stack, declared);
    return;
  }
  if (!/^[A-Za-z_][\w.]*$/.test(code)) return;
  const symbol = R.resolveSymbol(walk.proj, file.entry.path, code);
  if (symbol?.kind !== 'def') return;
  const target = readFile(walk.proj, symbol.file);
  if (target !== undefined) functionRoute(walk, target, symbol.def, path, declared, wrappers);
}

function include(walk: DjangoWalk, file: PyFile, range: Range, path: string, depth: number, stack: string[]): void {
  const code = codeOf(file, range);
  let target = range;
  if (code.startsWith('(')) {
    const close = R.closingBracket(file.code, range.start);
    if (close !== range.end - 1) return;
    const first = parts(file, { start: range.start + 1, end: close })[0];
    if (first === undefined) return;
    target = first;
  }
  const spec = literal(textOf(file, target));
  if (spec !== undefined) {
    const module = R.resolveModule(walk.proj, file.entry.path, spec);
    if (module !== undefined) walkUrlconf(walk, module, path, depth + 1, stack);
    return;
  }
  const targetCode = codeOf(file, target);
  if (targetCode.startsWith('[') || /\.urls$/.test(targetCode)) { patterns(walk, file, target, path, depth + 1, stack); return; }
  if (!/^[A-Za-z_][\w.]*$/.test(targetCode)) return;
  const symbol = R.resolveSymbol(walk.proj, file.entry.path, targetCode);
  if (symbol?.kind === 'module') walkUrlconf(walk, symbol.file, path, depth + 1, stack);
  else if (/^[A-Za-z_]\w*$/.test(targetCode)) patterns(walk, file, target, path, depth + 1, stack);
}

const VIEW_VERBS = new Set(['get', 'post', 'put', 'patch', 'delete']);

function sortMethods(methods: Iterable<string>): string[] {
  const set = new Set(methods);
  return [...HTTP_ORDER.filter((m) => set.has(m)), ...[...set].filter((m) => !HTTP_ORDER.includes(m)).sort()];
}

function functionMethods(def: PyDef): string[] {
  for (const decorator of def.decorators) {
    const name = /^\s*@([A-Za-z_][\w.]*)/.exec(decorator.text)?.[1]?.split('.').pop() ?? '';
    if (name === 'require_POST') return ['POST'];
    if (name === 'require_GET' || name === 'require_safe') return ['GET'];
    if (name === 'require_http_methods' || name === 'api_view') {
      const listed = [...decorator.text.matchAll(/['"]([A-Za-z]+)['"]/g)].map((m) => (m[1] ?? '').toUpperCase());
      if (listed.length > 0) return sortMethods(listed);
      if (name === 'api_view') return ['GET'];
    }
  }
  return ['GET', 'POST'];
}

function functionRoute(walk: DjangoWalk, file: PyFile, def: PyDef, path: string, declared: string, wrappers: string[]): void {
  addRoute(walk, {
    filePath: file.entry.path, framework: 'django', routePath: path, declaredPath: declared, methods: functionMethods(def), line: def.defLine,
    ...(wrappers.length > 0 ? { wrappedBy: wrappers } : {}),
  });
}

interface ClassShape { line: number; endLine: number; header: string; methods: PyDef[] }

function classShape(file: PyFile, line: number): ClassShape | undefined {
  const span = R.djangoHandler(file, line);
  if (span === undefined) return undefined;
  const inside = file.defs.filter((def) => def.defLine > line && def.defLine <= span.endLine);
  const indent = Math.min(...inside.map((def) => def.indent));
  const header = R.originalLines(file, line, Math.min(line + 5, span.endLine)).split(/\)\s*:/)[0] ?? '';
  return { line, endLine: span.endLine, header, methods: inside.filter((def) => def.indent === indent) };
}

function inheritedMethods(header: string): string[] {
  const bases = /\(([\s\S]*)$/.exec(header)?.[1] ?? '';
  const out = new Set<string>();
  if (/APIView|ViewSet/.test(bases)) {
    if (/\bModelViewSet\b/.test(bases) && !/ReadOnlyModelViewSet/.test(bases)) HTTP_ORDER.forEach((m) => out.add(m));
    if (/List|Retrieve|ReadOnly/.test(bases)) out.add('GET');
    if (/Create/.test(bases)) out.add('POST');
    if (/Update/.test(bases)) { out.add('PUT'); out.add('PATCH'); }
    if (/Destroy/.test(bases)) out.add('DELETE');
    return sortMethods(out);
  }
  out.add('GET');
  if (/Create|Update|Delete|Form|Edit|Wizard/.test(bases)) out.add('POST');
  return sortMethods(out);
}

function classRoutes(
  walk: DjangoWalk, file: PyFile, line: number, path: string, declared: string, wrappers: string[],
  actions: Array<{ method: string; action: string }> | undefined,
): void {
  const shape = classShape(file, line);
  if (shape === undefined) return;
  const wrapped = wrappers.length > 0 ? { wrappedBy: wrappers } : {};
  const route = (at: number, methods: string[]): void =>
    addRoute(walk, { filePath: file.entry.path, framework: 'django', routePath: path, declaredPath: declared, methods, line: at, ...wrapped });
  if (actions !== undefined) {
    for (const { method, action } of actions) {
      const def = shape.methods.find((candidate) => candidate.name === action);
      route(def?.defLine ?? line, [method]);
    }
    return;
  }
  const defined = new Set<string>();
  for (const def of shape.methods) {
    if (!VIEW_VERBS.has(def.name)) continue;
    defined.add(def.name.toUpperCase());
    route(def.defLine, [def.name.toUpperCase()]);
  }
  const inherited = inheritedMethods(shape.header).filter((method) => !defined.has(method));
  if (inherited.length > 0 || defined.size === 0) route(line, inherited.length > 0 ? inherited : ['GET']);
}

const STANDARD_ACTIONS: Record<string, { method: string; detail: boolean }> = {
  list: { method: 'GET', detail: false },
  create: { method: 'POST', detail: false },
  retrieve: { method: 'GET', detail: true },
  update: { method: 'PUT', detail: true },
  partial_update: { method: 'PATCH', detail: true },
  destroy: { method: 'DELETE', detail: true },
};

function drfRouter(walk: DjangoWalk, file: PyFile, expression: string, prefix: string): void {
  const target = /\./.test(expression)
    ? R.routerDefinition(walk.proj, file.entry.path, expression)
    : (assignments(file, expression).length > 0 ? { file: file.entry.path, name: expression } : R.routerDefinition(walk.proj, file.entry.path, expression));
  if (target === undefined) return;
  const owner = readFile(walk.proj, target.file);
  if (owner === undefined) return;
  const values = assignments(owner, target.name);
  if (values.length === 0 || !values.every((value) => /^\s*(?:[\w.]+\.)?(?:DefaultRouter|SimpleRouter)\s*\(/.test(value))) return;
  const REGISTER = new RegExp(`(?<![\\w.])${target.name}\\.register\\s*\\(`, 'g');
  let m: RegExpExecArray | null;
  while ((m = REGISTER.exec(owner.code)) !== null) {
    const open = m.index + m[0].length - 1;
    const close = R.closingBracket(owner.code, open);
    if (close === undefined) continue;
    const args = parts(owner, { start: open + 1, end: close });
    const plain = positional(owner, args);
    const at = literal(textOf(owner, plain[0] ?? keyword(owner, args, 'prefix') ?? { start: 0, end: 0 }));
    const viewset = plain[1] ?? keyword(owner, args, 'viewset');
    if (at === undefined || viewset === undefined) continue;
    const symbol = R.resolveSymbol(walk.proj, owner.entry.path, codeOf(owner, viewset));
    if (symbol?.kind !== 'class') continue;
    const viewFile = readFile(walk.proj, symbol.file);
    const own = at.replace(/^\/+|\/+$/g, '');
    const segment = own === '' ? '' : `${own}/`;
    if (viewFile !== undefined) viewsetRoutes(walk, viewFile, symbol.line, joinDjango(prefix, segment), `/${segment}`);
  }
}

function viewsetRoutes(walk: DjangoWalk, file: PyFile, line: number, base: string, declared: string): void {
  const shape = classShape(file, line);
  if (shape === undefined) return;
  const detail = `${base}{pk}/`;
  const route = (at: number, routePath: string, methods: string[]): void =>
    addRoute(walk, { filePath: file.entry.path, framework: 'django', routePath, declaredPath: declared + routePath.slice(base.length), methods, line: at });
  const defined = new Set<string>();
  for (const def of shape.methods) {
    const standard = STANDARD_ACTIONS[def.name];
    if (standard !== undefined) {
      defined.add(standard.method);
      route(def.defLine, standard.detail ? detail : base, [standard.method]);
      continue;
    }
    const action = def.decorators.find((decorator) => /^\s*@(?:[\w.]+\.)?action\b/.test(decorator.text));
    if (action === undefined) continue;
    const args = action.text.slice(action.text.indexOf('(') + 1, action.text.lastIndexOf(')'));
    const methods = [...(R.keywordArgument(args, 'methods') ?? '').matchAll(/['"]([A-Za-z]+)['"]/g)].map((m) => (m[1] ?? '').toUpperCase());
    const urlPath = literal(R.keywordArgument(args, 'url_path') ?? '') ?? def.name;
    const onDetail = (R.keywordArgument(args, 'detail') ?? '').trim() === 'True';
    route(def.defLine, `${onDetail ? detail : base}${urlPath}/`, methods.length > 0 ? sortMethods(methods) : ['GET']);
  }
  const inherited = inheritedMethods(shape.header).filter((method) => !defined.has(method));
  if (inherited.length > 0) route(line, base, inherited);
}

function djangoRoutes(proj: Project): ApiRoute[] {
  const walk: DjangoWalk = { proj, out: [], seen: new Set() };
  for (const root of rootUrlconfs(proj)) walkUrlconf(walk, root, '/', 0, []);
  return walk.out;
}

export function withPythonRouteTree(fileMap: FileMap, routes: ApiRoute[]): ApiRoute[] {
  if (!fileMap.entries.some((entry) => entry.extension === '.py')) return routes;
  const proj = R.project({ fileMap });
  const decorated = decoratorRoutes(proj, routes);
  const prefixed = withPrefixes(proj, decorated.routes);
  const django = djangoRoutes(proj);
  if (!decorated.changed && !prefixed.changed && django.length === 0) return routes;
  return [...prefixed.routes, ...django];
}

