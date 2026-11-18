import type { FileMapEntry } from './types.js';
import { pythonReading as R } from './pythonGuards.js';
import { enclosingDef, maskedLines } from './pythonScope.js';
import { readPythonTree, type PyNode, type PyTree } from './pythonParser.js';
import { isBindingIdentifier, statementOf } from './pythonBindings.js';

export const STORED_TEXT_FIELD = [
  /^[ \t]*([A-Za-z_]\w*)\s*=\s*(?:models\.)?(?:TextField|CharField)\s*\(/gm,
  /^[ \t]*([A-Za-z_]\w*)\s*(?::[^=\n]+)?=\s*(?:(?:db|sa|sqlalchemy|orm)\.)?(?:Column|mapped_column)\s*\(\s*(?:(?:db|sa|sqlalchemy)\.)?(?:Text|String|Unicode|UnicodeText)\b/gm,
  /^[ \t]*([A-Za-z_]\w*)\s*:\s*Mapped\[\s*(?:Optional\[\s*)?str\b/gm,
];

export function storedTextFields(code: string): Set<string> {
  const names = new Set<string>();
  for (const pattern of STORED_TEXT_FIELD) {
    for (const match of code.matchAll(pattern)) if (match[1] !== undefined) names.add(match[1]);
  }
  return names;
}

export interface PyClass {
  name: string;
  file: string;
  start: number;
  end: number;
  body: string;
  codeBody: string;
  storedFields: Set<string>;
  bases: string[] | undefined;
}

interface RenderCall { file: string; line: number; template: string | undefined; bindings: Map<string, string> | undefined }

interface Context {
  py: FileMapEntry[];
  html: FileMapEntry[];
  classes: Map<string, PyClass[]>;
  declarativeBases: Set<string>;
  renders: RenderCall[];
  dynamicTemplate: boolean;
  proj: ReturnType<typeof R.project>;
}

const contexts = new WeakMap<object, Context>();

function classesIn(entry: FileMapEntry): PyClass[] {
  const lines = maskedLines(entry.content);
  const code = lines.join('\n');
  const original = entry.content.split('\n');
  const out: PyClass[] = [];
  let offset = 0;
  lines.forEach((text, i) => {
    const lineStart = offset;
    offset += text.length + 1;
    const m = /^([ \t]*)class\s+([A-Za-z_]\w*)\s*/.exec(text);
    if (m === null) return;
    const indent = (m[1] ?? '').length;
    let bases: string[] | undefined = [];
    let headerEnd = i + 1;
    if (text[m[0].length] === '(') {
      const open = lineStart + m[0].length;
      const close = R.closingBracket(code, open);
      if (close === undefined) bases = undefined;
      else {
        bases = R.splitTopLevel(code.slice(open + 1, close).replace(/\\\n/g, '  '));
        headerEnd = code.slice(0, close).split('\n').length;
      }
    } else if (text[m[0].length] !== ':') bases = undefined;
    let end = headerEnd;
    for (let l = headerEnd + 1; l <= lines.length; l += 1) {
      const t = lines[l - 1] ?? '';
      if (t.trim() === '') continue;
      if ((/^[ \t]*/.exec(t)?.[0].length ?? 0) <= indent) break;
      end = l;
    }
    const body = original.slice(headerEnd, end).join('\n');
    const codeBody = lines.slice(headerEnd, end).join('\n');
    out.push({ name: m[2] ?? '', file: entry.path, start: i + 1, end, body, codeBody, storedFields: storedTextFields(body), bases });
  });
  return out;
}

function declarativeBaseNames(py: FileMapEntry[]): Set<string> {
  const declarative = new Set<string>();
  const other = new Set<string>();
  for (const entry of py) {
    for (const text of maskedLines(entry.content)) {
      const m = /^([A-Za-z_]\w*)\s*(?::[^=\n]+)?=(?!=)\s*(.*)$/.exec(text);
      if (m === null) continue;
      if (/^(?:[\w.]+\.)?declarative_base\s*\(/.test(m[2] ?? '')) declarative.add(m[1] ?? '');
      else other.add(m[1] ?? '');
    }
  }
  for (const name of other) declarative.delete(name);
  return declarative;
}

const RENDER = /(?<![\w.])(render_template|render|render_to_response|render_to_string|TemplateResponse)\s*\(/g;

function renderCalls(entry: FileMapEntry): { calls: RenderCall[]; dynamic: boolean } {
  const code = maskedLines(entry.content).join('\n');
  const calls: RenderCall[] = [];
  let dynamic = false;
  RENDER.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = RENDER.exec(code)) !== null) {
    const open = m.index + m[0].length - 1;
    const close = R.closingBracket(code, open);
    if (close === undefined) continue;
    const args = R.splitTopLevel(entry.content.slice(open + 1, close));
    const line = code.slice(0, m.index).split('\n').length;
    const positional = args.filter((arg) => !/^\w+\s*=(?!=)/.test(arg) && !arg.startsWith('*'));
    const nameAt = m[1] === 'render_template' || m[1] === 'render_to_string' || m[1] === 'render_to_response' ? 0 : 1;
    const nameArg = positional[nameAt] ?? R.keywordArgument(args.join(','), 'template_name');
    const template = nameArg === undefined ? undefined : /^[rRuU]?(['"])([^'"\n]+)\1$/.exec(nameArg.trim())?.[2];
    if (template === undefined) {
      if (nameArg !== undefined) dynamic = true;
      continue;
    }
    let bindings: Map<string, string> | undefined = new Map();
    if (args.some((arg) => arg.startsWith('**'))) bindings = undefined;
    else if (m[1] === 'render_template') {
      for (const arg of args) {
        const kw = /^(\w+)\s*=(?!=)\s*([\s\S]+)$/.exec(arg);
        if (kw !== null) bindings.set(kw[1] ?? '', (kw[2] ?? '').trim());
      }
    } else {
      const contextArg = positional[nameAt + 1] ?? R.keywordArgument(args.join(','), 'context');
      if (contextArg !== undefined) {
        const dict = contextArg.trim();
        if (!dict.startsWith('{') || !dict.endsWith('}')) bindings = undefined;
        else {
          for (const item of R.splitTopLevel(dict.slice(1, -1))) {
            const kv = /^(['"])(\w+)\1\s*:\s*([\s\S]+)$/.exec(item);
            if (kv === null) { bindings = undefined; break; }
            bindings.set(kv[2] ?? '', (kv[3] ?? '').trim());
          }
        }
      }
    }
    calls.push({ file: entry.path, line, template, bindings });
  }
  return { calls, dynamic };
}

function contextOf(entries: FileMapEntry[]): Context {
  const key = entries as unknown as object;
  const cached = contexts.get(key);
  if (cached !== undefined) return cached;
  const py = entries.filter((entry) => entry.extension === '.py');
  const html = entries.filter((entry) => entry.extension === '.html');
  const classes = new Map<string, PyClass[]>();
  const renders: RenderCall[] = [];
  let dynamicTemplate = false;
  for (const entry of py) {
    for (const cls of classesIn(entry)) classes.set(cls.name, [...(classes.get(cls.name) ?? []), cls]);
    const found = renderCalls(entry);
    renders.push(...found.calls);
    dynamicTemplate ||= found.dynamic;
  }
  const proj = R.project({ fileMap: { entries } as unknown as Parameters<typeof R.project>[0]['fileMap'] });
  const built = { py, html, classes, declarativeBases: declarativeBaseNames(py), renders, dynamicTemplate, proj };
  contexts.set(key, built);
  return built;
}

function projectClass(context: Context, name: string): PyClass | undefined {
  const found = context.classes.get(name);
  return found !== undefined && found.length === 1 ? found[0] : undefined;
}

const MODEL_ATTRIBUTE_ROOT = /^(?:models|db|sa|orm|sqlalchemy|django\.db\.models)\.Model$/;
const LIBRARY_ROOT = /^(?:object|Model|DeclarativeBase|DeclarativeBaseNoMeta|MappedAsDataclass|AsyncAttrs|TimeStampedModel|TimeFramedModel|SoftDeletableModel|UUIDModel)$/;

const LIBRARY_BASES = new Set([
  'django.db.models.Model', 'django.db.models.base.Model',
  'sqlalchemy.orm.DeclarativeBase', 'sqlalchemy.orm.DeclarativeBaseNoMeta', 'sqlalchemy.orm.MappedAsDataclass',
  'sqlalchemy.ext.asyncio.AsyncAttrs',
  'model_utils.models.TimeStampedModel', 'model_utils.models.TimeFramedModel', 'model_utils.models.SoftDeletableModel', 'model_utils.models.UUIDModel',
]);
const DECLARATIVE_FACTORIES = new Set(['sqlalchemy.orm.declarative_base', 'sqlalchemy.ext.declarative.declarative_base']);

type Followed = { kind: 'class'; cls: PyClass } | { kind: 'library'; path: string } | { kind: 'root' } | { kind: 'module'; file: string } | 'unproven';

function moduleBindings(tree: PyTree, name: string): PyNode[] {
  return tree.find((n) => n.type === 'identifier' && n.text === name && isBindingIdentifier(n)).filter((n) => {
    for (let p = n.parent; p !== undefined; p = p.parent) {
      const isOwnName = (p.type === 'function_definition' || p.type === 'class_definition') && p.child('name')?.same(n);
      if (!isOwnName && ['function_definition', 'class_definition', 'lambda'].includes(p.type)) return false;
    }
    return true;
  });
}

function followName(context: Context, file: string, dotted: string[], depth: number): Followed {
  if (depth > 6 || dotted.length === 0) return 'unproven';
  const entry = context.py.find((e) => e.path === file);
  const tree = entry === undefined ? undefined : readPythonTree(entry).tree;
  if (tree === undefined) return 'unproven';
  const [head, ...rest] = dotted as [string, ...string[]];
  const bindings = moduleBindings(tree, head);
  if (bindings.length === 0) return head === 'object' && rest.length === 0 ? { kind: 'root' } : 'unproven';
  if (bindings.length > 1) return 'unproven';
  const bound = bindings[0]!;
  if (statementOf(bound).parent?.type !== 'module') return 'unproven';
  const holder = bound.parent;
  if (holder?.type === 'class_definition') {
    const cls = (context.classes.get(head) ?? []).find((c) => c.file === file && c.start === holder.line);
    return cls !== undefined && rest.length === 0 ? { kind: 'class', cls } : 'unproven';
  }
  if (holder?.type === 'assignment') {
    const value = holder.child('right');
    const callee = value?.type === 'call' ? value.child('function') : undefined;
    if (callee === undefined || value === undefined) return 'unproven';
    const made = followName(context, file, callee.text.replace(/\s+/g, '').split('.'), depth + 1);
    if (made === 'unproven' || made.kind !== 'library') return 'unproven';
    if (DECLARATIVE_FACTORIES.has(made.path) && rest.length === 0) return { kind: 'root' };
    const passesModel = value.child('arguments')?.namedChildren.some((a) => a.type !== 'keyword_argument' || a.child('name')?.text === 'model_class');
    if (made.path === 'flask_sqlalchemy.SQLAlchemy' && rest.length === 1 && rest[0] === 'Model' && passesModel !== true) return { kind: 'root' };
    return 'unproven';
  }
  const statement = statementOf(bound);
  if (statement.type === 'import_from_statement') {
    const moduleNode = statement.child('module_name');
    const imported = holder?.type === 'aliased_import' ? holder.child('name')?.text : bound.text;
    if (moduleNode === undefined || imported === undefined) return 'unproven';
    const spec = moduleNode.text.replace(/\s+/g, '');
    const target = R.resolveModule(context.proj, file, `${spec}${spec.endsWith('.') ? '' : '.'}${imported}`);
    if (target !== undefined) return rest.length === 0 ? { kind: 'module', file: target } : followName(context, target, rest, depth + 1);
    const moduleFile = R.resolveModule(context.proj, file, spec);
    if (moduleFile !== undefined) return followName(context, moduleFile, [imported, ...rest], depth + 1);
    return spec.startsWith('.') ? 'unproven' : { kind: 'library', path: [spec, imported, ...rest].join('.') };
  }
  if (statement.type === 'import_statement') {
    const module = holder?.type === 'aliased_import' ? holder.child('name')?.text : bound.text;
    if (module === undefined) return 'unproven';
    const target = R.resolveModule(context.proj, file, module);
    if (target !== undefined) return rest.length === 0 ? { kind: 'module', file: target } : followName(context, target, rest, depth + 1);
    return { kind: 'library', path: [module, ...rest].join('.') };
  }
  return 'unproven';
}

function followedBase(context: Context, cls: PyClass, base: string): PyClass | 'library' | 'unproven' {
  const byName = baseClass(context, base);
  if (byName === 'unproven') return 'unproven';
  const followed = followName(context, cls.file, base.trim().split('.'), 0);
  if (followed === 'unproven') return 'unproven';
  if (byName === 'library') return followed.kind === 'root' || (followed.kind === 'library' && LIBRARY_BASES.has(followed.path)) ? 'library' : 'unproven';
  return followed.kind === 'class' && followed.cls === byName ? byName : 'unproven';
}

function baseClass(context: Context, base: string): PyClass | 'library' | 'unproven' {
  const text = base.trim();
  if (!/^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$/.test(text)) return 'unproven';
  if (MODEL_ATTRIBUTE_ROOT.test(text)) return 'library';
  const last = text.slice(text.lastIndexOf('.') + 1);
  const found = context.classes.get(last) ?? [];
  if (found.length === 1 && found[0] !== undefined) return found[0];
  if (found.length > 1) return 'unproven';
  if (text === last && context.declarativeBases.has(last)) return 'library';
  return LIBRARY_ROOT.test(last) ? 'library' : 'unproven';
}

function leafBinding(cls: PyClass, leaf: string): 'column' | 'other' | 'self' | 'none' {
  const code = cls.codeBody.split('\n');
  const original = cls.body.split('\n');
  const first = code.find((text) => text.trim() !== '');
  const level = first === undefined ? 0 : (/^[ \t]*/.exec(first)?.[0].length ?? 0);
  let result: 'column' | 'self' | 'none' = 'none';
  for (let i = 0; i < code.length; i += 1) {
    const text = code[i] ?? '';
    if (text.trim() !== '' && (/^[ \t]*/.exec(text)?.[0].length ?? 0) === level) {
      if (new RegExp(`^\\s*(?:async\\s+)?def\\s+${leaf}\\b`).test(text)) return 'other';
      if (new RegExp(`^\\s*${leaf}\\s*(?::|=(?!=))`).test(text)) {
        const line = original[i] ?? '';
        if (!STORED_TEXT_FIELD.some((pattern) => new RegExp(pattern.source, 'm').test(line))) return 'other';
        result = 'column';
        continue;
      }
    }
    if (result === 'none' && new RegExp(`\\bself\\.${leaf}\\s*=(?!=)`).test(text)) result = 'self';
  }
  return result;
}

export function receiverColumn(entries: FileMapEntry[], cls: PyClass, leaf: string): 'stored' | 'absent' | 'unproven' {
  const context = contextOf(entries);
  const chain: PyClass[] = [];
  const queue: PyClass[] = [cls];
  const seen = new Set<PyClass>();
  while (queue.length > 0) {
    const current = queue.shift() as PyClass;
    if (seen.has(current)) continue;
    seen.add(current);
    chain.push(current);
    if (chain.length > 32 || current.bases === undefined) return 'unproven';
    for (const base of current.bases) {
      const next = followedBase(context, current, base);
      if (next === 'unproven') return 'unproven';
      if (next !== 'library') queue.push(next);
    }
  }
  let stored = false;
  let assigned = false;
  for (const member of chain) {
    const binding = leafBinding(member, leaf);
    if (binding === 'other') return 'unproven';
    if (binding === 'self') assigned = true;
    if (member.storedFields.has(leaf) && binding !== 'column') return 'unproven';
    if (binding === 'column') stored = true;
  }
  if (stored) return 'stored';
  return assigned ? 'unproven' : 'absent';
}

const QUERY_SHAPES: RegExp[] = [
  /^([A-Z]\w*)\s*\.\s*(?:query|objects)\b/,
  /^(?:[\w.]+\.)?(?:get_object_or_404|get_list_or_404|get_or_404|first_or_404|one_or_404)\s*\(\s*([A-Z]\w*)\b/,
  /^(?:[\w.]*session|db)\s*\.\s*(?:get|query)\s*\(\s*([A-Z]\w*)\b/,
  /^(?:[\w.]+\.)?(?:scalars|scalar|execute)\s*\(\s*(?:[\w.]+\.)?select\s*\(\s*([A-Z]\w*)\s*\)/,
  /^(?:[\w.]+\.)?select\s*\(\s*([A-Z]\w*)\s*\)/,
  /^([A-Z]\w*)\s*\(/,
];

function typeOf(context: Context, entry: FileMapEntry, line: number, expression: string, depth: number): PyClass | undefined {
  if (depth > 3) return undefined;
  const text = expression.trim();
  for (const shape of QUERY_SHAPES) {
    const m = shape.exec(text);
    if (m !== null) return projectClass(context, m[1] ?? '');
  }
  if (!/^[a-z_]\w*$/.test(text)) return undefined;
  const lines = maskedLines(entry.content);
  const scope = enclosingDef(lines, line);
  if (scope === undefined || scope.params.includes(text)) return undefined;
  const original = entry.content.split('\n');
  let found: PyClass | undefined;
  let any = false;
  for (let l = scope.defLine + 1; l <= scope.endLine; l += 1) {
    const code = lines[l - 1] ?? '';
    if (!new RegExp(`\\b${text}\\b`).test(code)) continue;
    if (new RegExp(`\\bfor\\s+[^\\n]*?\\b${text}\\b[^\\n]*?\\s+in\\b|\\bas\\s+\\(?\\s*${text}\\b|\\b(?:global|nonlocal)\\b[^\\n]*\\b${text}\\b|\\b${text}\\s*(?::=|[-+*/%|&^@]=|//=|>>=|<<=|\\*\\*=)`).test(code)) return undefined;
    const targets = /^\s*([\w\s,.*()[\]]+?)\s*=(?!=)/.exec(code)?.[1] ?? '';
    if (targets.includes(',') && new RegExp(`\\b${text}\\b`).test(targets)) return undefined;
    const bind = new RegExp(`^\\s*${text}\\s*(?::[^=]+)?=(?!=)\\s*`).exec(code);
    if (bind === null) continue;
    any = true;
    const value = (original[l - 1] ?? '').slice(bind[0].length).trim();
    const typed = typeOf(context, entry, l, value, depth + 1);
    if (typed === undefined || (found !== undefined && found !== typed)) return undefined;
    found = typed;
  }
  return any ? found : undefined;
}

function referencedByTemplates(context: Context, entry: FileMapEntry): boolean {
  return context.html.some((other) => {
    if (other === entry) return false;
    for (const m of other.content.matchAll(/\{%-?\s*(?:include|extends|import|from)\s+(?:[\w.]+\(\s*)?['"]([^'"]+)['"]/g)) {
      if (namesTemplate(entry.path, m[1] ?? '')) return true;
    }
    return false;
  });
}

function namesTemplate(path: string, name: string): boolean {
  const normal = path.replace(/\\/g, '/');
  return normal === name || normal.endsWith(`/${name}`);
}

export function templateReceiverClass(entries: FileMapEntry[], entry: FileMapEntry, index: number, root: string): PyClass | undefined {
  const context = contextOf(entries);
  if (context.dynamicTemplate) return undefined;
  const before = entry.content.slice(0, index);
  const opened = [...before.matchAll(/\{%-?\s*macro\b/g)].length;
  const closed = [...before.matchAll(/\{%-?\s*endmacro\b/g)].length;
  if (opened > closed) return undefined;
  if (new RegExp(`\\{%-?\\s*(?:set|with)\\b[^%]*\\b${root}\\b`).test(entry.content)) return undefined;
  let variable = root;
  const loops = [...before.matchAll(/\{%-?\s*for\s+([\w\s,]+?)\s+in\s+([^%]+?)\s*-?%\}/g)];
  const ends = [...before.matchAll(/\{%-?\s*endfor\b/g)].length;
  const open = loops.slice(0, Math.max(0, loops.length - ends));
  for (const loop of [...open].reverse()) {
    const targets = (loop[1] ?? '').split(',').map((t) => t.trim());
    if (!targets.includes(root)) continue;
    const source = (loop[2] ?? '').trim();
    if (targets.length !== 1 || !/^[A-Za-z_]\w*$/.test(source)) return undefined;
    variable = source;
    break;
  }
  if (referencedByTemplates(context, entry)) return undefined;
  const renders = context.renders.filter((call) => call.template !== undefined && namesTemplate(entry.path, call.template));
  if (renders.length === 0) return undefined;
  let found: PyClass | undefined;
  for (const call of renders) {
    const expression = call.bindings?.get(variable);
    const view = context.py.find((candidate) => candidate.path === call.file);
    if (expression === undefined || view === undefined) return undefined;
    const typed = typeOf(context, view, call.line, expression, 0);
    if (typed === undefined || (found !== undefined && found !== typed)) return undefined;
    found = typed;
  }
  return found;
}

export function pythonReceiverClass(entries: FileMapEntry[], entry: FileMapEntry, line: number, root: string): PyClass | undefined {
  const context = contextOf(entries);
  if (root === 'self') {
    const owners = (context.classes.size === 0 ? [] : [...context.classes.values()].flat())
      .filter((cls) => cls.file === entry.path && cls.start < line && cls.end >= line);
    return owners.sort((a, b) => b.start - a.start)[0];
  }
  return typeOf(context, entry, line, root, 0);
}

const sanitisedCache = new WeakMap<PyClass, Map<string, boolean>>();

export function classSanitises(cls: PyClass, leaf: string, sanitiser: RegExp): boolean {
  let byLeaf = sanitisedCache.get(cls);
  if (byLeaf === undefined) { byLeaf = new Map(); sanitisedCache.set(cls, byLeaf); }
  const cached = byLeaf.get(leaf);
  if (cached !== undefined) return cached;
  let result = false;
  for (const m of cls.body.matchAll(new RegExp(`\\bself\\.${leaf}\\s*=(?!=)\\s*([^\\n]{0,300})`, 'g'))) {
    if (sanitiser.test(m[1] ?? '')) result = true;
  }
  for (const def of cls.body.matchAll(new RegExp(`^([ \\t]*)(?:async\\s+)?def\\s+${leaf}\\s*\\(`, 'gm'))) {
    const indent = (def[1] ?? '').length;
    const rest = cls.body.slice((def.index ?? 0) + def[0].length).split('\n').slice(1);
    const body: string[] = [];
    for (const text of rest) {
      if (text.trim() !== '' && (/^[ \t]*/.exec(text)?.[0].length ?? 0) <= indent) break;
      body.push(text);
    }
    if (sanitiser.test(body.join('\n'))) result = true;
  }
  byLeaf.set(leaf, result);
  return result;
}
