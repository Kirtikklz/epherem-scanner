import {
  balanced,
  conditionals,
  middlewareBodyOf,
  stripComments,
} from './middlewareGuard.js';
import { blankNestedFunctions } from './handlerGuardCall.js';
import { entryFor, importedFrom, type ResolutionContext } from './importedVerifier.js';

export type { ResolutionContext } from './importedVerifier.js';

const BODY_SOURCE = String.raw`\(?\s*(?:await\s+)?\(?\s*(?:[A-Za-z_$][\w$]*\s*\.\s*)?(?:req|request)\s*\.\s*(?:json\s*\(\s*\)|body\b|formData\s*\(\s*\))`;

const BODY_ACCESSORS = ['req\\.body', 'request\\.body'];

export interface BodyBindings {
  readonly values: ReadonlySet<string>;
  readonly wholeBody: ReadonlySet<string>;
}

function collectDestructuredNames(inner: string, into: Set<string>): void {
  for (const part of inner.split(',')) {
    const trimmed = part.trim();
    if (trimmed === '') continue;
    const renamed = /^[\w$'"[\]]+\s*:\s*([A-Za-z_$][\w$]*)/.exec(trimmed);
    const plain = /^\.{0,3}\s*([A-Za-z_$][\w$]*)/.exec(trimmed);
    const name = renamed?.[1] ?? plain?.[1];
    if (name !== undefined) into.add(name);
  }
}

export function bodyBindings(scope: string): BodyBindings {
  const values = new Set<string>();
  const wholeBody = new Set<string>();
  let match: RegExpExecArray | null;

  const destructured = new RegExp(
    String.raw`(?:const|let|var)\s*\{([^{};]{0,400}?)\}\s*(?::[^=\n]{0,120})?=\s*${BODY_SOURCE}`,
    'g',
  );
  while ((match = destructured.exec(scope)) !== null) collectDestructuredNames(match[1] ?? '', values);

  const aliased = new RegExp(
    String.raw`(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]{0,120})?=\s*${BODY_SOURCE}`,
    'g',
  );
  while ((match = aliased.exec(scope)) !== null) {
    const name = match[1];
    if (name === undefined) continue;
    wholeBody.add(name);
    values.add(name);
  }

  for (let pass = 0; pass < 3; pass += 1) {
    const before = values.size;
    const reference = referencePattern(values);
    const assignment = /(?:(?:const|let|var)\s+([A-Za-z_$][\w$]*)|^\s*([A-Za-z_$][\w$]*))\s*(?::[^=\n]{0,120})?=\s*([^\n;]{0,300})/gm;
    while ((match = assignment.exec(scope)) !== null) {
      const name = match[1] ?? match[2];
      const rhs = match[3] ?? '';
      if (name === undefined || values.has(name)) continue;
      if (/^\s*await\b/.test(rhs)) continue;
      if (reference.test(withoutForeignLookups(rhs, values))) values.add(name);
    }
    const rebound = /(?:const|let|var)\s*\{([^{};]{0,400}?)\}\s*(?::[^=\n]{0,120})?=\s*([^\n;]{0,200})/g;
    while ((match = rebound.exec(scope)) !== null) {
      const rhs = match[2] ?? '';
      if (/^\s*await\b/.test(rhs)) continue;
      if (reference.test(withoutForeignLookups(rhs, values))) collectDestructuredNames(match[1] ?? '', values);
    }
    if (values.size === before) break;
  }
  return { values, wholeBody };
}

function withoutForeignLookups(text: string, names: ReadonlySet<string>): string {
  return text.replace(/([A-Za-z_$][\w$.]*)\s*\[([^\]]{0,120})\]/g, (whole, base: string, index: string) => {
    const root = base.split('.')[0] ?? '';
    if (names.has(root)) return whole;
    return ` ${' '.repeat(Math.max(0, index.length))} `;
  });
}

function referencePattern(names: Iterable<string>, extra: readonly string[] = []): RegExp {
  const alternatives = [...names].map((name) => name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).concat(extra);
  if (alternatives.length === 0) return /$^/;
  return new RegExp(`(?:^|[^\\w$.])(?:${alternatives.join('|')})\\b`);
}

export function stripStringLiterals(line: string): string {
  return line.replace(/'(?:[^'\\\n]|\\.)*'/g, "''").replace(/"(?:[^"\\\n]|\\.)*"/g, '""');
}

const BODY_CHECK =
  /\btypeof\b|\binstanceof\b|\bArray\.isArray\s*\(|\bNumber\.(?:isInteger|isFinite|isNaN|isSafeInteger)\s*\(|\bisNaN\s*\(|\bisFinite\s*\(|\.length\s*(?:>=|<=|>|<|===|!==|==|!=)|\.trim\s*\(\s*\)|\.(?:includes|has|indexOf|endsWith|startsWith|match)\s*\(|\.test\s*\(|\b\w*(?:isValid\w*|isAllowed\w*|is[A-Z]\w*Id|validate\w*|assert\w*|clean\w*|sanitiz\w*|normali[sz]e\w*|whole\w*|ensure\w*|check\w*)\s*\(|[!=]==?|!/;

const REJECTION = /(?:res|response)\s*\.\s*status\s*\(\s*4\d\d\s*\)|\bstatus\s*:\s*4\d\d\b|\bthrow\s/;

function withoutNestedGuardRejections(consequent: string): string {
  let out = consequent;
  const head = /\bif\s*\(/g;
  for (let guard = 0; guard < 32; guard += 1) {
    head.lastIndex = 0;
    const match = head.exec(out);
    if (match === null) break;
    const open = out.indexOf('(', match.index);
    if (open === -1) break;
    let depth = 0;
    let close = -1;
    for (let j = open; j < out.length; j += 1) {
      const char = out[j];
      if (char === '(') depth += 1;
      else if (char === ')') {
        depth -= 1;
        if (depth === 0) { close = j; break; }
      }
    }
    if (close === -1) {
      return `${out.slice(0, match.index)}${' '.repeat(out.length - match.index)}`;
    }
    const inner = guardConsequent(out, close + 1);
    const at = out.indexOf(inner, close + 1);
    const end = at === -1 ? close + 1 : at + inner.length;
    out = `${out.slice(0, match.index)}${' '.repeat(end - match.index)}${out.slice(end)}`;
  }
  return out;
}

function guardConsequent(scope: string, afterCondition: number): string {
  let i = afterCondition;
  while (i < scope.length && /\s/.test(scope[i] ?? '')) i += 1;
  if (scope[i] === '{') {
    let depth = 0;
    for (let j = i; j < Math.min(scope.length, i + 4000); j += 1) {
      const char = scope[j];
      if (char === '{') depth += 1;
      else if (char === '}') {
        depth -= 1;
        if (depth === 0) return scope.slice(i, j + 1);
      }
    }
    return scope.slice(i, Math.min(scope.length, i + 4000));
  }
  const semicolon = scope.indexOf(';', i);
  const end = semicolon === -1 ? Math.min(scope.length, i + 400) : Math.min(semicolon + 1, i + 400);
  return scope.slice(i, end);
}

export function manualBodyControl(scope: string, bindings: BodyBindings): boolean {
  const reference = referencePattern(bindings.values, BODY_ACCESSORS);
  const guard = /(?:^|[^\w$])(?:if|else\s+if)\s*\(/g;
  let match: RegExpExecArray | null;
  while ((match = guard.exec(scope)) !== null) {
    const open = scope.indexOf('(', match.index);
    if (open === -1) continue;
    let depth = 0;
    let close = -1;
    for (let j = open; j < Math.min(scope.length, open + 2000); j += 1) {
      const char = scope[j];
      if (char === '(') depth += 1;
      else if (char === ')') {
        depth -= 1;
        if (depth === 0) { close = j; break; }
      }
    }
    if (close === -1) continue;
    const condition = stripStringLiterals(scope.slice(open + 1, close));
    if (!reference.test(condition)) continue;
    if (!BODY_CHECK.test(condition)) continue;
    if (!REJECTION.test(withoutNestedGuardRejections(guardConsequent(scope, close + 1)))) continue;
    return true;
  }
  return false;
}

function balancedArguments(text: string, openIndex: number, limit = 6000): string {
  let depth = 0;
  const end = Math.min(text.length, openIndex + limit);
  for (let i = openIndex; i < end; i += 1) {
    const char = text[i];
    if (char === '(' || char === '[' || char === '{') depth += 1;
    else if (char === ')' || char === ']' || char === '}') {
      depth -= 1;
      if (depth === 0) return text.slice(openIndex + 1, i);
    }
  }
  return text.slice(openIndex + 1, end);
}

function templateLiterals(text: string): { raw: string; expressions: string[] }[] {
  const out: { raw: string; expressions: string[] }[] = [];
  let i = 0;
  while (i < text.length) {
    const start = text.indexOf('`', i);
    if (start === -1) break;
    let j = start + 1;
    let depth = 0;
    let expressionStart = -1;
    const expressions: string[] = [];
    while (j < text.length) {
      if (text[j] === '\\') { j += 2; continue; }
      if (text[j] === '$' && text[j + 1] === '{') {
        if (depth === 0) expressionStart = j + 2;
        depth += 1;
        j += 2;
        continue;
      }
      if (text[j] === '}' && depth > 0) {
        depth -= 1;
        if (depth === 0 && expressionStart >= 0) {
          expressions.push(text.slice(expressionStart, j));
          expressionStart = -1;
        }
        j += 1;
        continue;
      }
      if (text[j] === '`' && depth === 0) break;
      j += 1;
    }
    out.push({ raw: text.slice(start, Math.min(j + 1, text.length)), expressions });
    i = j + 1;
  }
  return out;
}

const MONGO_QUERY =
  /\.\s*(?:find|findOne|findOneAndUpdate|findOneAndDelete|findOneAndReplace|updateOne|updateMany|deleteOne|deleteMany|countDocuments|aggregate|distinct)\s*\(/g;
const SQL_CALL = /\b(?:query|execute|exec|raw|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(/;
const SQL_KEYWORD = /\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|WHERE|VALUES)\b/i;
const MARKUP_SINK = /\b(?:innerHTML|outerHTML|dangerouslySetInnerHTML|document\s*\.\s*write)\b/;
const HTML_TAG =
  /<(?:html|body|div|span|p|table|tr|td|th|h[1-6]|a|b|strong|em|li|ul|ol|img|br|hr|style|script|section|font|center)\b/i;
const SYSTEM_CHANNEL = /\b(?:system|instructions)\s*:|\brole\s*:\s*['"](?:system|developer)['"]/;
const SYSTEM_CHANNEL_BINDING =
  /(?:const|let|var)\s+(?:system\w*|instructions?)\s*(?::[^=\n]{0,80})?=\s*([^\n;]{0,400})/g;

const STORE_WRITE =
  /(?:^|[^\w$])[\w$.[\]'"]+\s*\.\s*(?:create|createMany|insert|insertOne|insertMany|save|update|updateOne|updateMany|updateByPk|upsert|replaceOne|findOneAndUpdate|findByIdAndUpdate|findOneAndReplace|bulkWrite|set)\s*\(/g;

export interface SinkOptions {
  readonly mongo: boolean;
}

export type DangerousSinkReason =
  | 'raw-query'
  | 'sql-interpolation'
  | 'sql-concatenation'
  | 'raw-markup'
  | 'html-interpolation'
  | 'model-system-prompt'
  | 'mass-assignment';

export const DANGEROUS_SINK_WORDING: Readonly<Record<DangerousSinkReason, { readonly plain: string; readonly technical: string }>> = {
  'raw-query': {
    plain: 'a submitted value can carry query operators into a database query filter',
    technical: 'a body value is placed in a Mongo query filter without being forced to a plain value (it can carry a query operator)',
  },
  'sql-interpolation': {
    plain: 'a submitted value reaches a raw database query',
    technical: 'a body value is interpolated into SQL text handed to a query call',
  },
  'sql-concatenation': {
    plain: 'a submitted value reaches a raw database query',
    technical: 'a body value is concatenated into SQL text handed to a query call',
  },
  'raw-markup': {
    plain: 'a submitted value is written into raw HTML',
    technical: 'a body value is written through a raw-markup sink such as innerHTML or dangerouslySetInnerHTML',
  },
  'html-interpolation': {
    plain: 'a submitted value is written into raw HTML',
    technical: 'a body value is interpolated unescaped into an HTML template string',
  },
  'model-system-prompt': {
    plain: "a submitted value is placed into an AI model's system instructions",
    technical: 'a body value is placed in the system or instructions channel of an outbound model call',
  },
  'mass-assignment': {
    plain: 'the whole submitted object is written to the data store',
    technical: 'the whole body object is passed into a data-store write (any field the caller adds is stored)',
  },
};

export function bodyReachesDangerousSink(scope: string, bindings: BodyBindings, options: SinkOptions): DangerousSinkReason[] {
  const valueReference = referencePattern(bindings.values, BODY_ACCESSORS);
  const wholeAlternatives = [...bindings.wholeBody, ...BODY_ACCESSORS];
  const reasons: DangerousSinkReason[] = [];
  let match: RegExpExecArray | null;

  if (options.mongo) {
    MONGO_QUERY.lastIndex = 0;
    while ((match = MONGO_QUERY.exec(scope)) !== null) {
      const argument = balancedArguments(scope, match.index + match[0].length - 1);
      const raw = argument
        .replace(/\$(?:eq|in|nin|all|size)\s*:\s*(?:\[[^\]]*\]|[^,}\]]+)/g, ' ')
        .replace(/\b(?:String|Number|Boolean|ObjectId|parseInt|parseFloat|Date)\s*\([^)]*\)/g, ' ')
        .replace(/[\w.$?[\]'"]+\s*\.\s*(?:toString|toLowerCase|toUpperCase|trim|normalizeEmail|toHexString)\s*\([^)]*\)/g, ' ');
      if (valueReference.test(raw)) { reasons.push('raw-query'); break; }
    }
  }
  if (SQL_CALL.test(scope)) {
    for (const template of templateLiterals(scope)) {
      if (!SQL_KEYWORD.test(template.raw)) continue;
      if (template.expressions.some((expression) => valueReference.test(expression))) {
        reasons.push('sql-interpolation');
        break;
      }
    }
    const concatenated = /["'][^"'\n]{0,200}?\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|VALUES)\b[^"'\n]{0,200}?["']\s*\+\s*([^\n;)]{0,120})/gi;
    while ((match = concatenated.exec(scope)) !== null) {
      if (valueReference.test(match[1] ?? '')) { reasons.push('sql-concatenation'); break; }
    }
  }
  if (MARKUP_SINK.test(scope)) {
    for (const raw of scope.split('\n')) {
      if (MARKUP_SINK.test(raw) && valueReference.test(raw)) { reasons.push('raw-markup'); break; }
    }
  }
  for (const template of templateLiterals(scope)) {
    if (!HTML_TAG.test(template.raw)) continue;
    if (template.expressions.some((expression) => valueReference.test(expression))) {
      reasons.push('html-interpolation');
      break;
    }
  }
  if (SYSTEM_CHANNEL.test(scope)) {
    for (const raw of scope.split('\n')) {
      const line = raw.trim();
      if (!SYSTEM_CHANNEL.test(line)) continue;
      const value = line.replace(/\brole\s*:\s*['"](?:system|developer)['"]\s*,?/, ' ');
      if (valueReference.test(value)) { reasons.push('model-system-prompt'); break; }
    }
  }
  SYSTEM_CHANNEL_BINDING.lastIndex = 0;
  while ((match = SYSTEM_CHANNEL_BINDING.exec(scope)) !== null) {
    if (valueReference.test(stripStringLiterals(match[1] ?? ''))) { reasons.push('model-system-prompt'); break; }
  }
  if (wholeAlternatives.length > 0) {
    const spread = new RegExp(`\\.\\.\\.\\s*(?:${wholeAlternatives.join('|')})\\b`);
    const bare = new RegExp(`^\\s*(?:${wholeAlternatives.join('|')})\\s*$`);
    const mongoSet = new RegExp(`\\$set(?:OnInsert)?\\s*:\\s*(?:\\{[^}]*\\.\\.\\.\\s*)?(?:${wholeAlternatives.join('|')})\\b`);
    if (mongoSet.test(scope)) reasons.push('mass-assignment');
    STORE_WRITE.lastIndex = 0;
    while ((match = STORE_WRITE.exec(scope)) !== null) {
      const argument = balancedArguments(scope, match.index + match[0].length - 1);
      if (spread.test(argument) || bare.test(argument) || mongoSet.test(argument)) {
        reasons.push('mass-assignment');
        break;
      }
    }
    if (/\.\s*save\s*\(/.test(scope)) {
      const constructed = /\bnew\s+[A-Z][\w$]*\s*\(/g;
      while ((match = constructed.exec(scope)) !== null) {
        const argument = balancedArguments(scope, match.index + match[0].length - 1);
        if (spread.test(argument) || bare.test(argument)) { reasons.push('mass-assignment'); break; }
      }
    }
    if (new RegExp(`Object\\.assign\\s*\\([^,)]{0,80},\\s*(?:${wholeAlternatives.join('|')})\\b`).test(scope)) {
      reasons.push('mass-assignment');
    }
  }
  return [...new Set(reasons)];
}

const MAX_HELPER_DEPTH = 4;
const MAX_HELPER_BODY = 8_000;
const MAX_HELPER_SCOPE = 40_000;

const FIELD_ENFORCEMENT =
  /\btypeof\b|\binstanceof\b|\bArray\.isArray\s*\(|\bNumber\.(?:isInteger|isFinite|isNaN|isSafeInteger)\s*\(|\bisNaN\s*\(|\bisFinite\s*\(|\.length\s*(?:>=|<=|>|<|===|!==|==|!=)|\.\s*(?:test|match|includes|has|startsWith|endsWith)\s*\(|\/[^/\n]{2,200}\/[gimsuy]*\s*\.\s*test\s*\(|(?:>=|<=|>|<)\s*[\w$.]|[\w$.]\s*(?:>=|<=|>|<)\s*\d/;

const FIELD_REJECTION =
  /\bthrow\b|\bfail\s*\(\s*4\d\d\b|(?:res|response)\s*\.\s*status\s*\(\s*4\d\d\s*\)|\bstatus\s*:\s*4\d\d\b|\berror\s*\(\s*4\d\d\b/;

const SUBJECT_SCHEMA_PARSE = /\.\s*(?:parse|parseAsync|validateSync|assert)\s*\(/;

function derivedFromSubject(code: string, subject: string): Set<string> {
  const names = new Set<string>([subject]);
  for (let pass = 0; pass < 3; pass += 1) {
    const before = names.size;
    const reference = referencePattern(names);
    const assignment = /(?:(?:const|let|var)\s+([A-Za-z_$][\w$]*)|^\s*([A-Za-z_$][\w$]*))\s*(?::[^=\n]{0,120})?=\s*([^\n;]{0,300})/gm;
    let match: RegExpExecArray | null;
    while ((match = assignment.exec(code)) !== null) {
      const name = match[1] ?? match[2];
      const rhs = match[3] ?? '';
      if (name === undefined || names.has(name)) continue;
      if (/^\s*await\b/.test(rhs)) continue;
      if (reference.test(withoutForeignLookups(rhs, names))) names.add(name);
    }
    const destructured = /(?:const|let|var)\s*\{([^{};]{0,400}?)\}\s*(?::[^=\n]{0,120})?=\s*([^\n;]{0,200})/g;
    while ((match = destructured.exec(code)) !== null) {
      const rhs = match[2] ?? '';
      if (/^\s*await\b/.test(rhs)) continue;
      if (reference.test(withoutForeignLookups(rhs, names))) collectDestructuredNames(match[1] ?? '', names);
    }
    if (names.size === before) break;
  }
  return names;
}

interface HelperDeclaration {
  readonly params: string[];
  readonly body: string;
}

function fieldHelperOf(content: string, name: string): HelperDeclaration | undefined {
  const body = middlewareBodyOf(content, name);
  if (body === undefined || body.length > MAX_HELPER_BODY) return undefined;
  const n = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const heads = [
    new RegExp(`(?:export\\s+)?(?:default\\s+)?(?:async\\s+)?function\\s*\\*?\\s+${n}\\s*\\(`),
    new RegExp(`(?:export\\s+)?(?:const|let|var)\\s+${n}\\s*(?::[^=\\n]{0,200})?=\\s*(?:async\\s+)?function\\s*\\*?\\s*\\(`),
    new RegExp(`(?:export\\s+)?(?:const|let|var)\\s+${n}\\s*(?::[^=\\n]{0,200})?=\\s*(?:async\\s*)?\\(`),
    new RegExp(`(?:public|private|protected|static|async)\\s+(?:[A-Za-z]+\\s+)*${n}\\s*\\(`),
  ];
  for (const head of heads) {
    const match = head.exec(content);
    if (match?.index === undefined) continue;
    const open = content.indexOf('(', match.index + match[0].length - 1);
    if (open === -1) continue;
    const list = balanced(content, open, '(', ')', MAX_HELPER_BODY);
    if (list === undefined) continue;
    return { params: parameterNames(list.inner), body };
  }
  const single = new RegExp(
    `(?:export\\s+)?(?:const|let|var)\\s+${n}\\s*(?::[^=\\n]{0,200})?=\\s*(?:async\\s*)?([A-Za-z_$][\\w$]*)\\s*=>`,
  ).exec(content);
  if (single?.[1] !== undefined) return { params: [single[1]], body };
  return undefined;
}

function parameterNames(list: string): string[] {
  const names: string[] = [];
  let depth = 0;
  let start = 0;
  const parts: string[] = [];
  for (let i = 0; i < list.length; i += 1) {
    const ch = list[i] ?? '';
    if (ch === '{' || ch === '(' || ch === '[' || ch === '<') depth += 1;
    else if (ch === '}' || ch === ')' || ch === ']' || ch === '>') depth -= 1;
    else if (ch === ',' && depth === 0) { parts.push(list.slice(start, i)); start = i + 1; }
  }
  parts.push(list.slice(start));
  for (const part of parts) {
    const trimmed = part.trim().replace(/^\.\.\./, '');
    const plain = /^([A-Za-z_$][\w$]*)/.exec(trimmed);
    names.push(plain?.[1] ?? '');
  }
  return names;
}

const fieldHelperCache = new WeakMap<object, Map<string, boolean>>();

function fieldCacheFor(resolution: ResolutionContext): Map<string, boolean> {
  let cache = fieldHelperCache.get(resolution);
  if (cache === undefined) {
    cache = new Map();
    fieldHelperCache.set(resolution, cache);
  }
  return cache;
}

function helperValidates(
  resolution: ResolutionContext,
  filePath: string,
  name: string,
  position: number,
  depth: number,
  visited: Set<string>,
): boolean {
  if (depth > MAX_HELPER_DEPTH) return false;
  const key = `${filePath}::${name}::${position}`;
  if (visited.has(key)) return false;
  visited.add(key);
  const cache = fieldCacheFor(resolution);
  const cached = cache.get(key);
  if (cached !== undefined) return cached;

  const definedIn = importedFrom(resolution, filePath, name);
  const searchPaths = definedIn === undefined ? [filePath] : [definedIn, filePath];
  let verdict = false;
  for (const path of searchPaths) {
    const entry = entryFor(resolution, path);
    if (entry === undefined) continue;
    const declaration = fieldHelperOf(entry.content, name);
    if (declaration === undefined) continue;
    const subject = declaration.params[position] ?? declaration.params[0] ?? '';
    if (subject === '') continue;
    if (classifyFieldHelper(resolution, path, declaration.body, subject, depth, visited)) {
      verdict = true;
      break;
    }
  }
  cache.set(key, verdict);
  return verdict;
}

function classifyFieldHelper(
  resolution: ResolutionContext,
  filePath: string,
  rawBody: string,
  subject: string,
  depth: number,
  visited: Set<string>,
): boolean {
  const code = blankNestedFunctions(stripComments(rawBody));
  const subjects = derivedFromSubject(code, subject);
  const subjectReference = referencePattern(subjects);

  for (const item of conditionals(code)) {
    if (item.depth !== 0) continue;
    const condition = stripStringLiterals(item.condition);
    if (!subjectReference.test(condition)) continue;
    if (!FIELD_ENFORCEMENT.test(condition)) continue;
    if (!FIELD_REJECTION.test(item.consequent)) continue;
    return true;
  }

  for (const call of callsWithin(code)) {
    if (!SUBJECT_SCHEMA_PARSE.test(call.callee)) continue;
    if (PARSE_NOT_VALIDATION.test(call.callee)) continue;
    if (subjectReference.test(stripStringLiterals(call.args))) return true;
  }

  if (depth >= MAX_HELPER_DEPTH) return false;
  for (const call of callsWithin(blankConditionalConsequents(code))) {
    const name = calleeName(call.callee);
    if (name === undefined || name === subject) continue;
    const position = argumentPositionMatching(call.args, subjectReference);
    if (position === -1) continue;
    if (helperValidates(resolution, filePath, name, position, depth + 1, visited)) return true;
  }
  return false;
}

const PARSE_NOT_VALIDATION =
  /\b(?:JSON|Date|URL|url|qs|querystring|Number|path|yaml|YAML|toml|ini|semver|cookie|jwt|jsonwebtoken|jose|Papa|papaparse)\s*\.\s*(?:parse|parseAsync)\s*$/;

function blankConditionalConsequents(code: string): string {
  let out = code;
  for (const item of conditionals(code)) {
    const at = out.indexOf(item.consequent, item.conditionIndex);
    if (at === -1) continue;
    out = `${out.slice(0, at)}${' '.repeat(item.consequent.length)}${out.slice(at + item.consequent.length)}`;
  }
  return out;
}

interface CallSite {
  readonly callee: string;
  readonly args: string;
  readonly index: number;
}

function callsWithin(code: string): CallSite[] {
  const calls: CallSite[] = [];
  const pattern = /\b([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\(/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(code)) !== null) {
    const callee = match[1];
    if (callee === undefined) continue;
    const last = callee.split('.').map((part) => part.trim()).pop() ?? '';
    if (CALL_KEYWORDS.has(last)) continue;
    const open = match.index + match[0].length - 1;
    calls.push({ callee, args: balancedArguments(code, open, MAX_HELPER_BODY), index: match.index });
    if (calls.length > 400) break;
  }
  return calls;
}

const CALL_KEYWORDS = new Set([
  'if', 'for', 'while', 'switch', 'catch', 'return', 'throw', 'typeof', 'await',
  'function', 'new', 'delete', 'void', 'do', 'else', 'try', 'yield', 'instanceof', 'in',
]);

function calleeName(callee: string): string | undefined {
  const segments = callee.split('.').map((part) => part.trim()).filter((part) => part !== '');
  if (segments.length !== 1) return undefined;
  const name = segments[0];
  return name === undefined || CALL_KEYWORDS.has(name) ? undefined : name;
}

function argumentPositionMatching(args: string, reference: RegExp): number {
  let depth = 0;
  let start = 0;
  const parts: string[] = [];
  for (let i = 0; i < args.length; i += 1) {
    const ch = args[i] ?? '';
    if (ch === '{' || ch === '(' || ch === '[') depth += 1;
    else if (ch === '}' || ch === ')' || ch === ']') depth -= 1;
    else if (ch === ',' && depth === 0) { parts.push(args.slice(start, i)); start = i + 1; }
  }
  parts.push(args.slice(start));
  for (let i = 0; i < parts.length; i += 1) {
    if (reference.test(stripStringLiterals(parts[i] ?? ''))) return i;
  }
  return -1;
}

export function fieldHelperValidated(
  scope: string,
  bindings: BodyBindings,
  resolution: ResolutionContext,
  filePath: string,
): Set<string> {
  const validated = new Set<string>();
  if (scope === '' || scope.length > MAX_HELPER_SCOPE) return validated;
  const reference = referencePattern(bindings.values, BODY_ACCESSORS);
  const code = stripComments(scope);
  for (const call of callsWithin(code)) {
    const name = calleeName(call.callee);
    if (name === undefined) continue;
    const position = argumentPositionMatching(call.args, reference);
    if (position === -1) continue;
    if (!helperValidates(resolution, filePath, name, position, 0, new Set())) continue;
    for (const bound of boundLocals(code, call.index)) validated.add(bound);
    validated.add(`${name}()`);
  }
  return validated;
}

function boundLocals(code: string, index: number): string[] {
  const head = code.slice(Math.max(0, index - 260), index);
  const declaration = /(?:const|let|var)\s+(\{[^{}=]{0,200}\}|[A-Za-z_$][\w$]*)\s*(?::[^=\n]{0,160})?=\s*(?:await\s+)?$/.exec(head);
  const target = declaration?.[1];
  if (target === undefined) return [];
  if (!target.startsWith('{')) return [target];
  const set = new Set<string>();
  collectDestructuredNames(target.slice(1, -1), set);
  return [...set];
}

function unvalidatedValueReachesWrite(
  scope: string,
  bindings: BodyBindings,
  validated: ReadonlySet<string>,
): boolean {
  const residual = [...bindings.values].filter((name) => !validated.has(name));
  if (residual.length === 0) return false;
  const reference = referencePattern(residual, BODY_ACCESSORS);
  STORE_WRITE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = STORE_WRITE.exec(scope)) !== null) {
    const argument = balancedArguments(scope, match.index + match[0].length - 1);
    if (reference.test(stripStringLiterals(argument))) return true;
  }
  return false;
}

export interface HelperResolutionInput {
  readonly resolution: ResolutionContext;
  readonly filePath: string;
}

export function manualControlWithoutDangerousSink(
  scope: string,
  options: SinkOptions,
  helper?: HelperResolutionInput,
): { suppress: boolean; sinks: DangerousSinkReason[]; credit: 'guard' | 'field-helper' | 'none' } {
  const bindings = bodyBindings(scope);
  let credit: 'guard' | 'field-helper' | 'none' = 'none';
  if (manualBodyControl(scope, bindings)) {
    credit = 'guard';
  } else if (helper !== undefined) {
    const validated = fieldHelperValidated(scope, bindings, helper.resolution, helper.filePath);
    if (validated.size > 0 && !unvalidatedValueReachesWrite(scope, bindings, validated)) {
      credit = 'field-helper';
    }
  }
  if (credit === 'none') return { suppress: false, sinks: [], credit };
  const sinks = bodyReachesDangerousSink(scope, bindings, options);
  return { suppress: sinks.length === 0, sinks, credit };
}
