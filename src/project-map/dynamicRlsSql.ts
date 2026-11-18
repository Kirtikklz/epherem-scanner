export interface DynamicSqlStatement {
  sql: string;
  line: number;
  arrayLine: number;
  element: string;
  templateStart: number;
  templateEnd: number;
}

const MAX_LOOP_BODY = 20_000;
const MAX_ARRAY_TEXT = 8_000;
const MAX_ELEMENTS = 500;

const FOREACH_LOOP = new RegExp(
  String.raw`\bFOREACH\s+([A-Za-z_]\w*)\s+IN\s+ARRAY\s+(ARRAY\s*\[([\s\S]{0,${MAX_ARRAY_TEXT}}?)\]|[A-Za-z_]\w*)\s+LOOP\b([\s\S]{0,${MAX_LOOP_BODY}}?)\bEND\s+LOOP\b`,
  'gi',
);

const EXECUTE_FORMAT = /\bEXECUTE\s+format\s*\(\s*'/gi;

function lineOfIndex(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i += 1) if (content[i] === '\n') line += 1;
  return line;
}

function arrayElements(body: string): string[] | undefined {
  const items = body
    .split(',')
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
  if (items.length === 0 || items.length > MAX_ELEMENTS) return undefined;
  const out: string[] = [];
  for (const item of items) {
    const literal = /^'((?:[^']|'')*)'(?:\s*::\s*\w+)?$/.exec(item);
    if (literal === null) return undefined;
    out.push((literal[1] ?? '').replace(/''/g, "'"));
  }
  return out;
}

function declaredArray(
  content: string,
  name: string,
  before: number,
  readElements: (body: string) => string[] | undefined = arrayElements,
): { elements: string[]; index: number } | undefined {
  const escaped = name.replace(/[^\w]/g, '');
  const declaration = new RegExp(
    String.raw`\b${escaped}\s+(?:text|varchar|character\s+varying|name)\s*\[\s*\]\s*(?::=|=|DEFAULT)\s*ARRAY\s*\[([\s\S]{0,${MAX_ARRAY_TEXT}}?)\]`,
    'gi',
  );
  let found: { elements: string[]; index: number } | undefined;
  for (const match of content.slice(0, before).matchAll(declaration)) {
    const elements = readElements(match[1] ?? '');
    found = elements === undefined ? undefined : { elements, index: match.index ?? 0 };
  }
  return found;
}

function readQuoted(text: string, start: number): { value: string; end: number } | undefined {
  let value = '';
  for (let i = start; i < text.length; i += 1) {
    const char = text[i];
    if (char !== "'") {
      value += char;
      continue;
    }
    if (text[i + 1] === "'") {
      value += "'";
      i += 1;
      continue;
    }
    return { value, end: i + 1 };
  }
  return undefined;
}

function quoteIdentifier(name: string): string {
  return /^[a-z_][a-z0-9_$]*$/.test(name) ? name : `"${name.replace(/"/g, '""')}"`;
}

export function renderFormat(template: string, argCount: number, value: string): string | undefined {
  let out = '';
  let next = 0;
  for (let i = 0; i < template.length; i += 1) {
    const char = template[i];
    if (char !== '%') {
      out += char;
      continue;
    }
    const spec = /^%(?:(\d+)\$)?([sIL%])/.exec(template.slice(i));
    if (spec === null) return undefined;
    i += spec[0].length - 1;
    const type = spec[2];
    if (type === '%') {
      out += '%';
      continue;
    }
    const position = spec[1] !== undefined ? Number(spec[1]) : (next += 1);
    if (spec[1] !== undefined) next = position;
    if (position < 1 || position > argCount) return undefined;
    if (type === 's') out += value;
    else if (type === 'I') out += quoteIdentifier(value);
    else out += `'${value.replace(/'/g, "''")}'`;
  }
  return out;
}

export interface PolicySweep {
  line: number;
  start: number;
  end: number;
  tables: string[] | undefined;
  keep: string[] | undefined;
  decidable: boolean;
}

const PG_POLICIES_LOOP = new RegExp(
  String.raw`\bFOR\s+([A-Za-z_]\w*)\s+IN\s+SELECT\b[\s\S]{0,2000}?\bFROM\s+pg_policies\b([\s\S]{0,4000}?)\bLOOP\b([\s\S]{0,${MAX_LOOP_BODY}}?)\bEND\s+LOOP\b`,
  'gi',
);

function keepListElements(body: string): string[] | undefined {
  return arrayElements(body.replace(/--[^\n]*/g, ' '));
}

function arrayOperand(content: string, operand: string, before: number): string[] | undefined {
  const literal = /^ARRAY\s*\[([\s\S]*)\]$/i.exec(operand.trim());
  if (literal !== null) return keepListElements(literal[1] ?? '');
  const name = /^[A-Za-z_]\w*$/.exec(operand.trim())?.[0];
  return name === undefined ? undefined : declaredArray(content, name, before, keepListElements)?.elements;
}

export function findPolicySweeps(content: string): PolicySweep[] {
  if (!/\bpg_policies\b/i.test(content)) return [];
  const sweeps: PolicySweep[] = [];
  for (const loop of content.matchAll(PG_POLICIES_LOOP)) {
    const variable = loop[1] ?? '';
    const body = loop[3] ?? '';
    const drop = new RegExp(
      String.raw`\bEXECUTE\s+format\s*\(\s*'\s*DROP\s+POLICY\b[^']*'\s*,\s*${variable}\s*\.\s*policyname\b`,
      'i',
    );
    if (!drop.test(body)) continue;
    const start = loop.index ?? 0;
    const where = (loop[2] ?? '').replace(/--[^\n]*/g, ' ').trim();
    let tables: string[] | undefined;
    let keep: string[] = [];
    let decidable = /^WHERE\b/i.test(where);
    const conjuncts = where.replace(/^WHERE\b/i, '').split(/\bAND\b/i).map((part) => part.trim());
    for (const conjunct of conjuncts) {
      if (/^schemaname\s*=\s*'public'$/i.test(conjunct)) continue;
      const one = /^tablename\s*=\s*'([^']+)'$/i.exec(conjunct);
      const list = /^tablename\s+IN\s*\(([^)]*)\)$/i.exec(conjunct);
      if (one !== null || list !== null) {
        const named = one !== null ? [one[1] ?? ''] : arrayElements(list?.[1] ?? '');
        if (named === undefined) decidable = false;
        else tables = [...(tables ?? []), ...named.map((table) => table.toLowerCase())];
        continue;
      }
      const kept =
        /^NOT\s*\(\s*policyname\s*=\s*ANY\s*\(\s*([\s\S]+?)\s*\)\s*\)$/i.exec(conjunct) ??
        /^policyname\s*<>\s*ALL\s*\(\s*([\s\S]+?)\s*\)$/i.exec(conjunct);
      const notIn = /^policyname\s+NOT\s+IN\s*\(([^)]*)\)$/i.exec(conjunct);
      const names =
        kept !== null ? arrayOperand(content, kept[1] ?? '', start) : notIn !== null ? arrayElements(notIn[1] ?? '') : undefined;
      if ((kept !== null || notIn !== null) && names !== undefined) {
        keep = [...keep, ...names];
        continue;
      }
      decidable = false;
    }
    if (tables === undefined) decidable = false;
    sweeps.push({
      line: lineOfIndex(content, start),
      start,
      end: start + loop[0].length,
      tables,
      keep: decidable ? keep : undefined,
      decidable,
    });
  }
  return sweeps;
}

export function expandDynamicRlsStatements(content: string): DynamicSqlStatement[] {
  if (!/\bFOREACH\b/i.test(content) || !/\bformat\s*\(/i.test(content)) return [];
  const statements: DynamicSqlStatement[] = [];
  for (const loop of content.matchAll(FOREACH_LOOP)) {
    const loopIndex = loop.index ?? 0;
    const variable = (loop[1] ?? '').toLowerCase();
    let elements: string[] | undefined;
    let arrayIndex = loopIndex;
    if (loop[3] !== undefined) {
      elements = arrayElements(loop[3]);
    } else {
      const declared = declaredArray(content, loop[2] ?? '', loopIndex);
      elements = declared?.elements;
      if (declared !== undefined) arrayIndex = declared.index;
    }
    if (elements === undefined) continue;
    const arrayLine = lineOfIndex(content, arrayIndex);

    const body = loop[4] ?? '';
    const bodyStart = loopIndex + (loop[0].length - body.length - (/\bEND\s+LOOP\b$/i.exec(loop[0])?.[0].length ?? 0));
    for (const call of body.matchAll(EXECUTE_FORMAT)) {
      const afterQuote = (call.index ?? 0) + call[0].length;
      const template = readQuoted(body, afterQuote);
      if (template === undefined) continue;
      const rest = /^\s*((?:,\s*[A-Za-z_]\w*\s*)*)\)/.exec(body.slice(template.end));
      if (rest === null) continue;
      const args = (rest[1] ?? '')
        .split(',')
        .map((arg) => arg.trim().toLowerCase())
        .filter((arg) => arg.length > 0);
      if (args.length === 0 || args.some((arg) => arg !== variable)) continue;
      const line = lineOfIndex(content, bodyStart + (call.index ?? 0));
      for (const element of elements) {
        const rendered = renderFormat(template.value, args.length, element);
        if (rendered === undefined) break;
        const sql = /;\s*$/.test(rendered) ? rendered : `${rendered};`;
        statements.push({
          sql,
          line,
          arrayLine,
          element,
          templateStart: bodyStart + afterQuote,
          templateEnd: bodyStart + template.end - 1,
        });
      }
    }
  }
  return statements;
}
