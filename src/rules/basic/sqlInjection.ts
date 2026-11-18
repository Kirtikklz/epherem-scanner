import { analyzeFileAst, astVerdict, confidenceWithProof, userTaintedLines } from '../../ast/astAnalysis.js';
import { crossFileAstHits } from '../../ast/crossFileTaint.js';
import { makeFinding } from '../../shared/findingFactory.js';
import type { FileMapEntry, Finding, RuleContext, ScanRule } from '../../shared/types.js';
import { findMatches, lineAt } from '../../shared/utils.js';
import { windowAround } from '../../shared/userInput.js';
import { analyzeTaint, usesUserInput, type TaintMap } from '../../shared/taint.js';
import { jsHelperCalls, projectSqlHelpers, pythonHelperCalls } from '../../shared/sqlHelpers.js';
import { stripCommentsAndStrings } from '../../shared/source.js';
import { pythonSqlFromConstantFragments } from '../../shared/pythonSql.js';
import { pythonCallArguments, pythonDependencyAliases, pythonMasked, pythonValueReaches, type FollowOptions } from '../../shared/pythonFlow.js';

const CODE_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py']);

const JS_SQL_CONCAT =
  /(?:query|execute|exec|raw|prepare)\s*\(\s*(`[^`]*\$\{[^`]*`|['"][^'"]*['"]\s*\+[^;)]+)/gi;
const JS_TEMPLATE_SQL =
  /`\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|WHERE|FROM)\b[^`]*\$\{[^`]*`/gi;
const JS_JOINED_SQL_TEXT = /"\s*(?:SELECT|INSERT|UPDATE|DELETE)\b[^"\n]*"\s*\+|'\s*(?:SELECT|INSERT|UPDATE|DELETE)\b[^'\n]*'\s*\+/gi;
const PY_SQL_FSTRING =
  /(?:execute|executemany)\s*\(\s*f?["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*(?:\{|%s?\s*%|["']\s*[+%])/gi;

const SQL_VERBS = /\b(?:SELECT|INSERT|UPDATE|DELETE|UPSERT|DROP|ALTER|CREATE|WITH|FROM|WHERE)\b/i;
const SQL_SINK_LINE = /(?:\b(?:db|pool|client|conn|connection|database|knex|sequelize|prisma|sql|drizzle|dataSource|repository|repo|entityManager|manager)\s*\.\s*(?:query|execute|raw)\s*\(|\$queryRawUnsafe\s*\(|\$executeRawUnsafe\s*\(|\b(?:cursor|conn|connection)\s*\.\s*(?:execute|executemany)\s*\()/i;
const DYNAMIC_SQL_TEXT = /`[^`]*\$\{|['"][^'"]*['"]\s*\+|\+\s*['"]|\b(?:req|request)\.(?:body|query|params)\b|searchParams\.get\s*\(/i;

function pythonQueryTextReaches(content: string, callIndex: number, opts: FollowOptions): boolean {
  const open = content.indexOf('(', callIndex);
  if (open < 0) return false;
  const first = pythonCallArguments(content, open).find((a) => a.keyword === undefined);
  return first !== undefined && pythonValueReaches(content, first.start, first.end, opts);
}

const PY_DB_EXECUTE = /(?<![\w.])((?:[A-Za-z_]\w*\s*\.\s*)*)(execute|executemany|exec_driver_sql)\s*\(/g;
const PY_DB_RECEIVER = /(?:^|\.)\s*(?:cursor|cur|conn|connection|con|db|session|engine|database|\w+_session|\w+_cursor|\w+_conn)\s*\.\s*$/i;
const PY_EXTRA = /\.\s*extra\s*\(/g;
const PY_MANAGER_CALL = /\bobjects\s*(?:\.\s*\w+\s*\([^()]*\)\s*)*\.\s*\w+\s*\(/g;
const SQL_STATEMENT_TEXT = /\b(?:SELECT\b[\s\S]*\bFROM|INSERT\s+INTO|UPDATE\b[\s\S]*\bSET|DELETE\s+FROM)\b/i;

function pythonSqlSinks(content: string, opts: FollowOptions): { index: number; line: number }[] {
  const masked = pythonMasked(content);
  const out: { index: number; line: number }[] = [];
  const add = (index: number): void => { out.push({ index, line: lineNumberAt(content, index) }); };
  for (const m of masked.matchAll(PY_DB_EXECUTE)) {
    if (m.index === undefined || !PY_DB_RECEIVER.test(m[1] ?? '')) continue;
    const at = m.index + (m[1] ?? '').length;
    if (pythonQueryTextReaches(content, at, opts)) add(at);
  }
  for (const m of masked.matchAll(PY_EXTRA)) {
    if (m.index === undefined) continue;
    const open = m.index + m[0].length - 1;
    const sqlArgs = pythonCallArguments(content, open).filter((a) => a.keyword !== undefined && /^(?:where|select|tables|order_by)$/.test(a.keyword));
    if (sqlArgs.some((a) => pythonValueReaches(content, a.start, a.end, opts))) add(m.index + m[0].indexOf('extra'));
  }
  for (const m of masked.matchAll(PY_MANAGER_CALL)) {
    if (m.index === undefined) continue;
    const open = m.index + m[0].length - 1;
    const first = pythonCallArguments(content, open).find((a) => a.keyword === undefined);
    if (first === undefined || !SQL_STATEMENT_TEXT.test(content.slice(first.start, first.end))) continue;
    if (pythonValueReaches(content, first.start, first.end, opts)) add(m.index + m[0].lastIndexOf('.') + 1);
  }
  return out;
}

function helperSqlSinks(context: RuleContext, entry: FileMapEntry, taint: TaintMap): { index: number; line: number; helper: string }[] {
  const helpers = projectSqlHelpers(context.fileMap.entries);
  const out: { index: number; line: number; helper: string }[] = [];
  const nameAt = (index: number): string => /^[A-Za-z_$][\w$]*/.exec(entry.content.slice(index))?.[0] ?? 'helper';
  if (entry.extension === '.py') {
    const opts = { aliases: pythonDependencyAliases(context.fileMap.entries) };
    for (const index of pythonHelperCalls(entry, helpers.py)) {
      if (!pythonFirstArgumentIsSql(entry.content, index)) continue;
      if (!pythonQueryTextReaches(entry.content, index, opts)) continue;
      if (pythonSqlFromConstantFragments(entry.content, index)) continue;
      out.push({ index, line: lineNumberAt(entry.content, index), helper: nameAt(index) });
    }
    return out;
  }
  if (!JS_HELPER_EXTENSIONS.has(entry.extension)) return out;
  const code = stripCommentsAndStrings(entry.content);
  for (const index of jsHelperCalls(entry, helpers.js)) {
    const open = entry.content.indexOf('(', index);
    if (open < 0) continue;
    const arg = jsFirstArgument(entry.content, code, open).trim();
    if (!jsArgumentIsDynamicSql(entry.content, arg, index)) continue;
    if (!usesUserInput(windowAround(entry.content, index, 360), taint, index)) continue;
    out.push({ index, line: lineNumberAt(entry.content, index), helper: nameAt(index) });
  }
  return out;
}

const JS_HELPER_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);

function jsFirstArgument(content: string, code: string, open: number): string {
  let depth = 0;
  for (let i = open; i < Math.min(code.length, open + 2000); i += 1) {
    const c = code[i];
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === ']' || c === '}') {
      depth -= 1;
      if (depth === 0) return content.slice(open + 1, i);
    } else if (c === ',' && depth === 1) return content.slice(open + 1, i);
  }
  return '';
}

function jsArgumentIsDynamicSql(content: string, arg: string, callIndex: number): boolean {
  if (SQL_STATEMENT_TEXT.test(arg) && DYNAMIC_SQL_TEXT.test(arg)) return true;
  const ident = /^[A-Za-z_$][\w$]*$/.exec(arg)?.[0];
  if (ident === undefined) return false;
  const escaped = ident.replace(/[$]/g, '\\$&');
  let bound: string | undefined;
  for (const m of content.slice(0, callIndex).matchAll(new RegExp(`(?:\\b(?:const|let|var)\\s+|(?<![\\w$.])(?=${escaped}\\s*=[^=]))${escaped}\\s*(?::[^=;]+)?=\\s*([\\s\\S]{0,500}?);`, 'g'))) {
    bound = m[1];
  }
  return bound !== undefined && SQL_STATEMENT_TEXT.test(bound) && DYNAMIC_SQL_TEXT.test(bound);
}

function pythonFirstArgumentIsSql(content: string, callIndex: number): boolean {
  const open = content.indexOf('(', callIndex);
  if (open < 0) return false;
  const first = pythonCallArguments(content, open).find((a) => a.keyword === undefined);
  if (first === undefined) return false;
  const text = content.slice(first.start, first.end).trim();
  if (SQL_STATEMENT_TEXT.test(text)) return true;
  if (!/^[A-Za-z_]\w*$/.test(text)) return false;
  const lines = content.slice(0, callIndex).split('\n');
  for (let i = lines.length - 1; i >= Math.max(0, lines.length - 80); i -= 1) {
    if (new RegExp(`^\\s*${text}\\s*=[^=]`).test(lines[i] ?? '')) {
      return SQL_STATEMENT_TEXT.test(content.split('\n').slice(i, i + 4).join('\n'));
    }
  }
  return false;
}

function sinkOpensOnTheLineBefore(content: string, line: number): boolean {
  for (let previous = line - 1; previous >= Math.max(1, line - 2); previous -= 1) {
    const text = lineAt(content, previous);
    if (text.trim() === '') continue;
    return SQL_SINK_LINE.test(text) && /\(\s*$/.test(text);
  }
  return false;
}

function hasSqlFindingInvariant(line: string): boolean {
  return SQL_SINK_LINE.test(line) && SQL_VERBS.test(line);
}

function lineStarts(content: string): number[] {
  const starts = [0];
  for (let i = 0; i < content.length; i += 1) if (content.charCodeAt(i) === 10) starts.push(i + 1);
  return starts;
}

function lineNumberAt(content: string, index: number): number {
  const starts = lineStarts(content);
  let low = 0;
  let high = starts.length - 1;
  while (low <= high) {
    const mid = Math.floor((low + high) / 2);
    const start = starts[mid] ?? 0;
    const next = starts[mid + 1] ?? Number.POSITIVE_INFINITY;
    if (index < start) high = mid - 1;
    else if (index >= next) low = mid + 1;
    else return mid + 1;
  }
  return 1;
}

function firstCallArg(line: string): string | undefined {
  const open = line.indexOf('(');
  if (open === -1) return undefined;
  return /^\s*([A-Za-z_$][\w$]*)\b/.exec(line.slice(open + 1))?.[1];
}

function resolvedSqlEvidence(content: string, sinkLine: number): { line: number; text: string } | undefined {
  const sourceLine = lineAt(content, sinkLine);
  if (hasSqlFindingInvariant(sourceLine)) return { line: sinkLine, text: sourceLine };
  if (!SQL_SINK_LINE.test(sourceLine)) return undefined;
  const ident = firstCallArg(sourceLine);
  if (ident === undefined) return undefined;
  const escaped = ident.replace(/[$]/g, '\\$&');
  const sinkIndex = content.indexOf(sourceLine);
  const declarations = [
    new RegExp(`\\b(?:const|let|var)\\s+${escaped}\\s*(?::[^=;]+)?=\\s*([\\s\\S]{0,500}?);`, 'g'),
    new RegExp(`\\b${escaped}\\s*=\\s*([\\s\\S]{0,500}?);`, 'g'),
  ];
  for (const pattern of declarations) {
    for (const match of content.matchAll(pattern)) {
      const text = match[0] ?? '';
      if (match.index === undefined || (sinkIndex !== -1 && match.index > sinkIndex)) continue;
      if (!SQL_VERBS.test(text) || !DYNAMIC_SQL_TEXT.test(text)) continue;
      return { line: lineNumberAt(content, match.index), text: text.split(/\r?\n/)[0]?.trim() ?? text.trim() };
    }
  }
  const fnPattern = new RegExp(`function\\s+${escaped}\\s*\\([^)]*\\)\\s*\\{([\\s\\S]{0,800}?)\\}`, 'g');
  for (const match of content.matchAll(fnPattern)) {
    const body = match[1] ?? '';
    if (match.index === undefined || (sinkIndex !== -1 && match.index > sinkIndex)) continue;
    if (SQL_VERBS.test(body) && /return[\s\S]{0,180}(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+)/i.test(body)) {
      return { line: lineNumberAt(content, match.index), text: (match[0] ?? '').split(/\r?\n/)[0]?.trim() ?? ident };
    }
  }
  return undefined;
}

export const sqlInjection: ScanRule = {
  id: 'sql_injection',
  title: 'Possible SQL injection from unsafe query construction',
  category: 'injection',
  kind: 'basic',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    for (const entry of context.fileMap.entries) {
      if (!CODE_EXTENSIONS.has(entry.extension)) continue;
      const taint = analyzeTaint(entry.content);
      const ast = analyzeFileAst(entry.path, entry.content, entry.extension, crossFileAstHits(context.projectMap.crossFileTaint, entry.path));
      const seen = new Set<number>();
      for (const pattern of [JS_SQL_CONCAT, JS_TEMPLATE_SQL, PY_SQL_FSTRING, JS_JOINED_SQL_TEXT]) {
        for (const match of findMatches(entry.content, pattern)) {
          if (seen.has(match.line)) continue;
          const candidateLine = lineAt(entry.content, match.line);
          if (candidateLine.includes('$queryRaw`')) continue;
          if (!SQL_SINK_LINE.test(candidateLine) && !sinkOpensOnTheLineBefore(entry.content, match.line)) continue;
          if (pattern === JS_JOINED_SQL_TEXT && !sinkOpensOnTheLineBefore(entry.content, match.line)) continue;
          const verdict = astVerdict(ast, 'sql', match.line);
          if (verdict === 'suppress') continue;
          if (entry.extension === '.py' && verdict !== 'confirm' && pythonSqlFromConstantFragments(entry.content, match.index)) continue;
          if (verdict !== 'confirm') {
            const scope = windowAround(entry.content, match.index, 360);
            if (!usesUserInput(scope, taint, match.index) && !(entry.extension === '.py' && pythonQueryTextReaches(entry.content, match.index, { aliases: pythonDependencyAliases(context.fileMap.entries) }))) continue;
          }
          seen.add(match.line);
          findings.push(
            makeFinding({
              ruleId: this.id,
              title: this.title,
              severity: 'critical',
              confidence: confidenceWithProof(verdict, 'medium'),
              filePath: entry.path,
              lineStart: match.line,
              evidence: match.snippet,
              userExplanation:
                'This database query is built by gluing user input directly into the SQL text. An attacker can send crafted input to read, change, or delete data they should not be able to. Use parameterised queries instead of string building.',
              technicalExplanation:
                `${entry.path}:${match.line} constructs SQL via concatenation/interpolation with request-derived data in scope. Use parameter binding so values are never parsed as SQL.`,
              fixHint:
                'Replace string concatenation with parameterised queries: pass values as bound parameters ($1/?/:name) rather than embedding them in the SQL string. With an ORM, use its query builder instead of raw interpolated SQL.',
              category: this.category,
            }),
          );
        }
      }
      if (entry.extension === '.py') {
        for (const sink of pythonSqlSinks(entry.content, { aliases: pythonDependencyAliases(context.fileMap.entries) })) {
          if (seen.has(sink.line)) continue;
          if (astVerdict(ast, 'sql', sink.line) === 'suppress') continue;
          if (pythonSqlFromConstantFragments(entry.content, sink.index)) continue;
          seen.add(sink.line);
          findings.push(
            makeFinding({
              ruleId: this.id,
              title: this.title,
              severity: 'critical',
              confidence: 'medium',
              filePath: entry.path,
              lineStart: sink.line,
              evidence: lineAt(entry.content, sink.line).trim(),
              userExplanation:
                'This database query is built by gluing user input directly into the SQL text. An attacker can send crafted input to read, change, or delete data they should not be able to. Use parameterised queries instead of string building.',
              technicalExplanation:
                `${entry.path}:${sink.line} constructs SQL via concatenation/interpolation with request-derived data in scope. Use parameter binding so values are never parsed as SQL.`,
              fixHint:
                'Replace string concatenation with parameterised queries: pass values as bound parameters ($1/?/:name) rather than embedding them in the SQL string. With an ORM, use its query builder instead of raw interpolated SQL.',
              category: this.category,
            }),
          );
        }
      }
      for (const sink of helperSqlSinks(context, entry, taint)) {
        if (seen.has(sink.line)) continue;
        if (astVerdict(ast, 'sql', sink.line) === 'suppress') continue;
        seen.add(sink.line);
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: this.title,
            severity: 'critical',
            confidence: 'medium',
            filePath: entry.path,
            lineStart: sink.line,
            evidence: lineAt(entry.content, sink.line).trim(),
            userExplanation:
              'This database query is built by gluing user input directly into the SQL text, then run through a helper function in your code. An attacker can send crafted input to read, change, or delete data they should not be able to. Use parameterised queries instead of string building.',
            technicalExplanation:
              `${entry.path}:${sink.line} passes SQL built via concatenation/interpolation, with request-derived data in scope, to ${sink.helper}(), whose parameter reaches a database query call unchanged. Use parameter binding so values are never parsed as SQL.`,
            fixHint:
              `Give ${sink.helper}() the query and its values separately (a placeholder such as ? or $1 in the SQL text, the values as a second argument it passes on to the database call), so values are never part of the SQL string.`,
            category: this.category,
          }),
        );
      }
      for (const [line] of userTaintedLines(ast, 'sql')) {
        if (seen.has(line)) continue;
        const evidence = resolvedSqlEvidence(entry.content, line);
        if (evidence === undefined || seen.has(evidence.line)) continue;
        seen.add(evidence.line);
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: this.title,
            severity: 'critical',
            confidence: 'high',
            filePath: entry.path,
            lineStart: evidence.line,
            evidence: evidence.text,
            userExplanation:
              'This database query is built from user input. An attacker can send crafted input to read, change, or delete data they should not be able to. Use parameterised queries instead of string building.',
            technicalExplanation:
              `${entry.path}:${evidence.line}: syntax-aware analysis traced request-derived data into SQL text that reaches a database query sink. Use parameter binding so values are never parsed as SQL.`,
            fixHint:
              'Replace string concatenation with parameterised queries: pass values as bound parameters ($1/?/:name) rather than embedding them in the SQL string. With an ORM, use its query builder instead of raw interpolated SQL.',
            category: this.category,
          }),
        );
      }
    }
    return findings;
  },
};





