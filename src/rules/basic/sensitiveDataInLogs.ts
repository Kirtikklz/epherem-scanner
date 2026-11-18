import { makeFinding } from '../../shared/findingFactory.js';
import type { Finding, RuleContext, ScanRule, Severity, Confidence } from '../../shared/types.js';
import { stripCommentsOnly, usesHashComments } from '../../shared/source.js';
import { findMatches, lineAt } from '../../shared/utils.js';
import {
  LOG_SAFE_SCALAR_PROP,
  LOG_SENSITIVE_IN_TEMPLATE,
  LOG_SENSITIVE_VALUE,
  nameIsBooleanFlag,
  sensitiveCategories,
  valueProvesNotSensitive,
} from '../../shared/sensitiveData.js';
import { balancedEnd } from '../../shared/emittedValue.js';

const CODE_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py']);

const LOG_SINK = /\b(?:console\.(?:log|info|warn|error|debug)|logger\.\w+|log\.\w+|print|logging\.(?:info|warning|error|exception|debug|critical))\s*\(/g;
const SENSITIVE_VALUE = LOG_SENSITIVE_VALUE;
const WHOLE_SECRET_OBJECT = /\b(?:req|request)\.body\b|\b(?:req|request)\.headers\b|\bprocess\.env\b(?!\.\w)|\bheaders\b|\bcookies\b/i;
const BAG_COUNT_ACCESSOR = /\b(?:headers|cookies|body|env)\s*(?:\.\s*\w+\s*)*\.\s*(?:length|size|count)\b/i;
const BAG_LITERAL_LOOKUP =
  /\b(?:headers|cookies|body|env)\s*(?:\.\s*(?:get|getAll)\s*\(\s*|\[\s*)(['"`])([^'"`]{1,80})\1/gi;

function bagSelections(expression: string): string[] | undefined {
  const selections: string[] = [];
  let covered = 0;
  let bagMentions = 0;
  for (const bag of expression.matchAll(/\b(?:headers|cookies|body|env)\b/gi)) {
    void bag;
    bagMentions += 1;
  }
  if (bagMentions === 0) return undefined;
  for (const match of expression.matchAll(BAG_LITERAL_LOOKUP)) {
    selections.push(match[2] ?? '');
    covered += 1;
  }
  for (const match of expression.matchAll(new RegExp(BAG_COUNT_ACCESSOR.source, 'gi'))) {
    void match;
    covered += 1;
  }
  return covered >= bagMentions ? selections : undefined;
}

function selectsOnlyHarmlessFields(expression: string): boolean {
  const selections = bagSelections(expression);
  if (selections === undefined) return false;
  return selections.every((key) => !LOG_SENSITIVE_VALUE.test(key) && !/^(?:cookie|set-cookie)$/i.test(key));
}
const ERROR_REVIEW_VALUE = /\b(?:providerError|authError|stripeError|githubError|supabaseError|clerkError|requestError|responseError|sessionError|err|error|e)\b/i;
const RAW_EXCHANGE_ACCESS =
  /\.\s*(?:response|request|config|headers|rawResponse|originalError|cause)\b|\.\.\.\s*[A-Za-z_$][\w$]*(?:Error|error|err)\b/;

interface LogRisk {
  severity: Severity;
  confidence: Confidence;
  reason: string;
  technical: string;
}

function callArgs(content: string, openParenIndex: number): string {
  let depth = 0;
  let quote: string | undefined;
  let escaped = false;
  let out = '';
  for (let i = openParenIndex; i < content.length && i < openParenIndex + 800; i += 1) {
    const ch = content[i] ?? '';
    if (quote !== undefined) {
      out += ch;
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === quote) quote = undefined;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; out += ch; continue; }
    if (ch === '(') { depth += 1; if (depth === 1) continue; }
    if (ch === ')') { depth -= 1; if (depth === 0) break; }
    out += ch;
  }
  return out.trim();
}

function splitTopLevelArgs(args: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let quote: string | undefined;
  let escaped = false;
  let current = '';
  for (const ch of args) {
    if (quote !== undefined) {
      current += ch;
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === quote) quote = undefined;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; current += ch; continue; }
    if (ch === '(' || ch === '{' || ch === '[') depth += 1;
    if (ch === ')' || ch === '}' || ch === ']') depth = Math.max(0, depth - 1);
    if (ch === ',' && depth === 0) {
      out.push(current.trim());
      current = '';
      continue;
    }
    current += ch;
  }
  if (current.trim().length > 0) out.push(current.trim());
  return out;
}

function isStaticText(arg: string): boolean {
  return /^(['"])(?:\\.|(?!\1).)*\1$/.test(arg.trim());
}

function isLoggerSetup(arg: string): boolean {
  return /(?:logging|getLogger)\.getLogger\s*\(|logging\.basicConfig\s*\(/.test(arg);
}

const SENSITIVE_IN_TEMPLATE = LOG_SENSITIVE_IN_TEMPLATE;
function templateInterpolatesSensitive(arg: string): boolean {
  const t = arg.trim();
  if (!/^`/.test(t) || !/\$\{/.test(t)) return false;
  const re = /\$\{([^}]*)\}/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(t)) !== null) {
    const inner = (m[1] ?? '').trim();
    if (SENSITIVE_IN_TEMPLATE.test(inner) && !logsOnlyPresenceOf(inner)) return true;
  }
  return false;
}

function isBooleanPresenceCheck(arg: string): boolean {
  const trimmed = arg.trim();
  return /^!!\s*[A-Za-z_$][\w$.?]*$/.test(trimmed) ||
    /^Boolean\s*\([^)]*\)$/.test(trimmed) ||
    /^[A-Za-z_$][\w$.?]*\s*(?:!==|!=|===|==)\s*(?:null|undefined)$/.test(trimmed);
}

const TERNARY_SPLIT = /^([^?]+?)\?([\s\S]*):([\s\S]*)$/;
function logsOnlyPresenceOf(expression: string): boolean {
  const trimmed = expression.trim();
  if (trimmed === '') return false;
  if (isBooleanPresenceCheck(trimmed)) return true;
  if (SAFE_SCALAR_PROP.test(trimmed)) return true;
  const ternary = TERNARY_SPLIT.exec(trimmed);
  if (ternary !== null) {
    const whenTrue = stripStringLiterals(ternary[2] ?? '');
    const whenFalse = stripStringLiterals(ternary[3] ?? '');
    if (!SENSITIVE_IN_TEMPLATE.test(whenTrue) && !SENSITIVE_IN_TEMPLATE.test(whenFalse)) return true;
  }
  return false;
}

const SAFE_SCALAR_PROP = LOG_SAFE_SCALAR_PROP;
function stripStringLiterals(text: string): string {
  return text.replace(/(['"])(?:\\.|(?!\1)[^\\])*\1/g, "''");
}

function tier4ShouldSkip(arg: string): boolean {
  const isTemplate = /^`/.test(arg);
  if (isTemplate) {
    const sensitiveInterps: string[] = [];
    const re = /\$\{([^}]*)\}/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(arg)) !== null) {
      const inner = m[1] ?? '';
      if (SENSITIVE_VALUE.test(inner)) sensitiveInterps.push(inner.trim());
    }
    if (sensitiveInterps.length === 0) return true;
    return sensitiveInterps.every((expr) => logsOnlyPresenceOf(expr));
  }
  if (SAFE_SCALAR_PROP.test(arg)) return true;
  return !SENSITIVE_VALUE.test(stripStringLiterals(arg));
}

function objectFieldsProveNoLeak(objectText: string): boolean {
  const fields = splitTopLevelArgs(objectText.slice(1, -1));
  if (fields.length === 0) return false;
  let sawRiskyField = false;
  for (const field of fields) {
    if (!SENSITIVE_VALUE.test(field)) continue;
    sawRiskyField = true;
    const separator = field.indexOf(':');
    if (separator === -1) return false;
    const name = field.slice(0, separator).trim().replace(/^['"`]|['"`]$/g, '');
    const value = field.slice(separator + 1).trim();
    if (nameIsBooleanFlag(name)) continue;
    if (!SENSITIVE_VALUE.test(name) && !SENSITIVE_VALUE.test(stripStringLiterals(value))) continue;
    if (!valueProvesNotSensitive(value) && !SAFE_SCALAR_PROP.test(value)) return false;
  }
  return sawRiskyField;
}

function classifyLoggedArg(arg: string): LogRisk | undefined {
  const trimmed = arg.trim();
  if (trimmed === '' || isStaticText(trimmed) || isBooleanPresenceCheck(trimmed) || isLoggerSetup(trimmed)) return undefined;

  if (templateInterpolatesSensitive(trimmed)) {
    return {
      severity: 'high',
      confidence: 'high',
      reason: 'The log template interpolates a password, token, secret, key, cookie, authorization value, or similar credential.',
      technical: 'logs a template string interpolation containing a sensitive value',
    };
  }

  if (WHOLE_SECRET_OBJECT.test(trimmed) && !selectsOnlyHarmlessFields(trimmed)) {
    return {
      severity: 'medium',
      confidence: 'high',
      reason: 'The log writes a whole request, headers, cookies, or environment object that commonly contains credentials.',
      technical: 'logs a whole request/env object rather than selecting non-sensitive fields',
    };
  }

  if (/^\{[\s\S]*\}$/.test(trimmed) && SENSITIVE_VALUE.test(trimmed)) {
    if (objectFieldsProveNoLeak(trimmed)) return undefined;
    return {
      severity: 'high',
      confidence: 'high',
      reason: 'The structured log includes a field whose name indicates a password, token, secret, key, or similar credential.',
      technical: 'logs a structured object containing a sensitive field name',
    };
  }

  if (SENSITIVE_VALUE.test(trimmed)) {
    if (tier4ShouldSkip(trimmed)) return undefined;
    return {
      severity: 'low',
      confidence: 'low',
      reason: 'The log writes an expression whose name suggests a password, token, secret, or key. Review whether the actual secret value (not just an id or label) is being logged.',
      technical: 'logs an expression whose name suggests a credential; low-confidence review signal — verify before treating as a leak',
    };
  }

  if (ERROR_REVIEW_VALUE.test(trimmed) && RAW_EXCHANGE_ACCESS.test(trimmed) && !/\.message\b/.test(trimmed)) {
    return {
      severity: 'low',
      confidence: 'low',
      reason: 'The log writes an error together with its raw HTTP exchange (response, request, config, or headers). Provider errors carry the original request headers, so an Authorization or Cookie header can reach the log this way.',
      technical: 'logs an error object together with its raw request/response; this is a low-confidence review finding',
    };
  }

  return undefined;
}

const OBJECT_BINDING = /(?:(?:const|let|var)\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*\{/g;

const SELECT_LIST = /\bselect\s+([\s\S]{1,800}?)\s+from\b/i;
const NAME_BINDING = /(?:(?:const|let|var)\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=/g;

const BINDING_VALUE_WINDOW = 600;

interface LocalBindings {
  objectKeys: Map<string, string[]>;
  queryColumns: Map<string, string[]>;
}

function readLocalBindings(content: string): LocalBindings {
  const objectKeys = new Map<string, string[]>();
  const queryColumns = new Map<string, string[]>();

  OBJECT_BINDING.lastIndex = 0;
  let match = OBJECT_BINDING.exec(content);
  while (match !== null) {
    const name = match[1];
    const open = match.index + match[0].length;
    const end = balancedEnd(content, open, '{', '}');
    if (name !== undefined && end !== undefined) {
      objectKeys.set(name, objectLiteralKeys(content.slice(open, end)));
    }
    match = OBJECT_BINDING.exec(content);
  }

  NAME_BINDING.lastIndex = 0;
  let bound = NAME_BINDING.exec(content);
  while (bound !== null) {
    const name = bound[1];
    const value = content.slice(bound.index + bound[0].length, bound.index + bound[0].length + BINDING_VALUE_WINDOW);
    const select = SELECT_LIST.exec(value);
    if (name !== undefined && select !== null) {
      const columns = selectListColumns(select[1] ?? '');
      if (columns.length > 0) queryColumns.set(name, columns);
    }
    bound = NAME_BINDING.exec(content);
  }
  return { objectKeys, queryColumns };
}

function objectLiteralKeys(body: string): string[] {
  const keys: string[] = [];
  for (const field of splitTopLevelArgs(body)) {
    const trimmed = field.trim();
    if (trimmed === '' || trimmed.startsWith('...')) continue;
    const separator = trimmed.indexOf(':');
    const name = (separator === -1 ? trimmed : trimmed.slice(0, separator)).trim();
    const bare = name.replace(/^['"`]|['"`]$/g, '');
    if (/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(bare)) keys.push(bare);
  }
  return keys;
}

function selectListColumns(list: string): string[] {
  const columns: string[] = [];
  for (const piece of list.split(',')) {
    const trimmed = piece.trim();
    if (trimmed === '' || trimmed.includes('*')) continue;
    const aliased = /\bas\s+([A-Za-z_][A-Za-z0-9_]*)\s*$/i.exec(trimmed);
    const raw = aliased !== null ? (aliased[1] ?? '') : trimmed;
    const leaf = raw.split('.').pop() ?? '';
    if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(leaf)) columns.push(leaf);
  }
  return columns;
}

function spreadNames(objectText: string): string[] {
  const names: string[] = [];
  for (const field of splitTopLevelArgs(objectText.slice(1, -1))) {
    const trimmed = field.trim();
    if (!trimmed.startsWith('...')) continue;
    const name = trimmed.slice(3).trim();
    if (/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(name)) names.push(name);
  }
  return names;
}

function resolvedFieldsAreSensitive(arg: string, bindings: LocalBindings): string[] | undefined {
  const trimmed = arg.trim();
  const names: string[] = [];
  if (trimmed.startsWith('{') && trimmed.endsWith('}')) names.push(...spreadNames(trimmed));
  else if (/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(trimmed)) names.push(trimmed);

  for (const name of names) {
    const fields = bindings.objectKeys.get(name) ?? bindings.queryColumns.get(name);
    if (fields === undefined || fields.length === 0) continue;
    const claimed = sensitiveCategories(fields).filter((category) => LOGGABLE_HARM.has(category));
    if (claimed.length === 0) continue;
    return fields.filter((field) => sensitiveCategories([field]).some((category) => LOGGABLE_HARM.has(category)));
  }
  return undefined;
}

const LOGGABLE_HARM = new Set(['credential', 'one-time secret', 'financial', 'national id']);

const EXPORTED_FUNCTION =
  /export\s+(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)\s*\{|export\s+const\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>\s*\{/g;

const WRAPPER_BODY_LIMIT = 1200;

function wrapperSinkNames(context: RuleContext, fromPath: string): Set<string> {
  const sinks = new Set<string>();
  const fileImports = context.projectMap.imports.find((entry) => entry.filePath === fromPath);
  if (fileImports === undefined) return sinks;
  for (const importRef of fileImports.imports) {
    const target = importRef.resolvedPath;
    const bindings = importRef.bindings;
    if (target === undefined || bindings === undefined || bindings.length === 0) continue;
    const module = context.fileMap.entries.find((candidate) => candidate.path === target);
    if (module === undefined) continue;
    for (const name of bindings) {
      if (forwardsToLogSink(module.content, name)) sinks.add(name);
    }
  }
  return sinks;
}

function forwardsToLogSink(moduleContent: string, exportName: string): boolean {
  EXPORTED_FUNCTION.lastIndex = 0;
  let declaration = EXPORTED_FUNCTION.exec(moduleContent);
  while (declaration !== null) {
    const name = declaration[1] ?? declaration[3];
    const parameters = declaration[2] ?? declaration[4] ?? '';
    if (name === exportName) {
      const open = declaration.index + declaration[0].length;
      const end = balancedEnd(moduleContent, open, '{', '}');
      if (end === undefined || end - open > WRAPPER_BODY_LIMIT) return false;
      return bodyForwardsParameter(moduleContent.slice(open, end), parameterNames(parameters));
    }
    declaration = EXPORTED_FUNCTION.exec(moduleContent);
  }
  return false;
}

function parameterNames(parameters: string): string[] {
  return splitTopLevelArgs(parameters)
    .map((parameter) => (parameter.split(/[:=]/)[0] ?? '').trim())
    .filter((name) => /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(name));
}

function bodyForwardsParameter(body: string, parameters: readonly string[]): boolean {
  if (parameters.length === 0) return false;
  LOG_SINK.lastIndex = 0;
  let sink = LOG_SINK.exec(body);
  while (sink !== null) {
    const open = body.indexOf('(', sink.index);
    const end = open === -1 ? undefined : balancedEnd(body, open + 1, '(', ')');
    if (open !== -1 && end !== undefined) {
      for (const argument of splitTopLevelArgs(body.slice(open + 1, end))) {
        if (forwardsWhole(argument, parameters)) return true;
      }
    }
    sink = LOG_SINK.exec(body);
  }
  return false;
}

function forwardsWhole(argument: string, parameters: readonly string[]): boolean {
  const value = unwrapSerialisers(argument.trim());
  if (parameters.includes(value)) return true;
  if (!value.startsWith('{') || !value.endsWith('}')) return false;
  for (const field of splitTopLevelArgs(value.slice(1, -1))) {
    const trimmed = field.trim();
    if (!trimmed.startsWith('...')) continue;
    if (parameters.includes(unwrapSerialisers(trimmed.slice(3).trim()))) return true;
  }
  return false;
}

const SERIALISER_CALL = /^(?:JSON\s*\.\s*stringify|util\s*\.\s*inspect|inspect|String)\s*\(/;

function unwrapSerialisers(expression: string): string {
  let value = expression.trim();
  for (let depth = 0; depth < 4; depth += 1) {
    const call = SERIALISER_CALL.exec(value);
    if (call === null) return value;
    const end = balancedEnd(value, call[0].length, '(', ')');
    if (end === undefined || end !== value.length - 1) return value;
    value = splitTopLevelArgs(value.slice(call[0].length, end))[0]?.trim() ?? value;
  }
  return value;
}

function wrapperSinkPattern(names: ReadonlySet<string>): RegExp {
  return new RegExp(`(?<![A-Za-z0-9_$.])(?:${[...names].join('|')})\\s*\\(`, 'g');
}

function resolvedFieldRisk(args: readonly string[], bindings: LocalBindings): LogRisk | undefined {
  for (const arg of args) {
    const fields = resolvedFieldsAreSensitive(arg, bindings);
    if (fields === undefined) continue;
    return {
      severity: 'high',
      confidence: 'medium',
      reason: `The logged value carries personal or financial fields (${fields.slice(0, 4).join(', ')}) that are defined elsewhere in this file rather than named in the log call.`,
      technical: `logs a value whose fields resolve to ${fields.slice(0, 4).join(', ')} — a spread of a local object, or the result of a SELECT projecting those columns`,
    };
  }
  return undefined;
}

export const sensitiveDataInLogs: ScanRule = {
  id: 'sensitive_data_in_logs',
  title: 'Sensitive data written to logs',
  category: 'logging',
  kind: 'basic',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    for (const entry of context.fileMap.entries) {
      if (!CODE_EXTENSIONS.has(entry.extension)) continue;
      const seen = new Set<number>();
      const scanContent = stripCommentsOnly(entry.content, usesHashComments(entry.extension, entry.label));
      const wrappers = wrapperSinkNames(context, entry.path);
      const bindings = readLocalBindings(scanContent);
      const sinks = wrappers.size === 0 ? [LOG_SINK] : [LOG_SINK, wrapperSinkPattern(wrappers)];
      for (const match of sinks.flatMap((sink) => findMatches(scanContent, sink))) {
        if (seen.has(match.line)) continue;
        const openParen = scanContent.indexOf('(', match.index);
        if (openParen === -1) continue;
        const args = splitTopLevelArgs(callArgs(scanContent, openParen));
        const risk =
          args.map(classifyLoggedArg).find((candidate): candidate is LogRisk => candidate !== undefined) ??
          resolvedFieldRisk(args, bindings);
        if (risk === undefined) continue;
        seen.add(match.line);
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: this.title,
            severity: risk.severity,
            confidence: risk.confidence,
            filePath: entry.path,
            lineStart: match.line,
            evidence: lineAt(entry.content, match.line),
            userExplanation:
              `${risk.reason} Logs are often stored, shipped to third parties, and widely readable, so secrets in logs frequently leak. Remove or mask the sensitive fields before logging.`,
            technicalExplanation:
              `${entry.path}:${match.line} ${risk.technical}. Redact the value, log only a non-sensitive id, or log a boolean presence check instead of the underlying value.`,
            fixHint:
              'Log a non-sensitive identifier instead of the secret, or mask it (e.g. show only the last 4 chars). Never log req.body, headers, cookies, or process.env wholesale.',
            category: this.category,
          }),
        );
      }
    }
    return findings;
  },
};
