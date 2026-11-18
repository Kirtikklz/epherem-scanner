import { analyzeFileAst, astVerdict, confidenceWithProof, userTaintedLines } from '../../ast/astAnalysis.js';
import { crossFileAstHits } from '../../ast/crossFileTaint.js';
import { makeFinding } from '../../shared/findingFactory.js';
import type { FileMapEntry, Finding, RuleContext, ScanRule } from '../../shared/types.js';
import { findMatches, lineAt } from '../../shared/utils.js';
import { innerHtmlValueIsInert } from '../../shared/inertMarkup.js';
import { referencesUserInput, windowAround } from '../../shared/userInput.js';
import { routeHandlerScopeForLine } from '../../shared/handlerScope.js';
import { isInsideComment, isInsideDevelopmentOnlyBlock } from '../../shared/liveCode.js';
import { pythonCallArguments } from '../../shared/pythonSettings.js';
import { stripCommentsAndStrings, stripCommentsOnly } from '../../shared/source.js';
import { analyzeTaint, usesUserInput } from '../../shared/taint.js';
import { classSanitises, pythonReceiverClass, receiverColumn, storedTextFields, templateReceiverClass, type PyClass } from '../../shared/pythonTemplateContext.js';
import { enclosingDef, maskedLines } from '../../shared/pythonScope.js';

const CODE_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.html']);

const TEMPLATE_VIEW_EXTENSIONS = new Set([
  '.ejs', '.hbs', '.handlebars', '.pug', '.jade', '.njk', '.nunjucks', '.erb', '.mustache',
]);

const TEMPLATE_RAW_OUTPUT =
  /<%-\s*([^%]{1,200}?)\s*%>|<%==\s*([^%]{1,200}?)\s*%>|\{\{\{\s*([^}]{1,200}?)\s*\}\}\}|\{\{&\s*([^}]{1,200}?)\s*\}\}|\{\{\s*([^}|]{1,200}?)\s*\|\s*safe\s*\}\}|!\{\s*([^}]{1,200}?)\s*\}/g;

const PUG_UNESCAPED_LINE = /^[ \t]*[\w.#()[\]='"|-]*!=(?!=)[ \t]*(\S[^\n]{0,200})$/gm;

const ERB_RAW_OUTPUT =
  /<%==\s*([^%]{1,200}?)\s*-?%>|<%=\s*(raw\s*[( ][^%]{1,200}?|[^%]{1,200}?\.html_safe(?:[^%]{0,60}?)?)\s*-?%>/g;

const CODEGEN_TEMPLATE_PATH = /(^|\/)(lib\/templates|generators)\//i;

const TEMPLATE_INCLUDE = /^\s*include\b/i;

const LAYOUT_BODY_SLOT = /^body$/;
const HTML_DOCUMENT_SHELL = /<!DOCTYPE\s+html\b|<html[\s>]/i;

function isLayoutBodySlot(expression: string, content: string): boolean {
  return LAYOUT_BODY_SLOT.test(expression) && HTML_DOCUMENT_SHELL.test(content);
}

const REACT_DANGEROUS = /dangerouslySetInnerHTML\s*=\s*\{\{[\s\S]{0,160}?__html\s*:\s*([^}]+)\}\}/g;
const DOM_HTML_SINK = /\.(?:innerHTML|outerHTML)\s*=\s*([^;]+)|\bdocument\.write(?:ln)?\s*\(([^)]*)\)|\.insertAdjacentHTML\s*\(([^)]*)\)/g;
const TEMPLATE_UNESCAPED = /\{\{\{[\s\S]{0,80}?\}\}\}|\|\s*safe\b|v-html\s*=|\bmark_safe\s*\(|dangerouslySetInnerHTML/g;

const ESTABLISHED_SANITIZER =
  /DOMPurify\.sanitize\s*\(|sanitize\s*\([^)]*,\s*\{[^}]*ALLOWED_TAGS|\bhe\.(?:encode|escape)\s*\(|_\.escape\s*\(|lodash\.escape\s*\(|validator\.escape\s*\(|Handlebars\.escapeExpression\s*\(|htmlspecialchars\s*\(/i;
export const CUSTOM_SANITIZER_CALL =
  /\b((?:[A-Za-z_$][\w$]*)?(?:sanitize|escape|escHTML|htmlEscape|escapeHTML|encodeHTML|encodeHtml)[A-Za-z_$\w]*|esc)\s*\(/i;

const VALUE_MAY_BEGIN = /[(,=:[!&|?{};+\-*%~^<>]$/;

function conciseArrowBodyFrom(content: string, from: number, max: number): string | undefined {
  let quote: string | undefined;
  let escaped = false;
  for (let i = from; i < content.length && i < from + max; i += 1) {
    const ch = content[i] ?? '';
    if (quote !== undefined) {
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === quote) quote = undefined;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; continue; }
    if (ch === '/') {
      const before = content.slice(Math.max(from, i - 40), i).replace(/\s+$/, '');
      if (before !== '' && !VALUE_MAY_BEGIN.test(before)) continue;
      const end = regexLiteralEnd(content, i);
      if (end === undefined) return undefined;
      i = end;
      continue;
    }
    if (ch === ';') return content.slice(from, i);
  }
  return undefined;
}

function regexLiteralEnd(content: string, open: number): number | undefined {
  let escaped = false;
  let inClass = false;
  for (let i = open + 1; i < content.length; i += 1) {
    const ch = content[i] ?? '';
    if (ch === '\n') return undefined;
    if (escaped) { escaped = false; continue; }
    if (ch === '\\') { escaped = true; continue; }
    if (ch === '[') { inClass = true; continue; }
    if (ch === ']') { inClass = false; continue; }
    if (ch === '/' && !inClass) return i;
  }
  return undefined;
}

export function helperBody(content: string, name: string): string | undefined {
  const escaped = name.replace(/[$]/g, '\\$&');
  const patterns = [
    new RegExp(`function\\s+${escaped}\\s*\\([^)]*\\)\\s*\\{([\\s\\S]{0,900}?)\\}`, 'i'),
    new RegExp(`(?:const|let|var)\\s+${escaped}\\s*=\\s*(?:\\([^)]*\\)|[A-Za-z_$][\\w$]*)\\s*=>\\s*\\{([\\s\\S]{0,900}?)\\}`, 'i'),
  ];
  for (const pattern of patterns) {
    const match = pattern.exec(content);
    if (match?.[1] !== undefined) return match[1];
  }
  const head = new RegExp(
    `(?:const|let|var)\\s+${escaped}\\s*=\\s*(?:async\\s*)?(?:\\([^)]{0,400}\\)|[A-Za-z_$][\\w$]*)\\s*=>\\s*(?!\\{)`,
  ).exec(content);
  if (head?.index === undefined) return undefined;
  return conciseArrowBodyFrom(content, head.index + head[0].length, 900);
}

function customHelperProvesEscaping(content: string, scope: string): boolean {
  const name = CUSTOM_SANITIZER_CALL.exec(scope)?.[1];
  if (name === undefined) return false;
  const body = helperBody(content, name);
  if (body === undefined) return false;
  return /replace\s*\([\s\S]{0,360}(?:&lt;|&gt;|&amp;|&#x?3c|&quot;|&#x?27)/i.test(body);
}

function isJsonLdSerialization(scope: string, argument: string): boolean {
  return /type\s*=\s*["']application\/ld\+json["']/i.test(scope) && /^JSON\.stringify\s*\(/.test(argument.trim()) && !/\+|`[^`]*\$\{/i.test(argument);
}

function isHtmlSanitized(content: string, scope: string): boolean {
  return ESTABLISHED_SANITIZER.test(scope) || customHelperProvesEscaping(content, scope) || (/\bescapeHtml\s*\(/.test(scope) && /function\s+escapeHtml[\s\S]{0,500}(?:&lt;|&gt;|&amp;)/i.test(content));
}

const INTERPOLATION = /\$\{([^}]{1,200})\}/g;
const IDENTIFIER_ROOT = /(?<![.\w$])([A-Za-z_$][\w$]*)/g;
const NOT_A_VALUE = new Set([
  'true', 'false', 'null', 'undefined', 'new', 'typeof', 'void', 'in', 'of',
  'String', 'Number', 'Boolean', 'JSON', 'Math', 'Object', 'Array', 'Date',
]);

function valueRoots(argument: string): string[] {
  const text = argument.includes('${')
    ? [...argument.matchAll(INTERPOLATION)].map((m) => m[1] ?? '').join(' ')
    : argument;
  const withoutStrings = text
    .replace(/`(?:\\.|[^`\\$])*`/g, ' ')
    .replace(/'(?:\\.|[^'\\])*'/g, ' ')
    .replace(/"(?:\\.|[^"\\])*"/g, ' ');
  const roots = new Set<string>();
  for (const match of withoutStrings.matchAll(IDENTIFIER_ROOT)) {
    const name = match[1];
    if (name !== undefined && !NOT_A_VALUE.has(name)) roots.add(name);
  }
  return [...roots];
}

function constInitializer(content: string, name: string): string | undefined {
  const escaped = name.replace(/[$]/g, '\\$&');
  const declaration = new RegExp(`\\bconst\\s+${escaped}\\s*=\\s*`).exec(content);
  if (declaration === null) return undefined;
  const start = declaration.index + declaration[0].length;
  let depth = 0;
  for (let i = start; i < content.length && i - start < 20_000; i += 1) {
    const c = content[i];
    if (c === '[' || c === '{' || c === '(') depth += 1;
    else if (c === ']' || c === '}' || c === ')') {
      depth -= 1;
      if (depth < 0) return content.slice(start, i);
    } else if (depth === 0 && (c === ';' || c === '\n')) {
      return content.slice(start, i);
    }
  }
  return undefined;
}

function isLiteralOnly(text: string): boolean {
  const stripped = text
    .replace(/`(?:\\.|[^`\\$])*`/g, ' ')
    .replace(/'(?:\\.|[^'\\])*'/g, ' ')
    .replace(/"(?:\\.|[^"\\])*"/g, ' ')
    .replace(/(?<![.\w$])[A-Za-z_$][\w$]*\s*:/g, ' ')
    .replace(/\b(?:true|false|null|undefined)\b/g, ' ')
    .replace(/\b\d[\d_.eE+-]*\b/g, ' ');
  return !/[A-Za-z_$]/.test(stripped);
}

function iterationSource(content: string, name: string): string | undefined {
  const escaped = name.replace(/[$]/g, '\\$&');
  const patterns = [
    new RegExp(`([A-Za-z_$][\\w$]*)\\s*\\.\\s*(?:forEach|map|flatMap|filter)\\s*\\(\\s*\\(?\\s*${escaped}\\b`),
    new RegExp(`for\\s*\\(\\s*(?:const|let|var)\\s+${escaped}\\s+of\\s+([A-Za-z_$][\\w$]*)`),
  ];
  for (const pattern of patterns) {
    const match = pattern.exec(content);
    if (match?.[1] !== undefined) return match[1];
  }
  return undefined;
}

function rootIsDeveloperConstant(content: string, name: string, depth = 0): boolean {
  if (depth > 2) return false;
  const initializer = constInitializer(content, name);
  if (initializer !== undefined && isLiteralOnly(initializer)) return true;
  const source = iterationSource(content, name);
  if (source !== undefined) return rootIsDeveloperConstant(content, source, depth + 1);
  return false;
}

function valueIsDeveloperConstant(content: string, argument: string): boolean {
  const roots = valueRoots(argument);
  if (roots.length === 0) return false;
  return roots.every((root) => rootIsDeveloperConstant(content, root));
}

function indexOfLine(content: string, line: number): number | undefined {
  let index = 0;
  for (let current = 1; current < line; current += 1) {
    const next = content.indexOf('\n', index);
    if (next === -1) return undefined;
    index = next + 1;
  }
  while (index < content.length && (content[index] === ' ' || content[index] === '\t')) index += 1;
  return index < content.length ? index : undefined;
}

function isStaticLiteralOnly(argument: string): boolean {
  const trimmed = argument.trim();
  if (trimmed === '') return false;
  if (!/['"`]/.test(trimmed)) return false;
  const withoutLiterals = trimmed
    .replace(/`(?:\\.|[^`\\$])*`/g, '')
    .replace(/'(?:\\.|[^'\\])*'/g, '')
    .replace(/"(?:\\.|[^"\\])*"/g, '');
  return /^[\s+();]*$/.test(withoutLiterals);
}

const PY_TEMPLATE_SAFE = /\{\{\s*([^{}]{1,200}?)\s*\|\s*safe\s*(?:\|[^{}]*)?\}\}/g;
const PY_MARK_SAFE = /(?<![\w.])mark_safe\s*\(/g;
const PY_SANITISER =
  /(?<![\w.])(?:escape|conditional_escape|strip_tags)\s*\(|\b(?:html|markupsafe|bleach|nh3)\s*\.\s*(?:escape|clean|linkify)\s*\(|\bmarkdown2?\s*\.\s*markdown\s*\([^)]*\bsafe_mode\s*=\s*(?!False\b|None\b)\S|\bmistune\s*\.\s*\w+\s*\([^)]*\bescape\s*=\s*True\b/;
const SANITISING_FILTER = /^(?:bleach|clean|sanitize|sanitise|escape|e|forceescape|striptags)$/;
function oneStep(value: string): { root: string; leaf: string } | undefined {
  const m = /^([A-Za-z_]\w*)\.([A-Za-z_]\w*)$/.exec(value.trim());
  return m === null ? undefined : { root: m[1] ?? '', leaf: m[2] ?? '' };
}

function sanitisedInFunction(content: string, line: number, root: string, leaf: string): boolean {
  const lines = maskedLines(content);
  const scope = enclosingDef(lines, line);
  if (scope === undefined) return false;
  const original = content.split('\n');
  for (let l = scope.defLine + 1; l < line; l += 1) {
    const bind = new RegExp(`^\\s*${root}\\.${leaf}\\s*=(?!=)\\s*`).exec(lines[l - 1] ?? '');
    if (bind !== null && PY_SANITISER.test((original[l - 1] ?? '').slice(bind[0].length))) return true;
  }
  return false;
}

function storedAttribute(value: string): string | undefined {
  return /^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\.([A-Za-z_]\w*)$/.exec(value.trim())?.[1];
}
const F_STRING_FIELD = /\{([^{}]+)\}/g;
const HTML_ELEMENT = /<[A-Za-z][\w-]*[\s>/]/;

function receiverKeeps(entries: FileMapEntry[], cls: PyClass | undefined, leaf: string): 'keep' | 'drop' | 'unproven' {
  if (cls === undefined) return 'unproven';
  const column = receiverColumn(entries, cls, leaf);
  if (column === 'unproven') return 'unproven';
  if (column === 'absent') return 'drop';
  return classSanitises(cls, leaf, PY_SANITISER) ? 'drop' : 'keep';
}

function markSafeValues(argument: string): string[] {
  const trimmed = argument.trim();
  if (/^[rbRB]?[fF][rbRB]?['"]/.test(trimmed)) return [...trimmed.matchAll(F_STRING_FIELD)].map((m) => (m[1] ?? '').trim());
  return [trimmed];
}

const RESPONSE_SEND = /\bres\s*\.\s*(?:send|write|end)\s*\(/g;
const MARKUP_TAG = /<\/?[A-Za-z][\w-]*(?:\s|>|\/>)/;
const ESCAPED_VALUE = /^\s*(?:escape|escapeHtml|escapeHTML|htmlEscape|escapeHTMLEntities|encodeHTML|encodeHtml|sanitize|sanitizeHtml|DOMPurify\s*\.\s*sanitize|xss|filterXSS|he\s*\.\s*(?:encode|escape)|validator\s*\.\s*escape|_\s*\.\s*escape|lodash\s*\.\s*escape|encodeURIComponent|Number|parseInt|parseFloat)\s*\(/;

function markupBuiltFromPieces(text: string): boolean {
  if (!MARKUP_TAG.test(text)) return false;
  const interpolated = [...text.matchAll(/\$\{([^}]{1,200})\}/g)].map((m) => m[1] ?? '');
  const joined = /['"`]\s*\+|\+\s*['"`]/.test(text);
  if (joined) return true;
  return interpolated.some((value) => !ESCAPED_VALUE.test(value));
}

function firstArgumentText(content: string, code: string, open: number): string {
  let depth = 0;
  for (let i = open; i < Math.min(code.length, open + 3000); i += 1) {
    const c = code[i];
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === ']' || c === '}') {
      depth -= 1;
      if (depth === 0) return content.slice(open + 1, i);
    } else if (c === ',' && depth === 1) return content.slice(open + 1, i);
  }
  return '';
}

function reflectedHtmlResponses(entry: FileMapEntry): { index: number; line: number }[] {
  if (!RESPONSE_SINK_EXTENSIONS.has(entry.extension) || !/\bres\s*\.\s*(?:send|write|end)\s*\(/.test(entry.content)) return [];
  const code = stripCommentsAndStrings(entry.content);
  const taint = analyzeTaint(entry.content);
  const out: { index: number; line: number }[] = [];
  for (const m of code.matchAll(RESPONSE_SEND)) {
    if (m.index === undefined) continue;
    const open = m.index + m[0].length - 1;
    const arg = firstArgumentText(entry.content, code, open).trim();
    let sent = arg;
    const name = /^[A-Za-z_$][\w$]*$/.exec(arg)?.[0];
    if (name !== undefined) {
      const escaped = name.replace(/[$]/g, '\\$&');
      const before = entry.content.slice(Math.max(0, m.index - 3000), m.index);
      const bindings = [...before.matchAll(new RegExp(`(?:\\b(?:const|let|var)\\s+${escaped}\\s*=|(?<![\\w$.])${escaped}\\s*\\+=)\\s*([\\s\\S]{0,600}?)(?:;|\\n)`, 'g'))];
      let from = 0;
      bindings.forEach((b, i) => { if (/^(?:const|let|var)\b/.test((b[0] ?? '').trimStart())) from = i; });
      sent = bindings.slice(from).map((b) => b[1] ?? '').join(' + ');
    }
    if (sent === '' || !markupBuiltFromPieces(sent)) continue;
    if (!usesUserInput(sent, taint, m.index)) continue;
    out.push({ index: m.index, line: entry.content.slice(0, m.index).split('\n').length });
  }
  return out;
}

const RESPONSE_SINK_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts']);

export const crossSiteScripting: ScanRule = {
  id: 'xss',
  title: 'Possible cross-site scripting (XSS) via unsafe HTML rendering',
  category: 'xss',
  kind: 'basic',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const pythonSources = context.fileMap.entries.filter((entry) => entry.extension === '.py');
    const pythonCode = pythonSources.map((entry) => entry.content).join('\n');
    const storedFields = storedTextFields(pythonCode);
    const isStored = (value: string): boolean => {
      const attribute = storedAttribute(value);
      return attribute !== undefined && storedFields.has(attribute);
    };
    for (const entry of context.fileMap.entries) {
      if (TEMPLATE_VIEW_EXTENSIONS.has(entry.extension)) {
        if (CODEGEN_TEMPLATE_PATH.test(entry.path.replace(/\\/g, '/'))) continue;
        const templateSeen = new Set<number>();
        const patterns = entry.extension === '.erb'
          ? [ERB_RAW_OUTPUT]
          : [TEMPLATE_RAW_OUTPUT, PUG_UNESCAPED_LINE];
        for (const pattern of patterns) {
          for (const match of findMatches(entry.content, pattern)) {
            const expression = (
              match.groups[0] ??
              match.groups[1] ??
              match.groups[2] ??
              match.groups[3] ??
              match.groups[4] ??
              match.groups[5] ??
              match.groups[6] ??
              ''
            ).trim();
            if (expression === '') continue;
            if (TEMPLATE_INCLUDE.test(expression)) continue;
            if (isLayoutBodySlot(expression, entry.content)) continue;
            if (isStaticLiteralOnly(expression)) continue;
            if (isInsideComment(entry.content, match.index, entry.extension, entry.label)) continue;
            if (templateSeen.has(match.line)) continue;
            templateSeen.add(match.line);
            findings.push(
              makeFinding({
                ruleId: this.id,
                title: this.title,
                severity: 'high',
                confidence: 'medium',
                filePath: entry.path,
                lineStart: match.line,
                evidence: match.snippet,
                userExplanation:
                  'This page template writes a value into the page as raw HTML instead of plain text. Templates normally escape values automatically; this one has been told not to. If that value ever contains anything a user typed, they can inject a script that runs in other visitors browsers.',
                technicalExplanation:
                  `${entry.path}:${match.line} uses an unescaped template output tag for \`${expression.slice(0, 80)}\`. The escaping default has been explicitly overridden, and a template carries no data flow to prove where the value came from, so this is reported wherever the rendered expression is not a literal.`,
                fixHint:
                  'Use the escaping output form for this value (for example <%= %> rather than <%- %>, {{ }} rather than {{{ }}}, or = rather than != in Pug). If raw HTML is genuinely required, sanitize the value with DOMPurify or a proven equivalent before it reaches the template.',
                category: this.category,
              }),
            );
          }
        }
        continue;
      }
      if (!CODE_EXTENSIONS.has(entry.extension)) continue;
      const ast = analyzeFileAst(entry.path, entry.content, entry.extension, crossFileAstHits(context.projectMap.crossFileTaint, entry.path));
      const seen = new Set<number>();
      for (const pattern of [REACT_DANGEROUS, DOM_HTML_SINK, TEMPLATE_UNESCAPED]) {
        for (const match of findMatches(entry.content, pattern)) {
          if (seen.has(match.line)) continue;
          const verdict = astVerdict(ast, 'html', match.line);
          if (verdict === 'suppress') continue;
          if (isInsideComment(entry.content, match.index, entry.extension, entry.label)) continue;
          if (isInsideDevelopmentOnlyBlock(entry.content, match.index)) continue;
          const argument = (match.groups[0] ?? match.groups[1] ?? match.groups[2] ?? '').trim();
          if (argument !== '' && /^['"][^'"]*['"]$/.test(argument)) continue;
          if (verdict !== 'confirm' && isStaticLiteralOnly(argument)) continue;
          const scope = windowAround(entry.content, match.index, 520);
          if (argument !== '' && isJsonLdSerialization(scope, argument)) continue;
          if (isHtmlSanitized(entry.content, scope)) continue;
          if (pythonSources.length > 0 && pattern === DOM_HTML_SINK && verdict !== 'confirm'
            && innerHtmlValueIsInert(entry.content, match.index, match.matchText)) continue;
          const dynamic = referencesUserInput(scope)
            || /\$\{|\bprops?\.|\bstate\.|\bsettings\.|\bconfig\.|\.\w+\b/.test(argument);
          if (verdict !== 'confirm' && !dynamic) continue;
          if (verdict !== 'confirm'
            && !referencesUserInput(scope)
            && valueIsDeveloperConstant(entry.content, argument)) continue;
          seen.add(match.line);
          const confidence = confidenceWithProof(verdict, referencesUserInput(scope) ? 'medium' : 'low');
          findings.push(
            makeFinding({
              ruleId: this.id,
              title: this.title,
              severity: confidence === 'low' ? 'medium' : 'high',
              confidence,
              filePath: entry.path,
              lineStart: match.line,
              evidence: match.snippet,
              userExplanation:
                'This code puts data into the page as raw HTML instead of plain text. If any of that data came from a user, they can inject a script that runs in other visitors browsers and steals their sessions. Render it as text, or clean the HTML first.',
              technicalExplanation:
                `${entry.path}:${match.line} writes a dynamic value into a raw-HTML sink. Established sanitizers such as DOMPurify are trusted; custom sanitize-like helpers must visibly escape HTML metacharacters to suppress this finding.`,
              fixHint:
                'Prefer rendering as text. If HTML is required, sanitize with DOMPurify or a proven equivalent before inserting, and never pass raw request or configurable content to these sinks.',
              category: this.category,
            }),
          );
        }
      }
      for (const sink of reflectedHtmlResponses(entry)) {
        if (seen.has(sink.line)) continue;
        if (astVerdict(ast, 'html', sink.line) === 'suppress') continue;
        seen.add(sink.line);
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: this.title,
            severity: 'high',
            confidence: 'medium',
            filePath: entry.path,
            lineStart: sink.line,
            evidence: lineAt(entry.content, sink.line).trim().slice(0, 240),
            userExplanation:
              'This route sends back an HTML page built from what the visitor sent. Anyone can craft a link that puts a script into that page, and it runs in the browser of whoever opens the link, with their session. Escape the value, or send it as text.',
            technicalExplanation:
              `${entry.path}:${sink.line} passes markup assembled from request-derived values to res.send/res.write/res.end, which Express serves as text/html. No escaper wraps the interpolated values.`,
            fixHint:
              'Escape every value before it goes into the HTML (for example escape-html: `${escapeHtml(q)}`), render a template that escapes by default, or send the value as text or JSON instead of HTML.',
            category: this.category,
          }),
        );
      }
      if (pythonSources.length > 0 && (entry.extension === '.html' || entry.extension === '.py')) {
        const rawOutputs: { index: number; line: number; values: string[]; evidence: string }[] = [];
        if (entry.extension === '.html' && HTML_ELEMENT.test(entry.content)) {
          for (const match of findMatches(entry.content, PY_TEMPLATE_SAFE)) {
            const [value = '', ...filters] = (match.groups[0] ?? '').split('|').map((part) => part.trim());
            if (value === '' || isStaticLiteralOnly(value) || isLayoutBodySlot(value, entry.content)) continue;
            if (filters.some((filter) => SANITISING_FILTER.test(filter.replace(/\(.*$/s, '').trim()))) continue;
            if (!isStored(value)) continue;
            const step = oneStep(value);
            const cls = step === undefined ? undefined : templateReceiverClass(context.fileMap.entries, entry, match.index, step.root);
            if (step !== undefined && receiverKeeps(context.fileMap.entries, cls, step.leaf) === 'drop') continue;
            rawOutputs.push({ index: match.index, line: match.line, values: [value], evidence: match.snippet });
          }
        } else if (entry.extension === '.py') {
          const code = stripCommentsOnly(entry.content, true);
          for (const match of findMatches(code, PY_MARK_SAFE)) {
            const argument = pythonCallArguments(code, match.index + match.matchText.length - 1);
            if (argument === undefined || argument.trim() === '' || isStaticLiteralOnly(argument)) continue;
            const values = markSafeValues(argument).filter((value) => {
              if (!isStored(value)) return false;
              const step = oneStep(value);
              if (step === undefined) return true;
              const cls = pythonReceiverClass(context.fileMap.entries, entry, match.line, step.root);
              if (receiverKeeps(context.fileMap.entries, cls, step.leaf) === 'drop') return false;
              return !sanitisedInFunction(entry.content, match.line, step.root, step.leaf);
            });
            if (values.length === 0) continue;
            rawOutputs.push({ index: match.index, line: match.line, values, evidence: lineAt(entry.content, match.line) });
          }
        }
        for (const raw of rawOutputs) {
          if (seen.has(raw.line)) continue;
          if (isInsideComment(entry.content, raw.index, entry.extension, entry.label)) continue;
          seen.add(raw.line);
          findings.push(
            makeFinding({
              ruleId: this.id,
              title: this.title,
              severity: 'high',
              confidence: 'medium',
              filePath: entry.path,
              lineStart: raw.line,
              evidence: raw.evidence,
              userExplanation:
                'This page writes a stored value into the page as raw HTML instead of plain text. Jinja and Django escape values automatically; this one has been marked safe so they do not. If that value ever contains anything a user typed, such as a post, a profile or a comment, it can carry a script that runs in the browser of everyone who views the page.',
              technicalExplanation:
                `${entry.path}:${raw.line} marks \`${raw.values.join(', ').slice(0, 80)}\` as safe HTML (|safe or mark_safe) with no sanitiser this scan can see. The escaping default has been explicitly overridden, so this is reported wherever the value is not a literal.`,
              fixHint:
                'Drop |safe / mark_safe and let the template escape the value. If it must be HTML, clean it first with bleach.clean or nh3.clean and an allow-list of tags, or build it with format_html / Markup.format, which escape their arguments.',
              category: this.category,
            }),
          );
        }
      }
      for (const [line] of userTaintedLines(ast, 'html')) {
        if (seen.has(line)) continue;
        if (isHtmlSanitized(entry.content, routeHandlerScopeForLine(entry.content, line))) continue;
        const lineStart = indexOfLine(entry.content, line);
        if (lineStart !== undefined
          && isInsideComment(entry.content, lineStart, entry.extension, entry.label)) continue;
        seen.add(line);
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: this.title,
            severity: 'high',
            confidence: 'high',
            filePath: entry.path,
            lineStart: line,
            evidence: lineAt(entry.content, line),
            userExplanation:
              'This code puts user-controlled data into the page as raw HTML. A user can inject a script that runs in other visitors browsers and steals their sessions.',
            technicalExplanation:
              `${entry.path}:${line}: syntax-aware analysis traced request-derived data into a raw-HTML sink with no proven sanitizer recognised in this file.`,
            fixHint:
              'Validate and constrain the user-supplied value before it reaches this sink, or render it as text instead of HTML.',
            category: this.category,
          }),
        );
      }
    }
    return findings;
  },
};


