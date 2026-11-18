import type { Finding, RuleContext, ScanRule } from '../../shared/types.js';
import { pythonCallArguments } from '../../shared/pythonSettings.js';
import { patternRule, type Probe } from './patternRule.js';
import { pythonOwnRaiseOnly, pythonRaiserIndex, type RaiserIndex } from '../../shared/pythonRaises.js';
import { pythonHandlerSpan, pythonRouteGuard } from '../../shared/pythonGuards.js';
import { pythonNameProved, pythonReadsOnlyProved } from '../../shared/pythonFlow.js';

// A 4xx status means the message is meant for the caller.
const STATUS_LITERAL = /\bstatus(?:Code)?\s*[:(=]\s*(\d{3})\b/g;

function closingParen(content: string, openParenIndex: number): number | undefined {
  if (content[openParenIndex] !== '(') return undefined;
  let depth = 0;
  for (let i = openParenIndex; i < content.length && i < openParenIndex + 600; i += 1) {
    const ch = content[i];
    if (ch === '(') depth += 1;
    else if (ch === ')') {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return undefined;
}

function respondsWithClientErrorOnly(content: string, index: number): boolean {
  const lineStart = content.lastIndexOf('\n', index) + 1;
  const open = content.indexOf('(', index);
  const close = open === -1 ? undefined : closingParen(content, open);
  const end = close ?? content.indexOf('\n', index);
  if (end === -1 || end <= lineStart) return false;
  const call = content.slice(lineStart, end + 1);
  STATUS_LITERAL.lastIndex = 0;
  const codes = [...call.matchAll(STATUS_LITERAL)].map((match) => Number(match[1]));
  if (codes.length === 0) return false;
  return codes.every((code) => code >= 400 && code < 500);
}

// A stack trace is never a message meant for the caller.
const CARRIES_A_STACK = /\.\s*stack\b|stack\s*:\s*err/;

const NODE_PROBE: Probe = {
  pattern: /(?:res\.(?:json|send)|NextResponse\.json)\s*\([^\n;]{0,240}\b(?:err(?:or)?\.(?:stack|message)|stack\s*:\s*err)/g,
  title: 'Node error details returned', severity: 'medium', confidence: 'high',
  explanation: 'An HTTP response exposes an exception message or stack trace. This can reveal file paths, queries, libraries, and other details useful to attackers.',
  technical: 'Server exception details flow directly into the client response.',
  fix: 'Return a fixed public error code/message and log the detailed exception only in protected server-side telemetry.',
  suppress: ({ content, index, matchText }) =>
    !CARRIES_A_STACK.test(matchText) && respondsWithClientErrorOnly(content, index),
};

const PYTHON_SAME_LINE =
  /(?:jsonify\s*\(|JSONResponse\s*\(|HTTPException\s*\([^)]*detail\s*=)[^\n]{0,180}(?:str\s*\(\s*(?:e|err|exc)|traceback)/y;
const PYTHON_RESPONDING_CALL = /(?:jsonify|JSONResponse|HTTPException|(?<![\w.])Response)\s*\(/g;
const PYTHON_LEAK = /str\s*\(\s*(?:e|err|exc)|traceback/;
const PYTHON_TRACEBACK = /traceback/;
// str(exc) used only as a lookup key never reaches the response.
const PYTHON_LOOKUP_KEY = /\.get\s*\(\s*str\s*\(\s*(?:e|err|exc)\w*\s*\)\s*(?=[,)])/g;
const PYTHON_MESSAGE_OF = /str\s*\(\s*((?:e|err|exc)\w*)\s*\)/g;
const PROJECT_CLASS = /^[ \t]*class[ \t]+([A-Za-z_]\w*)/gm;
const APP_RAISED = /\braise\s+(?:[A-Za-z_]\w*\.)*(HTTPException|ValidationError)\s*\(/g;
const APP_OWNED_FRAMEWORK_ERRORS = new Set(['HTTPException', 'ValidationError']);
const BINDING_LOOKBACK_CHARS = 4000;

const escapeName = (name: string): string => name.replace(/[$]/g, '\\$&');

const PYTHON_STR_CANDIDATE = /str\s*\(\s*(?:e|err|exc)/;
const TRACEBACK_CALL = /\btraceback\s*\.\s*(?:format_exc|format_exception|format_exception_only|format_tb|format_stack|extract_tb|extract_stack|print_exc|print_exception)\s*\(/;
const TRACEBACK_IMPORTED_CALL = /(?<![\w.])(?:format_exc|format_exception|format_tb|extract_tb|print_exc)\s*\(/;

const RESPONDING_HEAD = /^\s*(?:jsonify|JSONResponse|HTTPException|Response)\s*\(/;

function tracebackCarried(content: string, index: number, text: string): boolean {
  if (!PYTHON_TRACEBACK.test(text)) return false;
  const imported = /^\s*from\s+traceback\s+import\b/m.test(content);
  if (TRACEBACK_CALL.test(text) || (imported && TRACEBACK_IMPORTED_CALL.test(text))) return true;
  return !pythonReadsOnlyProved(content, index, text.replace(RESPONDING_HEAD, ''));
}

function boundClasses(content: string, index: number, name: string): string[] | undefined {
  const from = Math.max(0, index - BINDING_LOOKBACK_CHARS);
  const before = content.slice(from, index);
  const n = escapeName(name);
  const binders = [
    new RegExp(`\\bexcept\\s+\\(?([^:\\n]+?)\\)?\\s+as\\s+${n}\\s*:`, 'g'),
    new RegExp(`[(,]\\s*${n}\\s*:\\s*([A-Za-z_][\\w.]*)\\s*[,)=]`, 'g'),
  ];
  let best: { at: number; types: string } | undefined;
  for (const binder of binders) {
    for (const match of before.matchAll(binder)) {
      if (best === undefined || match.index > best.at) best = { at: match.index, types: match[1] ?? '' };
    }
  }
  if (best === undefined) return undefined;
  return best.types
    .split(',')
    .map((part) => part.trim().split('.').pop() ?? '')
    .filter((part) => part !== '');
}

function pythonProjectFacts(context: RuleContext): { classes: Set<string>; raised: Set<string>; raisers: RaiserIndex } {
  const classes = new Set<string>();
  const raised = new Set<string>();
  for (const entry of context.fileMap.entries) {
    if (entry.extension !== '.py') continue;
    for (const match of entry.content.matchAll(PROJECT_CLASS)) if (match[1] !== undefined) classes.add(match[1]);
    for (const match of entry.content.matchAll(APP_RAISED)) if (match[1] !== undefined) raised.add(match[1]);
  }
  return { classes, raised, raisers: pythonRaiserIndex(context.fileMap.entries) };
}

function pythonProbe(facts: { classes: Set<string>; raised: Set<string>; raisers: RaiserIndex }): Probe {
  const appWritten = (type: string): boolean =>
    facts.classes.has(type) || (APP_OWNED_FRAMEWORK_ERRORS.has(type) && facts.raised.has(type));
  return {
    pattern: PYTHON_RESPONDING_CALL,
    title: 'Python exception returned', severity: 'medium', confidence: 'high',
    explanation: 'A Python endpoint appears to return raw exception details to the caller.',
    technical: 'The response serializes an exception or traceback instead of a stable public error.',
    fix: 'Return a generic public error and record the exception in access-controlled server logs with a correlation ID.',
    suppress: ({ content, index, matchText, path }) => {
      PYTHON_SAME_LINE.lastIndex = index;
      const sameLine = PYTHON_SAME_LINE.exec(content);
      const args = pythonCallArguments(content, index + matchText.length - 1);
      const leak = [sameLine?.[0], args]
        .map((text) => text?.replace(PYTHON_LOOKUP_KEY, '.get(_'))
        .filter((text): text is string => text !== undefined && PYTHON_LEAK.test(text));
      if (leak.length === 0) return true;
      const isPython = path.endsWith('.py');
      if (isPython) {
        const lineEnd = content.indexOf('\n', index);
        const judged = [sameLine === null ? undefined : content.slice(index, lineEnd === -1 ? content.length : lineEnd), args]
          .filter((text): text is string => text !== undefined && PYTHON_TRACEBACK.test(text));
        if (judged.length > 0 && args === undefined) return false;
        if (judged.some((text) => tracebackCarried(content, index, text))) return false;
      } else if (leak.some((text) => PYTHON_TRACEBACK.test(text))) return false;
      let names = new Set(leak.flatMap((text) => [...text.matchAll(PYTHON_MESSAGE_OF)].map((m) => m[1] ?? '')));
      if (isPython) {
        if (!leak.some((text) => PYTHON_STR_CANDIDATE.test(text))) return true;
        const whole = args !== undefined && PYTHON_LEAK.test(args) ? [args] : leak;
        if (whole.some((text) => PYTHON_STR_CANDIDATE.test(text.replace(PYTHON_MESSAGE_OF, '_')))) return false;
        const candidates = names.size;
        names = new Set([...names].filter((name) => !pythonNameProved(content, index, name)));
        if (candidates > 0 && names.size === 0) return true;
      }
      if (names.size === 0) return false;
      return [...names].every((name) => {
        const types = boundClasses(content, index, name);
        if (types !== undefined && types.length > 0 && types.every(appWritten)) return true;
        return pythonOwnRaiseOnly(content, index, name, facts.raisers);
      });
    },
  };
}

function adminOnlyPython(context: RuleContext, finding: Finding): boolean {
  if (!finding.filePath.endsWith('.py')) return false;
  for (const route of context.projectMap.apiRoutes) {
    if (route.filePath !== finding.filePath) continue;
    const span = pythonHandlerSpan(context, route);
    if (span === undefined || finding.lineStart < span.startLine || finding.lineStart > span.endLine) continue;
    return pythonRouteGuard(context, route, finding.lineStart)?.level === 'admin';
  }
  return false;
}

export const verboseErrorResponse: ScanRule = {
  id: 'verbose_error_response',
  title: 'Response may expose internal error details',
  category: 'data_exposure',
  kind: 'basic',
  run(context: RuleContext): Finding[] {
    const findings = patternRule({
      id: this.id,
      title: this.title,
      category: this.category,
      probes: [NODE_PROBE, pythonProbe(pythonProjectFacts(context))],
    }).run(context);
    return findings.map((finding) => adminOnlyPython(context, finding) ? { ...finding, severity: 'low' } : finding);
  },
};
