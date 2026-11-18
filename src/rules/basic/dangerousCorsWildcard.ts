import { detectSupabaseFunctionAuth } from '../../shared/supabaseFunctionAuth.js';
import { cookieAuthenticationIn, deploymentUnitOf, usesCookieAuthentication } from '../../shared/cookieAuthentication.js';
import { makeFinding } from '../../shared/findingFactory.js';
import type { Confidence, Finding, RuleContext, ScanRule, Severity } from '../../shared/types.js';
import { windowAround } from '../../shared/userInput.js';
import { findMatches } from '../../shared/utils.js';
import { entryFor, importedFrom } from '../../shared/importedVerifier.js';
import { balanced, middlewareBodyOf } from '../../shared/middlewareGuard.js';
import { stripCommentsOnly } from '../../shared/source.js';
import { isPythonNonProductionSetting, pythonCallArguments } from '../../shared/pythonSettings.js';

const WILDCARD_HEADER = /['"]Access-Control-Allow-Origin['"]\s*[,:]\s*['"]\*['"]/gi;

const REFLECTED_ORIGIN_HEADER = /['"]access-control-allow-origin['"]\s*[,:]\s*[^\n]*\borigin\b/gi;

// An exact origin allowlist near the reflected origin makes it safe.
const LOCAL_ORIGIN_ALLOWLIST =
  /\b(?:allowed|permitted|valid|accepted|whitelist|allowlist|origins?)[\w$]*\s*\.\s*(?:includes|has|indexOf|some|find)\s*\(|\b(?:includes|has)\s*\(\s*[\w$.]*origin\b|\borigin\s*===|===\s*[\w$.]*origin\b/i;
const CORS_OPTIONS_BLOCK = /cors\s*\(\s*\{[\s\S]{0,300}?\}\s*\)/g;
const BARE_CORS_CALL = /app\.use\(\s*cors\(\s*\)\s*\)/g;
const CODE_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py']);

const ORIGIN_ARGUMENT_CALL = /\b([A-Za-z_$][\w$]*)\s*\(\s*(?:[\w$]+\s*\.\s*)*origin\s*[,)]/gi;
const CALLEE_NOT_A_GUARD = /^(?:if|for|while|switch|return|catch|function|typeof|await|new)$/i;
const MAX_ORIGIN_PREDICATES = 3;

const COLLECTION_LOOP = /\.\s*(?:some|findIndex|find)\s*\(/g;
const SUBSTRING_TEST = /\.\s*(?:startsWith|endsWith|indexOf|lastIndexOf|includes)\s*\(/g;
const REGEX_TEST_ON_ARGUMENT = /\.\s*(?:test|exec)\s*\(/g;
const REGEX_TEST_ON_RECEIVER = /\.\s*(?:match|matchAll|search)\s*\(/g;
const HELPER_CALL = /(?<![\w$.])([A-Za-z_$][\w$]*)\s*\(/g;
const STRING_LITERAL = /(['"])((?:\\.|(?!\1)[^\\\n])*)\1/g;
const MAX_LOOPS_PER_PREDICATE = 5;
const MAX_HELPERS_PER_CALLBACK = 3;
const MAX_LIST_CHARS = 2_000;
const MAX_DECLARATION_BODY_CHARS = 12_000;

const escapeName = (name: string): string => name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function splitTopLevel(text: string, angles = false): string[] {
  const parts: string[] = [];
  let depth = 0;
  let start = 0;
  let quote: string | undefined;
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i];
    if (quote !== undefined) {
      if (c === '\\') i += 1;
      else if (c === quote) quote = undefined;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') quote = c;
    else if (c === '(' || c === '[' || c === '{' || (angles && c === '<')) depth += 1;
    else if (c === ')' || c === ']' || c === '}' || (angles && c === '>' && text[i - 1] !== '=')) depth -= 1;
    else if (c === ',' && depth === 0) {
      parts.push(text.slice(start, i).trim());
      start = i + 1;
    }
  }
  const last = text.slice(start).trim();
  if (last !== '' || parts.length === 0) parts.push(last);
  return parts;
}

const parameterName = (parameter: string): string | undefined =>
  /^(?:(?:public|private|protected|readonly)\s+)*([A-Za-z_$][\w$]*)\s*(?:[?!]?\s*[:=]|$)/.exec(parameter)?.[1];

interface Declaration {
  params: (string | undefined)[];
  body: string;
}

function declarationOf(content: string, name: string): Declaration | undefined {
  const body = middlewareBodyOf(content, name);
  if (body === undefined) return undefined;
  const n = escapeName(name);
  const heads = [
    new RegExp(`(?:export\\s+)?(?:default\\s+)?(?:async\\s+)?function\\s*\\*?\\s+${n}\\s*\\(`),
    new RegExp(`(?:export\\s+)?(?:const|let|var)\\s+${n}\\s*(?::[^=\\n]{0,200})?=\\s*(?:async\\s+)?function\\b[^(]{0,80}\\(`),
    new RegExp(`(?:export\\s+)?(?:const|let|var)\\s+${n}\\s*(?::[^=\\n]{0,200})?=\\s*(?:async\\s*)?\\(`),
  ];
  for (const [index, head] of heads.entries()) {
    const match = head.exec(content);
    if (match === null) continue;
    const params = balanced(content, match.index + match[0].length - 1, '(', ')', MAX_LIST_CHARS);
    if (params === undefined) return undefined;
    const tail = content.slice(params.end + 1, params.end + 1 + 400);
    const opens = (index === 2 ? /^\s*(?::[^{=]{0,200})?=>\s*\{/ : /^\s*(?::[^{=]{0,200})?\{/).exec(tail);
    if (opens === null) return undefined;
    const own = balanced(content, params.end + opens[0].length, '{', '}', MAX_DECLARATION_BODY_CHARS);
    if (own?.inner !== body) return undefined;
    return { params: splitTopLevel(params.inner, true).map(parameterName), body };
  }
  return undefined;
}

function inlineCallback(argument: string): { element: string; body: string } | undefined {
  const arrow =
    /^(?:async\s+)?(?:\(\s*([A-Za-z_$][\w$]*)\s*(?::[^,()]*)?(?:,[^()]*)?\)|([A-Za-z_$][\w$]*))\s*(?::[^=()]{0,80})?=>([\s\S]*)$/.exec(
      argument,
    );
  const element = arrow?.[1] ?? arrow?.[2];
  if (arrow !== null && element !== undefined) return { element, body: arrow[3] ?? '' };
  const fn = /^(?:async\s+)?function\b[^(]*\(\s*([A-Za-z_$][\w$]*)[^)]*\)\s*(?::[^{]{0,80})?\{([\s\S]*)\}$/.exec(argument);
  if (fn?.[1] !== undefined) return { element: fn[1], body: fn[2] ?? '' };
  return undefined;
}

const OPERAND_ENDS = '(?![\\w$])(?!\\s*(?:\\?\\.|\\.|\\(|\\[))';

function comparesExactly(code: string, a: string, b: string, operator: string): boolean {
  const operand = (name: string): string => `(?<![\\w$.])${escapeName(name)}${OPERAND_ENDS}`;
  const op = `\\s*(?<![=!<>])${operator}(?!=)\\s*`;
  return new RegExp(`${operand(a)}${op}${operand(b)}|${operand(b)}${op}${operand(a)}`).test(code);
}

function bareReceiver(code: string, dot: number): string | undefined {
  return /(?:^|[^\w$.\])?])([A-Za-z_$][\w$]*)\s*\??$/.exec(code.slice(0, dot))?.[1];
}

function asksAboutThePattern(code: string, dot: number, callOpen: number, element: string | undefined): boolean {
  if (element === undefined || bareReceiver(code, dot) !== element) return false;
  const args = balanced(code, callOpen, '(', ')', MAX_LIST_CHARS);
  return args !== undefined && /^\s*(['"])(?:\\.|(?!\1)[^\\\n])*\1\s*$/.test(args.inner);
}

function substringTestIn(code: string, element?: string): boolean {
  for (const match of code.matchAll(SUBSTRING_TEST)) {
    if (!asksAboutThePattern(code, match.index, match.index + match[0].length - 1, element)) return true;
  }
  return false;
}

function literalAnchored(source: string, flags: string): boolean {
  if (flags.includes('m') || !source.startsWith('^') || !source.endsWith('$')) return false;
  const slashes = /(\\*)\$$/.exec(source)?.[1]?.length ?? 0;
  if (slashes % 2 === 1) return false;
  let depth = 0;
  let inClass = false;
  for (let i = 0; i < source.length; i += 1) {
    const c = source[i];
    if (c === '\\') i += 1;
    else if (inClass) inClass = c !== ']';
    else if (c === '[') inClass = true;
    else if (c === '(') depth += 1;
    else if (c === ')') depth -= 1;
    else if (c === '|' && depth === 0) return false;
  }
  return true;
}

const REGEX_LITERAL_AT_END = /\/((?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\n[])+)\/([a-z]*)$/;
const REGEX_LITERAL_WHOLE = /^\/((?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\n[])+)\/([a-z]*)$/;

function regexAnchored(code: string, expression: string, followIdentifier = true): boolean {
  const text = expression.trim();
  const literal = REGEX_LITERAL_WHOLE.exec(text);
  if (literal !== null) return literalAnchored(literal[1] ?? '', literal[2] ?? '');
  const constructed = /^(?:new\s+)?RegExp\s*\(/.exec(text);
  if (constructed !== null) {
    const args = balanced(text, constructed[0].length - 1, '(', ')', MAX_LIST_CHARS);
    if (args === undefined || args.end !== text.length - 1) return false;
    const [pattern = '', flags, ...rest] = splitTopLevel(args.inner);
    if (rest.length > 0) return false;
    if (flags !== undefined && !/^(['"])[a-z]*\1$/.test(flags)) return false;
    if (flags?.includes('m') === true) return false;
    const whole = REGEX_LITERAL_WHOLE.exec(pattern);
    if (whole !== null) return literalAnchored(whole[1] ?? '', whole[2] ?? '');
    for (const piece of pattern.matchAll(STRING_LITERAL)) if (piece[2]?.includes('|') === true) return false;
    const opensWithCaret = /^(['"])\^/.test(pattern);
    const closesWithDollar = /(?:^|[^\\])\$(['"])$/.test(pattern);
    return opensWithCaret && closesWithDollar;
  }
  if (!followIdentifier || !/^[A-Za-z_$][\w$]*$/.test(text)) return false;
  const n = escapeName(text);
  const bindings = [...code.matchAll(new RegExp(`(?<![\\w$.])${n}\\s*(?::[^=\\n]{0,80})?=(?![=>])`, 'g'))];
  const declared = new RegExp(`(?:const|let|var)\\s+${n}\\s*(?::[^=\\n]{0,80})?=(?![=>])\\s*`).exec(code);
  if (bindings.length !== 1 || declared === null) return false;
  const from = declared.index + declared[0].length;
  const value = code.slice(from);
  const call = /^(?:new\s+)?RegExp\s*\(/.exec(value);
  if (call !== null) {
    const args = balanced(value, call[0].length - 1, '(', ')', MAX_LIST_CHARS);
    return args !== undefined && regexAnchored(code, value.slice(0, args.end + 1), false);
  }
  const lit = /^\/((?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\n[])+)\/([a-z]*)/.exec(value);
  return lit !== null && literalAnchored(lit[1] ?? '', lit[2] ?? '');
}

function regexTestsIn(code: string): { subject: string; anchored: boolean }[] {
  const tests: { subject: string; anchored: boolean }[] = [];
  for (const match of code.matchAll(REGEX_TEST_ON_ARGUMENT)) {
    const args = balanced(code, match.index + match[0].length - 1, '(', ')', MAX_LIST_CHARS);
    const before = code.slice(0, match.index).trimEnd();
    let receiver: string | undefined;
    if (before.endsWith(')')) {
      let depth = 0;
      for (let i = before.length - 1; i >= 0; i -= 1) {
        if (before[i] === ')') depth += 1;
        if (before[i] !== '(') continue;
        depth -= 1;
        if (depth > 0) continue;
        const callee = /(?:new\s+)?RegExp\s*$/.exec(before.slice(0, i));
        receiver = callee === null ? undefined : before.slice(callee.index);
        break;
      }
    } else {
      const identifier = /(?<![\w$])[A-Za-z_$][\w$]*$/.exec(before);
      const prior = identifier === null ? '' : before[identifier.index - 1];
      receiver =
        identifier !== null && prior !== '/' && prior !== '.' ? identifier[0] : REGEX_LITERAL_AT_END.exec(before)?.[0];
    }
    tests.push({
      subject: args?.inner.trim() ?? '',
      anchored: receiver !== undefined && regexAnchored(code, receiver),
    });
  }
  for (const match of code.matchAll(REGEX_TEST_ON_RECEIVER)) {
    const args = balanced(code, match.index + match[0].length - 1, '(', ')', MAX_LIST_CHARS);
    const pattern = args === undefined ? undefined : splitTopLevel(args.inner)[0];
    tests.push({
      subject: bareReceiver(code, match.index) ?? '',
      anchored: pattern !== undefined && regexAnchored(code, pattern),
    });
  }
  return tests;
}

function helperProvesExactMatch(
  context: RuleContext,
  predicatePath: string,
  predicateName: string,
  callback: { element: string; body: string },
  origin: string,
): boolean {
  let examined = 0;
  for (const call of callback.body.matchAll(HELPER_CALL)) {
    const name = call[1];
    if (name === undefined || name === predicateName || CALLEE_NOT_A_GUARD.test(name)) continue;
    if (/\bnew\s*$/.test(callback.body.slice(0, call.index))) continue;
    const args = balanced(callback.body, call.index + call[0].length - 1, '(', ')', MAX_LIST_CHARS);
    if (args === undefined) continue;
    const passed = splitTopLevel(args.inner);
    const originAt = passed.indexOf(origin);
    const elementAt = passed.indexOf(callback.element);
    if (originAt === -1 || elementAt === -1) continue;
    if (examined >= MAX_HELPERS_PER_CALLBACK) return false;
    examined += 1;
    const entry = entryFor(context, importedFrom(context, predicatePath, name) ?? predicatePath);
    const helper = entry === undefined ? undefined : declarationOf(entry.content, name);
    const helperOrigin = helper?.params[originAt];
    const helperElement = helper?.params[elementAt];
    if (helper === undefined || helperOrigin === undefined || helperElement === undefined) continue;
    if (helperOrigin === helperElement) continue;
    const code = stripCommentsOnly(helper.body);
    if (substringTestIn(code, helperElement)) continue;
    const tests = regexTestsIn(code);
    if (tests.some((test) => !test.anchored)) continue;
    if (comparesExactly(code, helperOrigin, helperElement, '===')) return true;
    if (tests.some((test) => test.subject === helperOrigin)) return true;
  }
  return false;
}

function loopProvesExactMembership(context: RuleContext, path: string, content: string, name: string): boolean {
  const predicate = declarationOf(content, name);
  const origin = predicate?.params[0];
  if (predicate === undefined || origin === undefined) return false;
  const code = stripCommentsOnly(predicate.body);
  if (substringTestIn(code)) return false;
  if (regexTestsIn(code).some((test) => !test.anchored)) return false;
  let loops = 0;
  for (const loop of code.matchAll(COLLECTION_LOOP)) {
    if ((loops += 1) > MAX_LOOPS_PER_PREDICATE) return false;
    const args = balanced(code, loop.index + loop[0].length - 1, '(', ')', MAX_DECLARATION_BODY_CHARS);
    const callback = args === undefined ? undefined : inlineCallback(splitTopLevel(args.inner)[0] ?? '');
    if (callback === undefined || callback.element === origin) continue;
    if (comparesExactly(callback.body, callback.element, origin, '={2,3}')) return true;
    if (helperProvesExactMatch(context, path, name, callback, origin)) return true;
  }
  return false;
}

function resolvedPredicateProvesOriginAllowlist(
  context: RuleContext,
  filePath: string,
  window: string,
): boolean {
  let examined = 0;
  for (const match of window.matchAll(ORIGIN_ARGUMENT_CALL)) {
    const name = match[1];
    if (name === undefined || CALLEE_NOT_A_GUARD.test(name)) continue;
    if (examined >= MAX_ORIGIN_PREDICATES) return false;
    examined += 1;
    const definedIn = importedFrom(context, filePath, name) ?? filePath;
    const entry = entryFor(context, definedIn);
    if (entry === undefined) continue;
    const body = middlewareBodyOf(entry.content, name);
    if (body === undefined) continue;
    if (LOCAL_ORIGIN_ALLOWLIST.test(body)) return true;
    if (loopProvesExactMembership(context, definedIn, entry.content, name)) return true;
  }
  return false;
}

// A wildcard origin is high severity only when credentials are allowed.
const ALLOW_CREDENTIALS_HEADER = /['"]?Access-Control-Allow-Credentials['"]?\s*[,:]\s*['"]?true['"]?/i;

const ORIGIN_HEADER_READ =
  /headers\s*(?:\.\s*get\s*\(\s*['"]origin['"]|\[\s*['"]origin['"]\s*\]|\.\s*origin\b)|\.\s*(?:header|get)\s*\(\s*['"]origin['"]/i;

const ORIGIN_ALLOWLIST_TEST =
  /\b(?:allowed|permitted|valid|accepted|whitelist|allowlist)[\w$]*\s*\.\s*(?:includes|has|indexOf|some|find)\s*\(|\b(?:includes|has)\s*\(\s*[\w$.]*origin\b/i;

function hasOriginAllowlistGuard(content: string): boolean {
  return ORIGIN_HEADER_READ.test(content) && ORIGIN_ALLOWLIST_TEST.test(content);
}

type CredentialEvidence = 'option' | 'header' | 'cookie-project' | 'none';

type OriginForm = 'reflected' | 'literal';

interface WildcardVerdict {
  severity: Severity;
  confidence: Confidence;
  credentialed: boolean;
  evidence: CredentialEvidence;
  supabaseEdge?: { name: string; verifyJwt: boolean };
}

const EVIDENCE_CLAUSE: Record<Exclude<CredentialEvidence, 'none'>, string> = {
  option: 'credentials: true in the same cors() options sends Access-Control-Allow-Credentials: true',
  header: 'this file sets Access-Control-Allow-Credentials: true',
  'cookie-project': 'this project authenticates with a cookie-based session',
};

const SUPABASE_FUNCTION_DIR = /(?:^|\/)supabase\/functions\/([^/]+)\//;

function supabaseEdgeLookup(context: RuleContext): (path: string) => { name: string; verifyJwt: boolean } | undefined {
  const byName = new Map<string, boolean>();
  for (const fn of detectSupabaseFunctionAuth(context.fileMap)) byName.set(fn.name, fn.verifyJwt);
  return (path: string) => {
    const name = SUPABASE_FUNCTION_DIR.exec(path)?.[1];
    if (name === undefined) return undefined;
    const verifyJwt = byName.get(name);
    return verifyJwt === undefined ? undefined : { name, verifyJwt };
  };
}

interface PythonCorsShape {
  index: number;
  credentials: boolean;
  library: 'starlette' | 'flask-cors' | 'django-cors-headers';
}
const STARLETTE_CORS = /\bCORSMiddleware\s*,/g;
const STARLETTE_ALL_ORIGINS = /\ballow_origins\s*=\s*(?:\[\s*['"]\*['"]\s*,?\s*\]|\(\s*['"]\*['"]\s*,?\s*\)|['"]\*['"])/;
const STARLETTE_CREDENTIALS = /\ballow_credentials\s*=\s*True\b/;
const FLASK_CORS_CALL = /(?<![\w.])(?:CORS|cross_origin)\s*\(/g;
const FLASK_CORS_ALL_ORIGINS = /\borigins\s*=\s*(?:\[\s*['"]\*['"]\s*,?\s*\]|['"]\*['"])/;
const FLASK_CORS_CREDENTIALS = /\bsupports_credentials\s*=\s*True\b/;
const DJANGO_CORS_ALL = /^[ \t]*(?:CORS_ALLOW_ALL_ORIGINS|CORS_ORIGIN_ALLOW_ALL)\s*=\s*True\b/gm;
const DJANGO_CORS_CREDENTIALS = /^[ \t]*CORS_ALLOW_CREDENTIALS\s*=\s*True\b/m;

function enclosingCallOpen(code: string, index: number): number | undefined {
  let depth = 0;
  for (let i = index - 1; i >= 0 && index - i < 2_000; i -= 1) {
    const c = code[i];
    if (c === ')' || c === ']' || c === '}') depth += 1;
    else if (c === '(' || c === '[' || c === '{') {
      if (depth === 0) return c === '(' ? i : undefined;
      depth -= 1;
    }
  }
  return undefined;
}

function pythonCorsWildcards(path: string, code: string): PythonCorsShape[] {
  const shapes: PythonCorsShape[] = [];
  for (const match of code.matchAll(STARLETTE_CORS)) {
    const open = enclosingCallOpen(code, match.index);
    const args = open === undefined ? undefined : pythonCallArguments(code, open);
    if (open === undefined || args === undefined) continue;
    const origins = STARLETTE_ALL_ORIGINS.exec(args);
    if (origins === null) continue;
    shapes.push({ index: open + 1 + origins.index, credentials: STARLETTE_CREDENTIALS.test(args), library: 'starlette' });
  }
  for (const match of code.matchAll(FLASK_CORS_CALL)) {
    const args = pythonCallArguments(code, match.index + match[0].length - 1);
    if (args === undefined || !FLASK_CORS_ALL_ORIGINS.test(args)) continue;
    shapes.push({ index: match.index, credentials: FLASK_CORS_CREDENTIALS.test(args), library: 'flask-cors' });
  }
  for (const match of code.matchAll(DJANGO_CORS_ALL)) {
    const at = match.index + (match[0].length - match[0].trimStart().length);
    shapes.push({ index: at, credentials: DJANGO_CORS_CREDENTIALS.test(code), library: 'django-cors-headers' });
  }
  return shapes.filter((shape) => !isPythonNonProductionSetting(path, code, shape.index));
}

const PYTHON_CORS_WORDING: Record<PythonCorsShape['library'], { form: string; reflected: string; literal: string; fix: string }> = {
  starlette: {
    form: 'CORSMiddleware is configured with allow_origins=["*"], which',
    reflected: "CORSMiddleware is configured with allow_origins=[\"*\"] and allow_credentials=True, which makes Starlette echo the request's own Origin header back",
    literal: 'CORSMiddleware is configured with allow_origins=["*"], which sends the literal "*"',
    fix: 'Pass the origins you serve, e.g. allow_origins=["https://yourapp.com"], and keep allow_credentials=True only with that explicit list.',
  },
  'flask-cors': {
    form: 'flask-cors is configured with origins="*", which',
    reflected: "flask-cors is configured with origins=\"*\" and supports_credentials=True, which makes it echo the request's own Origin header back",
    literal: 'flask-cors is configured with origins="*", which sends the literal "*"',
    fix: 'Pass the origins you serve, e.g. CORS(app, origins=["https://yourapp.com"], supports_credentials=True). Never combine a wildcard origin with credentials.',
  },
  'django-cors-headers': {
    form: 'django-cors-headers is configured with CORS_ALLOW_ALL_ORIGINS = True, which',
    reflected: "django-cors-headers is configured with CORS_ALLOW_ALL_ORIGINS = True and CORS_ALLOW_CREDENTIALS = True, which makes it echo the request's own Origin header back",
    literal: 'django-cors-headers is configured with CORS_ALLOW_ALL_ORIGINS = True, which sends the literal "*"',
    fix: 'Replace CORS_ALLOW_ALL_ORIGINS = True with CORS_ALLOWED_ORIGINS = ["https://yourapp.com"]. Never combine allow-all with CORS_ALLOW_CREDENTIALS = True.',
  },
};

export const dangerousCorsWildcard: ScanRule = {
  id: 'dangerous_cors_wildcard',
  title: 'CORS allows all origins',
  category: 'cors',
  kind: 'basic',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const cookieProject = usesCookieAuthentication(context);
    const supabaseEdgeFor = supabaseEdgeLookup(context);
    const cookieByUnit = new Map<string, boolean>();
    const cookieEvidenceFor = (filePath: string): boolean => {
      const unit = deploymentUnitOf(filePath);
      if (unit === undefined) return cookieProject;
      const cached = cookieByUnit.get(unit);
      if (cached !== undefined) return cached;
      const answer = cookieAuthenticationIn(
        context.fileMap.entries.filter((candidate) => deploymentUnitOf(candidate.path) === unit),
      );
      cookieByUnit.set(unit, answer);
      return answer;
    };

    const verdictFor = (
      entry: { path: string; content: string },
      credentialsInBlock: boolean,
      origin: OriginForm,
    ): WildcardVerdict => {
      const evidence: CredentialEvidence = credentialsInBlock
        ? 'option'
        : ALLOW_CREDENTIALS_HEADER.test(entry.content)
          ? 'header'
          : cookieEvidenceFor(entry.path)
            ? 'cookie-project'
            : 'none';
      const edge = supabaseEdgeFor(entry.path);
      if (evidence === 'none') {
        return { severity: 'low', confidence: 'low', credentialed: false, evidence, ...(edge ? { supabaseEdge: edge } : {}) };
      }
      if (origin === 'literal') {
        return { severity: 'low', confidence: 'low', credentialed: false, evidence, ...(edge ? { supabaseEdge: edge } : {}) };
      }
      return {
        severity: evidence === 'option' ? 'critical' : 'high',
        confidence: 'high',
        credentialed: true,
        evidence,
        ...(edge ? { supabaseEdge: edge } : {}),
      };
    };

    const explain = (verdict: WildcardVerdict, form: string, stated: string): { user: string; tech: string } => {
      if (verdict.credentialed && verdict.evidence !== 'none') {
        return {
          user:
            'Your server echoes back whichever website is asking AND lets that website send your users\' cookies, so a malicious page a signed-in user visits can read their private data from this API and send requests as them. Restrict allowed origins to the domains you actually control.',
          tech: `${stated}, so every origin is allowed, and credentials are in play: ${EVIDENCE_CLAUSE[verdict.evidence]}. A browser shares a credentialed response with an echoed origin, which enables cross-site authenticated reads and requests (CSRF-equivalent). Set an explicit origin allowlist.`,
        };
      }
      if (verdict.evidence !== 'none') {
        const opening =
          verdict.evidence === 'cookie-project' ? 'Your project signs users in with cookies' : 'Credentials are switched on';
        return {
          user:
            `Any website can read the responses from this endpoint. ${opening}, but browsers refuse to share a response made with the visitor's cookies when the allowed origin is the literal "*", so a third-party page gets no more than an anonymous request would. If this API is not meant to be public, restrict the allowed origins. Do not make credentials "work" by echoing back whatever origin asks: that turns this into a serious problem.`,
          tech: `${stated}, so every origin is allowed, and credentials evidence is present: ${EVIDENCE_CLAUSE[verdict.evidence]}. Browsers refuse to share a response to a credentialed request when Access-Control-Allow-Origin is the literal "*", so the wildcard exposes no authenticated data; reported at low severity as a policy question rather than a credential leak. Replacing the "*" with an echo of the request Origin would make the credentials effective and the exposure real.`,
        };
      }
      const edge = verdict.supabaseEdge;
      const edgeNote =
        edge === undefined
          ? ''
          : ` This is the standard Supabase edge-function \`corsHeaders\` block for "${edge.name}", whose callers authenticate with a Bearer JWT in the Authorization header` +
            (edge.verifyJwt
              ? ' that the platform verifies (supabase/config.toml leaves verify_jwt at its default of true).'
              : ' (supabase/config.toml sets verify_jwt = false for it, so this function must check the token itself — a separate question from CORS).');
      return {
        user:
          'Any website can read the responses from this endpoint. No browser credentials are in play (no Access-Control-Allow-Credentials and no cookie-based session was found), so a third-party page gets no more than an anonymous request already would — but if this API is not meant to be public, restrict the allowed origins.',
        tech:
          `${form} allows every origin. No Access-Control-Allow-Credentials and no cookie-based session was found in this project, so the browser will not attach ambient credentials and the wildcard exposes no authenticated data; reported at low severity as a policy question rather than a credential leak.${edgeNote}`,
      };
    };

    for (const entry of context.fileMap.entries) {
      if (!CODE_EXTENSIONS.has(entry.extension)) continue;
      if (hasOriginAllowlistGuard(entry.content)) continue;

      for (const match of findMatches(entry.content, CORS_OPTIONS_BLOCK)) {
        const block = match.matchText;
        const allowsAllOrigins = /origin\s*:\s*(['"`]\*['"`]|true)/.exec(block);
        if (allowsAllOrigins === null) continue;
        const origin: OriginForm = allowsAllOrigins[1] === 'true' ? 'reflected' : 'literal';
        const withCredentials = /credentials\s*:\s*true/.test(block);
        const verdict = verdictFor(entry, withCredentials, origin);
        const text = explain(
          verdict,
          'cors() is configured with origin "*" or true, which',
          origin === 'reflected'
            ? "cors() is configured with origin: true, which echoes the request's own Origin header back"
            : 'cors() is configured with origin "*", which sends the literal "*"',
        );
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: withCredentials && origin === 'reflected' ? 'CORS allows all origins with credentials' : this.title,
            severity: verdict.severity,
            confidence: verdict.confidence,
            filePath: entry.path,
            lineStart: match.line,
            evidence: match.snippet,
            userExplanation: text.user,
            technicalExplanation: text.tech,
            fixHint:
              "Pass an explicit allowlist to cors(), e.g. cors({ origin: ['https://yourapp.com'], credentials: true }). Never combine a wildcard origin with credentials.",
            category: this.category,
          }),
        );
      }

      for (const match of findMatches(entry.content, WILDCARD_HEADER)) {
        const verdict = verdictFor(entry, false, 'literal');
        const text = explain(
          verdict,
          'Access-Control-Allow-Origin is hardcoded to "*", which',
          'Access-Control-Allow-Origin is hardcoded to the literal "*"',
        );
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: this.title,
            severity: verdict.severity,
            confidence: verdict.confidence,
            filePath: entry.path,
            lineStart: match.line,
            evidence: match.snippet,
            userExplanation: text.user,
            technicalExplanation: text.tech,
            fixHint:
              "Replace the wildcard with your real origin(s): validate the request Origin header against an allowlist and echo the matched origin back, e.g. res.setHeader('Access-Control-Allow-Origin', 'https://yourapp.com').",
            category: this.category,
          }),
        );
      }

      for (const match of findMatches(entry.content, REFLECTED_ORIGIN_HEADER)) {
        const gate = windowAround(entry.content, match.index, 400);
        if (LOCAL_ORIGIN_ALLOWLIST.test(gate)) continue;
        if (resolvedPredicateProvesOriginAllowlist(context, entry.path, gate)) continue;
        const verdict = verdictFor(entry, false, 'reflected');
        const text = explain(
          verdict,
          "Access-Control-Allow-Origin echoes the caller's own Origin header without checking it against an allowlist, which",
          "Access-Control-Allow-Origin echoes the caller's own Origin header back without checking it against an allowlist",
        );
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: this.title,
            severity: verdict.severity,
            confidence: verdict.confidence,
            filePath: entry.path,
            lineStart: match.line,
            evidence: match.snippet,
            userExplanation: text.user,
            technicalExplanation: text.tech,
            fixHint:
              "Test the request Origin for EXACT membership of an allowlist before echoing it back — e.g. `if (ALLOWED_ORIGINS.includes(origin))`. A startsWith/endsWith check is not enough: an attacker can register a domain that begins or ends with yours. Add `Vary: Origin` so a shared cache cannot serve one origin's response to another.",
            category: this.category,
          }),
        );
      }

      for (const match of findMatches(entry.content, BARE_CORS_CALL)) {
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: 'CORS enabled with default (allow-all) settings',
            severity: 'medium',
            confidence: 'low',
            filePath: entry.path,
            lineStart: match.line,
            evidence: match.snippet,
            userExplanation:
              'cors() with no options allows requests from any origin by default. If this API is not meant to be public, pass an explicit list of allowed origins.',
            technicalExplanation:
              'app.use(cors()) defaults to Access-Control-Allow-Origin: *. This may be intentional for public APIs, so confidence is low; verify intent and restrict origins if the API is private.',
            fixHint:
              "If this API is not meant to be public, configure cors with an explicit allowlist: app.use(cors({ origin: ['https://yourapp.com'] })). If it is intentionally public, no change is needed.",
            category: this.category,
          }),
        );
      }

      if (entry.extension === '.py') {
        const code = stripCommentsOnly(entry.content, true);
        for (const shape of pythonCorsWildcards(entry.path, code)) {
          const origin: OriginForm = shape.credentials ? 'reflected' : 'literal';
          const verdict = verdictFor(entry, shape.credentials, origin);
          const wording = PYTHON_CORS_WORDING[shape.library];
          const text = explain(verdict, wording.form, shape.credentials ? wording.reflected : wording.literal);
          const line = code.slice(0, shape.index).split('\n').length;
          findings.push(
            makeFinding({
              ruleId: this.id,
              title: shape.credentials ? 'CORS allows all origins with credentials' : this.title,
              severity: verdict.severity,
              confidence: verdict.confidence,
              filePath: entry.path,
              lineStart: line,
              evidence: (entry.content.split('\n')[line - 1] ?? '').trim(),
              userExplanation: text.user,
              technicalExplanation: text.tech,
              fixHint: wording.fix,
              category: this.category,
            }),
          );
        }
      }
    }
    return findings;
  },
};
