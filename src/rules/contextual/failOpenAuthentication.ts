import { mayVouchForProject } from '../../input/fileFilters.js';
import { stripCommentsOnly, usesHashComments } from '../../shared/source.js';
import { findMatches, lineAt } from '../../shared/utils.js';
import { makeFinding } from '../../shared/findingFactory.js';
import type { Finding, FileMapEntry, RuleContext, ScanRule } from '../../shared/types.js';
import { SVELTEKIT_IDENTITY } from '../../shared/frameworkModel.js';

// Bounded brace walk, so a malformed file cannot hang the scan.
const MAX_BLOCK_SCAN_CHARS = 40_000;
const MAX_CONTINUATION_CHARS = 1_500;
const MAX_SWALLOW_BODY_CHARS = 400;

type FailOpenShape =
  | 'swallowed_catch'
  | 'catch_calls_next'
  | 'catch_returns_authorized'
  | 'inverted_error_branch';

interface FailOpenSite {
  line: number;
  shape: FailOpenShape;
  signal: string;
  errorPath: string;
  continuation: string;
  snippet: string;
}

export const failOpenAuthentication: ScanRule = {
  id: 'fail_open_authentication',
  title: 'Authentication fails open — an error lets the request through',
  category: 'authentication',
  kind: 'contextual',
  run(context: RuleContext): Finding[] {
    const entries = [...context.fileMap.entries].sort((a, b) => a.path.localeCompare(b.path));
    const findings: Finding[] = [];
    for (const entry of entries) {
      if (!isAnalysableSource(entry, context.projectMap.scannerRootPrefix)) continue;
      for (const site of findFailOpenSites(entry)) {
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: this.title,
            severity: 'high',
            confidence: 'high',
            filePath: entry.path,
            lineStart: site.line,
            evidence:
              `an authentication check (${site.signal}) at line ${site.line} sits on a path whose ` +
              `error branch ${describeShape(site.shape)} — ${site.errorPath} — and execution then ` +
              `reaches a protected operation (${site.continuation}) rather than refusing the ` +
              'request; no 401/403, throw, redirect or next(error) on the error path',
            userExplanation:
              'Your code checks who is making this request — and then wraps that check so that if ' +
              'it goes wrong, the error is thrown away and the request carries on as though the ' +
              'check had passed. Anything that makes the check fail becomes a way in, and the ' +
              'thing most likely to make it fail is exactly what an attacker sends: a made-up, ' +
              'expired or tampered-with login token. A real user with a real token gets in; so ' +
              'can someone with a fake one, whenever the fake one causes an error and the error is ' +
              'ignored. This can be worse than having no check at all, because the code reads as ' +
              'though the door is locked, and other security tools will agree the door is there. ' +
              'Whatever the check does when it succeeds, a request whose check fails with an error ' +
              'goes through. The fix is to make failure mean ' +
              'refusal: when the check cannot complete, the request must be turned away.',
            technicalExplanation:
              `${entry.path}:${site.line} performs a protective authentication signal ` +
              `(${site.signal}) inside a try block or as the receiver of a promise .catch, and the ` +
              `error path ${describeShape(site.shape)}: ${site.errorPath}. That path contains no ` +
              'denial — no throw or re-throw, no returned error response, no res.status(401/403), ' +
              'no redirect, no next(error) and no error-handling helper given the response — and ' +
              'it is not terminal: execution continues into ' +
              `${site.continuation}, a privileged operation in the same function. The identity is ` +
              'not handled as possibly-absent on that path, so this is not optional-auth-by-design. ' +
              'A verification that throws — a forged, expired or malformed credential is the ' +
              'ordinary cause — therefore takes the OPEN branch. This is reported as a control ' +
              'that is present and unenforceable rather than a missing one: absence-based rules ' +
              'see a real check on the route and stay silent.',
            fixHint:
              'Make the error path a denial. Move the protected work out of the error path: return ' +
              '401/403, throw, redirect to sign-in, or call next(error) — never call next() with ' +
              'no argument, return true, return a user object, or fall through. If the check is ' +
              'genuinely optional for this route, resolve the identity to null on failure and gate ' +
              'every privileged operation on it explicitly, so an anonymous caller can only reach ' +
              'public data.',
            category: this.category,
            extraFixRequirements: [
              'Do not fix this by narrowing the catch to a specific error type unless every other error still denies — an unexpected error must fail closed too.',
              'Do not log-and-continue. A logged failure is still a granted request; the log is read after the fact, the request is served now.',
              'Re-check every route that reaches this code: for as long as the error path has been open, a caller whose credentials failed to verify may have been let through.',
              'If some callers are meant to be anonymous, make that explicit — resolve the identity to null and branch on it — rather than leaving an error to decide it.',
            ],
          }),
        );
      }
    }
    return findings;
  },
};

const PROTECTIVE_AUTH_SIGNAL = new RegExp(
  /\.getUser\s*\(|\bgetUser\s*\(|\bgetAuth\s*\(\s*(?:req|request|ctx|context)\b|\.getSession\s*\(|\bgetSession\s*\(|\bgetServerSession\s*\(|jwt\.verify\s*\(|\bverify(?:IdToken|Token|Session|Jwt|JWT|Auth\w*)\s*\(|\.\s*isAuthenticated\s*\(\s*\)|\bpassport\s*\.\s*authenticate\s*\(|\b[\w$]*auth[\w$]*(?:\(\))?\s*\.\s*currentUser\b|\bcurrentUser\s*\(|\breq\.session\b|\brequest\.cookies\b|\bcookies\s*\(\s*\)\s*\.\s*get|\bcookies\.get\s*\(\s*['"](?:session|token|auth)|\bauth\s*(?:\(\s*\))?\s*\.\s*protect\s*\(|\b(?:require|assert|ensure|check)(?:Auth\w*|Admin|User|Session|Login|Owner|Role|Member|Account|Permission|SignedIn|Authenticated)\w*\s*\(|\bwithAuth\w*\s*\(|\bauth\s*\(\s*(?:\)|(?:req|request|ctx|context)\b)/.source + `|${SVELTEKIT_IDENTITY.source}`,
);

function firstProtectiveSignal(code: string): string | undefined {
  const match = PROTECTIVE_AUTH_SIGNAL.exec(code);
  return match?.[0]?.trim();
}

// next(err) denies; only a bare next() lets the request through.
const DENIAL_ACTION =
  /\bthrow\b|\bnext\s*\(\s*[A-Za-z_$]|\bres\s*\.\s*(?:status|sendStatus)\b|\bctx\s*\.\s*throw\b|\bredirect\s*\(|\bprocess\s*\.\s*exit\s*\(|\bLogger\s*\.\s*fatal\b|\bnotFound\s*\(|\babort\s*\(/;

const DENIAL_ON_ERROR_PATH = new RegExp(`\\breturn\\b|${DENIAL_ACTION.source}`);

const RETURNS_ABSENT_VALUE =
  /\breturn\s*\(?\s*(?:null|undefined|void\s+0|false|\{\s*\}|\[\s*\]|0)\s*\)?\s*(?:[;),\n]|$)|\breturn\s+[A-Z_][A-Z0-9_]*(?:\s*\.\s*[A-Z_][A-Z0-9_]*)*\s*(?:[;),\n]|$)/;

const RETURNS_ASSERTING_VALUE =
  /\breturn\s+(?:true|!0)\s*(?:[;),\n]|$)|\breturn\s+1\s*(?:[;),\n]|$)|\breturn\s*\{[^}]{0,300}\b(?:id|userId|uid|role|roles|isAdmin|admin|isAuthenticated|authenticated|authorized|email|username|permissions?|scopes?)\s*:\s*(?:['"`][^'"`\n]{0,80}['"`]|true|1|\[)/;

const PROTECTED_OPERATION =
  /\b(?:db|prisma|supabase|knex|mongoose|sequelize|pool|client|collection|admin)\s*\.\s*\w|\.\s*(?:findUnique|findFirst|findMany|findOne|findById|findByPk|create|createMany|update|updateMany|updateOne|updateOneAndUpdate|findOneAndUpdate|findByIdAndUpdate|upsert|insert|insertOne|delete|deleteMany|deleteOne|destroy|remove|save|from|rpc)\s*\(|\b(?:res|reply)\s*\.\s*(?:json|send)\s*\(|\bResponse\s*\.\s*json\s*\(|\bNextResponse\s*\.\s*json\s*\(|\bnew\s+Response\s*\(|\bhandler\s*\(|\bnext\s*\(\s*\)|\bresolve\s*\(\s*event\b/;

// Calls that grant nothing (UI, toasts, sign-out, logging) are not fail-open.
const UNPRIVILEGED_CALL =
  /(?:await\s+)?[\w$.]*\b(?:console\s*\.\s*\w+|(?:set|clear|reset)[A-Z]\w*|toast(?:\s*\.\s*\w+)?|AsyncStorage\s*\.\s*(?:clear|removeItem|setItem)|(?:local|session)Storage\s*\.\s*(?:clear|removeItem|setItem)|signOut|logout|navigate|Logger\s*\.\s*\w+|router\s*\.\s*\w+)\s*\([^()]{0,300}\)/g;

const IDENTITY_TOKEN =
  /\b(?:user|users|session|currentSession|currentUser|token|auth|authed|uid|userId|claims|account|identity|jwt|principal|role|roles|member|owner)\b/i;

const ABSENT_TOLERANT_IDENTITY = new RegExp(
  String.raw`(?:${IDENTITY_TOKEN.source})[\w$]*\s*(?:\?\.|\?\?|\|\|\s*(?:null|undefined|\{\s*\}))` +
    String.raw`|\bif\s*\(\s*!\s*[\w$.]*(?:${IDENTITY_TOKEN.source})` +
    String.raw`|(?:${IDENTITY_TOKEN.source})[\w$]*\s*(?:===?|!==?)\s*(?:null|undefined)`,
  'i',
);

const ASSIGNS_ABSENT_IDENTITY = new RegExp(
  String.raw`[\w$.]*(?:${IDENTITY_TOKEN.source})[\w$]*\s*=\s*(?:null|undefined|void\s+0|false|\{\s*\})\s*(?:[;,\n]|$)`,
  'i',
);


const BARE_NEXT = /(?:^|[^\w$.])next\s*\(\s*\)/;
const ERROR_CLASSIFYING_CONDITIONAL =
  /\bif\s*\(\s*[^)\n]{0,200}\b(?:err|error|e)\w*\s*(?:instanceof\b|\.\s*(?:name|code|status|message)\b|===|!==)/i;

const TRY_BLOCK = /\btry\s*\{/g;
const CATCH_HEAD = /^\s*catch\s*(?:\([^)]{0,120}\))?\s*\{/;
const FINALLY_HEAD = /^\s*finally\s*\{/;
const PROMISE_CATCH_HEAD = /\.catch\s*\(/g;
const INVERTED_ERROR_BRANCH =
  /\bif\s*\(\s*(?:!!\s*)?((?:[A-Za-z_$][\w$]*\s*\.\s*)?[A-Za-z_$][\w$]*)\s*\)\s*\{([^{}]{0,300})\}/g;
const ERROR_NAMED = /err/i;

const JS_TS_EXTENSIONS: ReadonlySet<string> = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.mts', '.cts',
]);

function isAnalysableSource(entry: FileMapEntry, scannerRootPrefix?: string): boolean {
  if (!JS_TS_EXTENSIONS.has(entry.extension)) return false;
  return mayVouchForProject(entry.path, scannerRootPrefix);
}

function matchBrace(source: string, open: number): number {
  let depth = 0;
  const limit = Math.min(source.length, open + MAX_BLOCK_SCAN_CHARS);
  for (let index = open; index < limit; index += 1) {
    const character = source[index];
    if (character === '{') depth += 1;
    else if (character === '}') {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

function continuationAfter(source: string, from: number): string {
  let depth = 0;
  const limit = Math.min(source.length, from + MAX_CONTINUATION_CHARS);
  for (let index = from; index < limit; index += 1) {
    const character = source[index];
    if (character === '{') depth += 1;
    else if (character === '}') {
      if (depth === 0) return source.slice(from, index);
      depth -= 1;
    }
  }
  return source.slice(from, limit);
}

function hasExecutableContinuation(tail: string): boolean {
  return /[A-Za-z_$0-9]/.test(stripLeadingFinally(tail));
}

function stripLeadingFinally(tail: string): string {
  const head = /^\s*finally\s*\{/.exec(tail);
  if (head === null) return tail;
  const close = matchBrace(tail, head[0].length - 1);
  return close < 0 ? '' : tail.slice(close + 1);
}

function catchFallsThrough(catchBody: string): boolean {
  return !DENIAL_ON_ERROR_PATH.test(catchBody);
}

function findFailOpenSites(entry: FileMapEntry): FailOpenSite[] {
  const source = stripCommentsOnly(entry.content, usesHashComments(entry.extension, entry.label));
  const sites: FailOpenSite[] = [];
  const seen = new Set<number>();

  collectTryCatchSites(entry, source, sites, seen);
  collectPromiseCatchSites(entry, source, sites, seen);
  collectInvertedBranchSites(entry, source, sites, seen);

  sites.sort((a, b) => a.line - b.line);
  return sites;
}

function collectTryCatchSites(
  entry: FileMapEntry,
  source: string,
  sites: FailOpenSite[],
  seen: Set<number>,
): void {
  for (const match of findMatches(source, TRY_BLOCK)) {
    const open = match.index + match.matchText.length - 1;
    const close = matchBrace(source, open);
    if (close < 0) continue;
    const tryBody = source.slice(open + 1, close);

    const signal = firstProtectiveSignal(tryBody);
    if (signal === undefined) continue;

    const head = CATCH_HEAD.exec(source.slice(close + 1, close + 200));
    if (head === null) continue;
    const catchOpen = close + 1 + head[0].length - 1;
    const catchClose = matchBrace(source, catchOpen);
    if (catchClose < 0) continue;
    const catchBody = source.slice(catchOpen + 1, catchClose);
    if (catchBody.trim().length > MAX_SWALLOW_BODY_CHARS) continue;

    if (!catchFallsThrough(catchBody)) continue;
    if (ASSIGNS_ABSENT_IDENTITY.test(catchBody)) continue;

    const bareNext = BARE_NEXT.test(catchBody);
    if (bareNext && ERROR_CLASSIFYING_CONDITIONAL.test(catchBody)) continue;

    const tail = continuationAfter(source, catchClose + 1);
    const continues = hasExecutableContinuation(tail);
    if (!bareNext && !continues) continue;

    const scope = bareNext ? catchBody : tail;
    if (!isProtectedContinuation(scope)) continue;
    if (ABSENT_TOLERANT_IDENTITY.test(scope)) continue;

    if (seen.has(match.line)) continue;
    seen.add(match.line);
    sites.push({
      line: match.line,
      shape: bareNext ? 'catch_calls_next' : 'swallowed_catch',
      signal,
      errorPath: condense(catchBody) || '(empty)',
      continuation: condense(scope),
      snippet: lineAt(entry.content, match.line).trim().slice(0, 160),
    });
  }
}

function collectPromiseCatchSites(
  entry: FileMapEntry,
  source: string,
  sites: FailOpenSite[],
  seen: Set<number>,
): void {
  for (const match of findMatches(source, PROMISE_CATCH_HEAD)) {
    const openParen = match.index + match.matchText.length - 1;
    const closeParen = matchParen(source, openParen);
    if (closeParen < 0) continue;
    const body = handlerBody(source.slice(openParen + 1, closeParen));
    if (body === undefined || body.trim() === '') continue;

    const receiver = receiverChain(source, match.index);
    const signal = firstProtectiveSignal(receiver);
    if (signal === undefined) continue;

    if (RETURNS_ABSENT_VALUE.test(body)) continue;
    if (DENIAL_ACTION.test(body)) continue;

    const asserts = RETURNS_ASSERTING_VALUE.test(body);
    const bareNext = BARE_NEXT.test(body);
    if (bareNext && ERROR_CLASSIFYING_CONDITIONAL.test(body)) continue;

    const tail = continuationAfter(source, closeParen + 1);
    if (!asserts && !bareNext && !hasExecutableContinuation(tail)) continue;

    const scope = asserts || bareNext ? `${body} ${tail}` : tail;
    if (!isProtectedContinuation(scope)) continue;
    if (ABSENT_TOLERANT_IDENTITY.test(tail)) continue;

    if (seen.has(match.line)) continue;
    seen.add(match.line);
    sites.push({
      line: match.line,
      shape: bareNext ? 'catch_calls_next' : 'catch_returns_authorized',
      signal,
      errorPath: condense(body),
      continuation: condense(scope),
      snippet: lineAt(entry.content, match.line).trim().slice(0, 160),
    });
  }
}

function handlerBody(inner: string): string | undefined {
  const arrow = inner.indexOf('=>');
  if (arrow >= 0) {
    const body = inner.slice(arrow + 2).trim();
    if (body.startsWith('{')) return body.slice(1, body.lastIndexOf('}'));
    return `return ${body}`;
  }
  const brace = inner.indexOf('{');
  if (/^\s*(?:async\s+)?function\b/.test(inner) && brace >= 0) {
    return inner.slice(brace + 1, inner.lastIndexOf('}'));
  }
  return undefined;
}

function matchParen(source: string, open: number): number {
  let depth = 0;
  const limit = Math.min(source.length, open + MAX_BLOCK_SCAN_CHARS);
  for (let index = open; index < limit; index += 1) {
    const character = source[index];
    if (character === '(') depth += 1;
    else if (character === ')') {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

function collectInvertedBranchSites(
  entry: FileMapEntry,
  source: string,
  sites: FailOpenSite[],
  seen: Set<number>,
): void {
  for (const match of findMatches(source, INVERTED_ERROR_BRANCH)) {
    const name = match.groups[0] ?? '';
    if (!ERROR_NAMED.test(name)) continue;
    const branch = match.groups[1] ?? '';

    const binding = bindingStatementAbove(source, match.index, name);
    if (binding === undefined) continue;
    const signal = firstProtectiveSignal(binding);
    if (signal === undefined) continue;

    if (!catchFallsThrough(branch)) continue;
    if (BARE_NEXT.test(branch) && ERROR_CLASSIFYING_CONDITIONAL.test(branch)) continue;

    const tail = continuationAfter(source, match.index + match.matchText.length);
    if (!hasExecutableContinuation(tail)) continue;
    if (!isProtectedContinuation(tail)) continue;
    if (ABSENT_TOLERANT_IDENTITY.test(tail)) continue;

    if (seen.has(match.line)) continue;
    seen.add(match.line);
    sites.push({
      line: match.line,
      shape: 'inverted_error_branch',
      signal,
      errorPath: `if (${name}) { ${condense(branch) || 'nothing' } }`,
      continuation: condense(tail),
      snippet: lineAt(entry.content, match.line).trim().slice(0, 160),
    });
  }
}

function bindingStatementAbove(source: string, index: number, name: string): string | undefined {
  const window = source.slice(Math.max(0, index - 400), index);
  const trimmed = window.replace(/\s+$/, '').replace(/;$/, '');
  const statement = trimmed.slice(statementStart(trimmed));
  const binds = new RegExp(
    String.raw`(?:const|let|var)\b[^=;]{0,200}\b${escapeForRegExp(name)}\b[^=;]{0,80}=` +
      String.raw`|\b${escapeForRegExp(name)}\s*=[^=]`,
  );
  return binds.test(statement) ? statement : undefined;
}

function statementStart(text: string): number {
  let depth = 0;
  for (let index = text.length - 1; index >= 0; index -= 1) {
    const character = text[index];
    if (character === '}' || character === ')' || character === ']') depth += 1;
    else if (character === '{' || character === '(' || character === '[') {
      if (depth === 0) return index + 1;
      depth -= 1;
    } else if (character === ';' && depth === 0) return index + 1;
  }
  return 0;
}

function isProtectedContinuation(tail: string): boolean {
  if (tail.trim() === '') return false;
  const remaining = tail.replace(UNPRIVILEGED_CALL, ' ');
  return PROTECTED_OPERATION.test(remaining);
}

const CONTINUES_EXPRESSION = /^\s*(?:[.)\]},?:;]|\?\.|=>|[+\-*/%&|^<>=!]|`)/;
const ONLY_WHITESPACE = /^\s*$/;

function receiverChain(source: string, catchIndex: number): string {
  const window = source.slice(Math.max(0, catchIndex - 400), catchIndex);
  let boundary = Math.max(window.lastIndexOf(';'), window.lastIndexOf('{'), window.lastIndexOf('}'));
  for (let index = window.length - 1; index > boundary; index -= 1) {
    if (window[index] !== '\n') continue;
    const remainder = window.slice(index + 1);
    if (ONLY_WHITESPACE.test(remainder)) continue;
    if (CONTINUES_EXPRESSION.test(remainder)) continue;
    boundary = index;
    break;
  }
  return boundary >= 0 ? window.slice(boundary + 1) : window;
}

function escapeForRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function condense(text: string): string {
  return text.replace(/\s+/g, ' ').trim().slice(0, 200);
}

function describeShape(shape: FailOpenShape): string {
  switch (shape) {
    case 'swallowed_catch':
      return 'swallows the error without refusing the request';
    case 'catch_calls_next':
      return 'calls next() with no argument, passing the request on';
    case 'catch_returns_authorized':
      return 'returns a value that asserts the caller is authorised';
    case 'inverted_error_branch':
      return 'tests for the error and then proceeds anyway';
  }
}
