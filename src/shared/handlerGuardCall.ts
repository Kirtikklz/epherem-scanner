import {
  FAILED_TEST,
  IDENTITY_SUBJECT,
  LIMITER_LIBRARY,
  RATE_REJECTION,
  ROLE_SUBJECT,
  SIGNATURE_SUBJECT,
  SIGNATURE_VERIFY,
  balanced,
  conditionals,
  middlewareBodyOf,
  stripComments,
} from './middlewareGuard.js';
import { entryFor, importedFrom } from './importedVerifier.js';
import { stripCommentsOnly } from './source.js';
import { IDENTITY_FETCH } from '../project-map/detectAuthSignals.js';
import type { GuardLookup } from './types.js';

export interface HandlerGuardEffects {
  role: boolean;
  rejection: boolean;
  signature: boolean;
  rateLimit: boolean;
}

const NO_GUARD: HandlerGuardEffects = {
  role: false,
  rejection: false,
  signature: false,
  rateLimit: false,
};

const MAX_RESOLUTION_DEPTH = 4;
const MAX_SCOPE_CHARS = 40_000;
const MAX_BODY_CHARS = 12_000;
const MAX_RETURN_EXPR = 300;

const SELF_BLOCKING =
  /\bthrow\b|\bredirect\s*\(|\bnotFound\s*\(|\bunauthorized\s*\(|\bforbidden\s*\(/;

const RETURNED_REJECTION =
  /\bstatus\s*:\s*(?:400|401|403|419|429)\b|\.\s*status\s*\(\s*(?:400|401|403|419|429)\s*\)|\bsendStatus\s*\(\s*(?:401|403|419|429)\s*\)|\bNextResponse\s*\.\s*redirect\s*\(|\bstatusCode\s*:\s*(?:401|403|419|429)\b/;

const OWNERSHIP_SUBJECT =
  /(?:\b|(?<=[a-z0-9_$]))(?:owner|Owner|OWNER)(?:s|S|ship|Ship|SHIP|ed|Ed|By)?(?![a-z])/;

const ROLE_OR_OWNERSHIP = new RegExp(`${ROLE_SUBJECT.source}|${OWNERSHIP_SUBJECT.source}`, 'i');

const IS_A_TEST = /[!=]==?|\.\s*(?:includes|has|indexOf|some|every|startsWith)\s*\(|\bin\b/;

const RETURNS_NOTHING = /^(?:null|undefined)$/;

const NULL_TERNARY_ARM = /\?\s*(?:null|undefined)\s*:|:\s*(?:null|undefined)\s*$/;

export const COUNTER_OVER_LIMIT =
  /\b(?:count|counter|hits?|attempts?|requests?|tokens?|calls?|tries|used|usage)\b[\w$.]*\s*(?:>=|>|<=|<)\s*[\w$.]*\b(?:limit|limits|max|maximum|threshold|quota|cap|allowance|allowed)\b|\b(?:limit|limits|max|maximum|threshold|quota|cap|allowance|allowed)\b[\w$.]*\s*(?:>=|>|<=|<)\s*[\w$.]*\b(?:count|counter|hits?|attempts?|requests?|tokens?|calls?|tries|used|usage)\b/i;

const RATE_WINDOW =
  /\bwindowMs\b|\bwindow\b|\bresetAt\b|\bresetTime\b|\bexpiresAt\b|\bexpiry\b|\bretryAfter\b|\bDate\s*\.\s*now\s*\(|\bttl\b|\bperMinute\b|\bperHour\b|\bperSecond\b|\bduration\b/i;

const CALL_SITE_EXIT = /\breturn\b|\bthrow\b|\bredirect\s*\(|\bnotFound\s*\(/;

export interface HelperClassification {
  blocks: { identity: boolean; role: boolean; signature: boolean; rate: boolean };
  decides: { identity: boolean; role: boolean; signature: boolean; rate: boolean };
  rejectionKeys: string[];
}

const NOTHING: HelperClassification = {
  blocks: { identity: false, role: false, signature: false, rate: false },
  decides: { identity: false, role: false, signature: false, rate: false },
  rejectionKeys: [],
};

const helperCache = new WeakMap<GuardLookup, Map<string, HelperClassification>>();

function cacheFor(context: GuardLookup): Map<string, HelperClassification> {
  let cache = helperCache.get(context);
  if (cache === undefined) {
    cache = new Map();
    helperCache.set(context, cache);
  }
  return cache;
}

function escape(name: string): string {
  return name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function blankNestedFunctions(code: string): string {
  let out = code;
  const head = /(?:\bfunction\b[^(){}]{0,120}\([^()]{0,300}\)\s*|\)\s*(?::[^=>\n]{0,120})?=>\s*|\b[A-Za-z_$][\w$]*\s*=>\s*)\{/g;
  for (let guard = 0; guard < 64; guard += 1) {
    head.lastIndex = 0;
    const match = head.exec(out);
    if (match === null) break;
    const open = match.index + match[0].length - 1;
    const block = balanced(out, open, '{', '}', MAX_BODY_CHARS);
    if (block === undefined) {
      out = `${out.slice(0, match.index)}${' '.repeat(out.length - match.index)}`;
      break;
    }
    out = `${out.slice(0, match.index)}${' '.repeat(block.end + 1 - match.index)}${out.slice(block.end + 1)}`;
  }
  return out;
}

function returnExpressions(code: string): string[] {
  const out: string[] = [];
  for (const match of code.matchAll(/\breturn\b([^;\n]{0,300})/g)) {
    const expr = (match[1] ?? '').trim();
    if (expr !== '') out.push(expr.slice(0, MAX_RETURN_EXPR));
  }
  return out;
}

function rejectionKeysIn(consequent: string): string[] {
  const keys: string[] = [];
  for (const match of consequent.matchAll(/\breturn\s*\{/g)) {
    const open = match.index + match[0].length - 1;
    const object = balanced(consequent, open, '{', '}', MAX_BODY_CHARS);
    if (object === undefined) continue;
    for (const pair of topLevelKeys(object.inner)) {
      if (RETURNED_REJECTION.test(pair.value) && !keys.includes(pair.key)) keys.push(pair.key);
    }
  }
  return keys;
}

function topLevelKeys(inner: string): Array<{ key: string; value: string }> {
  const pairs: Array<{ key: string; value: string }> = [];
  let depth = 0;
  let keyStart = 0;
  let key: string | undefined;
  for (let i = 0; i < inner.length; i += 1) {
    const ch = inner[i] ?? '';
    if (ch === '{' || ch === '(' || ch === '[') { depth += 1; continue; }
    if (ch === '}' || ch === ')' || ch === ']') { depth -= 1; continue; }
    if (depth !== 0) continue;
    if (ch === ':' && key === undefined) {
      const name = /([A-Za-z_$][\w$]*)\s*$/.exec(inner.slice(keyStart, i));
      key = name?.[1];
      keyStart = i + 1;
      continue;
    }
    if (ch === ',') {
      if (key !== undefined) pairs.push({ key, value: inner.slice(keyStart, i) });
      key = undefined;
      keyStart = i + 1;
    }
  }
  if (key !== undefined) pairs.push({ key, value: inner.slice(keyStart) });
  return pairs;
}

const FALLTHROUGH_REFUSAL =
  /\bthrow\s+(?:new\s+)?(?:[\w.]*(?:Unauthorized|Forbidden|Authentication|Authorization)\w*\b|error\s*\(\s*(?:401|403)\b|redirect\s*\(|\w[\w.]*\s*\([^)]{0,120}\b(?:401|403)\b)/g;
const CONDITIONAL_STATEMENT_HEAD = /\b(?:if|else|for|while|switch|case|catch|do)\b|\?/;

function refusesOnFallThrough(code: string): boolean {
  if (!/\breturn\b/.test(code)) return false;

  FALLTHROUGH_REFUSAL.lastIndex = 0;
  for (const match of code.matchAll(FALLTHROUGH_REFUSAL)) {
    const at = match.index;
    if (braceDepthAt(code, at) !== 0) continue;
    let from = at;
    while (from > 0 && !'{};\n'.includes(code[from - 1] as string)) from -= 1;
    if (CONDITIONAL_STATEMENT_HEAD.test(code.slice(from, at))) continue;
    return true;
  }
  return false;
}

function braceDepthAt(code: string, index: number): number {
  let depth = 0;
  for (let i = 0; i < index && i < code.length; i += 1) {
    const ch = code[i];
    if (ch === '{') depth += 1;
    else if (ch === '}') depth -= 1;
  }
  return depth;
}

export function classifyGuardBody(raw: string): HelperClassification {
  const code = blankNestedFunctions(stripComments(raw));
  const conds = conditionals(code).filter((item) => item.depth === 0);
  const returns = returnExpressions(code);

  const blocksOn = (subject: RegExp): boolean =>
    conds.some((item) =>
      subject.test(item.condition) && FAILED_TEST.test(item.condition) && SELF_BLOCKING.test(item.consequent));
  const returnsRefusalOn = (subject: RegExp): boolean =>
    conds.some((item) =>
      subject.test(item.condition) && FAILED_TEST.test(item.condition) &&
      /\breturn\b/.test(item.consequent) && RETURNED_REJECTION.test(item.consequent));
  const returnsTestOn = (subject: RegExp): boolean =>
    returns.some((expr) => subject.test(expr) && IS_A_TEST.test(expr));

  const rateBlocks =
    (conds.some((item) =>
      COUNTER_OVER_LIMIT.test(item.condition) &&
      (SELF_BLOCKING.test(item.consequent) || RATE_REJECTION.test(item.consequent))) &&
      RATE_WINDOW.test(code)) ||
    (LIMITER_LIBRARY.test(code) && RATE_REJECTION.test(code) && SELF_BLOCKING.test(code));
  const rateDecides =
    (LIMITER_LIBRARY.test(code) && RATE_WINDOW.test(code)) ||
    (COUNTER_OVER_LIMIT.test(code) && RATE_WINDOW.test(code) && RATE_REJECTION.test(code));

  const refusingReturns = returns.filter((expr) => RETURNED_REJECTION.test(expr));
  const decidesByReturn = refusingReturns.length > 0 && refusingReturns.length < returns.length;

  const rejectionKeys: string[] = [];
  for (const item of conds) {
    if (!FAILED_TEST.test(item.condition)) continue;
    if (!IDENTITY_SUBJECT.test(item.condition) && !ROLE_OR_OWNERSHIP.test(item.condition) &&
      !SIGNATURE_SUBJECT.test(item.condition)) continue;
    for (const key of rejectionKeysIn(item.consequent)) {
      if (!rejectionKeys.includes(key)) rejectionKeys.push(key);
    }
  }

  const verifies = SIGNATURE_VERIFY.test(code) || WEB_CRYPTO_MAC.test(code);

  const fallThrough = refusesOnFallThrough(code);

  const handsBackNothing = (expr: string): boolean =>
    RETURNS_NOTHING.test(expr.trim()) || NULL_TERNARY_ARM.test(expr);
  const identityOrNothing =
    IDENTITY_FETCH.test(code) &&
    returns.some(handsBackNothing) &&
    returns.some((expr) => IDENTITY_SUBJECT.test(expr) && !RETURNS_NOTHING.test(expr.trim()));

  return {
    blocks: {
      identity: blocksOn(IDENTITY_SUBJECT) || (fallThrough && IDENTITY_SUBJECT.test(code)),
      role: blocksOn(ROLE_OR_OWNERSHIP) || (fallThrough && ROLE_OR_OWNERSHIP.test(code)),
      signature: verifies && blocksOn(SIGNATURE_SUBJECT),
      rate: rateBlocks,
    },
    decides: {
      identity: returnsRefusalOn(IDENTITY_SUBJECT) || returnsTestOn(IDENTITY_SUBJECT) ||
        identityOrNothing,
      role: returnsRefusalOn(ROLE_OR_OWNERSHIP) || returnsTestOn(ROLE_OR_OWNERSHIP),
      signature: verifies &&
        (returnsRefusalOn(SIGNATURE_SUBJECT) || returnsTestOn(SIGNATURE_SUBJECT) || decidesByReturn),
      rate: rateDecides,
    },
    rejectionKeys,
  };
}

const WEB_CRYPTO_MAC =
  /\bcrypto\s*\.\s*subtle\s*\.\s*(?:sign|verify|importKey)\s*\(|\bconstantTimeEqual\s*\(|['"`]?HMAC['"`]?\s*[,)]/;

const bodiesByEntry = new WeakMap<object, Map<string, string | undefined>>();
function helperBodyOf(entry: { content: string }, name: string): string | undefined {
  let bodies = bodiesByEntry.get(entry);
  if (bodies === undefined) { bodies = new Map(); bodiesByEntry.set(entry, bodies); }
  if (bodies.has(name)) return bodies.get(name);
  const body = middlewareBodyOf(entry.content, name);
  bodies.set(name, body);
  return body;
}

function classifyHelper(
  context: GuardLookup,
  filePath: string,
  name: string,
  depth: number,
  visited: Set<string>,
): HelperClassification {
  if (depth > MAX_RESOLUTION_DEPTH) return NOTHING;
  const key = `${filePath}::${name}`;
  if (visited.has(key)) return NOTHING;
  visited.add(key);
  const cache = cacheFor(context);
  const cached = cache.get(key);
  if (cached !== undefined) return cached;

  const definedIn = importedFrom(context, filePath, name);
  const searchPaths = definedIn === undefined ? [filePath] : [definedIn, filePath];

  let result = NOTHING;
  for (const path of searchPaths) {
    const entry = entryFor(context, path);
    if (entry === undefined) continue;
    const body = helperBodyOf(entry, name);
    if (body === undefined) {
      const onward = path === filePath ? undefined : importedFrom(context, path, name);
      if (onward === undefined) continue;
      const lifted = classifyHelper(context, path, name, depth + 1, visited);
      if (hasAnyEffect(lifted)) { result = lifted; break; }
      continue;
    }
    const direct = classifyGuardBody(body);
    const lifted = liftFromCallees(context, path, body, direct, depth, visited);
    if (hasAnyEffect(lifted)) { result = lifted; break; }
  }

  cache.set(key, result);
  return result;
}

function hasAnyEffect(item: HelperClassification): boolean {
  return Object.values(item.blocks).some(Boolean) || Object.values(item.decides).some(Boolean);
}

function liftFromCallees(
  context: GuardLookup,
  filePath: string,
  rawBody: string,
  direct: HelperClassification,
  depth: number,
  visited: Set<string>,
): HelperClassification {
  if (depth >= MAX_RESOLUTION_DEPTH) return direct;
  const code = blankNestedFunctions(stripComments(rawBody));
  const lifted = {
    blocks: { ...direct.blocks },
    decides: { ...direct.decides },
    rejectionKeys: [...direct.rejectionKeys],
  };
  for (const call of statementLevelCalls(code)) {
    const callee = classifyHelper(context, filePath, call, depth + 1, visited);
    lifted.blocks.identity ||= callee.blocks.identity;
    lifted.blocks.role ||= callee.blocks.role;
    lifted.blocks.signature ||= callee.blocks.signature;
    lifted.blocks.rate ||= callee.blocks.rate;
  }
  return lifted;
}

function statementLevelCalls(code: string): string[] {
  const names: string[] = [];
  const depths = new Array<number>(code.length);
  let depth = 0;
  for (let i = 0; i < code.length; i += 1) {
    const ch = code[i];
    if (ch === '}') depth -= 1;
    depths[i] = depth;
    if (ch === '{') depth += 1;
  }
  const pattern =
    /(?:^|[;\n])\s*(?:(?:const|let|var)\s+(?:\{[^{}=]{0,200}\}|[A-Za-z_$][\w$]*)\s*(?::[^=\n]{0,160})?=\s*)?(?:await\s+)?([A-Za-z_$][\w$]*)\s*\(/g;
  for (const match of code.matchAll(pattern)) {
    if ((depths[match.index] ?? 0) !== 0) continue;
    const name = match[1];
    if (name === undefined || RESERVED.has(name) || names.includes(name)) continue;
    names.push(name);
  }
  return names;
}

const RESERVED = new Set([
  'if', 'for', 'while', 'switch', 'catch', 'return', 'throw', 'typeof', 'await',
  'function', 'new', 'delete', 'void', 'do', 'else', 'try', 'yield',
]);

interface HandlerCall {
  name: string;
  index: number;
  bound: string[];
}

function boundNames(target: string): string[] {
  const trimmed = target.trim();
  if (!trimmed.startsWith('{')) return trimmed === '' ? [] : [trimmed];
  const names: string[] = [];
  for (const part of trimmed.slice(1, -1).split(',')) {
    const token = part.trim();
    if (token === '') continue;
    const renamed = /^[A-Za-z_$][\w$]*\s*:\s*([A-Za-z_$][\w$]*)$/.exec(token);
    const plain = /^([A-Za-z_$][\w$]*)$/.exec(token);
    const name = renamed?.[1] ?? plain?.[1];
    if (name !== undefined && !names.includes(name)) names.push(name);
  }
  return names;
}

function handlerCalls(scope: string): HandlerCall[] {
  const calls: HandlerCall[] = [];
  const pattern =
    /(?:(?:const|let|var)\s+(\{[^{}=]{0,200}\}|[A-Za-z_$][\w$]*)\s*(?::[^=\n]{0,160})?=\s*)?(?:await\s+)?\b([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\(/g;
  for (const match of scope.matchAll(pattern)) {
    const token = match[2];
    if (token === undefined) continue;
    const segments = token.split('.').map((part) => part.trim()).filter((part) => part !== '');
    const name = segments[segments.length - 1];
    if (name === undefined || RESERVED.has(name)) continue;
    calls.push({ name, index: match.index, bound: boundNames(match[1] ?? '') });
  }
  return calls;
}

function callSiteRejects(scope: string, call: HandlerCall, rejectionKeys: readonly string[]): boolean {
  const conds = conditionals(scope);
  for (const item of conds) {
    if (item.conditionIndex + item.condition.length < call.index) continue;
    if (!CALL_SITE_EXIT.test(item.consequent)) continue;
    if (item.conditionIndex <= call.index && call.index < item.conditionIndex + item.condition.length) {
      if (FAILED_TEST.test(item.condition)) return true;
      continue;
    }
    for (const name of call.bound) {
      const n = escape(name);
      const falsy = new RegExp(
        `!\\s*${n}\\b|\\b${n}\\s*(?:\\.\\s*[A-Za-z_$][\\w$]*)*\\s*===?\\s*(?:null|undefined|false)\\b`);
      if (falsy.test(item.condition)) return true;
      for (const key of rejectionKeys) {
        const k = escape(key);
        if (new RegExp(`['"\`]?${k}['"\`]?\\s+in\\s+${n}\\b`).test(item.condition)) return true;
        if (new RegExp(`\\b${n}\\s*\\.\\s*${k}\\b`).test(item.condition)) return true;
      }
    }
  }
  return false;
}

export function handlerGuardEffects(
  context: GuardLookup,
  filePath: string,
  scope: string,
): HandlerGuardEffects {
  if (scope === '' || scope.length > MAX_SCOPE_CHARS) return { ...NO_GUARD };
  const code = stripCommentsOnly(scope);
  const effects: HandlerGuardEffects = { ...NO_GUARD };
  for (const call of handlerCalls(code)) {
    const helper = classifyHelper(context, filePath, call.name, 0, new Set());
    if (!hasAnyEffect(helper)) continue;
    effects.role ||= helper.blocks.role;
    effects.rejection ||= helper.blocks.identity;
    effects.signature ||= helper.blocks.signature;
    effects.rateLimit ||= helper.blocks.rate;
    if (!callSiteRejects(code, call, helper.rejectionKeys)) continue;
    effects.role ||= helper.decides.role;
    effects.rejection ||= helper.decides.identity;
    effects.signature ||= helper.decides.signature;
    effects.rateLimit ||= helper.decides.rate;
  }
  return effects;
}

const IDENTITY_BINDING = /^(?:user|session|account|profile|member|claims|auth|identity|principal|currentUser|userId|uid)$/i;

export function guardOnlyModules(
  context: GuardLookup,
  filePath: string,
  scope: string,
): string[] {
  if (scope === '' || scope.length > MAX_SCOPE_CHARS) return [];
  const code = stripCommentsOnly(scope);
  const guardOnly = new Map<string, boolean>();
  for (const call of handlerCalls(code)) {
    const definedIn = importedFrom(context, filePath, call.name);
    if (definedIn === undefined || definedIn === filePath) continue;
    const helper = classifyHelper(context, filePath, call.name, 0, new Set());
    const guards = helper.blocks.identity || helper.blocks.role ||
      helper.decides.identity || helper.decides.role;
    const identityOnly = call.bound.length === 0 ||
      call.bound.every((name) => IDENTITY_BINDING.test(name));
    guardOnly.set(definedIn, (guardOnly.get(definedIn) ?? true) && guards && identityOnly);
  }
  return [...guardOnly.entries()].filter(([, only]) => only).map(([path]) => path);
}

export function resolvesToRoleCheck(context: GuardLookup, filePath: string, scope: string): boolean {
  return handlerGuardEffects(context, filePath, scope).role;
}

export function resolvesToRejection(context: GuardLookup, filePath: string, scope: string): boolean {
  const effects = handlerGuardEffects(context, filePath, scope);
  return effects.rejection || effects.role;
}

export function resolvesToRateLimit(context: GuardLookup, filePath: string, scope: string): boolean {
  return handlerGuardEffects(context, filePath, scope).rateLimit;
}

export function resolvesToSignatureCheck(context: GuardLookup, filePath: string, scope: string): boolean {
  return handlerGuardEffects(context, filePath, scope).signature;
}
