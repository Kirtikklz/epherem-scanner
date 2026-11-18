import { stripCommentsAndStrings } from './source.js';

export type ControlState = 'proven' | 'absent' | 'unresolved';

export interface MiddlewareEffects {
  auth: boolean;
  admin: boolean;
  rateLimit: boolean;
  signature: boolean;
  validation: boolean;
}

const NO_EFFECTS: MiddlewareEffects = {
  auth: false,
  admin: false,
  rateLimit: false,
  signature: false,
  validation: false,
};

const MAX_BODY_CHARS = 12_000;
const MAX_HEAD_CHARS = 400;
const MAX_INLINE_CONSEQUENT = 300;
const MAX_CONDITION_CHARS = 400;

export const FAILED_TEST =
  /![^=]|\bnot\b|===?\s*(?:null|undefined|false)\b|!==?[^=]|\.length\s*===?\s*0\b|\bis\s+None\b/;

export const IDENTITY_SUBJECT =
  /\b(?:user|users|session|token|auth|authHeader|authorization|bearer|jwt|claims|uid|identity|principal|credential|credentials|account|apiKey|currentUser|signedIn|authenticated|authorized|cookie|cookies)\b|\b(?:user|session|auth|account|api)_?(?:id|Id|key|Key|token|Token)\b/;

export const ROLE_SUBJECT =
  /\b(?:role|roles|isAdmin|admin|isSuperAdmin|superadmin|permission|permissions|scope|scopes|claim|claims|privilege|privileges|ability|abilities|can|allowed|grants?)\b/i;

export const SIGNATURE_SUBJECT =
  /\b(?:signature|signatures|sig|hmac|digest|checksum|svix|webhookSecret|signingSecret)\b/i;

export const REJECTION =
  /\b(?:res|response|reply|ctx)\s*\.\s*(?:status|code|sendStatus)\s*\(\s*(?:401|403|419|429)\s*\)|\bstatus\s*:\s*(?:401|403|419|429)\b|\bsendStatus\s*\(\s*(?:401|403|419|429)\s*\)|\bthrow\b|\bnext\s*\(\s*(?!\s*\))[A-Za-z_$][\w$.]*|\bctx\s*\.\s*throw\s*\(|\babort\s*\(\s*(?:401|403)/;

export const RATE_REJECTION =
  /\b(?:res|response|reply|ctx)\s*\.\s*(?:status|code|sendStatus)\s*\(\s*429\s*\)|\bstatus\s*:\s*429\b|\bsendStatus\s*\(\s*429\s*\)|\b429\b/;

const RESUMES_DISPATCH = /\bnext\s*\(\s*\)/;

export const LIMITER_LIBRARY =
  /\brateLimit\s*\(|\bnew\s+RateLimiter\w*\s*\(|\bRateLimiter\w*\s*\(|\bslowDown\s*\(|\bnew\s+Ratelimit\s*\(|\bexpressBrute\b|\bnew\s+Bottleneck\s*\(|\.\s*(?:consume|tryConsume|removeTokens)\s*\(|\.\s*limit\s*\(/;

export const SIGNATURE_VERIFY =
  /\bcreateHmac\s*\(|\btimingSafeEqual\s*\(|\bconstructEvent\s*\(|\bnew\s+Webhook\s*\(|\bwebhooks?\s*\.\s*(?:verify|constructEvent|verifySignature)\s*\(|\bverifyHeader\s*\(/;

const VALIDATOR_CHAIN =
  /\b(?:body|param|params|query|header|cookie|check|checkExact)\s*\(\s*['"`][^'"`]*['"`]\s*\)\s*(?:\.\s*\w+\s*\([^)]*\)\s*)*\.\s*\w+\s*\(|\bcheckSchema\s*\(|\boneOf\s*\(\s*\[/;

const VALIDATION_RESULT_REJECTION = /\bvalidationResult\s*\(/;
const FOUR_XX = /\.\s*status\s*\(\s*4\d\d\s*\)|\bstatus\s*:\s*4\d\d\b|\bsendStatus\s*\(\s*4\d\d\s*\)/;

export function hasValidatorChain(middlewareText: string): boolean {
  return VALIDATOR_CHAIN.test(stripComments(middlewareText));
}

export function rejectsOnValidationResult(handlerText: string): boolean {
  const code = stripComments(handlerText);
  return VALIDATION_RESULT_REJECTION.test(code) && FOUR_XX.test(code);
}

export function stripComments(text: string): string {
  try {
    return stripCommentsAndStrings(text);
  } catch {
    return text;
  }
}

export function balanced(text: string, open: number, openCh: string, closeCh: string, cap: number): { inner: string; end: number } | undefined {
  let depth = 0;
  for (let i = open; i < text.length && i < open + cap; i += 1) {
    const c = text[i];
    if (c === openCh) depth += 1;
    else if (c === closeCh) {
      depth -= 1;
      if (depth === 0) return { inner: text.slice(open + 1, i), end: i };
    }
  }
  return undefined;
}

export interface Conditional {
  condition: string;
  consequent: string;
  conditionIndex: number;
  depth: number;
  consequentIndex: number;
}

export function conditionals(code: string): Conditional[] {
  const out: Conditional[] = [];
  const depths = braceDepths(code);
  const ifRe = /\bif\s*\(/g;
  for (let m = ifRe.exec(code); m !== null; m = ifRe.exec(code)) {
    const open = m.index + m[0].length - 1;
    const cond = balanced(code, open, '(', ')', MAX_CONDITION_CHARS);
    if (cond === undefined) continue;
    let i = cond.end + 1;
    while (i < code.length && /\s/.test(code[i] ?? '')) i += 1;
    let consequent: string;
    let consequentIndex: number;
    if (code[i] === '{') {
      const block = balanced(code, i, '{', '}', MAX_BODY_CHARS);
      consequent = block === undefined ? code.slice(i, i + MAX_INLINE_CONSEQUENT) : block.inner;
      consequentIndex = block === undefined ? i : i + 1;
    } else {
      const rest = code.slice(i, i + MAX_INLINE_CONSEQUENT);
      const semi = rest.indexOf(';');
      consequent = semi === -1 ? rest : rest.slice(0, semi + 1);
      consequentIndex = i;
    }
    out.push({
      condition: cond.inner,
      consequent,
      conditionIndex: open + 1,
      depth: depths[m.index] ?? 0,
      consequentIndex,
    });
  }
  return out;
}

function braceDepths(code: string): number[] {
  const depths = new Array<number>(code.length);
  let depth = 0;
  for (let i = 0; i < code.length; i += 1) {
    const ch = code[i];
    if (ch === '}') depth -= 1;
    depths[i] = depth;
    if (ch === '{') depth += 1;
  }
  return depths;
}

function rejectsOn(code: string, subject: RegExp, rejection: RegExp = REJECTION): boolean {
  for (const { condition, consequent } of conditionals(code)) {
    if (!subject.test(condition)) continue;
    if (!FAILED_TEST.test(condition)) continue;
    if (rejection.test(consequent)) return true;
  }
  return false;
}

export function classifyMiddlewareBody(rawBody: string): MiddlewareEffects {
  const code = stripComments(rawBody);
  const resumes = RESUMES_DISPATCH.test(code);
  if (!resumes) return { ...NO_EFFECTS };
  return {
    auth: rejectsOn(code, IDENTITY_SUBJECT),
    admin: rejectsOn(code, ROLE_SUBJECT),
    rateLimit: LIMITER_LIBRARY.test(code) && RATE_REJECTION.test(code),
    signature: SIGNATURE_VERIFY.test(code) && rejectsOn(code, SIGNATURE_SUBJECT),
    validation: VALIDATOR_CHAIN.test(code) || rejectsOn(code, /\b(?:body|payload|input|schema|errors|valid|validation)\b/i, FOUR_XX),
  };
}

export function middlewareBodyOf(content: string, name: string): string | undefined {
  const n = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const patterns = [
    new RegExp(`(?:export\\s+)?(?:default\\s+)?(?:async\\s+)?function\\s*\\*?\\s+${n}\\s*\\(`),
    new RegExp(`(?:export\\s+)?(?:const|let|var)\\s+${n}\\s*(?::[^=\\n]{0,200})?=\\s*(?:async\\s+)?function\\b`),
    new RegExp(
      `(?:export\\s+)?(?:const|let|var)\\s+${n}\\s*(?::[^=\\n]{0,200})?=\\s*(?:async\\s*)?` +
        `(?:\\([^)]{0,400}\\)|[A-Za-z_$][\\w$]*)\\s*(?::[^=>\\n]{0,200})?=>`,
    ),
    new RegExp(
      `(?:public|private|protected|readonly|static|declare)\\s+(?:[A-Za-z]+\\s+)*${n}\\s*(?::[^=\\n]{0,200})?=\\s*(?:async\\s*)?` +
        `(?:\\([^)]{0,400}\\)|[A-Za-z_$][\\w$]*)\\s*(?::[^=>\\n]{0,200})?=>`,
    ),
    new RegExp(`(?:public|private|protected|static|async)\\s+(?:[A-Za-z]+\\s+)*${n}\\s*\\([^)]{0,400}\\)\\s*(?::[^{\\n]{0,200})?\\{`),
  ];
  for (const pattern of patterns) {
    const match = pattern.exec(content);
    if (match?.index === undefined) continue;
    let from = match.index + match[0].length;
    if (content[from - 1] === '(') {
      const params = balanced(content, from - 1, '(', ')', MAX_BODY_CHARS);
      if (params !== undefined) from = params.end + 1;
    }
    const open = content.indexOf('{', from - 1);
    if (open === -1 || open - from > MAX_HEAD_CHARS) continue;
    const block = balanced(content, open, '{', '}', MAX_BODY_CHARS);
    if (block !== undefined) return block.inner;
  }
  return undefined;
}

function factoryBodyOf(content: string, name: string): string | undefined {
  const n = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const decl = new RegExp(
    `(?:export\\s+)?(?:const|let|var)\\s+${n}\\s*(?::[^=\\n]{0,200})?=\\s*(?:await\\s+)?([A-Za-z_$][\\w$]*)\\s*\\(`,
  ).exec(content);
  const factory = decl?.[1];
  if (factory === undefined || factory === name) return undefined;
  return middlewareBodyOf(content, factory);
}

export interface ResolvedMiddleware {
  filePath: string;
  effects: MiddlewareEffects;
}

export function resolveMiddleware(
  token: string,
  filePath: string,
  bindings: ReadonlyMap<string, string>,
  contentOf: (path: string) => string | undefined,
): ResolvedMiddleware | undefined {
  const parts = token.split('.').map((p) => p.trim()).filter((p) => p !== '');
  const head = parts[0];
  if (head === undefined) return undefined;
  const name = parts.length > 1 ? parts[parts.length - 1] ?? head : head;

  const candidates: string[] = [];
  const imported = bindings.get(head);
  if (imported !== undefined) candidates.push(imported);
  if (!candidates.includes(filePath)) candidates.push(filePath);

  for (const path of candidates) {
    const content = contentOf(path);
    if (content === undefined) continue;
    const body = middlewareBodyOf(content, name) ?? factoryBodyOf(content, name);
    if (body === undefined) continue;
    return { filePath: path, effects: classifyMiddlewareBody(body) };
  }
  return undefined;
}
