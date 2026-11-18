import { makeFinding } from '../../shared/findingFactory.js';
import type { Finding, RuleContext, ScanRule } from '../../shared/types.js';
import { findMatches } from '../../shared/utils.js';
import { stripCommentsAndStrings } from '../../shared/source.js';
import { CODE } from './patternRule.js';

// md5/sha1 count only for passwords or tokens, not checksums.
const WEAK_HASH = /(?:createHash\s*\(\s*['"](?:md5|sha1)['"]|hashlib\.(?:md5|sha1)\s*\()/gi;
const OBSOLETE_CIPHER =
  /(?:createCipheriv?\s*\(\s*['"][^'"]*(?:des|rc4|ecb)|algorithms?\.(?:DES|ARC4)|modes\.ECB)/gi;
const PREDICTABLE_TOKEN = /(?:token|secret|nonce|otp|reset|session)[\w$]*\s*=\s*Math\.random\s*\(/gi;

// Names that mark a value as a reset, verify or invite token.
const TOKEN_PURPOSE = /\b(?:reset|recover(?:y)?|forgot|verif\w*|confirm\w*|activat\w*|invit\w*|magic|one\s?time|otp|unsubscribe)\b/i;

const TOKEN_NOUN = /\b(?:tokens?|codes?|keys?|links?|nonce|secret|hash|digest)\b/i;

const ASSIGNED_NAME =
  /(?:(?:const|let|var)\s+|(?:this|user|account|record|doc|payload|data|update|set)\s*\.\s*)?([A-Za-z_$][\w$]*)\s*(?:=|:)\s*(?:await\s+)?$/;

function digestTargetName(content: string, matchIndex: number): string | undefined {
  const before = content.slice(Math.max(0, matchIndex - 200), matchIndex);
  return ASSIGNED_NAME.exec(before)?.[1];
}

function isTokenGenerationName(name: string): boolean {
  const segmented = name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .replace(/[_\-.]/g, ' ');
  return TOKEN_PURPOSE.test(segmented) && TOKEN_NOUN.test(segmented);
}

const SECURITY_CONTEXT =
  /\b(?:pass(?:word|wd|phrase)?|pwd|secret|token|session|sign(?:ature|ing)?|hmac|integrity|verif(?:y|ication)|authenticat|\bauth\b|api[_-]?key|credential|csrf|\bsalt\b|\bmac\b|cookie|\bjwt\b|\botp\b|2fa|mfa|private[_-]?key|access[_-]?token|refresh[_-]?token)/i;
function hashedInputs(content: string, matchIndex: number, matchText: string): string[] {
  const inputs: string[] = [];

  const selectionOpen = content.indexOf('(', matchIndex);
  if (/^hashlib\./.test(matchText)) {
    const arg = callArgument(content, selectionOpen);
    if (arg !== undefined) inputs.push(arg);
  }

  let cursor = closingParen(content, selectionOpen);
  while (cursor !== undefined) {
    const member = /^\s*\.\s*([A-Za-z_$][\w$]*)\s*\(/.exec(content.slice(cursor + 1, cursor + 1 + 80));
    if (member === null) break;
    const open = cursor + 1 + member[0].length - 1;
    if (member[1] === 'update') {
      const arg = callArgument(content, open);
      if (arg !== undefined) inputs.push(arg);
    }
    cursor = closingParen(content, open);
  }
  if (inputs.length > 0) return inputs;

  const binding = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]{0,120})?=\s*[^\n]{0,40}$/.exec(
    content.slice(Math.max(0, matchIndex - 160), matchIndex),
  );
  const name = binding?.[1];
  if (name === undefined) return inputs;
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  for (const update of content.matchAll(new RegExp(String.raw`(?<![.\w$])${escaped}\s*\.\s*update\s*\(`, 'g'))) {
    const arg = callArgument(content, (update.index ?? 0) + update[0].length - 1);
    if (arg !== undefined) inputs.push(arg);
  }
  return inputs;
}

function closingParen(content: string, openParenIndex: number): number | undefined {
  if (content[openParenIndex] !== '(') return undefined;
  let depth = 0;
  for (let i = openParenIndex; i < content.length && i < openParenIndex + 400; i += 1) {
    const ch = content[i];
    if (ch === '(') depth += 1;
    else if (ch === ')') {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return undefined;
}

function callArgument(content: string, openParenIndex: number): string | undefined {
  if (content[openParenIndex] !== '(') return undefined;
  let depth = 0;
  let out = '';
  for (let i = openParenIndex; i < content.length && i < openParenIndex + 240; i += 1) {
    const ch = content[i] ?? '';
    if (ch === '(') { depth += 1; if (depth === 1) continue; }
    if (ch === ')') { depth -= 1; if (depth === 0) break; }
    if (ch === ',' && depth === 1) break;
    out += ch;
  }
  const trimmed = out.trim();
  return trimmed === '' ? undefined : trimmed;
}

function isSensitiveText(text: string): boolean {
  if (SECURITY_CONTEXT.test(text)) return true;
  const segmented = text
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .replace(/[_\-.]/g, ' ');
  return SECURITY_CONTEXT.test(segmented);
}

function feedsSensitiveValue(inputs: readonly string[], content: string): boolean {
  for (const input of inputs) {
    if (isSensitiveText(input)) return true;
    const identifier = /^([A-Za-z_$][\w$]*)$/.exec(input)?.[1];
    if (identifier === undefined) continue;
    const escaped = identifier.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const definition = new RegExp(String.raw`\b(?:const|let|var)\s+${escaped}\s*(?::[^=;\n]{0,120})?=\s*([^;\n]{0,200})`);
    const rhs = definition.exec(content)?.[1];
    if (rhs !== undefined && isSensitiveText(rhs)) return true;
  }
  return false;
}

export const insecureCryptography: ScanRule = {
  id: 'insecure_cryptography',
  title: 'Insecure cryptography is used',
  category: 'authentication',
  kind: 'basic',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    for (const entry of context.fileMap.entries) {
      if (!CODE.has(entry.extension)) continue;
      const contextSource = stripCommentsAndStrings(entry.content);

      for (const match of findMatches(entry.content, WEAK_HASH)) {
        const inputs = hashedInputs(contextSource, match.index, match.matchText);

        const target = digestTargetName(contextSource, match.index);
        if (target !== undefined && isTokenGenerationName(target)) {
          findings.push(makeFinding({
            ruleId: this.id,
            title: `${this.title}: predictable account-recovery token`,
            severity: 'high',
            confidence: 'high',
            filePath: entry.path,
            lineStart: match.line,
            evidence: match.snippet,
            userExplanation:
              `The value "${target}" is what proves someone clicked the link you emailed them, and it is built with MD5/SHA-1. Those are fast and, over an input an attacker can narrow down — a timestamp, an email address, a counter — the result can simply be worked out. Anyone who can guess it takes over the account without the email.`,
            technicalExplanation:
              `${entry.path}:${match.line}: an account-recovery token (${target}) is derived from MD5/SHA-1${inputs.length > 0 ? ` over ${inputs.join(', ').slice(0, 100)}` : ''}. Token unguessability is the entire control here: a fast digest over low-entropy, attacker-observable input is enumerable offline. Generate it with crypto.randomBytes(32).toString('hex') (or randomUUID), store a hash of it, and give it a short expiry and single use.`,
            fixHint:
              "Generate the token with crypto.randomBytes(32).toString('hex') or crypto.randomUUID() - never from a hash of a timestamp, a counter, an email or Math.random(). Store only a SHA-256 of it, expire it in under an hour, and delete it the moment it is used.",
            category: this.category,
          }));
          continue;
        }

        if (!feedsSensitiveValue(inputs, contextSource)) continue;
        findings.push(makeFinding({
          ruleId: this.id,
          title: `${this.title}: weak hash algorithm`,
          severity: 'medium',
          confidence: 'high',
          filePath: entry.path,
          lineStart: match.line,
          evidence: match.snippet,
          userExplanation:
            'MD5 and SHA-1 are obsolete for security decisions and are especially unsafe for passwords.',
          technicalExplanation:
            `${entry.path}:${match.line}: MD5/SHA-1 lacks modern collision resistance and is fast to brute-force, and a security-sensitive value reaches this hash (${inputs.join(', ').slice(0, 120)}). Use a password KDF or an approved SHA-256+ construction instead.`,
          fixHint:
            'For passwords use Argon2id, scrypt, bcrypt, or PBKDF2 with per-user salts. For signatures/integrity use an approved SHA-256+ construction or HMAC. If this is only a non-security identifier/cache key, no change is required.',
          category: this.category,
        }));
      }

      for (const match of findMatches(entry.content, OBSOLETE_CIPHER)) {
        findings.push(makeFinding({
          ruleId: this.id,
          title: `${this.title}: obsolete cipher or mode`,
          severity: 'high',
          confidence: 'high',
          filePath: entry.path,
          lineStart: match.line,
          evidence: match.snippet,
          userExplanation:
            'The application selects an obsolete cipher or ECB mode, which does not provide safe modern encryption.',
          technicalExplanation: `${entry.path}:${match.line}: DES, RC4, and ECB are unsuitable for protecting application data.`,
          fixHint:
            'Use an authenticated encryption mode such as AES-256-GCM or ChaCha20-Poly1305 with random nonces and managed keys.',
          category: this.category,
        }));
      }

      for (const match of findMatches(entry.content, PREDICTABLE_TOKEN)) {
        findings.push(makeFinding({
          ruleId: this.id,
          title: `${this.title}: predictable security token`,
          severity: 'high',
          confidence: 'high',
          filePath: entry.path,
          lineStart: match.line,
          evidence: match.snippet,
          userExplanation:
            'A security-sensitive value is generated with Math.random(), whose output is predictable and unsuitable for tokens.',
          technicalExplanation: `${entry.path}:${match.line}: Math.random is not a cryptographically secure random number generator.`,
          fixHint:
            'Generate tokens with crypto.randomBytes/randomUUID or Web Crypto getRandomValues, using sufficient entropy.',
          category: this.category,
        }));
      }
    }
    return findings;
  },
};
