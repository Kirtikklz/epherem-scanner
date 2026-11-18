import { isScannerInternalPath } from '../../input/fileFilters.js';
import { makeFinding } from '../../shared/findingFactory.js';
import { enclosingFunctionScopeRange } from '../../shared/handlerScope.js';
import { librarySelfTestScope } from '../../shared/librarySelfTest.js';
import type { Confidence, Finding, RuleContext, ScanRule, Severity } from '../../shared/types.js';
import { findMatches, lineAt } from '../../shared/utils.js';
import { stripCommentsOnly, usesHashComments } from '../../shared/source.js';
import { pythonCallArguments } from '../../shared/pythonSettings.js';

const CODE_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py']);

interface JwtProbe {
  key: string;
  pattern: RegExp;
  severity: Severity;
  confidence: Confidence;
  title: string;
  user: string;
  tech: string;
  fix: string;
}

const PROBES: JwtProbe[] = [
  {
    key: 'decode_without_verify',
    pattern: /\bjwt\.decode\s*\(/g,
    severity: 'high',
    confidence: 'medium',
    title: 'JWT decoded without verifying its signature',
    user: 'This code reads the contents of a login token without checking that it is genuine. Anyone can forge a token and impersonate any user. Verify the signature instead of just decoding.',
    tech: 'jwt.decode() (or equivalent) reads claims without signature verification. Use jwt.verify() with the correct secret/public key; decode() must never gate access.',
    fix: 'Replace jwt.decode() with jwt.verify(token, secret, { algorithms: ["HS256"|"RS256"] }) and only trust claims from the verified result.',
  },
  {
    key: 'verify_none_alg',
    pattern: /algorithms?\s*:\s*\[?\s*['"]none['"]/gi,
    severity: 'critical',
    confidence: 'high',
    title: 'JWT verification allows the "none" algorithm',
    user: 'Your token check accepts tokens with no signature at all. That lets anyone log in as anyone. Remove "none" and require a real signing algorithm.',
    tech: 'The "none" algorithm disables signature verification entirely. Pin a specific algorithm (HS256/RS256) and never include "none" in the allowed list.',
    fix: 'Remove "none" from the algorithms option and pin exactly the algorithm you sign with (e.g. algorithms: ["RS256"]).',
  },
  {
    key: 'ignore_expiration',
    pattern: /ignoreExpiration\s*:\s*true/g,
    severity: 'high',
    confidence: 'high',
    title: 'JWT verification ignores token expiration',
    user: 'Your login tokens are accepted even after they expire, so a stolen token works forever. Stop ignoring expiration.',
    tech: 'ignoreExpiration: true disables the exp claim check. Remove it so expired tokens are rejected, and keep token lifetimes short.',
    fix: 'Remove ignoreExpiration: true so exp is enforced. Use short-lived access tokens with refresh tokens if you need longer sessions.',
  },
  {
    key: 'hardcoded_secret_arg',
    pattern: /\bjwt\.(?:sign|verify)\s*\([^,]+,\s*['"][^'"]{1,}['"]/g,
    severity: 'high',
    confidence: 'low',
    title: 'JWT secret hardcoded in source',
    user: 'The secret used to sign login tokens is written directly in the code. Anyone who sees the code can mint valid tokens. Move it to a server environment variable.',
    tech: 'A string literal is passed as the JWT secret/key. Load it from server-side configuration (process.env) and rotate the exposed value.',
    fix: 'Pass the secret from process.env (never a literal), and rotate the currently hardcoded secret since it is compromised.',
  },
];

const PYTHON_EXTENSION = '.py';
const PYTHON_VERIFICATION_OPT_OUT =
  /['"]verify_signature['"]\s*:\s*False\b|\bverify_signature\s*=\s*False\b|\bverify\s*=\s*False\b/;
const PYTHON_DECODE_WITH_VERIFICATION_OFF = {
  user: 'This code reads the contents of a login token with its signature check switched off, so anyone can forge a token and impersonate any user. Remove the option that disables verification.',
  tech: 'jwt.decode() is called with signature verification disabled (verify_signature False / verify=False). With PyJWT and python-jose, decode() verifies by default; the opt-out removes that check.',
  fix: 'Remove the verification opt-out and call jwt.decode(token, key, algorithms=["HS256"]) (or your real algorithm) so the signature is checked; only trust claims from that call.',
} as const;

function pythonDecodeDisablesVerification(content: string, match: { index: number; matchText: string }): boolean {
  const args = pythonCallArguments(content, match.index + match.matchText.length - 1);
  return args !== undefined && PYTHON_VERIFICATION_OPT_OUT.test(args);
}

const PYTHON_EXPIRY_OPT_OUT = /['"]verify_exp['"]\s*:\s*False\b|\bverify_exp\s*=\s*False\b/;
const PYTHON_DECODE_IGNORES_EXPIRY = {
  user: 'Your login tokens are accepted even after they expire, so a stolen token works forever. Stop switching off the expiry check.',
  tech: 'jwt.decode() is called with options={"verify_exp": False}, which disables the exp claim check. Remove it so expired tokens are rejected, and keep token lifetimes short.',
  fix: 'Remove "verify_exp": False from the decode options so exp is enforced. Use short-lived access tokens with refresh tokens if you need longer sessions.',
} as const;
const PYTHON_ALGORITHM_FROM_TOKEN = {
  title: "JWT algorithm taken from the token's own header",
  user: 'Your token check lets each token say which algorithm it should be checked with, so an attacker can pick one that your key does not protect and forge tokens. Fix the algorithm in your code instead.',
  tech: 'jwt.decode() takes its algorithms list from jwt.get_unverified_header(), i.e. from the unverified token itself. This enables algorithm confusion (for example an RS256 public key accepted as an HS256 secret). Pass a fixed list such as algorithms=["HS256"].',
  fix: 'Pass the algorithm you actually sign with as a fixed list, e.g. jwt.decode(token, key, algorithms=["HS256"]), and never read it from the token header.',
} as const;
const UNVERIFIED_HEADER_BINDING = /\b([A-Za-z_]\w*)\s*=\s*(?:[\w.]+\.)?get_unverified_header\s*\(/g;
const ALGORITHMS_ARGUMENT = /\balgorithms\s*=\s*([^,\n]+(?:\][^,\n]*)?)/;

function pythonAlgorithmFromToken(content: string, args: string): boolean {
  const value = ALGORITHMS_ARGUMENT.exec(args)?.[1];
  if (value === undefined) return false;
  if (/get_unverified_header\s*\(/.test(value)) return true;
  for (const binding of content.matchAll(UNVERIFIED_HEADER_BINDING)) {
    const name = binding[1];
    if (name !== undefined && new RegExp(`(?<![\\w.])${name}\\s*(?:\\[|\\.get\\s*\\()`).test(value)) return true;
  }
  return false;
}

function pythonDecodeWeakness(
  content: string,
  match: { index: number; matchText: string },
): { title: string; user: string; tech: string; fix: string } | undefined {
  const args = pythonCallArguments(content, match.index + match.matchText.length - 1);
  if (args === undefined) return undefined;
  if (PYTHON_EXPIRY_OPT_OUT.test(args)) {
    return { title: 'JWT verification ignores token expiration', ...PYTHON_DECODE_IGNORES_EXPIRY };
  }
  if (pythonAlgorithmFromToken(content, args)) return PYTHON_ALGORITHM_FROM_TOKEN;
  return undefined;
}

const JWT_LIBRARY = {
  namePattern: /(?:^|[@/\-_])(?:jsonwebtoken|jose|jwt|jws|jwa)(?:[-_.]|$)/i,
  mainExportPattern:
    /(?:module\.)?exports\s*(?:=|\.)[\s\S]{0,400}?\b(?:decode|verify|sign)\b|\bexport\s+(?:async\s+)?function\s+(?:decode|verify|sign|jwtVerify|decodeJwt)\b|\bexport\s*\{[^}]{0,300}\b(?:decode|verify|sign|jwtVerify|decodeJwt|SignJWT)\b/,
} as const;

function verifiedInEnclosingFunction(content: string, index: number, line: number): boolean {
  const VERIFY = /\bjwt\.verify\s*\(|j?wtVerify\s*\(/;
  const { start, end } = enclosingFunctionScopeRange(content, index);
  const wholeFile = start === 0 && end === content.length;
  if (wholeFile) return VERIFY.test(content.split('\n')[line - 1] ?? '');
  return VERIFY.test(content.slice(start, end));
}

export const weakJwtHandling: ScanRule = {
  id: 'weak_jwt_handling',
  title: 'Weak JWT handling',
  category: 'authentication',
  kind: 'basic',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const isLibrarySelfTest = librarySelfTestScope(context.fileMap.entries, JWT_LIBRARY);
    for (const entry of context.fileMap.entries) {
      if (!CODE_EXTENSIONS.has(entry.extension)) continue;
      if (isLibrarySelfTest(entry.path)) continue;
      if (isScannerInternalPath(entry.path, context.projectMap.scannerRootPrefix)) continue;
      if (!/jwt|jsonwebtoken|jose/i.test(entry.content)) continue;
      const scanContent = stripCommentsOnly(entry.content, usesHashComments(entry.extension, entry.label));
      const python = entry.extension === PYTHON_EXTENSION;
      for (const probe of PROBES) {
        for (const match of findMatches(scanContent, probe.pattern)) {
          const pythonOptOut = python && probe.key === 'decode_without_verify';
          if (pythonOptOut && !pythonDecodeDisablesVerification(scanContent, match)) {
            const weaker = pythonDecodeWeakness(scanContent, match);
            if (weaker !== undefined) {
              findings.push(
                makeFinding({
                  ruleId: this.id,
                  title: weaker.title,
                  severity: 'high',
                  confidence: 'high',
                  filePath: entry.path,
                  lineStart: match.line,
                  evidence: lineAt(entry.content, match.line),
                  userExplanation: weaker.user,
                  technicalExplanation: `${entry.path}:${match.line}: ${weaker.tech}`,
                  fixHint: weaker.fix,
                  category: this.category,
                }),
              );
            }
            continue;
          }
          if (probe.key === 'decode_without_verify') {
            if (verifiedInEnclosingFunction(scanContent, match.index, match.line)) continue;
          }
          if (probe.key === 'hardcoded_secret_arg' && /process\.env/.test(match.matchText)) continue;
          const text = pythonOptOut ? PYTHON_DECODE_WITH_VERIFICATION_OFF : probe;
          findings.push(
            makeFinding({
              ruleId: this.id,
              title: probe.title,
              severity: probe.severity,
              confidence: probe.confidence,
              filePath: entry.path,
              lineStart: match.line,
              evidence: lineAt(entry.content, match.line),
              userExplanation: text.user,
              technicalExplanation: `${entry.path}:${match.line}: ${text.tech}`,
              fixHint: text.fix,
              category: this.category,
            }),
          );
        }
      }
    }
    return findings;
  },
};
