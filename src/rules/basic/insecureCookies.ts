import { makeFinding } from '../../shared/findingFactory.js';
import type { Finding, RuleContext, ScanRule } from '../../shared/types.js';
import { stripCommentsOnly, usesHashComments } from '../../shared/source.js';
import { findMatches, lineAt } from '../../shared/utils.js';
import { isPythonNonProductionSetting, pythonCallArguments } from '../../shared/pythonSettings.js';
import { pythonCookieSpread } from '../../shared/pythonCookieSpread.js';

const CODE_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py']);

const COOKIE_SET =
  /\b(?:res|reply|response|ctx)\.cookie\s*\(\s*[^,]+,\s*[^,]+,\s*(\{[\s\S]{0,220}?\})\s*\)|\bcookies\(\)\s*\.set\s*\(\s*(\{[\s\S]{0,220}?\}|[^)]*)\)|\bset_cookie\s*\([^)]*\)|Set-Cookie['"]\s*,\s*['"]([^'"]+)['"]/g;
const SESSION_HINT = /session|sid|token|auth|jwt|connect\.sid/i;

const PYTHON_SET_COOKIE = /^set_cookie\s*\(/;
const PYTHON_FLAG = (name: string): RegExp => new RegExp(String.raw`\b${name}\s*=\s*(?!(?:False|None)\b)\S`, 'i');
const PYTHON_SESSION_HINT = /refresh/i;
const PYTHON_KEY_FLAG = (name: string): RegExp => new RegExp(String.raw`['"]${name}['"]\s*:\s*(?!(?:False|None)\b)\S`, 'i');

const PYTHON_SESSION_SETTING_OFF =
  /\b(SESSION_COOKIE_SECURE|SESSION_COOKIE_HTTPONLY)\b['"]?\s*\]?\s*[:=]\s*False\b/g;

const SESSION_MIDDLEWARE_CALL = /\b(?:session|cookieSession|expressSession|clientSessions)\s*\(\s*\{/g;

const SESSION_OPTIONS_KEY = /\b(?:secret|keys|resave|saveUninitialized|rolling|store|cookie|signed|maxAge|proxy)\s*:/;

const COOKIE_OPTIONS_KEY = /\bcookie\s*:\s*\{/;

const SECURE_ASSIGNED_LATER = /\.\s*cookie\s*\.\s*secure\s*=\s*(?!false\b)/;

function balancedBraces(text: string, open: number, cap = 2000): string | undefined {
  if (text[open] !== '{') return undefined;
  let depth = 0;
  for (let i = open; i < text.length && i < open + cap; i += 1) {
    const ch = text[i];
    if (ch === '{') depth += 1;
    else if (ch === '}') {
      depth -= 1;
      if (depth === 0) return text.slice(open, i + 1);
    }
  }
  return undefined;
}

function optionValue(objectText: string, key: string): string | undefined {
  const re = new RegExp(String.raw`(?:^|[{,\s])${key}\s*:\s*`, 'i');
  const m = re.exec(objectText);
  if (m === null) return undefined;
  const from = m.index + m[0].length;
  let depth = 0;
  let out = '';
  for (let i = from; i < objectText.length && i < from + 200; i += 1) {
    const ch = objectText[i] ?? '';
    if (ch === '{' || ch === '[' || ch === '(') depth += 1;
    else if (ch === '}' || ch === ']' || ch === ')') {
      if (depth === 0) break;
      depth -= 1;
    } else if (ch === ',' && depth === 0) break;
    out += ch;
  }
  const trimmed = out.trim();
  return trimmed === '' ? undefined : trimmed;
}

function isExplicitlyFalse(value: string | undefined): boolean {
  return value !== undefined && /^false$/i.test(value);
}

function secureIsSet(cookieOptions: string | undefined, fileCode: string): boolean {
  if (SECURE_ASSIGNED_LATER.test(fileCode)) return true;
  if (cookieOptions === undefined) return false;
  const value = optionValue(cookieOptions, 'secure');
  return value !== undefined && !isExplicitlyFalse(value);
}

function sessionCookieDefects(cookieOptions: string | undefined, fileCode: string): string[] {
  const valueOf = (key: string): string | undefined =>
    cookieOptions === undefined ? undefined : optionValue(cookieOptions, key);
  const defects: string[] = [];
  if (isExplicitlyFalse(valueOf('httpOnly'))) defects.push('HttpOnly');
  if (!secureIsSet(cookieOptions, fileCode)) {
    const sameSite = valueOf('sameSite');
    defects.push(
      sameSite !== undefined && /^['"`]none['"`]$/i.test(sameSite) ? 'Secure (required by SameSite=None)' : 'Secure',
    );
  }
  return defects;
}

export const insecureCookies: ScanRule = {
  id: 'insecure_cookies',
  title: 'Cookie set without secure attributes',
  category: 'cookies',
  kind: 'basic',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    for (const entry of context.fileMap.entries) {
      if (!CODE_EXTENSIONS.has(entry.extension)) continue;
      const scanContent = stripCommentsOnly(entry.content, usesHashComments(entry.extension, entry.label));
      const python = entry.extension === '.py';
      for (const match of findMatches(scanContent, COOKIE_SET)) {
        let block = match.matchText;
        const missing: string[] = [];
        let spreadUnread = false;
        if (python && PYTHON_SET_COOKIE.test(block)) {
          const args = pythonCallArguments(scanContent, match.index + block.indexOf('('));
          if (args === undefined) continue;
          block = `set_cookie(${args})`;
          const spread = pythonCookieSpread(entry.content, args);
          spreadUnread = spread?.unresolved === true && !/\bhttponly\s*=/i.test(args);
          const has = (flag: string): boolean =>
            PYTHON_FLAG(flag).test(args) || (spread !== undefined && (PYTHON_FLAG(flag).test(spread.supplied) || PYTHON_KEY_FLAG(flag).test(spread.supplied)));
          if (!has('httponly')) missing.push('HttpOnly');
          if (!has('secure')) missing.push('Secure');
          if (!has('samesite')) missing.push('SameSite');
        } else {
          if (!/httpOnly\s*:\s*true|HttpOnly/i.test(block)) missing.push('HttpOnly');
          if (!/secure\s*:\s*true|;\s*Secure/i.test(block)) missing.push('Secure');
          if (!/sameSite/i.test(block)) missing.push('SameSite');
        }
        const isSessionish = SESSION_HINT.test(block) || (python && PYTHON_SESSION_HINT.test(block));
        if (missing.length === 0) continue;
        if (!isSessionish) continue;
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: this.title,
            severity: missing.includes('HttpOnly') && !spreadUnread ? 'high' : 'medium',
            confidence: 'medium',
            filePath: entry.path,
            lineStart: match.line,
            evidence: `${lineAt(entry.content, match.line)} (missing: ${missing.join(', ')})`,
            userExplanation:
              `A login/session cookie is set without these protections: ${missing.join(', ')}. Without them, scripts can steal the cookie (missing HttpOnly), it can travel over plain HTTP (missing Secure), or other sites can send it (missing SameSite). Add all three.`,
            technicalExplanation:
              `${entry.path}:${match.line} sets a session-like cookie missing ${missing.join(', ')}. Set { httpOnly: true, secure: true, sameSite: 'lax' | 'strict' } (and a sensible path/maxAge).`,
            fixHint:
              "Set the cookie with httpOnly: true, secure: true, and sameSite: 'lax' (or 'strict' for sensitive flows). Ensure Secure is on in production over HTTPS.",
            category: this.category,
          }),
        );
      }

      if (python) {
        for (const match of findMatches(scanContent, PYTHON_SESSION_SETTING_OFF)) {
          if (isPythonNonProductionSetting(entry.path, scanContent, match.index)) continue;
          const flag = match.groups[0] === 'SESSION_COOKIE_HTTPONLY' ? 'HttpOnly' : 'Secure';
          findings.push(
            makeFinding({
              ruleId: this.id,
              title: this.title,
              severity: flag === 'HttpOnly' ? 'high' : 'medium',
              confidence: 'medium',
              filePath: entry.path,
              lineStart: match.line,
              evidence: `${lineAt(entry.content, match.line)} (session cookie setting turns off: ${flag})`,
              userExplanation:
                `Your settings switch off the ${flag} flag on the login session cookie. Without Secure the cookie travels over plain HTTP where anyone on the network can copy it; without HttpOnly any script on the page can read it. Set it to True in production.`,
              technicalExplanation:
                `${entry.path}:${match.line} sets ${match.groups[0]} = False, so the framework issues the session cookie without ${flag}. Set it to True in production settings (keep False only in a development configuration).`,
              fixHint:
                `Set ${match.groups[0]} = True in production settings, and SESSION_COOKIE_SAMESITE = "Lax" if it is not set already.`,
              category: this.category,
            }),
          );
        }
      }

      for (const call of findMatches(scanContent, SESSION_MIDDLEWARE_CALL)) {
        const braceIndex = scanContent.indexOf('{', call.index);
        if (braceIndex === -1) continue;
        const options = balancedBraces(scanContent, braceIndex);
        if (options === undefined) continue;
        if (!SESSION_OPTIONS_KEY.test(options)) continue;
        if (!SESSION_HINT.test(call.matchText) && !SESSION_HINT.test(options)) continue;
        let cookieOptions: string | undefined;
        const cookieKey = COOKIE_OPTIONS_KEY.exec(options);
        if (cookieKey !== null) {
          cookieOptions = balancedBraces(options, cookieKey.index + cookieKey[0].length - 1);
          if (cookieOptions === undefined) continue;
        }
        const missing = sessionCookieDefects(cookieOptions, scanContent);
        if (missing.length === 0) continue;
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: this.title,
            severity: missing.includes('HttpOnly') ? 'high' : 'medium',
            confidence: 'medium',
            filePath: entry.path,
            lineStart: call.line,
            evidence: `${lineAt(entry.content, call.line)} (session middleware cookie missing: ${missing.join(', ')})`,
            userExplanation:
              `The session middleware issues your login cookie, and it is configured without: ${missing.join(', ')}. Without Secure the cookie travels over plain HTTP where anyone on the network can copy it; with HttpOnly turned off any script on the page can read it. Set these in the session options.`,
            technicalExplanation:
              `${entry.path}:${call.line} configures a session middleware whose cookie options are missing ${missing.join(', ')}. Set { httpOnly: true, secure: true, sameSite: 'lax' } on the session cookie (secure conditioned on production if you serve plain HTTP locally).`,
            fixHint:
              "In the session middleware options set cookie: { httpOnly: true, secure: true, sameSite: 'lax' }. If you develop over plain HTTP, gate secure on NODE_ENV === 'production' rather than leaving it off. SameSite=None is only valid together with Secure.",
            category: this.category,
          }),
        );
      }
    }
    return findings;
  },
};
