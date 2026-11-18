import type { AuthSignal, AuthSignalKind, FileMapEntry } from '../shared/types.js';
import { findMatches, lineAt } from '../shared/utils.js';
import { stripCommentsAndStrings } from '../shared/source.js';
import { SVELTEKIT_IDENTITY } from '../shared/frameworkModel.js';

interface AuthProbe {
  kind: AuthSignalKind;
  pattern: RegExp;
  protective: boolean;
  selfChecked?: boolean;
}

const AUTH_PROBES: AuthProbe[] = [
  { kind: 'getUser', pattern: /\.getUser\s*\(|\bgetUser\s*\(/g, protective: true },
  {
    kind: 'auth_call',
    pattern: /\bgetAuth\s*\(\s*(?:req|request|ctx|context)\b/g,
    protective: true,
  },
  { kind: 'getSession', pattern: /\.getSession\s*\(|\bgetSession\s*\(|\bgetServerSession\s*\(/g, protective: true },
  {
    kind: 'auth_call',
    pattern:
      /\bauth\s*\(\s*(?:\)|(?:req|request|ctx|context)\b)|\b(?:require|assert|ensure|check)(?:Auth\w*|Admin|User|Session|Login|Owner|Role|Member|Account|Permission|SignedIn|Authenticated)\w*\s*\(|\bwithAuth\w*\s*\(/g,
    protective: true,
  },
  {
    kind: 'auth_call',
    pattern: /\bauth\s*(?:\(\s*\))?\s*\.\s*protect\s*\(/g,
    protective: true,
    selfChecked: true,
  },
  {
    kind: 'currentUser',
    pattern: /\b[\w$]*auth[\w$]*(?:\(\))?\s*\.\s*currentUser\b/gi,
    protective: true,
  },
  { kind: 'currentUser', pattern: /\bcurrentUser\s*\(/g, protective: true },
  {
    kind: 'jwt_check',
    pattern: /jwt\.verify\s*\(|\bverify(?:IdToken|Token|Session|Jwt|JWT|Auth\w*)\s*\(/g,
    protective: true,
  },
  {
    kind: 'auth_call',
    pattern: /\.\s*isAuthenticated\s*\(\s*\)/g,
    protective: true,
    selfChecked: true,
  },
  {
    kind: 'auth_call',
    pattern: /\bpassport\s*\.\s*authenticate\s*\(/g,
    protective: true,
    selfChecked: true,
  },
  {
    kind: 'auth_call',
    pattern: /\bthrow\s+(?:new\s+)?[\w.]*(?:Authentication|Authorization|Unauthorized|Forbidden)\w*Error\b/g,
    protective: true,
    selfChecked: true,
  },
  {
    kind: 'getSession',
    pattern: /\b[A-Za-z_$][\w$]*Get(?:Session|User)\s*\(/g,
    protective: true,
  },
  {
    kind: 'session_cookie_check',
    pattern: /req\.session\b|request\.cookies|cookies\(\)\.get|cookies\.get\s*\(\s*['"](session|token|auth)/g,
    protective: true,
  },
  {
    kind: 'middleware_protection',
    pattern: /NextResponse\.redirect\s*\(/g,
    protective: true,
  },
  {
    kind: 'getUser',
    pattern: new RegExp(`${SVELTEKIT_IDENTITY.source}(?!\\s*=[^=])`, 'g'),
    protective: true,
  },
  {
    kind: 'getUser',
    pattern:
      /\blocals\s*:\s*\{[^{}]{0,200}\b(?:session|user|account|member|auth|claims|userId)\b/g,
    protective: true,
  },
  { kind: 'signIn', pattern: /\bsignIn\w*\s*\(/g, protective: false },
  { kind: 'signUp', pattern: /\bsignUp\w*\s*\(/g, protective: false },
  { kind: 'onAuthStateChanged', pattern: /\bonAuthStateChanged\s*\(/g, protective: false },
];

const GUARD_WINDOW_LINES = 10;
const GUARD_LOOKBACK_LINES = 3;
const NEGATED_ABSENCE_PATTERN =
  /\bif\s*\(\s*[^)\n]{0,200}?(?:![^=]|\bnot\b|===?\s*(?:null|undefined|false)\b|!==?\s*(?:null|undefined)\b|\bis\s+None\b)|\bunless\b/i;
const AUTH_REFERENCE_PATTERN =
  /\b(user|session|token|auth|currentUser|uid|claims|account|identity|jwt|principal|authorized|authenticated|cookie|admin|owner|member|role|require(?:Admin|User|Auth\w*|Session|Owner|Role|Member)|signedIn)\b|\b(?:user|session|auth|clerk|account|owner|member|org|tenant)_?(?:id|uid|cookie|user|token|session)\b/i;
const EXIT_OR_BLOCK_PATTERN =
  /\breturn\b|\bthrow\b|\bredirect\s*\(|\bstatus\s*\(\s*40[13]\s*\)|\b40[13]\b|\bunauthorized\b|\bforbidden\b|\bnotFound\s*\(|\.protect\s*\(|\babort\s*\(/i;

const CLERK_V4_MIDDLEWARE = /\bauthMiddleware\s*\(/g;
const CLERK_V5_MIDDLEWARE = /\bclerkMiddleware\s*\(/g;
const CLERK_PROTECT_CALL = /\.\s*protect\s*\(/;

const IDENTITY_FETCH_KINDS: ReadonlySet<AuthSignalKind> = new Set<AuthSignalKind>([
  'getUser', 'getSession', 'jwt_check',
]);

export const IDENTITY_FETCH: RegExp = new RegExp(
  AUTH_PROBES
    .filter((probe) => probe.protective && IDENTITY_FETCH_KINDS.has(probe.kind))
    .map((probe) => probe.pattern.source)
    .join('|'),
);

export function detectAuthSignals(entry: FileMapEntry): AuthSignal[] {
  const signals: AuthSignal[] = [];
  const stripped = stripCommentsAndStrings(entry.content);
  const strippedLines = stripped.split('\n');

  for (const probe of AUTH_PROBES) {
    for (const match of findMatches(stripped, probe.pattern)) {
      signals.push({
        filePath: entry.path,
        line: match.line,
        index: match.index,
        kind: probe.kind,
        snippet: lineAt(entry.content, match.line),
        protective: probe.protective,
        checked:
          probe.protective &&
          (probe.selfChecked
            ? isWiredIntoControlFlow(strippedLines, match.line)
            : isGuardedNearby(strippedLines, match.line)),
      });
    }
  }
  if (entry.isLikelyMiddleware) {
    const protectsByDefault = CLERK_PROTECT_CALL.test(stripped);
    for (const [pattern, checked] of [
      [CLERK_V4_MIDDLEWARE, true],
      [CLERK_V5_MIDDLEWARE, protectsByDefault],
    ] as [RegExp, boolean][]) {
      for (const match of findMatches(stripped, pattern)) {
        signals.push({
          filePath: entry.path,
          line: match.line,
          index: match.index,
          kind: 'middleware_protection',
          snippet: lineAt(entry.content, match.line),
          protective: true,
          checked,
        });
      }
    }
  }
  signals.sort((a, b) => a.line - b.line || a.kind.localeCompare(b.kind));
  return signals;
}

const CONTROL_FLOW_PATTERN =
  /\bnext\s*\(|\breturn\b|\bthrow\b|\bredirect\s*\(|\bstatus\s*\(\s*40[13]\s*\)|\b40[13]\b|\.protect\s*\(|\babort\s*\(|ctx\.throw/i;

function isWiredIntoControlFlow(strippedLines: string[], signalLine: number): boolean {
  const start = Math.max(0, signalLine - 2);
  const end = Math.min(strippedLines.length, signalLine - 1 + GUARD_WINDOW_LINES);
  const window = strippedLines.slice(start, end).join('\n');
  return CONTROL_FLOW_PATTERN.test(window);
}

function isGuardedNearby(strippedLines: string[], signalLine: number): boolean {
  const start = Math.max(0, signalLine - 1 - GUARD_LOOKBACK_LINES);
  const end = Math.min(strippedLines.length, signalLine - 1 + GUARD_WINDOW_LINES);
  const window = strippedLines.slice(start, end).join('\n');
  return (
    NEGATED_ABSENCE_PATTERN.test(window) &&
    AUTH_REFERENCE_PATTERN.test(window) &&
    EXIT_OR_BLOCK_PATTERN.test(window)
  );
}

export function effectiveGuards(signals: AuthSignal[]): AuthSignal[] {
  return signals.filter((signal) => signal.protective && signal.checked);
}
