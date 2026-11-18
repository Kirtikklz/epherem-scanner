import { describe, expect, it } from 'vitest';
import { dangerousCorsWildcard } from '../../src/rules/basic/dangerousCorsWildcard.js';
import { weakJwtHandling } from '../../src/rules/basic/weakJwtHandling.js';
import type { Finding } from '../../src/shared/types.js';
import { memoryContext } from './helpers.js';

const PYTHON_USER =
  'This code reads the contents of a login token with its signature check switched off, so anyone can forge a token and impersonate any user. Remove the option that disables verification.';
const PYTHON_TECH =
  'jwt.decode() is called with signature verification disabled (verify_signature False / verify=False). With PyJWT and python-jose, decode() verifies by default; the opt-out removes that check.';
const PYTHON_FIX =
  'Remove the verification opt-out and call jwt.decode(token, key, algorithms=["HS256"]) (or your real algorithm) so the signature is checked; only trust claims from that call.';
const NODE_USER =
  'This code reads the contents of a login token without checking that it is genuine. Anyone can forge a token and impersonate any user. Verify the signature instead of just decoding.';
const NODE_TECH =
  'jwt.decode() (or equivalent) reads claims without signature verification. Use jwt.verify() with the correct secret/public key; decode() must never gate access.';
const NODE_FIX =
  'Replace jwt.decode() with jwt.verify(token, secret, { algorithms: ["HS256"|"RS256"] }) and only trust claims from the verified result.';

const jwtFindings = (path: string, source: string): Finding[] =>
  weakJwtHandling.run(memoryContext([[path, source]])).filter((f) => f.filePath === path);

const pythonModule = (...body: string[]): string =>
  ['import jwt', 'SECRET_KEY = "change-me"', 'ALGORITHM = "HS256"', '', 'def read(token):', ...body.map((l) => `    ${l}`), ''].join('\n');

describe('§2.1 a Python jwt.decode is reported only when its own arguments switch verification off', () => {
  it('PyJWT style: jwt.decode(token, key, algorithms=["HS256"]) verifies, so nothing is reported', () => {
    expect(jwtFindings('app/auth.py', pythonModule('return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])'))).toEqual([]);
  });

  it('python-jose style, across lines: nothing is reported', () => {
    const source = [
      'from jose import JWTError, jwt',
      'SECRET = "x"',
      'ALG = "HS256"',
      '',
      'def read(token):',
      '    payload = jwt.decode(',
      '        token,',
      '        SECRET,',
      '        algorithms=[ALG]',
      '    )',
      '    return payload',
      '',
    ].join('\n');
    expect(jwtFindings('backend/auth.py', source)).toEqual([]);
  });

  it('options={"verify_signature": False} is reported, with the Python text, at the same grade and title', () => {
    const findings = jwtFindings('app/auth.py', pythonModule('return jwt.decode(token, options={"verify_signature": False})'));
    expect(findings).toHaveLength(1);
    const [finding] = findings;
    expect(finding?.severity).toBe('high');
    expect(finding?.confidence).toBe('medium');
    expect(finding?.title).toBe('JWT decoded without verifying its signature');
    expect(finding?.lineStart).toBe(6);
    expect(finding?.userExplanation).toBe(PYTHON_USER);
    expect(finding?.technicalExplanation).toBe(`app/auth.py:6: ${PYTHON_TECH}`);
    expect(finding?.fixHint).toBe(PYTHON_FIX);
  });

  it('verify=False (PyJWT 1.x) is reported', () => {
    const findings = jwtFindings('app/auth.py', pythonModule('return jwt.decode(token, verify=False)'));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.userExplanation).toBe(PYTHON_USER);
  });

  it("single quotes and dict(verify_signature=False) are the same opt-out", () => {
    expect(jwtFindings('a.py', pythonModule("return jwt.decode(token, options={'verify_signature': False})"))).toHaveLength(1);
    expect(jwtFindings('b.py', pythonModule('return jwt.decode(token, options=dict(verify_signature=False))'))).toHaveLength(1);
  });

  it('the opt-out on a LATER LINE of the same call is read: the argument list is balanced, not a line', () => {
    const findings = jwtFindings(
      'app/auth.py',
      pythonModule('payload = jwt.decode(', '    token,', '    SECRET_KEY,', '    algorithms=[ALGORITHM],', '    options={"verify_signature": False},', ')', 'return payload'),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.lineStart).toBe(6);
  });

  it("only the call's OWN arguments count: an opt-out in the next call, or in a comment, is not this call's", () => {
    expect(
      jwtFindings('app/auth.py', pythonModule('payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])', 'other(verify=False)', 'return payload')),
    ).toEqual([]);
    expect(
      jwtFindings(
        'app/auth.py',
        pythonModule('payload = jwt.decode(', '    token,  # never pass verify=False here', '    SECRET_KEY,', '    algorithms=[ALGORITHM],', ')', 'return payload'),
      ),
    ).toEqual([]);
  });

  it('a ")" inside a string argument does not end the argument list early', () => {
    expect(
      jwtFindings('app/auth.py', pythonModule('return jwt.decode(token, ")", options={"verify_signature": False})')),
    ).toHaveLength(1);
  });

  it('Node jwt.decode(token) is still reported, with exactly today\'s text', () => {
    const source = "import jwt from 'jsonwebtoken';\nexport function read(token) {\n  return jwt.decode(token);\n}\n";
    const findings = jwtFindings('src/auth.ts', source);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.userExplanation).toBe(NODE_USER);
    expect(findings[0]?.technicalExplanation).toBe(`src/auth.ts:3: ${NODE_TECH}`);
    expect(findings[0]?.fixHint).toBe(NODE_FIX);
    expect(findings[0]?.severity).toBe('high');
  });

  it('PINNED CURRENT BEHAVIOUR, NOT A NEW CHECK: Python algorithms=["none"] produces nothing from verify_none_alg', () => {
    const findings = jwtFindings('app/auth.py', pythonModule('return jwt.decode(token, SECRET_KEY, algorithms=["none"])'));
    expect(findings.filter((f) => f.title === 'JWT verification allows the "none" algorithm')).toEqual([]);
    expect(findings).toEqual([]);
  });

  it('THE LEAD, CLOSED (python run, job 6b): Python options={"verify_exp": False} is reported as ignored expiry', () => {
    const findings = jwtFindings(
      'app/security.py',
      pythonModule('payload = jwt.decode(', '    token,', '    SECRET_KEY,', '    algorithms=[ALGORITHM],', '    options={"verify_exp": False},', ')', 'return payload'),
    );
    expect(findings.map((f) => f.title)).toEqual(['JWT verification ignores token expiration']);
  });
});

const corsAt = (files: [string, string][]): string[] =>
  dangerousCorsWildcard.run(memoryContext(files)).map((f) => `${f.filePath}:${f.lineStart}`);

const ORIGIN_MATCHES = [
  'function originMatches(origin: string, pattern: string): boolean {',
  '  if (pattern === origin) return true;',
  '  if (!pattern.includes("*")) return false;',
  '  // Escape everything, then re-open the single wildcard as "one label".',
  '  const rx = new RegExp(',
  '    "^" + pattern.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\\\$&").replace(/\\\\\\*/g, "[^.]+") + "$",',
  '  );',
  '  return rx.test(origin);',
  '}',
];

const ALLOWLIST = 'const allowlist = (): string[] => (Deno.env.get("ALLOWED_ORIGINS") ?? "").split(",").filter(Boolean);';

const predicate = (callback: string, extra: string[] = []): string[] => [
  'export function isAllowedOrigin(origin: string): boolean {',
  '  if (!origin) return false;',
  '  const list = allowlist();',
  '  if (list.length === 0) return false;',
  ...extra.map((line) => `  ${line}`),
  `  return list.some(${callback});`,
  '}',
];

const CORS_FOR = [
  'export function corsFor(req: Request) {',
  '  const origin = (req.headers.get("Origin") || "").replace(/\\/+$/, "");',
  '  const base = { "Vary": "Origin" };',
  '  if (!origin) return { headers: base };',
  '  if (!isAllowedOrigin(origin)) {',
  '    return { headers: base, rejected: true };',
  '  }',
  '  return {',
  '    headers: {',
  '      ...base,',
  '      "Access-Control-Allow-Origin": origin,',
  '      "Access-Control-Allow-Credentials": "true",',
  '    },',
  '  };',
  '}',
];

const HTTP = 'supabase/functions/_shared/http.ts';

const HEADER_LISTS = [
  '/** Headers a browser is allowed to READ off our responses. */',
  'const EXPOSED = [',
  '  "X-Api-Version",',
  '  "X-Request-Id",',
  '  "X-RateLimit-Limit",',
  '  "X-RateLimit-Remaining",',
  '  "X-RateLimit-Reset",',
  '  "Retry-After",',
  '].join(", ");',
  '',
  '/** Request headers a browser may SEND. supabase-js sends apikey / authorization / x-client-info. */',
  'const ALLOWED_REQUEST_HEADERS = [',
  '  "authorization",',
  '  "apikey",',
  '  "content-type",',
  '  "x-client-info",',
  '  "x-api-key",',
  '  "x-api-version",',
  '  "x-request-id",',
  '].join(", ");',
];

const oneFile = (helper: string[], callback = '(p) => originMatches(origin, p)', extra: string[] = []): [string, string][] => {
  const lines = [...CORS_FOR, '', ...HEADER_LISTS, '', ALLOWLIST, '', ...helper, '', ...predicate(callback, extra)];
  return [[HTTP, lines.join('\n')]];
};
const reflectionIn = (files: [string, string][]): string => {
  const lines = (files.find(([path]) => path === HTTP)?.[1] ?? '').split('\n');
  return `${HTTP}:${lines.indexOf('      "Access-Control-Allow-Origin": origin,') + 1}`;
};

describe("§2.2 cedric's allowlist loop is an exact allowlist, and is credited", () => {
  it('helper and predicate in the same file: no finding', () => {
    const files = oneFile(ORIGIN_MATCHES);
    expect(corsAt(files)).toEqual([]);
  });

  it('predicate and helper in an IMPORTED file: no finding', () => {
    const origin = [ALLOWLIST, '', 'export ' + ORIGIN_MATCHES.join('\n'), '', ...predicate('(p) => originMatches(origin, p)')].join('\n');
    const http = ['import { isAllowedOrigin } from "./origin.ts";', '', ...CORS_FOR].join('\n');
    expect(corsAt([['supabase/functions/_shared/origin.ts', origin], [HTTP, http]])).toEqual([]);
  });

  it('the helper imported by the predicate\'s own file: no finding', () => {
    const match = ['export ' + ORIGIN_MATCHES.join('\n')].join('\n');
    const http = [
      'import { originMatches } from "./match.ts";',
      ...CORS_FOR,
      '',
      ...HEADER_LISTS,
      '',
      ALLOWLIST,
      '',
      ...predicate('(p) => originMatches(origin, p)'),
    ].join('\n');
    expect(corsAt([['supabase/functions/_shared/match.ts', match], [HTTP, http]])).toEqual([]);
  });

  it('CONTROL: the same file with the predicate call removed is reported, so the credit is what went quiet', () => {
    const files = oneFile(ORIGIN_MATCHES);
    const [[path, content]] = files as [[string, string]];
    const ungated: [string, string][] = [[path, content.replace('if (!isAllowedOrigin(origin)) {', 'if (false) {')]];
    expect(corsAt(ungated)).toEqual([reflectionIn(ungated)]);
  });

  it('list.some((p) => p === origin) produces no finding', () => {
    expect(corsAt(oneFile([], '(p) => p === origin'))).toEqual([]);
  });

  it('(a) p == origin, and .find / .findIndex, are credited by the loop rule itself', () => {
    expect(corsAt(oneFile([], '(p) => p == origin'))).toEqual([]);
    expect(corsAt(oneFile([], '(p) => p == origin').map(([p, c]) => [p, c.replace('list.some(', 'list.find(')]))).toEqual([]);
    expect(
      corsAt(oneFile([], '(p) => p == origin').map(([p, c]) => [p, c.replace('return list.some((p) => p == origin);', 'return list.findIndex((p) => p == origin) !== -1;')])),
    ).toEqual([]);
  });

  it("the predicate's origin is its FIRST PARAMETER, whatever it is called", () => {
    const files = oneFile([], '(p) => p === o').map(([path, content]): [string, string] => [
      path,
      content.replace('export function isAllowedOrigin(origin: string): boolean {\n  if (!origin) return false;', 'export function isAllowedOrigin(o: string): boolean {\n  if (!o) return false;'),
    ]);
    expect(corsAt(files)).toEqual([]);
  });

  it('an anchored literal regex in the helper is credited', () => {
    const helper = ['function originMatches(origin: string, pattern: string): boolean {', '  return /^https:\\/\\/[a-z]+\\.example\\.com$/.test(origin);', '}'];
    expect(corsAt(oneFile(helper))).toEqual([]);
  });

  it('an exact === helper is credited', () => {
    const helper = ['function originMatches(origin: string, pattern: string): boolean {', '  return pattern === origin;', '}'];
    expect(corsAt(oneFile(helper))).toEqual([]);
  });
});

describe('§2.2 NEVER CREDITED, even inside a loop: the rule\'s existing refusals, named', () => {
  const stillReported = (files: [string, string][]): void => {
    expect(corsAt(files)).toEqual([reflectionIn(files)]);
  };

  it('list.some((p) => origin.startsWith(p)) is still reported', () => {
    stillReported(oneFile([], '(p) => origin.startsWith(p)'));
  });

  it('list.some((p) => origin.endsWith(p)) is still reported', () => {
    stillReported(oneFile([], '(p) => origin.endsWith(p)'));
  });

  it('list.some((p) => new RegExp(p).test(origin)) is still reported', () => {
    stillReported(oneFile([], '(p) => new RegExp(p).test(origin)'));
  });

  it('list.some((p) => new RegExp("^" + p).test(origin)), with no "$", is still reported', () => {
    stillReported(oneFile([], '(p) => new RegExp("^" + p).test(origin)'));
  });

  it('a comparison against a TRANSFORMED origin is not exact: p == origin.slice(0, p.length) is a prefix test', () => {
    stillReported(oneFile([], '(p) => p == origin.slice(0, p.length)'));
  });

  it('a helper that cannot be resolved is still reported', () => {
    const files = oneFile([]).map(([path, content]): [string, string] => [path, `import { originMatches } from "cors-kit";\n${content}`]);
    stillReported(files);
  });

  it('a substring test anywhere in the predicate refuses the credit, beside an exact loop', () => {
    stillReported(oneFile([], '(p) => p == origin', ['if (origin.endsWith(".vercel.app")) return true;']));
  });

  it('an exact compare written only in a COMMENT is not a loop', () => {
    const files = oneFile([]).map(([path, content]): [string, string] => [
      path,
      content.replace('  return list.some((p) => originMatches(origin, p));', '  // return list.some((p) => p == origin);\n  return true;'),
    ]);
    stillReported(files);
  });
});

describe('§2.2 the helper is READ: its comparison, its anchors, and which parameter is the origin', () => {
  const stillReported = (helper: string[], callback?: string): void => {
    const files = oneFile(helper, callback);
    expect(corsAt(files)).toEqual([reflectionIn(files)]);
  };
  const helperReturning = (...body: string[]): string[] => [
    'function originMatches(origin: string, pattern: string): boolean {',
    ...body.map((line) => `  ${line}`),
    '}',
  ];

  it('ANCHOR: a pattern built without "^" is reported', () => {
    stillReported(helperReturning('return new RegExp(pattern + "$").test(origin);'));
  });

  it('ANCHOR: a pattern built without "$" is reported', () => {
    stillReported(helperReturning('return new RegExp("^" + pattern).test(origin);'));
  });

  it('ANCHOR: a literal without "$", or without "^", is reported', () => {
    stillReported(helperReturning('if (pattern === origin) return true;', 'return /^https:\\/\\/app\\.example\\.com/.test(origin);'));
    stillReported(helperReturning('if (pattern === origin) return true;', 'return /https:\\/\\/app\\.example\\.com$/.test(origin);'));
  });

  it('ANCHOR: a top-level "|" splits the anchors, in a literal or in a built pattern', () => {
    stillReported(helperReturning('if (pattern === origin) return true;', 'return /^https:\\/\\/app\\.example\\.com|\\.example\\.com$/.test(origin);'));
    stillReported(helperReturning('return new RegExp("^" + pattern + "|" + FALLBACK + "$").test(origin);'));
  });

  it('an exact === beside a suffix test on the origin is reported', () => {
    stillReported(helperReturning('if (pattern === origin) return true;', 'return origin.endsWith(pattern);'));
  });

  it('a suffix test on a value DERIVED from the origin is reported', () => {
    stillReported(helperReturning('if (pattern === origin) return true;', 'const host = new URL(origin).host;', 'return host.endsWith(pattern);'));
  });

  it('the helper\'s origin is the parameter the ORIGIN was passed to, by position', () => {
    const helper = [
      'function sameOrigin(allowed: string, candidate: string): boolean {',
      '  if (candidate.endsWith(".example.com")) return true;',
      '  return allowed === candidate;',
      '}',
    ];
    stillReported(helper, '(p) => sameOrigin(p, origin)');
  });

  it('an expression-bodied helper is not read, because the shared reader would take the next function\'s body', () => {
    const helper = [
      'const originMatches = (origin: string, pattern: string): boolean => origin.endsWith(pattern);',
      'function unrelated(origin: string, pattern: string): boolean {',
      '  return pattern === origin;',
      '}',
    ];
    stillReported(helper);
  });
});
