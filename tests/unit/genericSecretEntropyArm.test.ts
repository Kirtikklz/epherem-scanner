import { describe, expect, it } from 'vitest';

import { hardcodedSecret } from '../../src/rules/basic/hardcodedSecret.js';
import { memoryContext } from './helpers.js';

const run = (files: [string, string][]): string[] =>
  hardcodedSecret.run(memoryContext(files)).map((f) => `${f.filePath}:${f.lineStart}`);

const titles = (files: [string, string][]): string[] =>
  hardcodedSecret.run(memoryContext(files)).map((f) => f.title);

const REAL_SECRET = 'MohY0/2zSQw/psWEnejC2ka3Al0oifvY4YjOkUaFfnI=';

describe('§4.7 the generic arm fires on a real high-entropy secret', () => {
  it('MUST FIRE: a base64 session secret the older pattern cannot reach', () => {
    expect(run([['docker-compose.yml', `      - AUTH_SECRET="${REAL_SECRET}"`]])).toEqual([
      'docker-compose.yml:1',
    ]);
  });

  it('names itself, so a reader can tell which arm fired', () => {
    expect(titles([['docker-compose.yml', `AUTH_SECRET="${REAL_SECRET}"`]])).toEqual([
      'Hardcoded secret in source code: High-entropy credential in a secret-named assignment',
    ]);
  });

  it('MUST FIRE: a passphrase, a name the older pattern never learned', () => {
    expect(run([['src/crypto.ts', `const passphrase = "${REAL_SECRET}";`]])).toEqual([
      'src/crypto.ts:1',
    ]);
  });
});

describe('§4.7 the entropy gate', () => {
  it('MUST STAY QUIET: a low-entropy value long enough to pass the length gate', () => {
    expect(run([['src/config.ts', 'const secret = "aaaaaaaa1aaaaaaaa1aaaaaaaa1aa==";']])).toEqual([]);
  });

  it('MUST STAY QUIET: a high-entropy value one character under the length floor', () => {
    expect(run([['src/config.ts', 'const credential = "aB3xK9mQ2vB7pLd4Rt6";']])).toHaveLength(0);
  });

  it('MUST STAY QUIET: letters only, however long', () => {
    expect(run([['src/config.ts', 'const passphrase = "correcthorsebatterystaplexyz";']])).toEqual([]);
  });

  it('MUST STAY QUIET: digits only', () => {
    expect(run([['src/config.ts', 'const credential = "8675309867530986753098";']])).toEqual([]);
  });

  it('MUST STAY QUIET: an import path assigned to a secret-named constant', () => {
    expect(run([['src/config.ts', 'const tokenPath = "./config/secrets/production/tokens.json";']]))
      .toEqual([]);
  });

  it('MUST STAY QUIET: a URL', () => {
    expect(run([['src/config.ts', 'const tokenEndpoint = "https://auth.example.com/oauth2/v2/token";']]))
      .toEqual([]);
  });

  it('MUST STAY QUIET: an ordinary JWT is the JWT arm’s business', () => {
    const jwt =
      ('ey' + 'JhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U');
    expect(run([['src/api.ts', `var token = '${jwt}';`]])).toEqual([]);
  });

  it('MUST STILL FIRE: a service_role JWT, from the JWT arm', () => {
    const payload = Buffer.from(JSON.stringify({ role: 'service_role', iss: 'supabase' })).toString(
      'base64url',
    );
    const jwt = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${payload}.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9`;
    expect(titles([['src/admin.ts', `const key = "${jwt}";`]])).toContain(
      'Hardcoded secret in source code: Supabase service role JWT',
    );
  });
});

describe('§4.7 the arm defers to everything that already keeps this rule clean', () => {
  it('MUST STAY QUIET: a NEXT_PUBLIC_ binding is public by construction', () => {
    expect(run([['.env.local.ts', `NEXT_PUBLIC_ANALYTICS_TOKEN="${REAL_SECRET}"`]])).toEqual([]);
  });

  it('MUST STAY QUIET: a VITE_ binding', () => {
    expect(run([['src/env.ts', `VITE_PUBLIC_TOKEN="${REAL_SECRET}"`]])).toEqual([]);
  });

  it('MUST STAY QUIET: an explicit placeholder', () => {
    expect(run([['src/config.ts', 'const apiKey = "your-api-key-goes-here-1234567";']])).toEqual([]);
  });

  it('MUST STAY QUIET: changeme', () => {
    expect(run([['src/config.ts', 'const secret = "changeme-changeme-changeme-xY=";']])).toEqual([]);
  });

  it('MUST STAY QUIET: an angle-bracket stand-in', () => {
    expect(run([['src/config.ts', 'const token = "<paste-your-32-byte-token-here>";']])).toEqual([]);
  });

  it('MUST STAY QUIET: a template interpolation is not a literal', () => {
    expect(run([['src/config.ts', 'const secret = `${process.env.AUTH_SECRET_VALUE_HERE}`;']]))
      .toEqual([]);
  });

  it('MUST STAY QUIET: an enum constant', () => {
    expect(run([['src/errors.ts', 'const secret = "TWO_FACTOR_SECRET_NOT_CONFIGURED";']])).toEqual([]);
  });

  it('MUST STAY QUIET: the generic arm inside a comment', () => {
    expect(run([['src/config.ts', `// const secret = "${REAL_SECRET}";`]])).toEqual([]);
  });

  it('MUST STILL FIRE: a provider key inside a comment is still committed', () => {
    expect(run([['src/config.ts', ('// const k = "sk' + '_live_4Rt6Ys1Kf3Nc8Wg5Hj0A9zQm";')]])).toEqual([
      'src/config.ts:1',
    ]);
  });
});

describe('§4.7 one literal, one finding', () => {
  it('a literal both generic patterns see is reported once, by the older arm', () => {
    const content = 'const apiKey = "aB3xK9mQ2vB7pLd4Rt6Ys1Kf";';
    expect(run([['src/config.ts', content]])).toHaveLength(1);
    expect(titles([['src/config.ts', content]])).toEqual([
      'Hardcoded secret in source code: Generic hardcoded credential',
    ]);
  });
});
