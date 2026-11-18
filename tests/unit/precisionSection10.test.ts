import { describe, expect, it } from 'vitest';
import { hardcodedSecret } from '../../src/rules/basic/hardcodedSecret.js';
import { sensitiveDataInLogs } from '../../src/rules/basic/sensitiveDataInLogs.js';
import { memoryContext } from './helpers.js';

const PKG: [string, string] = ['package.json', JSON.stringify({ name: 'x', dependencies: { express: '^4.18.0' } })];
const secrets = (code: string) => hardcodedSecret.run(memoryContext([PKG, ['src/a.ts', code]]));
const logs = (code: string) => sensitiveDataInLogs.run(memoryContext([PKG, ['src/a.ts', code]]));

describe('hardcoded_secret — precision', () => {
  it('does NOT flag an error-code / enum constant', () => {
    expect(secrets("export const AppError = { twoFactor: 'TWO_FACTOR_MISSING_SECRET', pw: 'INCORRECT_PASSWORD' };\n")).toHaveLength(0);
  });

  it('does NOT flag the sk- pattern matched inside a module name/path', () => {
    expect(secrets("import { maskRecipientTokensForDocument } from '@/utils/mask-recipient-tokens-for-document';\n")).toHaveLength(0);
  });

  it('STILL flags a real weak generic secret (lowercase words)', () => {
    const f = secrets("export const config = { cookieSecret: 'session_cookie_secret_key_here' };\n");
    expect(f.length).toBeGreaterThan(0);
  });

  it('STILL flags a real Stripe live key', () => {
    expect(secrets(("const stripe = require('stripe')('sk" + "_live_abcdefghijklmnopqrstuvwx');\n")).length).toBeGreaterThan(0);
  });

  it('STILL flags a real OpenAI key at a token boundary', () => {
    expect(secrets(("const key = 'sk" + "-proj-Ab12Cd34Ef56Gh78Ij90Kl';\n")).length).toBeGreaterThan(0);
  });
});

describe('sensitive_data_in_logs — precision (gate + down-rank)', () => {
  it('does NOT flag a sensitive word appearing only in descriptive template text', () => {
    expect(logs("console.log(`Backfill apiKey hash for page ${page}`);\n")).toHaveLength(0);
    expect(logs("console.log(`  Owner password:   changeme-in-prod`);\n")).toHaveLength(0);
  });

  it('does NOT flag a safe scalar accessor of a sensitive-named object', () => {
    expect(logs("console.error(`Failed at ${apiKey.id}`);\n")).toHaveLength(0);
    expect(logs('console.log(token.length);\n')).toHaveLength(0);
  });

  it('down-ranks a bare sensitive variable to a low-confidence review signal', () => {
    const f = logs('console.log(password);\n');
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe('low');
    expect(f[0]?.confidence).toBe('low');
  });

  it('STILL flags (high) a secret interpolated into a log template', () => {
    const f = logs('console.log(`auth token = ${accessToken}`);\n');
    expect(f.length).toBeGreaterThan(0);
    expect(f[0]?.severity).toBe('high');
  });

  it('STILL flags logging a whole request/env object', () => {
    expect(logs('console.log(req.body);\n').length).toBeGreaterThan(0);
  });
});
