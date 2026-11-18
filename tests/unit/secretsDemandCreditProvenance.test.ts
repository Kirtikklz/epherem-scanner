import { describe, expect, it } from 'vitest';

import { mayVouchForProject } from '../../src/input/fileFilters.js';
import { hardcodedSecret } from '../../src/rules/basic/hardcodedSecret.js';
import { memoryContext } from './helpers.js';

const at = (files: [string, string][]): string[] =>
  hardcodedSecret.run(memoryContext(files)).map((f) => `${f.filePath}:${f.lineStart}`);

const SECRET = 'MohY0/2zSQw/psWEnejC2ka3Al0oifvY4YjOkUaFfnI=';
const LINE = `const AUTH_SECRET = "${SECRET}";`;

const STRIPE = ('const stripeKey = "sk' + '_live_51H8xQ2LkdIwHu7ix";');

const PEM = [
  ('-----BEGIN RSA PRIV' + 'ATE KEY-----'),
  'MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu',
  'KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm',
  '-----END RSA PRIVATE KEY-----',
].join('\n');

describe('the same literal fires on an application path and not in a test tree', () => {
  it('fires in src/', () => {
    expect(at([['src/config.ts', LINE]])).toEqual(['src/config.ts:1']);
  });

  for (const directory of ['test', 'tests', '__tests__', 'spec', 'e2e', 'cypress', 'fixtures', '__fixtures__', 'mocks', 'examples', 'samples']) {
    it(`is silent under ${directory}/`, () => {
      expect(at([[`${directory}/config.ts`, LINE]])).toEqual([]);
    });
  }

  it('is silent in a nested fixture path, the shape this repository\'s own fixture has', () => {
    expect(at([['tests/fixtures/express-cors-insecure/server.js', LINE]])).toEqual([]);
  });

  it('is silent for a *.test.ts FILENAME outside any test directory', () => {
    expect(at([['src/config.test.ts', LINE]])).toEqual([]);
  });
});

describe('a format-validated provider key follows the same path rule', () => {
  it('fires in src/', () => {
    expect(at([['src/pay.ts', STRIPE]])).toEqual(['src/pay.ts:1']);
  });

  it('is silent under tests/fixtures/ — the self-scan row', () => {
    expect(at([['tests/fixtures/pay.ts', STRIPE]])).toEqual([]);
  });
});

describe('PEM key material follows the same path rule', () => {
  it('fires on an ordinary deployment path', () => {
    expect(at([['artifacts/cert/server.key', PEM]])).toEqual(['artifacts/cert/server.key:1']);
  });

  it('is silent under test/ — eight rows in the tests of a library', () => {
    expect(at([['test/rsa-private.pem', PEM]])).toEqual([]);
  });
});

const SERVICE_ROLE_JWT =
  'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.' +
  'eyJyb2xlIjogInNlcnZpY2Vfcm9sZSIsICJpc3MiOiAiYWNtZSIsICJpYXQiOiAxNzAwMDAwMDAwfQ.' +
  'c2lnbmF0dXJlLXBsYWNlaG9sZGVyLXZhbHVl';

describe('the service-role JWT arm is gated by the same predicate', () => {
  it('fires in src/', () => {
    expect(at([['src/db.ts', `const key = "${SERVICE_ROLE_JWT}";`]]))
      .toEqual(['src/db.ts:1']);
  });

  it('is silent under tests/e2e/', () => {
    expect(at([['tests/e2e/helpers.ts', `const key = "${SERVICE_ROLE_JWT}";`]])).toEqual([]);
  });

  it('is silent under tests/setup/', () => {
    expect(at([['tests/setup/e2e.ts', `const key = "${SERVICE_ROLE_JWT}";`]])).toEqual([]);
  });
});

describe('BOUNDARY CASES — widening the predicate past these costs real findings', () => {
  it('artifacts/ is NOT a non-production directory', () => {
    expect(at([['artifacts/cert/server.key', PEM]])).toEqual(['artifacts/cert/server.key:1']);
  });

  it('.env.example may vouch: the new gate never reaches it', () => {
    expect(mayVouchForProject('.env.example')).toBe(true);
  });

  it('config/env/test.js is not a test path', () => {
    expect(at([['config/env/test.js', LINE]])).toEqual(['config/env/test.js:1']);
  });
});
