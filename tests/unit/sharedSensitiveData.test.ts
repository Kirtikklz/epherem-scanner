import { describe, expect, it } from 'vitest';

import {
  classifySensitive,
  classifySensitiveColumns,
  isPlaceholderEnvValue,
  sensitiveCategories,
  valueProvesNotSensitive,
} from '../../src/shared/sensitiveData.js';
import { envFileIncluded } from '../../src/rules/basic/envFileIncluded.js';
import { firebaseReadableSensitiveData } from '../../src/rules/contextual/firebaseReadableSensitiveData.js';
import { massAssignment } from '../../src/rules/basic/massAssignment.js';
import { sensitiveDataInLogs } from '../../src/rules/basic/sensitiveDataInLogs.js';
import { supabaseReadableSensitiveData } from '../../src/rules/contextual/supabaseReadableSensitiveData.js';
import { memoryContext } from './helpers.js';

describe('§4.8 capability one — the value proves the name wrong', () => {
  it('`{ hasSecret: !!x }` is a boolean, not a secret', () => {
    expect(valueProvesNotSensitive('!!authOptions.secret')).toBe(true);
  });

  it("`password: '[REDACTED]'` carries the word REDACTED", () => {
    expect(valueProvesNotSensitive("'[REDACTED]'")).toBe(true);
  });

  it('a fixed-width tail or prefix of a token is not the token', () => {
    expect(valueProvesNotSensitive('token.slice(0, 8)')).toBe(true);
    expect(valueProvesNotSensitive('card.slice(-4)')).toBe(true);
  });

  it('a length or a count is not the value', () => {
    expect(valueProvesNotSensitive('apiKey.length')).toBe(true);
    expect(valueProvesNotSensitive('Object.keys(secrets).length')).toBe(true);
  });

  it('an explicit comparison to null is a presence check', () => {
    expect(valueProvesNotSensitive('user.password !== null')).toBe(true);
  });

  it('MUST NOT CLEAR: a real password, however unimpressive', () => {
    expect(valueProvesNotSensitive("'hunter2'")).toBe(false);
  });

  it('MUST NOT CLEAR: the secret itself, read from somewhere else', () => {
    expect(valueProvesNotSensitive('user.password')).toBe(false);
    expect(valueProvesNotSensitive('process.env.STRIPE_SECRET_KEY')).toBe(false);
  });

  it('MUST NOT CLEAR: a value it cannot read', () => {
    expect(valueProvesNotSensitive('await decrypt(vault.get(name))')).toBe(false);
    expect(valueProvesNotSensitive(undefined)).toBe(false);
  });
});

describe('§4.8 capability two — the non-English column set', () => {
  it('a clientes table is no longer empty', () => {
    expect(classifySensitiveColumns(['id', 'nome', 'profissao', 'dados', 'created_at'])).toEqual({
      critical: [],
      high: ['dados', 'nome', 'profissao'],
    });
  });

  it('Portuguese and Spanish credentials and ids land in the critical tier', () => {
    const m = classifySensitiveColumns(['senha', 'cpf', 'telefone', 'data_nascimento', 'contrasena']);
    expect(m.critical.sort()).toEqual(['contrasena', 'cpf', 'data_nascimento', 'senha', 'telefone']);
    expect(m.high).toEqual([]);
  });

  it('tiers match their English equivalents, so severity does not depend on language', () => {
    expect(classifySensitive('senha').tier).toBe(classifySensitive('password').tier);
    expect(classifySensitive('telefone').tier).toBe(classifySensitive('phone_number').tier);
    expect(classifySensitive('endereco').tier).toBe(classifySensitive('street_address').tier);
  });

  it('MUST STAY QUIET: a scenario name is not a person', () => {
    expect(classifySensitiveColumns(['cliente_id', 'nome_simulacao', 'nome_cenario'])).toEqual({
      critical: [],
      high: [],
    });
  });

  it('MUST STILL FIRE: the person-name compounds', () => {
    expect(classifySensitiveColumns(['primeiro_nome', 'nome_completo', 'sobrenome']).high).toEqual([
      'nome_completo',
      'primeiro_nome',
      'sobrenome',
    ]);
  });
});

describe('§4.8 the exclusions are scoped to expressions, never to schema columns', () => {
  it('a `hash` COLUMN is still critical', () => {
    expect(classifySensitive('password_hash', undefined, { kind: 'column' })).toEqual({
      sensitive: true,
      category: 'credential',
      tier: 'critical',
    });
  });

  it('a `passwordHash` EXPRESSION is still a credential, not a derivation', () => {
    expect(classifySensitive('passwordHash', undefined, { kind: 'expression' }).sensitive).toBe(true);
  });

  it('a `hasX` name states the field type, and clears it', () => {
    expect(classifySensitive('hasSecret', undefined, { kind: 'expression' }).sensitive).toBe(false);
    expect(classifySensitive('has_secret', undefined, { kind: 'column' }).sensitive).toBe(true);
  });

  it('a scalar accessor of the value is not the value', () => {
    expect(classifySensitive('token.length', undefined, { kind: 'expression' }).sensitive).toBe(false);
    expect(classifySensitive('token', undefined, { kind: 'expression' }).sensitive).toBe(true);
  });

  it('scope lets one vocabulary serve consumers with different remits', () => {
    expect(classifySensitive('email', undefined, { scope: ['credential'] }).sensitive).toBe(false);
    expect(classifySensitive('email').sensitive).toBe(true);
  });
});

describe('§4.8 every consumer keeps its existing findings', () => {
  const PKG_SUPABASE: [string, string] = [
    'package.json',
    '{"name":"x","dependencies":{"@supabase/supabase-js":"2.0.0"}}',
  ];

  it('CONSUMER 1 — supabase_readable_sensitive_data still fires on an English schema', () => {
    const ctx = memoryContext([
      PKG_SUPABASE,
      [
        'supabase/migrations/0001_init.sql',
        'CREATE TABLE public.profiles (id uuid primary key, date_of_birth date, phone_number text, latitude decimal);\n' +
          'ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;\n' +
          'CREATE POLICY "p" ON public.profiles FOR SELECT USING (true);\n',
      ],
    ]);
    const findings = supabaseReadableSensitiveData.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('critical');
    expect(findings[0]?.evidence).toContain('phone_number');
  });

  it('CONSUMER 2 — firebase_readable_sensitive_data still fires on an open collection', () => {
    const ctx = memoryContext([
      ['firestore.rules', 'service cloud.firestore {\n match /users/{id} {\n allow read;\n }\n}\n'],
      ['src/app.js', "db.collection('users').add({ email: e, phone: p });"],
    ]);
    const findings = firebaseReadableSensitiveData.run(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]?.evidence).toContain('users');
  });

  it('CONSUMER 3 — sensitive_data_in_logs still fires on a real logged credential', () => {
    const ctx = memoryContext([['src/auth.js', "console.log('token: ' + token);"]]);
    expect(sensitiveDataInLogs.run(ctx)).toHaveLength(1);
  });

  it('CONSUMER 3 — and on a structured object whose value proves nothing', () => {
    const ctx = memoryContext([['src/auth.js', 'logger.info({ userId, password: user.password });']]);
    expect(sensitiveDataInLogs.run(ctx)).toHaveLength(1);
  });

  it('CONSUMER 3 — but not when every sensitive field is proven harmless', () => {
    const ctx = memoryContext([
      [
        'src/auth.js',
        "console.log('NextAuth route loaded with options:', {\n  providers: authOptions.providers?.length || 0,\n  hasSecret: !!authOptions.secret\n});",
      ],
    ]);
    expect(sensitiveDataInLogs.run(ctx)).toEqual([]);
  });

  it('CONSUMER 3 — one unproven field is enough to keep the finding', () => {
    const ctx = memoryContext([
      ['src/auth.js', 'logger.info({ hasPassword: !!p, password: p });'],
    ]);
    expect(sensitiveDataInLogs.run(ctx)).toHaveLength(1);
  });

  it('CONSUMER 4 — env_file_included still separates a real secret from a placeholder', () => {
    const real = memoryContext([['.env', ('STRIPE_SECRET_KEY=sk' + '_live_4Rt6Ys1Kf3Nc8Wg5Hj0A9zQm\n')]]);
    expect(envFileIncluded.run(real)[0]?.severity).toBe('high');

    const placeholder = memoryContext([
      ['.env', 'GOOGLE_CLIENT_SECRET=123\nSESSION_SECRET=test_session_secret\nDATABASE_URL=postgres://user:pass@127.0.0.1:5432/app\n'],
    ]);
    expect(placeholder && envFileIncluded.run(placeholder)[0]?.severity).toBe('low');
  });

  it('CONSUMER 5 — mass_assignment still fires on the domain-object merge', () => {
    const ctx = memoryContext([['src/routes.js', 'Object.assign(user, req.body);']]);
    expect(massAssignment.run(ctx)).toHaveLength(1);
  });

  it('CONSUMER 5 — and still ignores an object that is not in the target list', () => {
    const ctx = memoryContext([['src/routes.js', 'Object.assign(widget, req.body);']]);
    expect(massAssignment.run(ctx)).toEqual([]);
  });

  it('the shared category labels still read as English prose for the report', () => {
    expect(sensitiveCategories(['date_of_birth', 'phone_number', 'nome'])).toEqual([
      'date of birth',
      'name',
      'phone',
    ]);
  });

  it('the env placeholder vocabulary survived the move intact', () => {
    expect(isPlaceholderEnvValue('GOOGLE_CLIENT_SECRET', '123')).toBe(true);
    expect(isPlaceholderEnvValue('OIDC_CLIENT_SECRET', 'client-secret')).toBe(true);
    expect(isPlaceholderEnvValue('SESSION_SECRET', 'test_session_secret')).toBe(true);
    expect(isPlaceholderEnvValue('STRIPE_SECRET_KEY', ('sk' + '_live_4Rt6Ys1Kf3Nc8Wg5Hj0A9zQm'))).toBe(false);
  });
});
