import { describe, expect, it } from 'vitest';

import { envFileIncluded } from '../../src/rules/basic/envFileIncluded.js';
import { memoryContext } from './helpers.js';

const PKG: [string, string] = ['package.json', '{"name":"x"}'];

const run = (body: string) => envFileIncluded.run(memoryContext([PKG, ['.env', body]]));
const one = (body: string) => {
  const findings = run(body);
  expect(findings).toHaveLength(1);
  return findings[0]!;
};

describe('env_file_included: a placeholder is not a credential', () => {
  it('a bare integer is not a client secret', () => {
    expect(one('GOOGLE_CLIENT_SECRET=123').severity).toBe('low');
  });

  it('a stray trailing separator does not rescue it', () => {
    expect(one('GITHUB_CLIENT_SECRET=123;').severity).toBe('low');
  });

  it('a placeholder word before an underscore counts — `\\b` did not', () => {
    expect(one('GOOGLE_CLIENT_SECRET=test_google_secret').severity).toBe('low');
    expect(one('SESSION_SECRET=test_session_secret').severity).toBe('low');
  });

  it('but it must still be a boundary: testing123 is a real password', () => {
    expect(one('DATABASE_PASSWORD=testing123').severity).toBe('high');
  });

  it('one character typed over and over is not a key', () => {
    expect(one(('OPENAI_API_KEY=sk' + '-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx')).severity).toBe('low');
  });

  it('the key said back is not a value', () => {
    expect(one('OIDC_CLIENT_SECRET=client-secret').severity).toBe('low');
    expect(one('DATABASE_PASSWORD=password').severity).toBe('low');
  });

  it('an RFC 2606 reserved domain is not a credential', () => {
    expect(one('SMTP_FROM_EMAIL=hello@example.com').severity).toBe('low');
    expect(one('SMTP_HOST=smtp.example.com').severity).toBe('low');
  });

  it('credentials against loopback are a local development template', () => {
    expect(one('DATABASE_URL=postgres://user:pass@127.0.0.1:5432/notes').severity).toBe('low');
    expect(one('DATABASE_URL=postgres://user:pass@localhost:5432/notes').severity).toBe('low');
  });

  it('a whole local .env.development shape lands on low', () => {
    const finding = one([
      'URL=https://local.notes.dev:3000',
      'DATABASE_URL=postgres://user:pass@127.0.0.1:5432/notes',
      'REDIS_URL=redis://127.0.0.1:6379',
      'SMTP_FROM_EMAIL=hello@example.com',
      'LOG_LEVEL=debug',
    ].join('\n'));
    expect(finding.severity).toBe('low');
    expect(finding.evidence).not.toContain('DATABASE_URL');
    expect(finding.evidence).not.toContain('SMTP_FROM_EMAIL');
  });
});

describe('env_file_included: a real credential is still named', () => {
  const named = (body: string): string => {
    const finding = one(body);
    expect(finding.severity).toBe('high');
    return finding.evidence;
  };

  it('a Stripe live key', () => {
    expect(named(('STRIPE_SECRET_KEY=sk' + '_live_51H8xKzAbCdEfGhIjKlMnOp'))).toContain('STRIPE_SECRET_KEY');
  });

  it('a Supabase service_role JWT', () => {
    expect(named('SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.sig'))
      .toContain('SUPABASE_SERVICE_ROLE_KEY');
  });

  it('a credentialed URL against a REMOTE host — the loopback rule must not swallow this', () => {
    expect(named('DATABASE_URL=postgres://admin:Hunter2Real@db.prod.acme.io:5432/main'))
      .toContain('DATABASE_URL');
  });

  it('a real password that is not the key said back', () => {
    expect(named('DATABASE_PASSWORD=Tr0ub4dor&3')).toContain('DATABASE_PASSWORD');
  });

  it('a long high-entropy key, even in a file full of placeholders', () => {
    const evidence = named([
      'SECRET_KEY=F0E5AD933D7F6FD8F4DBB3E038C501C052DC0593C686D21ACB30AE205D2F634B',
      'GOOGLE_CLIENT_SECRET=123',
      'SLACK_CLIENT_SECRET=123',
      'OIDC_CLIENT_SECRET=client-secret',
      'SMTP_USERNAME=test',
    ].join('\n'));
    expect(evidence).toContain('SECRET_KEY');
    expect(evidence).not.toContain('GOOGLE_CLIENT_SECRET');
    expect(evidence).not.toContain('OIDC_CLIENT_SECRET');
  });

  it('a private key header is still a secret, stub-looking body or not', () => {
    expect(named(('TLS_KEY=-----BEGIN RSA PRIV' + 'ATE KEY-----'))).toContain('TLS_KEY');
  });
});

describe('env_file_included: a name is not evidence either', () => {
  it('TWILIO_FROM_NUMBER is a phone number', () => {
    expect(one('TWILIO_FROM_NUMBER=+15005550006').severity).toBe('low');
  });

  it('TWILIO_AUTH_TOKEN and TWILIO_API_SECRET are still named', () => {
    const token = one('TWILIO_AUTH_TOKEN=8f4c2a9e1b7d3f6a0c5e');
    expect(token.severity).toBe('high');
    expect(token.evidence).toContain('TWILIO_AUTH_TOKEN');
    expect(one('TWILIO_API_SECRET=9d3b7e2a5c8f1064ab').severity).toBe('high');
  });

  it('a real OpenAI key survives the repeated-character rule', () => {
    const finding = one(('OPENAI_API_KEY=sk' + '-proj-9f2Ab7QcXm4Rt8Lv1Ndp3Ye6'));
    expect(finding.severity).toBe('high');
    expect(finding.evidence).toContain('OPENAI_API_KEY');
  });
});

describe('env_file_included: severity moved, the finding did not', () => {
  it('every placeholder file is still reported, exactly once', () => {
    for (const body of [
      'GOOGLE_CLIENT_SECRET=123',
      'GITHUB_CLIENT_SECRET=123;',
      'OIDC_CLIENT_SECRET=client-secret',
      'SMTP_FROM_EMAIL=hello@example.com',
      'DATABASE_URL=postgres://user:pass@127.0.0.1:5432/notes',
    ]) {
      expect(run(body)).toHaveLength(1);
    }
  });

  it('a template file is still exempt, and an empty one still silent', () => {
    expect(envFileIncluded.run(memoryContext([PKG, ['.env.example', 'GOOGLE_CLIENT_SECRET=123']]))).toHaveLength(0);
    expect(run('# nothing but a comment\n')).toHaveLength(0);
  });
});
