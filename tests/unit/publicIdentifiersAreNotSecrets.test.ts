import { describe, expect, it } from 'vitest';

import { envFileIncluded } from '../../src/rules/basic/envFileIncluded.js';
import { hardcodedSecret } from '../../src/rules/basic/hardcodedSecret.js';
import { memoryContext } from './helpers.js';

const run = (files: [string, string][]): string[] =>
  hardcodedSecret.run(memoryContext(files)).map((f) => `${f.filePath}:${f.lineStart}`);

const FIREBASE_KEY = ('AI' + 'zaSyD-NotARealKey-Xq7Tz2Lp9Vm4Rk8Wn3Q');
const MAPS_KEY = ('AI' + 'zaSyB-NotARealMapsKey-Hv2Jw9Kq4Zs7Tm1');

describe('A34 Firebase web config apiKey', () => {
  it('MUST GO QUIET: an apiKey inside initializeApp({...}) is a project identifier', () => {
    const content = [
      'firebase.initializeApp({',
      `  apiKey: "${FIREBASE_KEY}",`,
      '  authDomain: "demo-a8dd6.firebaseapp.com",',
      '  projectId: "demo-a8dd6",',
      '  storageBucket: "demo-a8dd6.firebasestorage.app",',
      '  messagingSenderId: "956348246783",',
      '  appId: "1:956348246783:web:175dd2d3ff5586b05c3aca"',
      '});',
    ].join('\n');
    expect(run([['public/firebase-messaging-sw.js', content]])).toEqual([]);
  });

  it('MUST GO QUIET: the same config written as JSON, with no initializeApp call', () => {
    const content = [
      '{',
      '  "projectId": "gen-lang-client-0080417759",',
      '  "appId": "1:495897390797:web:5075b507a44a44bd1c8384",',
      `  "apiKey": "${FIREBASE_KEY}",`,
      '  "authDomain": "gen-lang-client-0080417759.firebaseapp.com",',
      '  "storageBucket": "gen-lang-client-0080417759.firebasestorage.app",',
      '  "messagingSenderId": "495897390797"',
      '}',
    ].join('\n');
    expect(run([['firebase-applet-config.json', content]])).toEqual([]);
  });

  it('MUST STILL FIRE: a live Google Maps key in a committed <script src>', () => {
    const content = [
      '<!DOCTYPE html>',
      '<head>',
      `<script src="https://maps.googleapis.com/maps/api/js?key=${MAPS_KEY}&libraries=places"></script>`,
      '</head>',
    ].join('\n');
    expect(run([['public/index.html', content]])).toEqual(['public/index.html:3']);
  });

  it('MUST STILL FIRE: a bare apiKey with no Firebase siblings names no product', () => {
    const content = `const config = { apiKey: "${MAPS_KEY}" };`;
    expect(new Set(run([['src/maps.js', content]]))).toEqual(new Set(['src/maps.js:1']));
  });

  it('MUST STILL FIRE: a second Google key beside a Firebase config is not the config key', () => {
    const content = [
      'firebase.initializeApp({',
      `  apiKey: "${FIREBASE_KEY}",`,
      '  authDomain: "demo.firebaseapp.com",',
      '  projectId: "demo",',
      '});',
      `const translateKey = "${MAPS_KEY}";`,
    ].join('\n');
    expect(run([['src/firebase.js', content]])).toEqual(['src/firebase.js:6']);
  });
});

describe('A34 public env prefixes', () => {
  it('MUST GO QUIET: a value under NEXT_PUBLIC_ in a deploy manifest', () => {
    const content = [
      '    envVars:',
      '      - key: NEXT_PUBLIC_URL',
      '        value: https://example.onrender.com',
      '      - key: NEXT_PUBLIC_API_KEY',
      `        value: ${FIREBASE_KEY}`,
      '      - key: NEXT_PUBLIC_PROJECT_ID',
      '        value: demo-ed758',
    ].join('\n');
    expect(run([['render.yaml', content]])).toEqual([]);
  });

  it.each([
    ['VITE_', 'VITE_MAPS_KEY'],
    ['REACT_APP_', 'REACT_APP_MAPS_KEY'],
    ['EXPO_PUBLIC_', 'EXPO_PUBLIC_MAPS_KEY'],
    ['PUBLIC_', 'PUBLIC_MAPS_KEY'],
    ['GATSBY_', 'GATSBY_MAPS_KEY'],
  ])('MUST GO QUIET: %s is a public prefix in every framework that defines one', (_prefix, name) => {
    expect(run([['config.yaml', `${name}: ${MAPS_KEY}`]])).toEqual([]);
  });

  it('MUST STILL FIRE: a real secret placed under a public prefix', () => {
    const content = ('NEXT_PUBLIC_API_SECRET=sk' + '_live_51QjkLmNoPqRsTuVwXyZ0123');
    expect(run([['deploy.yaml', content]])).toEqual(['deploy.yaml:1']);
  });

  it('MUST STILL FIRE: a secret on the line after a public-prefixed one', () => {
    const content = [
      'NEXT_PUBLIC_SITE_URL=https://example.com',
      ('STRIPE_SECRET_KEY=sk' + '_live_51QjkLmNoPqRsTuVwXyZ0123'),
    ].join('\n');
    expect(run([['deploy.yaml', content]])).toEqual(['deploy.yaml:2']);
  });

  it('MUST STILL FIRE: a private key block is never public whatever names it', () => {
    const content = ('NEXT_PUBLIC_CERT="-----BEGIN RSA PRIV' + 'ATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDb3fJ8kQ2mAaXq\\n-----END RSA PRIVATE KEY-----"');
    expect(run([['config.yaml', content]])).toEqual(['config.yaml:1']);
  });

  it('MUST STILL FIRE: a Supabase service_role JWT in a seed script', () => {
    const payload = Buffer.from(JSON.stringify({ iss: 'supabase', role: 'service_role' })).toString('base64url');
    const jwt = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${payload}.HFzYs9uPRoJyRoJyRoJyRoJyRoJyRoJyRo`;
    expect(run([['scripts/seed.ts', `const SERVICE_ROLE_KEY = "${jwt}";`]])).toEqual(['scripts/seed.ts:1']);
  });
});

describe('A34 the two rules now agree', () => {
  const publicEnv = [
    'VITE_SUPABASE_URL="https://xbnrjwzryuonuinzuomk.supabase.co"',
    'VITE_SUPABASE_PUBLISHABLE_KEY="sb_publishable_lQTJrK09yoRsg2vHynu38g_Uh3qUYUq"',
    `VITE_FIREBASE_API_KEY="${FIREBASE_KEY}"`,
  ].join('\n');
  const publicManifest = [
    'envVars:',
    '  - key: VITE_SUPABASE_URL',
    '    value: https://xbnrjwzryuonuinzuomk.supabase.co',
    '  - key: VITE_FIREBASE_API_KEY',
    `    value: ${FIREBASE_KEY}`,
  ].join('\n');

  it('env_file_included reports it as informational, not a credential leak', () => {
    const findings = envFileIncluded.run(memoryContext([['.env', publicEnv]]));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('low');
  });

  it('hardcoded_secret no longer contradicts that verdict', () => {
    expect(run([['render.yaml', publicManifest]])).toEqual([]);
  });

  it('and both still call a real credential a real credential', () => {
    const realEnv = ('STRIPE_SECRET_KEY=sk' + '_live_51QjkLmNoPqRsTuVwXyZ0123');
    const envFinding = envFileIncluded.run(memoryContext([['.env', realEnv]]));
    expect(envFinding[0]?.severity).toBe('high');
    expect(run([['render.yaml', ('STRIPE_SECRET_KEY: sk' + '_live_51QjkLmNoPqRsTuVwXyZ0123')]]))
      .toEqual(['render.yaml:1']);
  });
});
