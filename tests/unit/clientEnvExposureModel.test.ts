import { describe, expect, it } from 'vitest';

import { envUsageWithoutServerBoundary } from '../../src/rules/contextual/envUsageWithoutServerBoundary.js';
import { memoryContext } from './helpers.js';

const clientComponent = (importPath: string): string =>
  ["'use client';", `import { value } from '${importPath}';`, 'export default function Page() { return <div>{String(value)}</div>; }'].join('\n');

const fired = (files: [string, string][]): string[] =>
  envUsageWithoutServerBoundary.run(memoryContext(files)).map((f) => `${f.filePath}:${f.lineStart}`);

const NEXT_PACKAGE = JSON.stringify({ name: 'app', dependencies: { next: '15.0.0', react: '19.0.0' } });
const VITE_PACKAGE = JSON.stringify({ name: 'app', dependencies: { react: '19.0.0' }, devDependencies: { vite: '5.0.0' } });
const CRA_PACKAGE = JSON.stringify({ name: 'app', dependencies: { react: '18.0.0', 'react-scripts': '5.0.1' } });
const PLAIN_PACKAGE = JSON.stringify({ name: 'app', dependencies: { react: '19.0.0' } });

describe('A35 Next.js inlines NEXT_PUBLIC_ and nothing else', () => {
  it('MUST GO QUIET: a non-prefixed secret is stripped from the client compilation', () => {
    expect(
      fired([
        ['package.json', NEXT_PACKAGE],
        ['next.config.js', 'module.exports = {};'],
        ['src/lib/env/server.ts', 'export const value = process.env.CLERK_SECRET_KEY;'],
        ['src/app/page.tsx', clientComponent('../lib/env/server')],
      ]),
    ).toEqual([]);
  });

  it.each(['DATABASE_URL', 'INNGEST_SIGNING_KEY', 'RECAPTCHA_SECRET_KEY', 'STRIPE_SECRET_KEY'])(
    'MUST GO QUIET: %s carries no public prefix, so Next.js embeds nothing',
    (name) => {
      expect(
        fired([
          ['package.json', NEXT_PACKAGE],
          ['next.config.js', 'module.exports = {};'],
          ['lib/config.ts', `export const value = process.env.${name};`],
          ['app/page.tsx', clientComponent('../lib/config')],
        ]),
      ).toEqual([]);
    },
  );

  it('MUST STILL FIRE: a real secret placed under NEXT_PUBLIC_', () => {
    const findings = envUsageWithoutServerBoundary.run(
      memoryContext([
        ['package.json', NEXT_PACKAGE],
        ['next.config.js', 'module.exports = {};'],
        ['lib/config.ts', 'export const value = process.env.NEXT_PUBLIC_API_SECRET;'],
        ['app/page.tsx', clientComponent('../lib/config')],
      ]),
    );
    expect(findings.map((f) => `${f.filePath}:${f.lineStart}`)).toEqual(['lib/config.ts:1']);
    expect(findings[0]?.fixHint).toMatch(/Rotate this value/);
  });

  it('MUST NOT FIRE: a public-prefixed API key is the normal shape of a public key', () => {
    expect(
      fired([
        ['package.json', NEXT_PACKAGE],
        ['next.config.js', 'module.exports = {};'],
        ['lib/firebase.ts', 'export const value = process.env.NEXT_PUBLIC_FIREBASE_API_KEY;'],
        ['app/page.tsx', clientComponent('../lib/firebase')],
      ]),
    ).toEqual([]);
  });
});

describe('A35 Vite exposes only import.meta.env.VITE_', () => {
  it('MUST STILL FIRE: a secret read through import.meta.env.VITE_ in a Vite app', () => {
    expect(
      fired([
        ['package.json', VITE_PACKAGE],
        ['vite.config.ts', 'export default {};'],
        ['src/lib/config.ts', 'export const value = import.meta.env.VITE_SESSION_SECRET;'],
        ['src/App.tsx', clientComponent('./lib/config')],
      ]),
    ).toEqual(['src/lib/config.ts:1']);
  });

  it('MUST GO QUIET: a non-VITE_ name on import.meta.env is stripped by Vite', () => {
    expect(
      fired([
        ['package.json', VITE_PACKAGE],
        ['vite.config.ts', 'export default {};'],
        ['src/lib/config.ts', 'export const value = import.meta.env.SESSION_SECRET;'],
        ['src/App.tsx', clientComponent('./lib/config')],
      ]),
    ).toEqual([]);
  });

  it('MUST STILL FIRE: process.env in a Vite app, because a project can define it back', () => {
    expect(
      fired([
        ['package.json', VITE_PACKAGE],
        ['vite.config.ts', 'export default {};'],
        ['src/lib/config.ts', 'export const value = process.env.SESSION_SECRET;'],
        ['src/App.tsx', clientComponent('./lib/config')],
      ]),
    ).toEqual(['src/lib/config.ts:1']);
  });
});

describe('A35 CRA inlines only REACT_APP_', () => {
  it('MUST GO QUIET: a non-prefixed secret under react-scripts', () => {
    expect(
      fired([
        ['package.json', CRA_PACKAGE],
        ['src/config.ts', 'export const value = process.env.SESSION_SECRET;'],
        ['src/App.tsx', clientComponent('./config')],
      ]),
    ).toEqual([]);
  });

  it('MUST STILL FIRE: a secret under REACT_APP_ really is inlined', () => {
    expect(
      fired([
        ['package.json', CRA_PACKAGE],
        ['src/config.ts', 'export const value = process.env.REACT_APP_SESSION_SECRET;'],
        ['src/App.tsx', clientComponent('./config')],
      ]),
    ).toEqual(['src/config.ts:1']);
  });
});

describe('A35 an unknown build keeps the old model', () => {
  it('MUST STILL FIRE: no recognised framework, so no exemption is granted', () => {
    expect(
      fired([
        ['package.json', PLAIN_PACKAGE],
        ['src/config.ts', 'export const value = process.env.SESSION_SECRET;'],
        ['src/App.tsx', clientComponent('./config')],
      ]),
    ).toEqual(['src/config.ts:1']);
  });

  it('MUST STILL FIRE: Next.js as a dev dependency of a Vite app does not decide the build', () => {
    expect(
      fired([
        ['package.json', VITE_PACKAGE],
        ['vite.config.ts', 'export default {};'],
        ['src/config.ts', 'export const value = import.meta.env.VITE_DATABASE_URL;'],
        ['src/App.tsx', clientComponent('./config')],
      ]),
    ).toEqual(['src/config.ts:1']);
  });
});
