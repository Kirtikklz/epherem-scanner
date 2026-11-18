import { describe, expect, it } from 'vitest';
import {
  createDependencyOriginResolver,
  MAX_ORIGIN_CHAIN_DEPTH,
} from '../../src/dependency-audit/dependencyOrigin.js';
import { memoryContext } from './helpers.js';

function resolverFor(files: [string, string][]) {
  return createDependencyOriginResolver(memoryContext(files).fileMap);
}

const npmQuery = (packageName: string, installedVersion: string, sourcePath?: string) => ({
  ecosystem: 'npm' as const,
  packageName,
  installedVersion,
  ...(sourcePath !== undefined ? { sourcePath } : {}),
});

function lockV3(packages: Record<string, unknown>): string {
  return JSON.stringify({ name: 'app', lockfileVersion: 3, packages }, null, 2);
}

describe('dependency origin — direct', () => {
  it('names the manifest that declares the package', () => {
    const origin = resolverFor([
      ['package.json', JSON.stringify({ dependencies: { express: '^4.17.1' } })],
      ['package-lock.json', lockV3({
        '': { dependencies: { express: '^4.17.1' } },
        'node_modules/express': { version: '4.17.1' },
      })],
    ]).resolve(npmQuery('express', '4.17.1', 'package-lock.json'));

    expect(origin.relationship).toBe('direct');
    expect(origin.declaredIn).toBe('package.json');
    expect(origin.manifestControlsInstalledCopy).toBe(true);
    expect(origin.chain).toBeUndefined();
  });

  it('finds a monorepo package in the workspace manifest that declares it', () => {
    const origin = resolverFor([
      ['package.json', JSON.stringify({ dependencies: {} })],
      ['apps/docs/package.json', JSON.stringify({ dependencies: { postcss: '^8.4.31' } })],
      ['package-lock.json', lockV3({
        '': {},
        'apps/docs': { name: 'docs', version: '1.0.0', dependencies: { postcss: '^8.4.31' } },
        'node_modules/postcss': { version: '8.4.31' },
      })],
    ]).resolve(npmQuery('postcss', '8.4.31', 'package-lock.json'));

    expect(origin.relationship).toBe('direct');
    expect(origin.declaredIn).toBe('apps/docs/package.json');
  });

  it('says the manifest entry does NOT control this copy, and names the copy that did', () => {
    const origin = resolverFor([
      ['package.json', JSON.stringify({ dependencies: { next: '^15.0.0', postcss: '^8.5.0' } })],
      ['package-lock.json', lockV3({
        '': { dependencies: { next: '^15.0.0', postcss: '^8.5.0' } },
        'node_modules/next': { version: '15.0.0', dependencies: { postcss: '8.4.31' } },
        'node_modules/next/node_modules/postcss': { version: '8.4.31' },
        'node_modules/postcss': { version: '8.5.6' },
      })],
    ]).resolve(npmQuery('postcss', '8.4.31', 'package-lock.json'));

    expect(origin.relationship).toBe('direct');
    expect(origin.manifestControlsInstalledCopy).toBe(false);
    expect(origin.chain).toEqual(['next', 'postcss']);
  });

  it('leaves "does the manifest control this copy" ABSENT when no lockfile can settle it', () => {
    const origin = resolverFor([
      ['package.json', JSON.stringify({ dependencies: { express: '^4.17.1' } })],
    ]).resolve(npmQuery('express', '4.17.1'));

    expect(origin.relationship).toBe('direct');
    expect(origin.manifestControlsInstalledCopy).toBeUndefined();
  });
});

describe('dependency origin — transitive chains', () => {
  it('npm v3: names the whole chain, root first, ending at the vulnerable package', () => {
    const origin = resolverFor([
      ['package.json', JSON.stringify({ devDependencies: { eslint: '^8.0.0' } })],
      ['package-lock.json', lockV3({
        '': { devDependencies: { eslint: '^8.0.0' } },
        'node_modules/eslint': { version: '8.0.0', dependencies: { glob: '^7.0.0' } },
        'node_modules/glob': { version: '7.2.0', dependencies: { minimatch: '^3.1.2' } },
        'node_modules/minimatch': { version: '3.1.2' },
      })],
    ]).resolve(npmQuery('minimatch', '3.1.2', 'package-lock.json'));

    expect(origin.relationship).toBe('transitive');
    expect(origin.chain).toEqual(['eslint', 'glob', 'minimatch']);
    expect(origin.declaredIn).toBe('package.json');
    expect(origin.graphSource).toBe('package-lock.json');
  });

  it('npm v3: prefers a NESTED copy over the hoisted one, the way npm resolves it', () => {
    const origin = resolverFor([
      ['package.json', JSON.stringify({ devDependencies: { parent: '^1.0.0' } })],
      ['package-lock.json', lockV3({
        '': { devDependencies: { parent: '^1.0.0' } },
        'node_modules/parent': { version: '1.0.0', dependencies: { minimatch: '3.0.4' } },
        'node_modules/parent/node_modules/minimatch': { version: '3.0.4' },
        'node_modules/minimatch': { version: '9.0.5' },
      })],
    ]).resolve(npmQuery('minimatch', '3.0.4', 'package-lock.json'));

    expect(origin.chain).toEqual(['parent', 'minimatch']);
  });

  it('npm v1: reads the nested tree and its `requires` edges', () => {
    const lock = JSON.stringify({
      name: 'app',
      lockfileVersion: 1,
      dependencies: {
        jsonwebtoken: { version: '8.5.1', requires: { semver: '^5.6.0' } },
        semver: { version: '5.7.0' },
      },
    });
    const origin = resolverFor([
      ['package.json', JSON.stringify({ dependencies: { jsonwebtoken: '^8.5.1' } })],
      ['package-lock.json', lock],
    ]).resolve(npmQuery('semver', '5.7.0', 'package-lock.json'));

    expect(origin.relationship).toBe('transitive');
    expect(origin.chain).toEqual(['jsonwebtoken', 'semver']);
  });

  it('yarn v1: maps a parent\'s declared range back to the block that resolved it', () => {
    const yarn = [
      '# THIS IS AN AUTOGENERATED FILE.',
      '',
      'express@^4.17.1:',
      '  version "4.17.1"',
      '  dependencies:',
      '    qs "6.7.0"',
      '',
      'qs@6.7.0:',
      '  version "6.7.0"',
      '',
    ].join('\n');
    const origin = resolverFor([
      ['package.json', JSON.stringify({ dependencies: { express: '^4.17.1' } })],
      ['yarn.lock', yarn],
    ]).resolve(npmQuery('qs', '6.7.0', 'yarn.lock'));

    expect(origin.relationship).toBe('transitive');
    expect(origin.chain).toEqual(['express', 'qs']);
  });

  it('pnpm v9: reads `snapshots` edges and strips the peer suffix', () => {
    const pnpm = [
      "lockfileVersion: '9.0'",
      '',
      'importers:',
      '',
      '  .:',
      '    dependencies:',
      "      '@vercel/functions':",
      '        specifier: ^3.7.5',
      '        version: 3.7.5(ws@8.18.1)',
      '',
      'packages:',
      '',
      "  '@vercel/functions@3.7.5':",
      '    resolution: {integrity: sha512-x}',
      '',
      '  ws@8.18.1:',
      '    resolution: {integrity: sha512-y}',
      '',
      'snapshots:',
      '',
      "  '@vercel/functions@3.7.5(ws@8.18.1)':",
      '    optionalDependencies:',
      '      ws: 8.18.1',
      '',
      '  ws@8.18.1: {}',
      '',
    ].join('\n');
    const origin = resolverFor([
      ['package.json', JSON.stringify({ dependencies: { '@vercel/functions': '^3.7.5' } })],
      ['pnpm-lock.yaml', pnpm],
    ]).resolve(npmQuery('ws', '8.18.1', 'pnpm-lock.yaml'));

    expect(origin.relationship).toBe('transitive');
    expect(origin.chain).toEqual(['@vercel/functions', 'ws']);
  });

  it('takes the SHORTEST chain when a package is reachable more than one way', () => {
    const origin = resolverFor([
      ['package.json', JSON.stringify({ dependencies: { alpha: '^1.0.0', beta: '^1.0.0' } })],
      ['package-lock.json', lockV3({
        '': { dependencies: { alpha: '^1.0.0', beta: '^1.0.0' } },
        'node_modules/alpha': { version: '1.0.0', dependencies: { mid: '^1.0.0' } },
        'node_modules/mid': { version: '1.0.0', dependencies: { victim: '^1.0.0' } },
        'node_modules/beta': { version: '1.0.0', dependencies: { victim: '^1.0.0' } },
        'node_modules/victim': { version: '1.0.0' },
      })],
    ]).resolve(npmQuery('victim', '1.0.0', 'package-lock.json'));

    expect(origin.chain).toEqual(['beta', 'victim']);
  });
});

describe('dependency origin — says "I could not tell" instead of guessing', () => {
  it('no manifest at all: cannot even ask whether the project declares it', () => {
    const origin = resolverFor([
      ['package-lock.json', lockV3({ '': {}, 'node_modules/minimatch': { version: '3.1.2' } })],
    ]).resolve(npmQuery('minimatch', '3.1.2', 'package-lock.json'));

    expect(origin.relationship).toBe('undetermined');
    expect(origin.undeterminedReason).toBe('no_manifest_found');
    expect(origin.chain).toBeUndefined();
  });

  it('manifest but no lockfile: nothing records who required what', () => {
    const origin = resolverFor([
      ['package.json', JSON.stringify({ dependencies: { eslint: '^8.0.0' } })],
    ]).resolve(npmQuery('minimatch', '3.1.2'));

    expect(origin.relationship).toBe('undetermined');
    expect(origin.undeterminedReason).toBe('no_dependency_graph');
  });

  it('lockfile does not carry this exact version', () => {
    const origin = resolverFor([
      ['package.json', JSON.stringify({ dependencies: { eslint: '^8.0.0' } })],
      ['package-lock.json', lockV3({
        '': { dependencies: { eslint: '^8.0.0' } },
        'node_modules/eslint': { version: '8.0.0', dependencies: { minimatch: '^9.0.0' } },
        'node_modules/minimatch': { version: '9.0.5' },
      })],
    ]).resolve(npmQuery('minimatch', '3.1.2', 'package-lock.json'));

    expect(origin.relationship).toBe('undetermined');
    expect(origin.undeterminedReason).toBe('package_not_in_graph');
  });

  it('nothing above the package leads to anything the project declared', () => {
    const origin = resolverFor([
      ['package.json', JSON.stringify({ dependencies: { unrelated: '^1.0.0' } })],
      ['package-lock.json', lockV3({
        '': { dependencies: { unrelated: '^1.0.0' } },
        'node_modules/unrelated': { version: '1.0.0' },
        'node_modules/orphan': { version: '2.0.0', dependencies: { minimatch: '^3.1.2' } },
        'node_modules/minimatch': { version: '3.1.2' },
      })],
    ]).resolve(npmQuery('minimatch', '3.1.2', 'package-lock.json'));

    expect(origin.relationship).toBe('undetermined');
    expect(origin.undeterminedReason).toBe('no_path_to_a_direct_dependency');
  });

  it(`a chain longer than ${MAX_ORIGIN_CHAIN_DEPTH} is reported as bounded, not as absent`, () => {
    const depth = MAX_ORIGIN_CHAIN_DEPTH + 1;
    const packages: Record<string, unknown> = {
      '': { dependencies: { p0: '^1.0.0' } },
      'node_modules/victim': { version: '1.0.0' },
    };
    for (let index = 0; index < depth; index += 1) {
      const child = index === depth - 1 ? 'victim' : `p${index + 1}`;
      packages[`node_modules/p${index}`] = { version: '1.0.0', dependencies: { [child]: '^1.0.0' } };
    }
    const origin = resolverFor([
      ['package.json', JSON.stringify({ dependencies: { p0: '^1.0.0' } })],
      ['package-lock.json', lockV3(packages)],
    ]).resolve(npmQuery('victim', '1.0.0', 'package-lock.json'));

    expect(origin.relationship).toBe('undetermined');
    expect(origin.undeterminedReason).toBe('search_bounded');
    expect(origin.searchBounds).toEqual([`chain-depth-cap-${MAX_ORIGIN_CHAIN_DEPTH}`]);
  });

  it(`a chain exactly ${MAX_ORIGIN_CHAIN_DEPTH} long is still reported in full`, () => {
    const depth = MAX_ORIGIN_CHAIN_DEPTH;
    const packages: Record<string, unknown> = {
      '': { dependencies: { p0: '^1.0.0' } },
      'node_modules/victim': { version: '1.0.0' },
    };
    for (let index = 0; index < depth; index += 1) {
      const child = index === depth - 1 ? 'victim' : `p${index + 1}`;
      packages[`node_modules/p${index}`] = { version: '1.0.0', dependencies: { [child]: '^1.0.0' } };
    }
    const origin = resolverFor([
      ['package.json', JSON.stringify({ dependencies: { p0: '^1.0.0' } })],
      ['package-lock.json', lockV3(packages)],
    ]).resolve(npmQuery('victim', '1.0.0', 'package-lock.json'));

    expect(origin.relationship).toBe('transitive');
    expect(origin.chain).toHaveLength(depth + 1);
    expect(origin.chain?.[0]).toBe('p0');
    expect(origin.chain?.[depth]).toBe('victim');
  });

  it('a malformed lockfile produces no parent, not an invented one', () => {
    const origin = resolverFor([
      ['package.json', JSON.stringify({ dependencies: { eslint: '^8.0.0' } })],
      ['package-lock.json', '{ this is not json'],
    ]).resolve(npmQuery('minimatch', '3.1.2', 'package-lock.json'));

    expect(origin.relationship).toBe('undetermined');
    expect(origin.chain).toBeUndefined();
  });

  it('a dependency cycle terminates instead of looping', () => {
    const origin = resolverFor([
      ['package.json', JSON.stringify({ dependencies: { unrelated: '^1.0.0' } })],
      ['package-lock.json', lockV3({
        '': { dependencies: { unrelated: '^1.0.0' } },
        'node_modules/unrelated': { version: '1.0.0' },
        'node_modules/a': { version: '1.0.0', dependencies: { b: '^1.0.0' } },
        'node_modules/b': { version: '1.0.0', dependencies: { a: '^1.0.0' } },
      })],
    ]).resolve(npmQuery('a', '1.0.0', 'package-lock.json'));

    expect(origin.relationship).toBe('undetermined');
    expect(origin.undeterminedReason).toBe('no_path_to_a_direct_dependency');
  });

  it('PyPI: declared packages are direct, undeclared ones are undetermined — never guessed', () => {
    const resolver = resolverFor([
      ['requirements.txt', 'Flask==2.0.1\nJinja2==3.0.0\n'],
    ]);
    expect(resolver.resolve({ ecosystem: 'PyPI', packageName: 'flask', installedVersion: '2.0.1' }))
      .toMatchObject({ relationship: 'direct', declaredIn: 'requirements.txt' });
    expect(resolver.resolve({ ecosystem: 'PyPI', packageName: 'werkzeug', installedVersion: '2.0.1' }))
      .toMatchObject({ relationship: 'undetermined', undeterminedReason: 'no_dependency_graph' });
  });
});

describe('dependency origin — stability', () => {
  it('gives the same answer on repeated calls and across resolver instances', () => {
    const files: [string, string][] = [
      ['package.json', JSON.stringify({ dependencies: { alpha: '^1.0.0' } })],
      ['package-lock.json', lockV3({
        '': { dependencies: { alpha: '^1.0.0' } },
        'node_modules/alpha': { version: '1.0.0', dependencies: { victim: '^1.0.0' } },
        'node_modules/victim': { version: '1.0.0' },
      })],
    ];
    const first = resolverFor(files).resolve(npmQuery('victim', '1.0.0', 'package-lock.json'));
    const reused = resolverFor(files);
    expect(reused.resolve(npmQuery('victim', '1.0.0', 'package-lock.json'))).toEqual(first);
    expect(reused.resolve(npmQuery('victim', '1.0.0', 'package-lock.json'))).toEqual(first);
  });
});

function bunLock(body: Record<string, unknown>): string {
  return JSON.stringify({ lockfileVersion: 1, ...body }, null, 2);
}

const ROOT_WORKSPACE = (dependencies: Record<string, string>) => ({
  '': { name: 'app', dependencies },
});

describe('dependency origin — bun.lock', () => {
  it('names the whole chain for a transitive package', () => {
    const origin = resolverFor([
      ['package.json', JSON.stringify({ dependencies: { vite: '^5.0.0' } })],
      ['bun.lock', bunLock({
        workspaces: ROOT_WORKSPACE({ vite: '^5.0.0' }),
        packages: {
          vite: ['vite@5.4.10', '', { dependencies: { esbuild: '^0.21.3' } }, 'sha512-a'],
          esbuild: ['esbuild@0.21.5', '', { optionalDependencies: { '@esbuild/linux-x64': '0.21.5' } }, 'sha512-b'],
          '@esbuild/linux-x64': ['@esbuild/linux-x64@0.21.5', '', {}, 'sha512-c'],
        },
      })],
    ]).resolve(npmQuery('@esbuild/linux-x64', '0.21.5', 'bun.lock'));

    expect(origin.relationship).toBe('transitive');
    expect(origin.chain).toEqual(['vite', 'esbuild', '@esbuild/linux-x64']);
    expect(origin.declaredIn).toBe('package.json');
    expect(origin.graphSource).toBe('bun.lock');
  });

  it('reads the NAME from element [0], not from the placement key', () => {
    const origin = resolverFor([
      ['package.json', JSON.stringify({ dependencies: { '@eslint-community/eslint-utils': '^4.4.0' } })],
      ['bun.lock', bunLock({
        workspaces: ROOT_WORKSPACE({ '@eslint-community/eslint-utils': '^4.4.0' }),
        packages: {
          '@eslint-community/eslint-utils': [
            '@eslint-community/eslint-utils@4.4.0', '',
            { dependencies: { 'eslint-visitor-keys': '^3.3.0' } }, 'sha512-a',
          ],
          '@eslint-community/eslint-utils/eslint-visitor-keys': [
            'eslint-visitor-keys@3.4.3', '', {}, 'sha512-b',
          ],
        },
      })],
    ]).resolve(npmQuery('eslint-visitor-keys', '3.4.3', 'bun.lock'));

    expect(origin.relationship).toBe('transitive');
    expect(origin.chain).toEqual(['@eslint-community/eslint-utils', 'eslint-visitor-keys']);
  });

  it('says the manifest entry controls this copy when the lockfile shows it does', () => {
    const origin = resolverFor([
      ['package.json', JSON.stringify({ dependencies: { postcss: '^8.4.31' } })],
      ['bun.lock', bunLock({
        workspaces: ROOT_WORKSPACE({ postcss: '^8.4.31' }),
        packages: { postcss: ['postcss@8.4.31', '', {}, 'sha512-a'] },
      })],
    ]).resolve(npmQuery('postcss', '8.4.31', 'bun.lock'));

    expect(origin.relationship).toBe('direct');
    expect(origin.manifestControlsInstalledCopy).toBe(true);
  });

  it('ONE COPY IS NOT EVERY COPY: names the chain that installed the nested one', () => {
    const origin = resolverFor([
      ['package.json', JSON.stringify({ dependencies: { postcss: '^8.4.31', tailwindcss: '^3.4.0' } })],
      ['bun.lock', bunLock({
        workspaces: ROOT_WORKSPACE({ postcss: '^8.4.31', tailwindcss: '^3.4.0' }),
        packages: {
          postcss: ['postcss@8.4.31', '', {}, 'sha512-a'],
          tailwindcss: ['tailwindcss@3.4.1', '', { dependencies: { postcss: '8.4.21' } }, 'sha512-b'],
          'tailwindcss/postcss': ['postcss@8.4.21', '', {}, 'sha512-c'],
        },
      })],
    ]).resolve(npmQuery('postcss', '8.4.21', 'bun.lock'));

    expect(origin.relationship).toBe('direct');
    expect(origin.manifestControlsInstalledCopy).toBe(false);
    expect(origin.chain).toEqual(['tailwindcss', 'postcss']);
  });

  it('leaves manifestControlsInstalledCopy ABSENT when the file carried no workspaces block', () => {
    const origin = resolverFor([
      ['package.json', JSON.stringify({ dependencies: { postcss: '^8.4.31' } })],
      ['bun.lock', bunLock({ packages: { postcss: ['postcss@8.4.31', '', {}, 'sha512-a'] } })],
    ]).resolve(npmQuery('postcss', '8.4.31', 'bun.lock'));

    expect(origin.relationship).toBe('direct');
    expect(origin.manifestControlsInstalledCopy).toBeUndefined();
  });

  it('reads a bun.lock with comments and a trailing comma, because that is what bun emits', () => {
    const jsonc = [
      '{',
      '  "lockfileVersion": 1,',
      '  // bun writes these, and the registry URLs below are full of "//"',
      '  "workspaces": { "": { "name": "app", "dependencies": { "vite": "^5.0.0" } } },',
      '  "packages": {',
      '    "vite": ["vite@5.4.10", "https://registry.npmjs.org/vite", { "dependencies": { "esbuild": "^0.21.3" } }, "sha512-a"],',
      '    "esbuild": ["esbuild@0.21.5", "", {}, "sha512-b"],',
      '  }',
      '}',
    ].join('\n');
    const origin = resolverFor([
      ['package.json', JSON.stringify({ dependencies: { vite: '^5.0.0' } })],
      ['bun.lock', jsonc],
    ]).resolve(npmQuery('esbuild', '0.21.5', 'bun.lock'));

    expect(origin.relationship).toBe('transitive');
    expect(origin.chain).toEqual(['vite', 'esbuild']);
  });

  it('NEVER A SILENT ZERO: an unreadable bun.lock says the graph is MISSING, not searched', () => {
    const origin = resolverFor([
      ['package.json', JSON.stringify({ dependencies: { vite: '^5.0.0' } })],
      ['bun.lock', '{ this is not a lockfile'],
    ]).resolve(npmQuery('esbuild', '0.21.5', 'bun.lock'));

    expect(origin.relationship).toBe('undetermined');
    expect(origin.undeterminedReason).toBe('no_dependency_graph');
  });

  it('NEVER A SILENT ZERO: a bun.lock with an empty packages map says the same', () => {
    const origin = resolverFor([
      ['package.json', JSON.stringify({ dependencies: { vite: '^5.0.0' } })],
      ['bun.lock', bunLock({ workspaces: ROOT_WORKSPACE({ vite: '^5.0.0' }), packages: {} })],
    ]).resolve(npmQuery('esbuild', '0.21.5', 'bun.lock'));

    expect(origin.undeterminedReason).toBe('no_dependency_graph');
  });

  it('a package genuinely absent from a readable bun.lock still says package_not_in_graph', () => {
    const origin = resolverFor([
      ['package.json', JSON.stringify({ dependencies: { vite: '^5.0.0' } })],
      ['bun.lock', bunLock({
        workspaces: ROOT_WORKSPACE({ vite: '^5.0.0' }),
        packages: { vite: ['vite@5.4.10', '', {}, 'sha512-a'] },
      })],
    ]).resolve(npmQuery('lodash', '4.17.20', 'bun.lock'));

    expect(origin.undeterminedReason).toBe('package_not_in_graph');
  });

  it('bun.lockb is never read: it is binary and no arm claims it', () => {
    const origin = resolverFor([
      ['package.json', JSON.stringify({ dependencies: { vite: '^5.0.0' } })],
      ['bun.lockb', 'bun-lockfile-format-v0 binary'],
    ]).resolve(npmQuery('esbuild', '0.21.5'));

    expect(origin.relationship).toBe('undetermined');
    expect(origin.undeterminedReason).toBe('no_dependency_graph');
  });
});

const BERRY_HEADER = ['__metadata:', '  version: 8', '  cacheKey: 10c0', ''].join('\n');

describe('dependency origin — yarn Berry', () => {
  it('reads the Berry version line, so a package in the file resolves to a chain', () => {
    const yarn = [
      BERRY_HEADER,
      '"mermaid@npm:^11.0.0":',
      '  version: 11.4.1',
      '  resolution: "mermaid@npm:11.4.1"',
      '  dependencies:',
      '    "@iconify/utils": "npm:^2.1.32"',
      '  languageName: node',
      '  linkType: hard',
      '',
      '"@iconify/utils@npm:^2.1.32":',
      '  version: 2.1.33',
      '  dependencies:',
      '    "@antfu/install-pkg": "npm:^1.1.0"',
      '',
      '"@antfu/install-pkg@npm:^1.1.0":',
      '  version: 1.1.0',
      '',
    ].join('\n');
    const origin = resolverFor([
      ['package.json', JSON.stringify({ dependencies: { mermaid: '^11.0.0' } })],
      ['yarn.lock', yarn],
    ]).resolve(npmQuery('@antfu/install-pkg', '1.1.0', 'yarn.lock'));

    expect(origin.relationship).toBe('transitive');
    expect(origin.chain).toEqual(['mermaid', '@iconify/utils', '@antfu/install-pkg']);
    expect(origin.graphSource).toBe('yarn.lock');
  });

  it('THE TRAP: a manifest range resolves through the `npm:` protocol, so control is TRUE not false', () => {
    const origin = resolverFor([
      ['package.json', JSON.stringify({ dependencies: { react: '^18.0.0' } })],
      ['yarn.lock', [BERRY_HEADER, '"react@npm:^18.0.0":', '  version: 18.3.1', ''].join('\n')],
    ]).resolve(npmQuery('react', '18.3.1', 'yarn.lock'));

    expect(origin.relationship).toBe('direct');
    expect(origin.manifestControlsInstalledCopy).toBe(true);
  });

  it('THE TRAP, url-encoded: `npm%3A` is the same protocol and resolves the same way', () => {
    const origin = resolverFor([
      ['package.json', JSON.stringify({ dependencies: { react: '^18.0.0' } })],
      ['yarn.lock', [BERRY_HEADER, '"react@npm%3A^18.0.0":', '  version: 18.3.1', ''].join('\n')],
    ]).resolve(npmQuery('react', '18.3.1', 'yarn.lock'));

    expect(origin.manifestControlsInstalledCopy).toBe(true);
  });

  it('CONTROL IS EARNED: resolving none of a manifest\'s entries leaves the answer ABSENT, not false', () => {
    const origin = resolverFor([
      ['package.json', JSON.stringify({ dependencies: { react: '^18.0.0' } })],
      ['yarn.lock', [
        BERRY_HEADER,
        '"react@patch:react@npm%3A17.0.2#~/.yarn/patches/react.patch":',
        '  version: 17.0.2',
        '',
      ].join('\n')],
    ]).resolve(npmQuery('react', '17.0.2', 'yarn.lock'));

    expect(origin.relationship).toBe('direct');
    expect(origin.manifestControlsInstalledCopy).toBeUndefined();
  });

  it('an ALIAS entry is filed under the package it really is, not the name it is called by', () => {
    const yarn = [
      BERRY_HEADER,
      '"wrap-ansi@npm:^7.0.0":',
      '  version: 7.0.0',
      '  dependencies:',
      '    string-width-cjs: "npm:string-width@^4.2.0"',
      '',
      '"string-width-cjs@npm:string-width@^4.2.0":',
      '  version: 4.2.3',
      '',
    ].join('\n');
    const resolver = resolverFor([
      ['package.json', JSON.stringify({ dependencies: { 'wrap-ansi': '^7.0.0' } })],
      ['yarn.lock', yarn],
    ]);

    expect(resolver.resolve(npmQuery('string-width', '4.2.3', 'yarn.lock')).chain)
      .toEqual(['wrap-ansi', 'string-width']);
    expect(resolver.resolve(npmQuery('string-width-cjs', '4.2.3', 'yarn.lock')).undeterminedReason)
      .toBe('package_not_in_graph');
  });

  it('NEVER A SILENT ZERO: a yarn.lock that yields no node says the graph is MISSING, not searched', () => {
    const origin = resolverFor([
      ['package.json', JSON.stringify({ dependencies: { react: '^18.0.0' } })],
      ['yarn.lock', [BERRY_HEADER, '"react@npm:^18.0.0":', '  resolution: "react@npm:18.3.1"', ''].join('\n')],
    ]).resolve(npmQuery('lodash', '4.17.20', 'yarn.lock'));

    expect(origin.relationship).toBe('undetermined');
    expect(origin.undeterminedReason).toBe('no_dependency_graph');
  });

  it('v1 DOES NOT MOVE: a classic dependency line still maps back to its block', () => {
    const yarn = [
      '# yarn lockfile v1',
      '',
      '"@babel/core@^7.12.11":',
      '  version "7.12.11"',
      '  dependencies:',
      '    "@babel/highlight" "^7.10.4"',
      '    qs "6.7.0"',
      '',
      '"@babel/highlight@^7.10.4":',
      '  version "7.10.4"',
      '',
      'qs@6.7.0:',
      '  version "6.7.0"',
      '',
    ].join('\n');
    const resolver = resolverFor([
      ['package.json', JSON.stringify({ dependencies: { '@babel/core': '^7.12.11' } })],
      ['yarn.lock', yarn],
    ]);

    expect(resolver.resolve(npmQuery('@babel/highlight', '7.10.4', 'yarn.lock')).chain)
      .toEqual(['@babel/core', '@babel/highlight']);
    expect(resolver.resolve(npmQuery('qs', '6.7.0', 'yarn.lock')).chain)
      .toEqual(['@babel/core', 'qs']);
    expect(resolver.resolve(npmQuery('@babel/core', '7.12.11', 'yarn.lock')).manifestControlsInstalledCopy)
      .toBe(true);
  });
});
