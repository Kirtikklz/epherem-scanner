import { describe, expect, it } from 'vitest';
import type { FileMap } from '../../src/shared/types.js';
import { collectDependenciesWithDiagnostics } from '../../src/stack-detection/collectDependencies.js';

function fileMap(entries: Array<[string, string]>): FileMap {
  return {
    rootPath: '/',
    entries: entries.map(([filePath, content]) => ({ path: filePath, content, extension: '.txt', label: 'other' as const })),
    skipped: [],
    skippedCount: 0,
    warnings: [],
  } as unknown as FileMap;
}

const cycles = (diagnostics: string[]): string[] =>
  diagnostics.flatMap((d) => {
    const m = /^Requirements include cycle \(([^)]*)\)/.exec(d);
    return m === null ? [] : [m[1] as string];
  });

describe('an include cycle is said once, and every file in it is read once', () => {
  it('two files that include each other', () => {
    const { dependencies, diagnostics } = collectDependenciesWithDiagnostics(fileMap([
      ['requirements-a.txt', '-r requirements-b.txt\nflask==2.0.0\n'],
      ['requirements-b.txt', '-rrequirements-a.txt\nrequests==2.25.0\n'],
    ]));
    expect(cycles(diagnostics)).toEqual(['requirements-b.txt line 1: -r requirements-a.txt']);
    expect(dependencies.map((d) => `${d.name}@${d.installedVersion} ${d.source}`)).toEqual([
      'flask@2.0.0 requirements-a.txt',
      'requests@2.25.0 requirements-b.txt',
    ]);
  });

  it('a file that includes itself', () => {
    expect(cycles(collectDependenciesWithDiagnostics(fileMap([['requirements.txt', '-r requirements.txt\n']])).diagnostics)).toEqual([
      'requirements.txt line 1: -r requirements.txt',
    ]);
  });

  it('a loop through three files, one of them reached only by the include', () => {
    expect(cycles(collectDependenciesWithDiagnostics(fileMap([
      ['requirements.txt', '-r lib/x.in\n'],
      ['lib/x.in', '-r ../requirements-dev.txt\n'],
      ['requirements-dev.txt', '-r requirements.txt\n'],
    ])).diagnostics)).toEqual(['requirements-dev.txt line 1: -r requirements.txt']);
  });

  it('a constraints loop still applies its pins, and nothing hangs', () => {
    const { dependencies, diagnostics } = collectDependenciesWithDiagnostics(fileMap([
      ['requirements.txt', '-c constraints.txt\nflask\n'],
      ['constraints.txt', '-c constraints-more.txt\n'],
      ['constraints-more.txt', '-c constraints.txt\nflask==2.0.0\n'],
    ]));
    expect(cycles(diagnostics)).toEqual(['constraints-more.txt line 1: -c constraints.txt']);
    expect(dependencies.map((d) => `${d.name}@${d.installedVersion} ${d.source}`)).toEqual(['flask@2.0.0 constraints-more.txt']);
  });

  it('TWIN: a diamond (two paths to one file) is not a cycle', () => {
    expect(cycles(collectDependenciesWithDiagnostics(fileMap([
      ['requirements.txt', '-r requirements-a.txt\n-r requirements-b.txt\n'],
      ['requirements-a.txt', '-r requirements-c.txt\n'],
      ['requirements-b.txt', '-r requirements-c.txt\n'],
      ['requirements-c.txt', 'flask==2.0.0\n'],
    ])).diagnostics)).toEqual([]);
  });
});
