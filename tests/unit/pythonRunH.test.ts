import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { CachedOsvClient, type OsvCacheFile } from '../../src/dependency-audit/osvClient.js';
import { OsvDependencyScanner } from '../../src/dependency-audit/osvDependencyScanner.js';
import { createDependencyOriginResolver } from '../../src/dependency-audit/dependencyOrigin.js';
import { classifyArchiveFile } from '../../src/input/fileFilters.js';
import { prepareInput } from '../../src/input/prepareInput.js';
import { scanProject } from '../../src/scanProject.js';
import { DEFAULT_INPUT_LIMITS } from '../../src/shared/constants.js';
import { isPythonRequirementsPath, pythonRequirementsRole } from '../../src/shared/pythonRequirementFiles.js';
import type { FileMap } from '../../src/shared/types.js';
import {
  collectDependenciesWithDiagnostics,
  pythonDependencyLine,
  type CollectedDependency,
} from '../../src/stack-detection/collectDependencies.js';

function fileMap(entries: Array<[string, string]>, skipped: Array<[string, string]> = []): FileMap {
  return {
    rootPath: '/',
    entries: entries.map(([filePath, content]) => ({
      path: filePath,
      content,
      extension: filePath.slice(filePath.lastIndexOf('.')),
      label: 'other' as const,
    })),
    skipped: skipped.map(([filePath, reason]) => ({ path: filePath, reason })),
    skippedCount: skipped.length,
    warnings: [],
  } as unknown as FileMap;
}

const collect = (entries: Array<[string, string]>, skipped: Array<[string, string]> = []) =>
  collectDependenciesWithDiagnostics(fileMap(entries, skipped));
const row = (d: CollectedDependency): string =>
  `${d.name}@${d.installedVersion ?? '-'} ${d.source}${d.declaredIn !== undefined ? ` decl=${d.declaredIn}` : ''}`;
const rows = (entries: Array<[string, string]>, skipped: Array<[string, string]> = []): string[] =>
  collect(entries, skipped).dependencies.map(row);
const said = (entries: Array<[string, string]>, skipped: Array<[string, string]> = []): string[] =>
  collect(entries, skipped).diagnostics;

const NOW = (): Date => new Date('2025-05-10T00:00:00Z');
const FIXTURE: OsvCacheFile = {
  source: 'jobH-advisory-fixture',
  generatedAt: '2025-05-01',
  advisories: [
    {
      id: 'GHSA-test-jobh-0001',
      package: 'sample-lib',
      ecosystem: 'PyPI',
      severity: 'high',
      summary: 'sample-lib before 2.0.0 is affected',
      ranges: [{ introduced: '0', fixed: '2.0.0' }],
    },
  ],
};
const scanner = (): OsvDependencyScanner => new OsvDependencyScanner({ client: new CachedOsvClient(FIXTURE), now: NOW });

describe('which pip files are read', () => {
  it('requirements files: the word with parts around it, and any .txt in a requirements directory', () => {
    for (const p of [
      'requirements.txt',
      'requirements-dev.txt',
      'dev-requirements.txt',
      'requirements.prod.txt',
      'test_requirements.txt',
      'backend/requirements_slim.txt',
      'requirements/base.txt',
      'deploy/Requirements/Prod.txt',
    ]) {
      expect(pythonRequirementsRole(p), p).toBe('requirements');
    }
  });

  it('constraints files, also inside a requirements directory', () => {
    for (const p of ['constraints.txt', 'constraints-py311.txt', 'requirements/constraints.txt', 'pip_constraints.txt']) {
      expect(pythonRequirementsRole(p), p).toBe('constraints');
    }
  });

  it('TWINS: other text, pip-tools inputs, look-alike words and hidden files are not', () => {
    for (const p of [
      'notes.txt',
      'requirements.in',
      'requirements.md',
      'requirementsx.txt',
      'myrequirements.txt',
      'docs/requirements/index.md',
      'requirements/.cache.txt',
      'requirements/sub/base.txt',
      'requirements',
    ]) {
      expect(pythonRequirementsRole(p), p).toBeUndefined();
      expect(isPythonRequirementsPath(p), p).toBe(false);
    }
  });

  it('ZIP extraction keeps them, and still refuses them in an ignored directory or over the size cap', () => {
    const keep = (p: string, size = 10): boolean => classifyArchiveFile(p, size, DEFAULT_INPUT_LIMITS).eligible;
    expect(keep('requirements-dev.txt')).toBe(true);
    expect(keep('requirements/base.txt')).toBe(true);
    expect(keep('constraints.txt')).toBe(true);
    expect(keep('notes.txt')).toBe(false);
    expect(keep('node_modules/pkg/requirements-dev.txt')).toBe(false);
    expect(classifyArchiveFile('requirements-dev.txt', DEFAULT_INPUT_LIMITS.maxFileSizeBytes + 1, DEFAULT_INPUT_LIMITS).reason).toBe('too_large');
  });

  describe('the input walk reads them', () => {
    let root: string;
    beforeAll(async () => {
      root = await mkdtemp(path.join(tmpdir(), 'pyrunH-walk-'));
      await mkdir(path.join(root, 'requirements'));
      await writeFile(path.join(root, 'app.py'), 'print("hello")\n');
      await writeFile(path.join(root, 'requirements-dev.txt'), 'pytest==7.0.0\n');
      await writeFile(path.join(root, 'requirements', 'base.txt'), 'flask==2.0.0\n');
      await writeFile(path.join(root, 'notes.txt'), 'flask==1.0.0\n');
    });
    afterAll(async () => {
      await rm(root, { recursive: true, force: true });
    });

    it('requirements-dev.txt and requirements/base.txt are read; notes.txt is refused as before', async () => {
      const prepared = await prepareInput(root);
      expect(prepared.files.map((f) => f.path).sort()).toEqual(['app.py', 'requirements-dev.txt', 'requirements/base.txt']);
      expect(prepared.skipped.map((s) => `${s.path}:${s.reason}`)).toContain('notes.txt:not_useful');
    });
  });
});

describe('every requirements file is read, each package on its own file and line', () => {
  it('a dev file and a requirements directory are installed sources', () => {
    expect(rows([
      ['requirements-dev.txt', 'pytest==7.0.0\n'],
      ['requirements/base.txt', '# base\n\nsample-lib==1.4.2\n'],
    ])).toEqual(['pytest@7.0.0 requirements-dev.txt decl=requirements-dev.txt', 'sample-lib@1.4.2 requirements/base.txt decl=requirements/base.txt']);
  });

  it('the line locator reads every requirements and constraints file, and still not other files', () => {
    expect(pythonDependencyLine('requirements-dev.txt', 'a==1.0\n\nsample-lib==1.4.2\n', 'sample-lib', '1.4.2')).toBe(3);
    expect(pythonDependencyLine('requirements/dev.txt', '-r base.txt\nsample-lib==1.4.2\n', 'sample-lib', '1.4.2')).toBe(2);
    expect(pythonDependencyLine('constraints.txt', 'x==1.0\nsample_lib==1.4.2\n', 'sample-lib', '1.4.2')).toBe(2);
    expect(pythonDependencyLine('setup.cfg', 'sample-lib==1.4.2\n', 'sample-lib', '1.4.2')).toBeUndefined();
  });

  it('a constraints file alone installs and declares nothing', () => {
    expect(rows([['constraints.txt', 'sample-lib==1.4.2\n']])).toEqual([]);
  });
});

describe('one package pinned in two files', () => {
  const findings = async (entries: Array<[string, string]>) => {
    const { dependencies, diagnostics } = collect(entries);
    const audit = await scanner().scanDependencies(dependencies, { parseDiagnostics: diagnostics });
    const { dependencyVulnerabilitiesToFindings } = await import('../../src/dependency-audit/dependencyFindings.js');
    const content = new Map(entries);
    return dependencyVulnerabilitiesToFindings(audit, undefined, (p, n, v) =>
      content.has(p) ? pythonDependencyLine(p, content.get(p) as string, n, v) : undefined,
    ).map((f) => `${f.filePath}:${f.lineStart}`);
  };

  it('one finding, and it stays on requirements.txt where it was before the other file was read', async () => {
    expect(await findings([
      ['requirements-a.txt', 'x==1.0\nsample-lib==1.4.2\n'],
      ['requirements.txt', 'sample-lib==1.4.2\n'],
    ])).toEqual(['requirements.txt:1']);
  });

  it('only in the dev file: the finding is on the dev file and its line', async () => {
    expect(await findings([['requirements-dev.txt', 'x==1.0\nsample-lib==1.4.2\n']])).toEqual(['requirements-dev.txt:2']);
  });
});

describe('who asked for it', () => {
  it('a package named only in a dev file is direct, declared there; a constraints file declares nothing', () => {
    const resolver = createDependencyOriginResolver(fileMap([
      ['requirements-dev.txt', 'sample-lib==1.4.2\n'],
      ['constraints.txt', 'other-lib==1.0.0\n'],
    ]));
    expect(resolver.resolve({ ecosystem: 'PyPI', packageName: 'sample-lib', installedVersion: '1.4.2' })).toEqual({
      relationship: 'direct',
      declaredIn: 'requirements-dev.txt',
    });
    expect(resolver.resolve({ ecosystem: 'PyPI', packageName: 'other-lib', installedVersion: '1.0.0' }).relationship).toBe('undetermined');
  });
});

describe('an editable, URL or VCS line is said, never dropped', () => {
  const text = [
    '-e .',
    '--editable=./lib',
    'git+https://example.invalid/a.git#egg=a',
    'hg+https://example.invalid/b',
    'https://example.invalid/c.whl',
    'file:./wheels/d.whl',
    'sample-lib==1.4.2 \\',
    '    --hash=sha256:00',
    '--index-url https://example.invalid/simple',
    '--extra-index-url https://example.invalid/more',
    '',
  ].join('\n');

  it('each is said with its file and line', () => {
    const lines = said([['requirements.txt', text]]).map((d) => /\(requirements\.txt line (\d+)\): "[^"]*" installs from ([^,]+),/.exec(d)?.slice(1).join(' '));
    expect(lines).toEqual([
      '1 an editable install (-e)',
      '2 an editable install (-e)',
      '3 a version-control (VCS) reference',
      '4 a version-control (VCS) reference',
      '5 a URL',
      '6 a URL',
    ]);
  });

  it('TWINS: the pin is still read, a VCS scheme is not taken for a package, and --hash or an index says nothing', () => {
    expect(rows([['requirements.txt', text]])).toEqual(['sample-lib@1.4.2 requirements.txt decl=requirements.txt']);
  });

  it('the same is said for a dev file', () => {
    expect(said([['requirements-dev.txt', '-e .\n']])).toHaveLength(1);
  });
});

const notRead = (diagnostics: string[]): string[] =>
  diagnostics.map((d) => /^Requirements include not read \((.*)\): (.*), so any dependencies/.exec(d)?.slice(1).join(' | ') ?? `OTHER ${d}`);

describe('-r and -c are followed relative to the file that holds them', () => {
  it('every spelling pip takes, with a comment after it', () => {
    const text = '-r a.txt\n-rb.txt\n--requirement c.txt\n--requirement=d.txt  # note\n-c e.txt\n--constraint=f.txt\n';
    expect(notRead(said([['requirements.txt', text]])).map((d) => d.split(' | ')[0])).toEqual([
      'requirements.txt line 1: -r a.txt',
      'requirements.txt line 2: -r b.txt',
      'requirements.txt line 3: -r c.txt',
      'requirements.txt line 4: -r d.txt',
      'requirements.txt line 5: -c e.txt',
      'requirements.txt line 6: -c f.txt',
    ]);
  });

  it('a target beside the including file, above it, and below it is found: nothing is said', () => {
    expect(said([
      ['app/requirements.txt', '-r requirements-dev.txt\n-r ../shared/requirements-base.txt\n-r sub/requirements-x.txt\n-r ./x/../requirements-y.txt\n'],
      ['app/requirements-dev.txt', ''],
      ['shared/requirements-base.txt', ''],
      ['app/sub/requirements-x.txt', ''],
      ['app/requirements-y.txt', ''],
    ])).toEqual([]);
  });

  it('a file reached only by an include, under another name, is read: as requirements for -r, constraints for -c', () => {
    const { dependencies } = collect([
      ['requirements.txt', '-r base.in\n-c pins.in\nflask\n'],
      ['base.in', 'sample-lib==1.4.2\n'],
      ['pins.in', 'flask==2.0.0\nother==1.0.0\n'],
    ]);
    expect(dependencies.map(row)).toEqual([
      'flask@2.0.0 pins.in decl=requirements.txt',
      'sample-lib@1.4.2 base.in decl=base.in',
    ]);
  });

  it('a file reached by two includes (a diamond) is read once', () => {
    const { dependencies, diagnostics } = collect([
      ['requirements.txt', '-r lib/a.in\n-r lib/b.in\n'],
      ['lib/a.in', '-r c.in\n'],
      ['lib/b.in', '-r c.in\n'],
      ['lib/c.in', '-e .\nsample-lib==1.4.2\n'],
    ]);
    expect(dependencies.map(row)).toEqual(['sample-lib@1.4.2 lib/c.in decl=lib/c.in']);
    expect(diagnostics).toHaveLength(1);
  });
});

describe('an include that cannot be read is said', () => {
  it('a missing file, and one the input walk skipped, with its reason', () => {
    expect(notRead(said([['requirements.txt', '-r requirements-base.txt\n-r base.in\n']], [['base.in', 'not_useful']]))).toEqual([
      'requirements.txt line 1: -r requirements-base.txt | the file is not among the files this scan read',
      'requirements.txt line 2: -r base.in | the input walk skipped the file (not_useful)',
    ]);
  });

  it('a path that leaves the project: climbing above the root, absolute, a drive, a home path', () => {
    const text = '-r ../shared.txt\n-r /etc/reqs.txt\n-r C:\\reqs.txt\n-r ~/reqs.txt\n-r \\\\host\\reqs.txt\n';
    expect(notRead(said([['requirements.txt', text]])).map((d) => d.split(' | ')[1])).toEqual(Array(5).fill('the path leads outside the project'));
  });

  it('from a subdirectory, climbing to the root is inside and one more is outside', () => {
    expect(notRead(said([
      ['app/requirements.txt', '-r ../requirements-root.txt\n-r ../../requirements-root.txt\n'],
      ['requirements-root.txt', ''],
    ]))).toEqual(['app/requirements.txt line 2: -r ../../requirements-root.txt | the path leads outside the project']);
  });

  it('a URL', () => {
    expect(notRead(said([['requirements.txt', '-r https://example.invalid/r.txt\n-c file:///tmp/c.txt\n']])).map((d) => d.split(' | ')[1])).toEqual(['it is a URL', 'it is a URL']);
  });

  it('an outside path is never looked up, even when a file of that name was read', () => {
    expect(notRead(said([['app/requirements.txt', '-r /requirements-x.txt\n'], ['requirements-x.txt', '']]))).toHaveLength(1);
  });
});

const unusedPins = (diagnostics: string[]): string[] =>
  diagnostics.flatMap((d) => {
    const m = /^Constraint pins not applied \((.*)\): (\d+) exact pin\(s\)/.exec(d);
    return m === null ? [] : [`${m[1]}:${m[2]}`];
  });

describe('a constraints pin is an installed version only for a package a requirements file asks for', () => {
  it('applied to an unpinned and a ranged name: the row names the constraints file, the line is the pin\'s', () => {
    const files: Array<[string, string]> = [
      ['requirements.txt', '-c constraints.txt\nsample-lib\nother>=1\n'],
      ['constraints.txt', '# pins\nother==1.5.0\nsample-lib==1.4.2\n'],
    ];
    expect(rows(files)).toEqual(['other@1.5.0 constraints.txt decl=requirements.txt', 'sample-lib@1.4.2 constraints.txt decl=requirements.txt']);
    expect(pythonDependencyLine('constraints.txt', files[1]?.[1] as string, 'sample-lib', '1.4.2')).toBe(3);
    expect(unusedPins(said(files))).toEqual([]);
  });

  it('names compare the PEP 503 way, and the row keeps the requirement\'s spelling', () => {
    expect(rows([['requirements.txt', '-c constraints.txt\nSample_Lib\n'], ['constraints.txt', 'Sample.LIB==1.4.2\n']])).toEqual([
      'Sample_Lib@1.4.2 constraints.txt decl=requirements.txt',
    ]);
  });

  it('TWIN: a requirement with its own exact pin keeps it; the constraint adds no row and is not unused', () => {
    const files: Array<[string, string]> = [['requirements.txt', '-c constraints.txt\nsample-lib==1.4.2\n'], ['constraints.txt', 'sample-lib==1.4.2\n']];
    expect(rows(files)).toEqual(['sample-lib@1.4.2 requirements.txt decl=requirements.txt']);
    expect(unusedPins(said(files))).toEqual([]);
  });

  it('TWIN: a ranged constraint gives no installed version', () => {
    expect(rows([['requirements.txt', '-c constraints.txt\nsample-lib\n'], ['constraints.txt', 'sample-lib<2\n']])).toEqual([
      'sample-lib@- requirements.txt decl=requirements.txt',
    ]);
  });

  it('a pin nothing asks for is counted and said; so is a constraints file no requirements file names', () => {
    expect(unusedPins(said([
      ['requirements.txt', '-c constraints.txt\nflask\n'],
      ['constraints.txt', 'flask==2.0.0\nurllib3==1.26.0\nidna==3.0\n'],
      ['ci/constraints.txt', 'six==1.0.0\n'],
    ]))).toEqual(['constraints.txt:2', 'ci/constraints.txt:1']);
  });

  it('it applies through -r: the dev file includes the file that names the constraints', () => {
    expect(rows([
      ['requirements-dev.txt', '-r requirements.txt\npytest\n'],
      ['requirements.txt', '-c constraints.txt\nflask\n'],
      ['constraints.txt', 'flask==2.0.0\npytest==7.0.0\n'],
    ])).toEqual(['flask@2.0.0 constraints.txt decl=requirements.txt', 'pytest@7.0.0 constraints.txt decl=requirements-dev.txt']);
  });

  it('and through a constraints file\'s own include', () => {
    expect(rows([
      ['requirements.txt', '-c constraints.txt\nflask\n'],
      ['constraints.txt', '-c constraints-more.txt\n'],
      ['constraints-more.txt', 'flask==2.0.0\n'],
    ])).toEqual(['flask@2.0.0 constraints-more.txt decl=requirements.txt']);
  });

  it('TWIN: not to another file that does not name it, and not to a name only a constraints file holds', () => {
    const files: Array<[string, string]> = [
      ['requirements.txt', '-c constraints.txt\nflask\n'],
      ['requirements-dev.txt', 'pytest\n'],
      ['constraints.txt', 'flask==2.0.0\npytest==7.0.0\n'],
    ];
    expect(rows(files)).toEqual(['flask@2.0.0 constraints.txt decl=requirements.txt', 'pytest@- requirements-dev.txt decl=requirements-dev.txt']);
    expect(unusedPins(said(files))).toEqual(['constraints.txt:1']);
  });

  it('TWIN: a constraints file pulled in with -r asks for nothing, so its pins stay unapplied and said', () => {
    expect(unusedPins(said([
      ['requirements.txt', '-r constraints.txt\n-c constraints.txt\nflask\n'],
      ['constraints.txt', 'urllib3==1.26.0\n'],
    ]))).toEqual(['constraints.txt:1']);
  });
});

describe('end to end: scanProject reads a dev file and a constraints file', () => {
  let root: string;
  beforeAll(async () => {
    root = await mkdtemp(path.join(tmpdir(), 'pyrunH-scan-'));
    await writeFile(path.join(root, 'app.py'), 'print("hello")\n');
    await writeFile(path.join(root, 'requirements-dev.txt'), '-c constraints.txt\npytest\nsample-lib\n');
    await writeFile(path.join(root, 'constraints.txt'), 'pytest==7.0.0\n\nsample-lib==1.4.2\n');
  });
  afterAll(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it('the finding is on the constraint\'s line', async () => {
    const report = await scanProject(root, { dependencyScanner: scanner() });
    const found = report.findings.filter((f) => f.ruleId === 'dependency_vulnerability').map((f) => `${f.dependency?.package}|${f.filePath}|${f.lineStart}`);
    expect(found).toEqual(['sample-lib|constraints.txt|3']);
  });
});
