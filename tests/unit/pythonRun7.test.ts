import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { CachedOsvClient, type OsvCacheFile } from '../../src/dependency-audit/osvClient.js';
import { OsvDependencyScanner } from '../../src/dependency-audit/osvDependencyScanner.js';
import { dependencyVulnerabilitiesToFindings } from '../../src/dependency-audit/dependencyFindings.js';
import { scanProject } from '../../src/scanProject.js';
import type { DependencyAuditSummary, FileMap } from '../../src/shared/types.js';
import {
  collectDependenciesWithDiagnostics,
  normalizePypiName,
  pythonDependencyLine,
  UNPARSED_DEPENDENCY_FILES,
  type CollectedDependency,
} from '../../src/stack-detection/collectDependencies.js';

function fileMap(entries: Array<[string, string]>): FileMap {
  return {
    rootPath: '/',
    entries: entries.map(([filePath, content]) => ({
      path: filePath,
      content,
      extension: filePath.slice(filePath.lastIndexOf('.')),
      label: 'other' as const,
    })),
    skipped: [],
    skippedCount: 0,
    warnings: [],
  } as unknown as FileMap;
}

const collect = (fm: FileMap): ReturnType<typeof collectDependenciesWithDiagnostics> =>
  collectDependenciesWithDiagnostics(fm);
const byName = (deps: CollectedDependency[], name: string): CollectedDependency[] =>
  deps.filter((dep) => dep.name === name);

const NOW = (): Date => new Date('2025-05-10T00:00:00Z');
const FIXTURE: OsvCacheFile = {
  source: 'job7-advisory-fixture',
  generatedAt: '2025-05-01',
  advisories: [
    {
      id: 'GHSA-test-job7-0001',
      package: 'sample-lib',
      ecosystem: 'PyPI',
      severity: 'high',
      summary: 'sample-lib before 2.0.0 is affected',
      ranges: [{ introduced: '0', fixed: '2.0.0' }],
    },
    {
      id: 'GHSA-test-job7-0002',
      package: 'left-pad-js',
      ecosystem: 'npm',
      severity: 'medium',
      summary: 'left-pad-js before 1.3.0 is affected',
      ranges: [{ introduced: '0', fixed: '1.3.0' }],
    },
  ],
};
const scanner = (): OsvDependencyScanner => new OsvDependencyScanner({ client: new CachedOsvClient(FIXTURE), now: NOW });
const audit = (fm: FileMap): Promise<DependencyAuditSummary> => {
  const { dependencies, diagnostics } = collect(fm);
  return scanner().scanDependencies(dependencies, { parseDiagnostics: diagnostics });
};
const poetryBlock = (name: string, version: string): string => `[[package]]\nname = "${name}"\nversion = "${version}"\n\n`;
const npmLock = JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/left-pad-js': { version: '1.2.0' } } });

describe('a Python version is compared to the advisory by PEP 440', () => {
  const versions = ['2.0.0rc1', '1.9.post2', '2.0.0.post1', '1!1.0.0', '1.5.0+cpu', '2.0.0+cpu', '2.0.0'];
  const lock = versions.map((version) => poetryBlock('sample-lib', version)).join('');

  it('pre-release and post-release below the fix are affected; at or above it, or a later epoch, are not', async () => {
    const result = await audit(fileMap([['poetry.lock', lock]]));
    expect(result.vulnerabilities.map((v) => v.version).sort()).toEqual(['1.5.0+cpu', '1.9.post2', '2.0.0rc1']);
  });

  it('every one of those versions is installed and looked up: none was dropped as "not exact"', () => {
    const installed = collect(fileMap([['poetry.lock', lock]])).dependencies.map((d) => d.installedVersion).sort();
    expect(installed).toEqual([...versions].sort());
  });

  it('an epoch pin in requirements.txt is exact too; STRICT TWIN: != is still a range', () => {
    const { dependencies } = collect(fileMap([['requirements.txt', 'sample-lib==1!1.0.0\nother-lib!=1.0\n']]));
    expect(byName(dependencies, 'sample-lib')[0]?.installedVersion).toBe('1!1.0.0');
    expect(byName(dependencies, 'other-lib')[0]?.installedVersion).toBeUndefined();
    expect(byName(dependencies, 'other-lib')[0]?.declaredRange).toBe('!=1.0');
  });
});

describe('names are compared the PEP 503 way', () => {
  it('lower case, and every run of -, _ and . made one -', () => {
    expect(normalizePypiName('Zope.Interface__Extra')).toBe('zope-interface-extra');
    expect(normalizePypiName('a-_.b')).toBe('a-b');
  });

  it('the line locator finds a requirement spelled another way', () => {
    expect(pythonDependencyLine('requirements.txt', 'other==1.0\nSample_Lib==1.4.2\n', 'sample-lib', '1.4.2')).toBe(2);
  });
});

describe('a Python dependency finding points at the line naming its package', () => {
  it('requirements.txt: the requirement line', () => {
    expect(pythonDependencyLine('api/requirements.txt', '# pins\n\nsample-lib==1.4.2\nother==1.0\n', 'sample-lib', '1.4.2')).toBe(3);
  });

  it('pyproject.toml: the line of the exact pin, in [project] and in poetry\'s table', () => {
    const pep621 = '[project]\nname = "svc"\ndependencies = [\n  "other>=1",\n  "sample-lib==1.4.2",\n]\n';
    expect(pythonDependencyLine('pyproject.toml', pep621, 'sample-lib', '1.4.2')).toBe(5);
    const poetry = '[tool.poetry]\nname = "svc"\n\n[tool.poetry.dependencies]\npython = "^3.11"\nsample-lib = "1.4.2"\n';
    expect(pythonDependencyLine('pyproject.toml', poetry, 'sample-lib', '1.4.2')).toBe(6);
  });

  it('poetry.lock: the block\'s name = line', () => {
    const lock = poetryBlock('other', '1.0') + poetryBlock('sample-lib', '1.4.2');
    expect(pythonDependencyLine('poetry.lock', lock, 'sample-lib', '1.4.2')).toBe(6);
  });

  it('NOT FOUND keeps line 1: another version, two lines, a file the locator does not read', () => {
    expect(pythonDependencyLine('requirements.txt', 'sample-lib==1.4.2\n', 'sample-lib', '1.4.3')).toBeUndefined();
    const twice = 'sample-lib==1.4.2 ; os_name == "nt"\nsample-lib==1.4.2 ; os_name != "nt"\n';
    expect(pythonDependencyLine('requirements.txt', twice, 'sample-lib', '1.4.2')).toBeUndefined();
    expect(pythonDependencyLine('setup.cfg', 'sample-lib==1.4.2\n', 'sample-lib', '1.4.2')).toBeUndefined();
    expect(pythonDependencyLine('uv.lock', poetryBlock('sample-lib', '1.4.2'), 'sample-lib', '1.4.2')).toBeUndefined();
  });

  it('the finding takes the locator\'s line for PyPI, and line 1 when it has none', async () => {
    const result = await audit(fileMap([['requirements.txt', 'flask==3.0.0\nsample-lib==1.4.2\n']]));
    expect(dependencyVulnerabilitiesToFindings(result, undefined, () => 2).map((f) => f.lineStart)).toEqual([2]);
    expect(dependencyVulnerabilitiesToFindings(result, undefined, () => undefined).map((f) => f.lineStart)).toEqual([1]);
    expect(dependencyVulnerabilitiesToFindings(result).map((f) => f.lineStart)).toEqual([1]);
  });

  it('AN npm FINDING KEEPS LINE 1: the locator is never asked about it', async () => {
    const result = await audit(fileMap([['package-lock.json', npmLock]]));
    const asked: string[] = [];
    const findings = dependencyVulnerabilitiesToFindings(result, undefined, (p) => {
      asked.push(p);
      return 7;
    });
    expect(findings.map((f) => `${f.dependency?.package}:${f.lineStart}`)).toEqual(['left-pad-js:1']);
    expect(asked).toEqual([]);
  });
});

describe('end to end: scanProject places PyPI rows and leaves npm rows at line 1', () => {
  let root: string;
  beforeAll(async () => {
    root = await mkdtemp(path.join(tmpdir(), 'pyrun7-scan-'));
    await writeFile(path.join(root, 'app.py'), 'print("hello")\n');
    await writeFile(path.join(root, 'requirements.txt'), 'other==1.0.0\n\nsample-lib==1.4.2\n');
    await writeFile(path.join(root, 'package-lock.json'), npmLock);
  });
  afterAll(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it('the requirements.txt row is on its requirement line; the package-lock row is on line 1', async () => {
    const report = await scanProject(root, { dependencyScanner: scanner() });
    const rows = report.findings
      .filter((f) => f.ruleId === 'dependency_vulnerability')
      .map((f) => `${f.dependency?.package}|${f.filePath}|${f.lineStart}`)
      .sort();
    expect(rows).toEqual(['left-pad-js|package-lock.json|1', 'sample-lib|requirements.txt|3']);
  });
});

describe('held: uv.lock and Pipfile.lock are still declared unread', () => {
  it('both stay in UNPARSED_DEPENDENCY_FILES until the browser preflight list moves with them', () => {
    expect(UNPARSED_DEPENDENCY_FILES['uv.lock']).toBe('PyPI');
    expect(UNPARSED_DEPENDENCY_FILES['pipfile.lock']).toBe('PyPI');
  });
});
