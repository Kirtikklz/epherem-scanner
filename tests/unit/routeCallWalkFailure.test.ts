import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildRouteSecurityProfiles, routeCallWalkFailures } from '../../src/project-map/buildRouteSecurity.js';
import { scanProject } from '../../src/scanProject.js';
import { routeProtectionGapWarnings } from '../../src/shared/analysisGapWarnings.js';
import type { DependencyVulnerabilityScanner } from '../../src/dependency-audit/dependencyAudit.js';
import type { FileMap, FileMapEntry, ProjectMap } from '../../src/shared/types.js';

vi.mock('typescript', async (importOriginal) => {
  const imported = (await importOriginal()) as { default?: typeof import('typescript') } & typeof import('typescript');
  const actual = imported.default ?? imported;
  return {
    default: {
      ...actual,
      isFunctionLike: (node: import('typescript').Node | undefined): boolean => {
        if (
          node !== undefined &&
          actual.isCallExpression(node) &&
          actual.isIdentifier(node.expression) &&
          node.expression.text === 'explodeCallWalk' &&
          (new Error().stack ?? '').includes('buildRouteSecurity')
        ) {
          throw new RangeError('Maximum call stack size exceeded');
        }
        return actual.isFunctionLike(node);
      },
    },
  };
});

const temporaries: string[] = [];

afterEach(async () => {
  await Promise.all(temporaries.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

function entry(filePath: string, content: string): FileMapEntry {
  return {
    path: filePath,
    extension: filePath.slice(filePath.lastIndexOf('.')),
    label: 'unknown_useful',
    size: content.length,
    isLikelyConfig: false,
    isLikelyApiRoute: false,
    isLikelyAuthRelated: false,
    isLikelyDatabaseRelated: false,
    isLikelyMiddleware: false,
    usesEnvVariables: false,
    technologyHints: [],
    content,
  };
}

const emptyProject = (): ProjectMap => ({ apiRoutes: [], imports: [] }) as unknown as ProjectMap;

function fileMap(entries: FileMapEntry[]): FileMap {
  return { rootPath: '/project', entries, skipped: [], skippedCount: 0, warnings: [] };
}

describe('a function whose calls could not be followed', () => {
  it('is recorded once per function, with its file and line, and nothing else is', () => {
    const map = emptyProject();
    buildRouteSecurityProfiles(
      fileMap([
        entry('src/a.ts', 'export function fine() { helper(); }\nexport function broken() {\n  explodeCallWalk();\n}\n'),
        entry('src/b.ts', 'function helper() {}\n'),
      ]),
      map,
    );
    expect(routeCallWalkFailures(map)).toEqual([{ filePath: 'src/a.ts', line: 2 }]);
  });

  it('A PROJECT WITH NO FAILURE HAS NO RECORD, and a rebuild starts from none', () => {
    const map = emptyProject();
    buildRouteSecurityProfiles(fileMap([entry('src/a.ts', 'function broken() { explodeCallWalk(); }\n')]), map);
    expect(routeCallWalkFailures(map)).toHaveLength(1);
    buildRouteSecurityProfiles(fileMap([entry('src/a.ts', 'function fine() {}\n')]), map);
    expect(routeCallWalkFailures(map)).toEqual([]);
    expect(routeCallWalkFailures(emptyProject())).toEqual([]);
  });

  it('the warning names five, counts the rest exactly, and leaves test fixtures out', () => {
    const map = emptyProject();
    const broken = Array.from({ length: 7 }, (_, i) => entry(`src/f${i}.ts`, `function broken${i}() { explodeCallWalk(); }\n`));
    buildRouteSecurityProfiles(fileMap([...broken, entry('tests/fixture.test.ts', 'function t() { explodeCallWalk(); }\n')]), map);
    expect(routeCallWalkFailures(map)).toHaveLength(8);
    expect(routeProtectionGapWarnings([], routeCallWalkFailures(map), (filePath) => !filePath.startsWith('tests/'))).toEqual([
      'Route protection analysis could not follow the calls made inside 7 functions, so on a route that reaches one of ' +
        'them, a login, permission or other check made in a function they call was not seen and may be reported as ' +
        'missing: "src/f0.ts:1", "src/f1.ts:1", "src/f2.ts:1", "src/f3.ts:1", "src/f4.ts:1"… and 2 more.',
    ]);
  });

  it('one function: the singular', () => {
    expect(routeProtectionGapWarnings([], [{ filePath: 'src/a.ts', line: 4 }], () => true)).toEqual([
      'Route protection analysis could not follow the calls made inside 1 function, so on a route that reaches it, a ' +
        'login, permission or other check made in a function it calls was not seen and may be reported as missing: ' +
        '"src/a.ts:4".',
    ]);
  });

  it('THE REPORT: the sentence reaches the warnings and moves no status', async () => {
    const completeAudit: DependencyVulnerabilityScanner = {
      scanDependencies: async (dependencies) => ({
        performed: true, incomplete: false, source: 'osv.dev', dependenciesCollected: dependencies.length,
        checked: dependencies.length, notChecked: [], vulnerabilities: [], diagnostics: [], note: 'complete',
      }),
    };
    const dir = await mkdtemp(path.join(tmpdir(), 'epherem-call-walk-'));
    temporaries.push(dir);
    await mkdir(path.join(dir, 'src'), { recursive: true });
    await writeFile(path.join(dir, 'src', 'lib.ts'), 'export function broken() {\n  explodeCallWalk();\n}\n');
    const report = await scanProject(dir, { dependencyScanner: completeAudit });
    expect(report.warnings).toEqual([
      'Route protection analysis could not follow the calls made inside 1 function, so on a route that reaches it, a ' +
        'login, permission or other check made in a function it calls was not seen and may be reported as missing: ' +
        '"src/lib.ts:1".',
    ]);
    expect(report.codeScanStatus).toBe('complete');
    expect(report.scanStatus).toBe('complete');
  }, 60_000);
});
