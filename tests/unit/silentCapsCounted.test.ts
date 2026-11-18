import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { analyzeFileAst, degradedAstFiles, degradedAstFilesUnnamed, runWithAstCache } from '../../src/ast/astAnalysis.js';
import { buildFileMap } from '../../src/file-map/buildFileMap.js';
import { prepareInput } from '../../src/input/prepareInput.js';
import { buildProjectMap } from '../../src/project-map/buildProjectMap.js';
import { ROUTE_CALL_GRAPH_LIMITS, routeCallWalkFailures } from '../../src/project-map/buildRouteSecurity.js';
import { scanProject } from '../../src/scanProject.js';
import { routeProtectionGapWarnings } from '../../src/shared/analysisGapWarnings.js';
import { detectStack } from '../../src/stack-detection/detectStack.js';
import type { DependencyVulnerabilityScanner } from '../../src/dependency-audit/dependencyAudit.js';
import type { ProjectMap, RouteControlAssessment, RouteSecurityProfile } from '../../src/shared/types.js';

const temporaries: string[] = [];

afterEach(async () => {
  await Promise.all(temporaries.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function project(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), 'epherem-silent-caps-'));
  temporaries.push(dir);
  for (const [name, body] of Object.entries(files)) {
    const target = path.join(dir, name);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, body);
  }
  return dir;
}

const completeAudit: DependencyVulnerabilityScanner = {
  scanDependencies: async (dependencies) => ({
    performed: true, incomplete: false, source: 'osv.dev', dependenciesCollected: dependencies.length,
    checked: dependencies.length, notChecked: [], vulnerabilities: [], diagnostics: [], note: 'complete',
  }),
};

const numbered = (count: number, make: (index: number) => [string, string]): Record<string, string> =>
  Object.fromEntries(Array.from({ length: count }, (_, index) => make(index)));

describe('(b) files too deeply nested to parse: five named, and exactly how many more', () => {
  const DEPTH = 3;
  const deep = (count: number): Record<string, string> =>
    numbered(count, (index) => [`src/deep-${String(index).padStart(2, '0')}.ts`, 'export const x = [[[[[1]]]]];\n']);
  const warningsFor = async (count: number): Promise<string[]> =>
    (await prepareInput(await project({ 'src/ok.ts': 'export const ok = 1;\n', ...deep(count) }), {
      limits: { maxSourceNestingDepth: DEPTH },
    })).warnings;
  const named = (warnings: string[]): string[] => warnings.filter((w) => /^"src\/deep-/.test(w));
  const more = (warnings: string[]): string[] => warnings.filter((w) => /^…and \d+ more/.test(w));

  it('eight such files: five named, then "…and 3 more", and all eight are counted as refused', async () => {
    const dir = await project({ 'src/ok.ts': 'export const ok = 1;\n', ...deep(8) });
    const prepared = await prepareInput(dir, { limits: { maxSourceNestingDepth: DEPTH } });
    expect(named(prepared.warnings)).toHaveLength(5);
    expect(more(prepared.warnings)).toEqual([
      `…and 3 more files nest brackets more than ${DEPTH} levels deep, so they were not analysed either.`,
    ]);
    expect(prepared.skipped.filter((skip) => skip.reason === 'nesting_too_deep')).toHaveLength(8);
  });

  it('six: the singular', async () => {
    expect(more(await warningsFor(6))).toEqual([
      `…and 1 more file nests brackets more than ${DEPTH} levels deep, so it was not analysed either.`,
    ]);
  });

  it('five: no further line at all', async () => {
    const warnings = await warningsFor(5);
    expect(named(warnings)).toHaveLength(5);
    expect(more(warnings)).toEqual([]);
    expect(warnings.join(' ')).not.toMatch(/Further files/);
  });

  it('NO NEW STATUS: the five named warnings already make the code scan incomplete', async () => {
    const report = await scanProject(await project({ 'src/ok.ts': 'export const ok = 1;\n', ...deep(5) }), {
      inputLimits: { maxSourceNestingDepth: DEPTH },
      dependencyScanner: completeAudit,
    });
    expect(report.codeScanStatus).toBe('incomplete');
  }, 60_000);

  it('the line avoids "skipped", so the report page does not drop it as its own skip line', async () => {
    for (const line of more(await warningsFor(8))) expect(line).not.toMatch(/skipped .*file/i);
  });
});

const CHAIN = `const b = ${'1+'.repeat(50_000)}1;\n`;

describe('(a) files the syntax-aware analysis could not walk: five named, and exactly how many more', () => {
  it('seven such files: five named, two counted', () => {
    const [named, unnamed] = runWithAstCache(() => {
      for (let index = 0; index < 7; index += 1) analyzeFileAst(`src/chain-${index}.js`, CHAIN, '.js');
      return [degradedAstFiles(), degradedAstFilesUnnamed()] as const;
    });
    expect(named).toEqual(['src/chain-0.js', 'src/chain-1.js', 'src/chain-2.js', 'src/chain-3.js', 'src/chain-4.js']);
    expect(unnamed).toBe(2);
  }, 120_000);

  it('a file asked about twice is one file', () => {
    const unnamed = runWithAstCache(() => {
      for (let index = 0; index < 6; index += 1) analyzeFileAst(`src/chain-${index}.js`, CHAIN, '.js');
      analyzeFileAst('src/chain-5.js', CHAIN, '.js');
      return degradedAstFilesUnnamed();
    });
    expect(unnamed).toBe(1);
  }, 120_000);

  it('the report: five named sentences, then the count, in the main warning list', async () => {
    const dir = await project({
      'package.json': '{"name":"chains","version":"1.0.0"}\n',
      ...numbered(6, (index) => [`src/chain-${index}.js`, CHAIN]),
    });
    const report = await scanProject(dir, { dependencyScanner: completeAudit });
    const inFull = report.warnings.filter((w) => /could not be analysed in full/.test(w));
    expect(inFull.filter((w) => /^"src\/chain-/.test(w))).toHaveLength(5);
    expect(inFull.filter((w) => /^…and/.test(w))).toEqual([
      '…and 1 more file could not be analysed in full; findings in that file rest on pattern matching alone.',
    ]);
    expect(report.codeScanStatus).toBe('incomplete');
  }, 180_000);
});

const [FUNCTIONS, CALL_EDGES, ROUTE_FUNCTIONS, CALL_DEPTH] = ROUTE_CALL_GRAPH_LIMITS;

describe('(c) the four call-graph limits', () => {
  it('CHANGE NO PROFILE: the reason strings are byte-identical to what the profiles carried before', () => {
    expect(ROUTE_CALL_GRAPH_LIMITS.map((limit) => limit.reason)).toEqual([
      'Route call-graph function limit (5000) exceeded.',
      'Route call-edge limit (25000) exceeded.',
      'Route call-graph function limit (500) exceeded.',
      'Route call depth limit (8) exceeded.',
    ]);
  });

  function profile(overrides: Partial<RouteSecurityProfile>): RouteSecurityProfile {
    const unknown = (): RouteControlAssessment => ({ status: 'unknown', evidence: [], reason: '' });
    return {
      id: 'route_x', filePath: 'src/server.ts', framework: 'express', routePath: '/x', method: 'GET', line: 1,
      analysisStatus: 'partial', analysisReasons: [], reachableFiles: [],
      authentication: unknown(), authorization: unknown(), inputValidation: unknown(), rateLimit: unknown(), csrfProtection: unknown(),
      databaseOperations: [], sensitiveEnvVars: [], securitySinks: [],
      ...overrides,
    };
  }

  it('one warning: every route named up to five, the rest counted, the limits in words, test fixtures left out', () => {
    const profiles = [
      ...Array.from({ length: 7 }, (_, index) =>
        profile({ routePath: `/deep/${index}`, line: index + 1, analysisReasons: [CALL_DEPTH.reason] })),
      profile({ routePath: '/wide', method: 'POST', line: 20, analysisReasons: [ROUTE_FUNCTIONS.reason] }),
      profile({ routePath: '/crossfile', analysisReasons: ['Cross-file AST node limit (2000000) exceeded.'] }),
      profile({ routePath: '/fine', analysisStatus: 'complete' }),
      profile({ filePath: 'tests/fixtures/server.ts', analysisReasons: [CALL_DEPTH.reason] }),
    ];
    const isScannable = (filePath: string): boolean => !filePath.startsWith('tests/');
    expect(routeProtectionGapWarnings(profiles, [], isScannable)).toEqual([
      "Route protection analysis stopped early on 8 routes because a route reaches more than 500 functions and a route's " +
        'calls go more than 8 levels deep, so on those routes a login, permission, input-validation, rate-limit or CSRF ' +
        'check that was not found in the code followed was marked unknown rather than missing, and this scan does not ' +
        'say whether they are protected: GET /deep/0 at "src/server.ts:1", GET /deep/1 at "src/server.ts:2", ' +
        'GET /deep/2 at "src/server.ts:3", GET /deep/3 at "src/server.ts:4", GET /deep/4 at "src/server.ts:5"… and 3 more.',
    ]);
  });

  it('one route: the singular, and no remainder', () => {
    expect(routeProtectionGapWarnings([profile({ analysisReasons: [FUNCTIONS.reason] })], [], () => true)).toEqual([
      'Route protection analysis stopped early on 1 route because the project has more than 5,000 functions, so on ' +
        'that route a login, permission, input-validation, rate-limit or CSRF check that was not found in the code ' +
        'followed was marked unknown rather than missing, and this scan does not say whether the route is protected: ' +
        'GET /x at "src/server.ts:1".',
    ]);
  });

  it('nothing stopped: no warning', () => {
    expect(routeProtectionGapWarnings([profile({ analysisStatus: 'complete' })], [], () => true)).toEqual([]);
  });

  async function projectMapOf(files: Record<string, string>): Promise<ProjectMap> {
    const fileMap = buildFileMap(await prepareInput(await project(files)));
    return buildProjectMap(fileMap, detectStack(fileMap));
  }
  const expressApp = (handlerBody: string, rest: string): string =>
    `const express = require('express');\nconst app = express();\n` +
    `app.post('/api/thing', (req, res) => { ${handlerBody} res.send('ok'); });\n${rest}`;
  const reasonsOf = (map: ProjectMap): string[] =>
    (map.routeSecurityProfiles ?? []).find((p) => p.routePath === '/api/thing')?.analysisReasons ?? [];
  const warningFor = (map: ProjectMap): string[] =>
    routeProtectionGapWarnings(map.routeSecurityProfiles ?? [], routeCallWalkFailures(map), () => true);

  it('REAL PROFILES, each limit: the profile carries the exported reason, and the warning names the route', async () => {
    const chain = Array.from({ length: 10 }, (_, i) => `function f${i}() { f${i + 1}(); }`).join('\n') + '\nfunction f10() {}\n';
    const wide = Array.from({ length: 501 }, (_, i) => `function w${i}() {}`).join('\n');
    const many = Array.from({ length: 5_001 }, (_, i) => `function m${i}() {}`).join('\n');
    const dense = Array.from({ length: 200 }, (_, i) =>
      `function d${i}() { ${Array.from({ length: 126 }, (_, k) => `d${(i + k + 1) % 200}();`).join(' ')} }`).join('\n');
    const cases: Array<[string, string, string, string]> = [
      ['depth', 'f0();', chain, CALL_DEPTH.reason],
      ['route functions', Array.from({ length: 501 }, (_, i) => `w${i}();`).join(' '), wide, ROUTE_FUNCTIONS.reason],
      ['project functions', '', many, FUNCTIONS.reason],
      ['call edges', 'd0();', dense, CALL_EDGES.reason],
    ];
    for (const [label, body, rest, reason] of cases) {
      const map = await projectMapOf({ 'src/server.js': expressApp(body, rest) });
      expect(reasonsOf(map), label).toContain(reason);
      const [warning] = warningFor(map);
      expect(warning, label).toMatch(/^Route protection analysis stopped early on 1 route because /);
      expect(warning, label).toContain('POST /api/thing at "src/server.js:3"');
    }
  }, 180_000);

  it('A ROUTE WITHIN EVERY LIMIT: complete profile, no warning', async () => {
    const map = await projectMapOf({ 'src/server.js': expressApp('f0();', 'function f0() { f1(); }\nfunction f1() {}\n') });
    expect(reasonsOf(map)).toEqual([]);
    expect(warningFor(map)).toEqual([]);
  }, 60_000);

  it('THE REPORT: the sentence is in the warnings, last, and moves no status', async () => {
    const chain = Array.from({ length: 10 }, (_, i) => `function f${i}() { f${i + 1}(); }`).join('\n') + '\nfunction f10() {}\n';
    const deepReport = await scanProject(await project({ 'src/server.js': expressApp('f0();', chain) }), { dependencyScanner: completeAudit });
    const shallowReport = await scanProject(
      await project({ 'src/server.js': expressApp('f0();', 'function f0() { f1(); }\nfunction f1() {}\n') }),
      { dependencyScanner: completeAudit },
    );
    const sentence = deepReport.warnings.at(-1) ?? '';
    expect(sentence).toMatch(/^Route protection analysis stopped early on 1 route because a route's calls go more than 8 levels deep/);
    expect(shallowReport.warnings.filter((w) => /Route protection analysis/.test(w))).toEqual([]);
    expect(deepReport.codeScanStatus).toBe(shallowReport.codeScanStatus);
    expect(deepReport.codeScanStatus).toBe('complete');
  }, 120_000);
});
