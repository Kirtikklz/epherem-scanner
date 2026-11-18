import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { buildFileMap } from '../../src/file-map/buildFileMap.js';
import { prepareInput } from '../../src/input/prepareInput.js';
import { buildProjectMap } from '../../src/project-map/buildProjectMap.js';
import { detectStack } from '../../src/stack-detection/detectStack.js';
import { scanProject } from '../../src/scanProject.js';
import { unreadRouteWarnings } from '../../src/shared/unreadRouteWarning.js';
import { absenceRoutesFor, routeMiddlewareAt, unreadRoutes } from '../../src/shared/routeControlModel.js';
import { buildAbsenceRouteModel } from '../../src/candidates/absence/routeModel.js';
import type { Finding, RuleContext, ScanReport } from '../../src/shared/types.js';
import { MockDependencyVulnerabilityScanner } from '../../src/dependency-audit/dependencyAudit.js';

const EXPRESS_PKG = '{"name":"fixture","dependencies":{"express":"^4.18.0"}}';

const unreadable = (n: number): string =>
  `app.post('/unread-${n}', requireAuth, (req, res) => { res.status(201).json({ ok: ${n} }); }\n`;

const readable = "app.put('/readable', (req, res) => { res.status(200).json({ ok: true }); });\n";

const HEADER = ["const express = require('express');", 'const app = express();', "const requireAuth = require('./auth');", ''].join('\n');

const AUTH_MODULE = [
  'module.exports = function requireAuth(req, res, next) {',
  '  if (!req.headers.authorization) return res.status(401).end();',
  '  next();',
  '};',
  '',
].join('\n');

async function project(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(path.join(tmpdir(), 'epherem-unread-'));
  for (const [relative, content] of Object.entries(files)) {
    const full = path.join(root, relative);
    await mkdir(path.dirname(full), { recursive: true });
    await writeFile(full, content, 'utf8');
  }
  return root;
}

async function contextFor(root: string): Promise<RuleContext> {
  const fileMap = buildFileMap(await prepareInput(root, {}));
  const stack = detectStack(fileMap);
  return { fileMap, projectMap: buildProjectMap(fileMap, stack), stack };
}

const scan = (root: string, absenceTags?: ReadonlySet<string>): Promise<ScanReport> =>
  scanProject(root, {
    dependencyScanner: new MockDependencyVulnerabilityScanner(),
    ...(absenceTags !== undefined ? { absenceTags } : {}),
  });

const ONLY_AUTH = new Set(['api-mutation-without-auth']);

const unreadWarningIn = (warnings: readonly string[]): string | undefined =>
  warnings.find((w) => w.includes('could not be read'));

const READABLE_EXPLANATION_TAIL =
  '. The route model resolved every middleware applied at the route, router and mount level and none ' +
  'resolved to a recognised auth guard. The check may live somewhere static analysis cannot follow ' +
  '(a gateway, a wrapper, a framework default); verify before changing anything.';

describe('E1 — an unreadable route is NAMED in the report', () => {
  let root: string;
  beforeAll(async () => {
    root = await project({
      'package.json': EXPRESS_PKG,
      'auth.js': AUTH_MODULE,
      'server.js': HEADER + readable + '\n' + unreadable(1),
    });
  });
  afterAll(() => rm(root, { recursive: true, force: true }));

  it('the model really could not read it — otherwise E1 proves nothing', async () => {
    const context = await contextFor(root);
    const unread = unreadRoutes(context);
    expect(unread).toHaveLength(1);
    expect(unread[0]?.relPath).toBe('/unread-1');
    expect(unread[0]?.spanResolved).toBe(false);
  });

  it('the RENDERED warning names the route, its file and its line', async () => {
    const context = await contextFor(root);
    const warnings = unreadRouteWarnings(context);
    expect(warnings).toHaveLength(1);
    const warning = warnings[0] ?? '';

    expect(warning).toContain('1 route registration could not be read');
    expect(warning).toContain('POST /unread-1');
    expect(warning).toContain('server.js');
    expect(warning).toMatch(/"[^"]*server\.js:\d+"/);
    expect(warning).not.toContain('registrations');
  });

  it('it reaches the REPORT, through fileMap.warnings, exactly once', async () => {
    const report = await scan(root);
    const matches = report.warnings.filter((w) => w.includes('could not be read'));
    expect(matches).toHaveLength(1);
    expect(matches[0]).toContain('POST /unread-1');
  });

  it('and it makes the CODE SCAN say it is incomplete, which is what it is', async () => {
    const report = await scan(root);
    expect(report.codeScanStatus).toBe('incomplete');
    expect(report.scanStatus).toBe('incomplete');
  });
});

describe('E2 — a project with NO unreadable routes gains no such warning', () => {
  let root: string;
  beforeAll(async () => {
    root = await project({
      'package.json': EXPRESS_PKG,
      'auth.js': AUTH_MODULE,
      'server.js': HEADER + readable + "app.post('/made', requireAuth, (req, res) => { res.status(201).end(); });\n",
    });
  });
  afterAll(() => rm(root, { recursive: true, force: true }));

  it('the model read every route', async () => {
    expect(unreadRoutes(await contextFor(root))).toHaveLength(0);
  });

  it('NO warning — not a reassuring one, none at all', async () => {
    expect(unreadRouteWarnings(await contextFor(root))).toEqual([]);
    const report = await scan(root);
    expect(unreadWarningIn(report.warnings)).toBeUndefined();
    expect(report.codeScanStatus).toBe('complete');
  });
});

describe('E3 — when the cap bites, the warning SAYS the list is partial', () => {
  let root: string;
  const TOTAL = 9;
  const CAP = 5;
  beforeAll(async () => {
    const routes = Array.from({ length: TOTAL }, (_, i) => unreadable(i + 1)).join('\n');
    root = await project({
      'package.json': EXPRESS_PKG,
      'auth.js': AUTH_MODULE,
      'server.js': HEADER + readable + '\n' + routes,
    });
  });
  afterAll(() => rm(root, { recursive: true, force: true }));

  it('nine routes really are unreadable', async () => {
    expect(unreadRoutes(await contextFor(root))).toHaveLength(TOTAL);
  });

  it('the warning states the TRUE TOTAL, not the number it named', async () => {
    const warning = unreadRouteWarnings(await contextFor(root))[0] ?? '';
    expect(warning).toContain(`${TOTAL} route registrations could not be read`);
    expect(warning).not.toContain(`${CAP} route registrations could not be read`);
  });

  it('the warning SAYS the list is partial, and says how many are missing', async () => {
    const warning = unreadRouteWarnings(await contextFor(root))[0] ?? '';
    expect(warning).toContain('This list is partial');
    expect(warning).toContain(`only the first ${CAP} are named`);
    expect(warning).toContain(`${TOTAL - CAP} further routes could not be read`);
    expect(warning).toContain('not named here');
  });

  it('it names exactly the cap, and the partiality claim comes BEFORE the list', async () => {
    const warning = unreadRouteWarnings(await contextFor(root))[0] ?? '';
    const named = [...warning.matchAll(/POST \/unread-\d+ at "/g)];
    expect(named).toHaveLength(CAP);
    expect(warning.indexOf('This list is partial')).toBeLessThan(warning.indexOf('The named routes are'));
  });

  it('and the whole claim is ONE string, so no note cap can split it from its list', async () => {
    const warnings = unreadRouteWarnings(await contextFor(root));
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain('This list is partial');
    expect(warnings[0]).toContain('POST /unread-1');
  });
});

describe('E4/E5 — the sentence on a finding is true of the route it describes', () => {
  let unreadRoot: string;
  let readRoot: string;
  beforeAll(async () => {
    unreadRoot = await project({
      'package.json': EXPRESS_PKG,
      'server.js': ["const express = require('express');", 'const app = express();', '', unreadable(1)].join('\n'),
    });
    readRoot = await project({
      'package.json': EXPRESS_PKG,
      'server.js': [
        "const express = require('express');",
        'const app = express();',
        '',
        "app.post('/orders', (req, res) => { res.status(201).json({ ok: true }); });",
        '',
      ].join('\n'),
    });
  });
  afterAll(async () => {
    await rm(unreadRoot, { recursive: true, force: true });
    await rm(readRoot, { recursive: true, force: true });
  });

  const authFinding = (report: ScanReport): Finding | undefined =>
    report.findings.find((f) => f.ruleId === 'api_mutation_without_auth' && f.detectionKind === 'absence');

  it('E4 — the explanation on an UNREAD route does not claim middleware was resolved', async () => {
    const finding = authFinding(await scan(unreadRoot, ONLY_AUTH));
    expect(finding).toBeDefined();
    const text = finding?.technicalExplanation ?? '';

    expect(text).not.toContain('The route model resolved every middleware');
    expect(text).toContain('could not read this route');
    expect(text).toContain('nothing was searched and nothing was ruled out');
    expect(text).toContain('rests on the absence of a reading, not on the absence of a guard');
  });

  it('E4 — and the finding itself has not moved: same rule, severity and confidence', async () => {
    const finding = authFinding(await scan(unreadRoot, ONLY_AUTH));
    expect(finding?.detectionKind).toBe('absence');
    expect(finding?.confidence).toBe('low');
    expect(finding?.ruleId).toBe('api_mutation_without_auth');
  });

  it('E5 — a READABLE route keeps the old sentence, byte for byte', async () => {
    const finding = authFinding(await scan(readRoot, ONLY_AUTH));
    expect(finding).toBeDefined();
    expect(finding?.technicalExplanation.endsWith(READABLE_EXPLANATION_TAIL)).toBe(true);
    expect(finding?.technicalExplanation).toContain(
      'The route model resolved every middleware applied at the route, router and mount level',
    );
  });

  it('E5 — and the readable project gains no unread-route warning', async () => {
    expect(unreadWarningIn((await scan(readRoot, ONLY_AUTH)).warnings)).toBeUndefined();
  });
});

describe('E6 — the earlier behaviour survives: this adds a sentence and changes no state', () => {
  let root: string;
  beforeAll(async () => {
    root = await project({
      'package.json': EXPRESS_PKG,
      'auth.js': AUTH_MODULE,
      'server.js': HEADER + readable + '\n' + unreadable(1),
    });
  });
  afterAll(() => rm(root, { recursive: true, force: true }));

  it('an unread route publishes middlewares: [] ONLY alongside spanResolved: false', async () => {
    const context = await contextFor(root);
    for (const route of buildAbsenceRouteModel(context.fileMap, context.projectMap)) {
      if (route.spanResolved) continue;
      expect(route.middlewares).toEqual([]);
      expect(route.handlerToken).toBeUndefined();
      expect(route.endLine).toBe(route.line);
    }
  });

  it('every control on an unread route reads `unresolved`, never `absent`', async () => {
    const context = await contextFor(root);
    const unread = buildAbsenceRouteModel(context.fileMap, context.projectMap).filter((r) => !r.spanResolved);
    expect(unread.length).toBeGreaterThan(0);
    for (const route of unread) {
      for (const control of Object.values(route.controls)) {
        expect(control.state).toBe('unresolved');
      }
    }
  });

  it('the model scanProject shares with the absence producer IS the one it would have built', async () => {
    const context = await contextFor(root);
    expect(absenceRoutesFor(context)).toEqual(buildAbsenceRouteModel(context.fileMap, context.projectMap));
  });

  it('`routeMiddlewareAt` still withholds for an unread route and answers [] for a read one', async () => {
    const context = await contextFor(root);
    const routes = buildAbsenceRouteModel(context.fileMap, context.projectMap);
    const unread = routes.find((r) => !r.spanResolved);
    const read = routes.find((r) => r.spanResolved && r.middlewares.length === 0);
    expect(unread).toBeDefined();
    expect(read).toBeDefined();
    expect(routeMiddlewareAt(context, unread?.filePath ?? '', unread?.line ?? 0)).toBeUndefined();
    expect(routeMiddlewareAt(context, read?.filePath ?? '', read?.line ?? 0)).toEqual([]);
  });
});
