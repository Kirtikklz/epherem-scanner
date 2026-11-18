import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { classifyFile } from '../../src/file-map/classifyFile.js';
import { buildFileMap } from '../../src/file-map/buildFileMap.js';
import { prepareInput } from '../../src/input/prepareInput.js';
import { buildProjectMap } from '../../src/project-map/buildProjectMap.js';
import {
  ROUTE_CALL_GRAPH_LIMITS,
  routeCallWalkFailures,
  UNRESOLVED_HANDLER_REASON,
} from '../../src/project-map/buildRouteSecurity.js';
import { extractApiRoutes } from '../../src/project-map/extractApiRoutes.js';
import { scanProject } from '../../src/scanProject.js';
import { routeProtectionGapWarnings } from '../../src/shared/analysisGapWarnings.js';
import { CappedNames } from '../../src/shared/cappedNames.js';
import { detectStack } from '../../src/stack-detection/detectStack.js';
import type { DependencyVulnerabilityScanner } from '../../src/dependency-audit/dependencyAudit.js';
import type { ApiRoute, ProjectMap, RouteControlAssessment, RouteSecurityProfile } from '../../src/shared/types.js';

const temporaries: string[] = [];

afterEach(async () => {
  await Promise.all(temporaries.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function project(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), 'epherem-python-routes-'));
  temporaries.push(dir);
  for (const [name, body] of Object.entries(files)) {
    const target = path.join(dir, name);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, body);
  }
  return dir;
}

function routesOf(filePath: string, content: string): ApiRoute[] {
  return extractApiRoutes(classifyFile({
    path: filePath,
    absolutePath: `/project/${filePath}`,
    extension: path.extname(filePath).toLowerCase(),
    size: content.length,
    content,
  }));
}

const route = (filePath: string, framework: ApiRoute['framework'], methods: string[], routePath: string, line: number): ApiRoute =>
  ({ filePath, framework, routePath, methods, line });

const FASTAPI_FILE =
  'from fastapi import FastAPI, APIRouter\n' +
  'app = FastAPI()\n' +
  'router = APIRouter()\n' +
  '\n' +
  '@router.get("/users")\n' +
  'def list_users():\n' +
  '    return []\n' +
  '\n' +
  '@app.post("/login")\n' +
  'def login(body: dict):\n' +
  '    return {}\n';

const FLASK_FILE =
  'from flask import Flask, Blueprint\n' +
  'app = Flask(__name__)\n' +
  'bp = Blueprint("admin", __name__)\n' +
  '@app.route("/data", methods=["GET", "POST"])\n' +
  'def data():\n' +
  '    return "ok"\n' +
  '\n' +
  "@bp.route('/report')\n" +
  'def report():\n' +
  '    return "ok"\n';

describe('each route pattern reads only its own language', () => {
  it('a .py file with @router.get, @app.post and Flask routes produces only Python routes', () => {
    expect(routesOf('api/main.py', FASTAPI_FILE)).toEqual([
      route('api/main.py', 'fastapi', ['GET'], '/users', 5),
      route('api/main.py', 'fastapi', ['POST'], '/login', 9),
    ]);
    expect(routesOf('web/app.py', FLASK_FILE)).toEqual([
      route('web/app.py', 'flask', ['GET', 'POST'], '/data', 4),
      route('web/app.py', 'flask', ['GET'], '/report', 8),
    ]);
  });

  it('a .ts file with router.get( and app.post( still produces Express routes', () => {
    const content =
      "import express from 'express';\n" +
      'const app = express();\n' +
      'const router = express.Router();\n' +
      "router.get('/users', (req, res) => res.json([]));\n" +
      'app.post("/login", (req, res) => res.send("ok"));\n' +
      'router.delete(`/users/:id`, remove);\n';
    expect(routesOf('src/server.ts', content)).toEqual([
      route('src/server.ts', 'express', ['GET'], '/users', 4),
      route('src/server.ts', 'express', ['POST'], '/login', 5),
      route('src/server.ts', 'express', ['DELETE'], '/users/:id', 6),
    ]);
    for (const extension of ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']) {
      expect(routesOf(`src/app${extension}`, "app.get('/health', (req, res) => res.send('ok'));\n"), extension)
        .toEqual([route(`src/app${extension}`, 'express', ['GET'], '/health', 1)]);
    }
  });

  it('a .js file with a decorator-looking comment is unaffected: its Express routes as before, and no Python route', () => {
    const content =
      "const app = require('express')();\n" +
      '// Ported from the old Python service, where this was:\n' +
      "// @router.get('/legacy')\n" +
      "// @app.route('/old', methods=['POST'])\n" +
      "app.get('/real', (req, res) => res.send('ok'));\n";
    expect(routesOf('src/server.js', content)).toEqual([
      route('src/server.js', 'express', ['GET'], '/legacy', 3),
      route('src/server.js', 'express', ['GET'], '/real', 5),
    ]);
  });

  it('a file in no route language produces no route: a tutorial page, a report, a template', () => {
    const sample = "<pre>app.get('/benefits', isAdmin, handler);\n@router.post('/items')\n@app.route('/x')</pre>\n";
    expect(routesOf('views/tutorial/a7.html', sample)).toEqual([]);
    expect(routesOf('sarif.json', JSON.stringify({ snippet: "router.post('/terminals', run)" }))).toEqual([]);
    expect(routesOf('views/page.ejs', sample)).toEqual([]);
  });
});

async function projectMapOf(files: Record<string, string>): Promise<ProjectMap> {
  const fileMap = buildFileMap(await prepareInput(await project(files)));
  return buildProjectMap(fileMap, detectStack(fileMap));
}

const labelsOf = (map: ProjectMap): string[] =>
  (map.routeSecurityProfiles ?? []).map((p) => `${p.framework} ${p.method} ${p.routePath} ${p.filePath}:${p.line}`);

describe('a Python project: each route is registered once', () => {
  it('one route per decorator, one profile per method, and no Express copy', async () => {
    const map = await projectMapOf({ 'api/main.py': FASTAPI_FILE, 'web/app.py': FLASK_FILE });
    expect(map.apiRoutes.map((r) => r.framework).sort()).toEqual(['fastapi', 'fastapi', 'flask', 'flask']);
    expect(labelsOf(map)).toEqual([
      'flask GET /data web/app.py:4',
      'flask POST /data web/app.py:4',
      'fastapi POST /login api/main.py:9',
      'flask GET /report web/app.py:8',
      'fastapi GET /users api/main.py:5',
    ]);
    for (const profile of map.routeSecurityProfiles ?? []) {
      expect(profile.analysisReasons).toEqual([UNRESOLVED_HANDLER_REASON]);
    }
  });
});

function profile(overrides: Partial<RouteSecurityProfile>): RouteSecurityProfile {
  const assessed = (status: RouteControlAssessment['status']): RouteControlAssessment => ({ status, evidence: [], reason: '' });
  return {
    id: 'route_x', filePath: 'api/main.py', framework: 'fastapi', routePath: '/x', method: 'GET', line: 1,
    analysisStatus: 'partial', analysisReasons: [UNRESOLVED_HANDLER_REASON], reachableFiles: [],
    authentication: assessed('unknown'), authorization: assessed('not_applicable'),
    inputValidation: assessed('not_applicable'), rateLimit: assessed('unknown'), csrfProtection: assessed('not_applicable'),
    databaseOperations: [], sensitiveEnvVars: [], securitySinks: [],
    ...overrides,
  };
}
const everything = (): boolean => true;
const [FUNCTIONS] = ROUTE_CALL_GRAPH_LIMITS;

describe('the sentences: Python routes, and routes whose handler could not be located', () => {
  it('CHANGE NO PROFILE: the reason string is byte-identical to what profiles carried before', () => {
    expect(UNRESOLVED_HANDLER_REASON).toBe('The route handler could not be resolved to a JavaScript/TypeScript function.');
  });

  it('seven Python routes: five named, "… and 2 more", fastapi and flask alike, test fixtures left out', () => {
    const profiles = [
      ...Array.from({ length: 6 }, (_, index) => profile({ routePath: `/users/${index}`, line: 10 + index })),
      profile({ framework: 'flask', filePath: 'web/app.py', routePath: '/users/9', method: 'POST', line: 4 }),
      profile({ filePath: 'tests/fixtures/app.py', routePath: '/fixture' }),
      profile({ routePath: '/found', analysisStatus: 'complete', analysisReasons: [] }),
    ];
    const isScannable = (filePath: string): boolean => !filePath.startsWith('tests/');
    expect(routeProtectionGapWarnings(profiles, [], isScannable)).toEqual([
      'Route protection analysis reads JavaScript and TypeScript handlers only, so it did not follow the code of ' +
        '7 Python routes, and a missing login, permission, input-validation, rate-limit or CSRF check on them can go ' +
        'unreported; only checks that match Python code by pattern examined them: GET /users/0 at "api/main.py:10", ' +
        'GET /users/1 at "api/main.py:11", GET /users/2 at "api/main.py:12", GET /users/3 at "api/main.py:13", ' +
        'GET /users/4 at "api/main.py:14"… and 2 more.',
    ]);
  });

  it('one Python route: the singular, and no remainder', () => {
    expect(routeProtectionGapWarnings([profile({})], [], everything)).toEqual([
      'Route protection analysis reads JavaScript and TypeScript handlers only, so it did not follow the code of ' +
        '1 Python route, and a missing login, permission, input-validation, rate-limit or CSRF check on it can go ' +
        'unreported; only checks that match Python code by pattern examined it: GET /x at "api/main.py:1".',
    ]);
  });

  it('six routes whose handler was not found: five named, "… and 1 more"', () => {
    const profiles = Array.from({ length: 6 }, (_, index) =>
      profile({ framework: 'express', filePath: 'src/routes.ts', routePath: `/r${index}`, line: index + 1 }));
    expect(routeProtectionGapWarnings(profiles, [], everything)).toEqual([
      'The handler code of 6 routes could not be located, so route protection analysis did not follow it, and a ' +
        'missing login, permission, input-validation, rate-limit or CSRF check on them can go unreported: ' +
        'GET /r0 at "src/routes.ts:1", GET /r1 at "src/routes.ts:2", GET /r2 at "src/routes.ts:3", ' +
        'GET /r3 at "src/routes.ts:4", GET /r4 at "src/routes.ts:5"… and 1 more.',
    ]);
  });

  it('one route whose handler was not found: the singular; a SvelteKit route is said the same way', () => {
    expect(routeProtectionGapWarnings(
      [profile({ framework: 'sveltekit', filePath: 'src/routes/+layout.server.ts', routePath: '/', line: 6 })],
      [], everything,
    )).toEqual([
      'The handler code of 1 route could not be located, so route protection analysis did not follow it, and a ' +
        'missing login, permission, input-validation, rate-limit or CSRF check on it can go unreported: ' +
        'GET / at "src/routes/+layout.server.ts:6".',
    ]);
  });

  it('A ROUTE IS COUNTED ONCE per file, line and method, not once per profile', () => {
    const profiles = [
      profile({ framework: 'express', filePath: 'src/min.js', routePath: '/a', line: 3 }),
      profile({ framework: 'express', filePath: 'src/min.js', routePath: '/b', line: 3 }),
      profile({ framework: 'express', filePath: 'src/min.js', routePath: '/a', line: 3, method: 'POST' }),
      profile({ framework: 'flask', filePath: 'web/app.py', routePath: '/data', line: 4, method: 'GET' }),
      profile({ framework: 'flask', filePath: 'web/app.py', routePath: '/data', line: 4, method: 'POST' }),
      profile({ framework: 'flask', filePath: 'web/app.py', routePath: '/data', line: 4, method: 'POST' }),
    ];
    const [python, unlocated] = routeProtectionGapWarnings(profiles, [], everything);
    expect(python).toMatch(/ the code of 2 Python routes, /);
    expect(python).toMatch(/: GET \/data at "web\/app\.py:4", POST \/data at "web\/app\.py:4"\.$/);
    expect(unlocated).toMatch(/^The handler code of 2 routes could not be located, /);
    expect(unlocated).toMatch(/: GET \/a at "src\/min\.js:3", POST \/a at "src\/min\.js:3"\.$/);
  });

  it('a route stopped at a call-graph limit is said by the limit sentence, not as a missing handler', () => {
    const warnings = routeProtectionGapWarnings(
      [profile({ framework: 'express', filePath: 'src/server.ts', analysisReasons: [FUNCTIONS.reason, UNRESOLVED_HANDLER_REASON].sort() })],
      [], everything,
    );
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/^Route protection analysis stopped early on 1 route because the project has more than 5,000 functions/);
  });

  it('nothing unresolved: no sentence', () => {
    expect(routeProtectionGapWarnings([profile({ analysisStatus: 'complete', analysisReasons: [] })], [], everything)).toEqual([]);
  });

  it('CappedNames: an identity makes two names one record; without one, the name is the identity', () => {
    const names = new CappedNames(1);
    expect(names.add('GET /a at "f:1"', 'f|1|GET')).toBe(true);
    expect(names.add('GET /b at "f:1"', 'f|1|GET')).toBe(false);
    expect(names.add('GET /c at "f:2"')).toBe(false);
    expect(names.add('GET /c at "f:2"')).toBe(false);
    expect([names.named, names.total, names.unnamed]).toEqual([['GET /a at "f:1"'], 2, 1]);
  });
});

const warningFor = (map: ProjectMap): string[] =>
  routeProtectionGapWarnings(map.routeSecurityProfiles ?? [], routeCallWalkFailures(map), everything);

const completeAudit: DependencyVulnerabilityScanner = {
  scanDependencies: async (dependencies) => ({
    performed: true, incomplete: false, source: 'osv.dev', dependenciesCollected: dependencies.length,
    checked: dependencies.length, notChecked: [], vulnerabilities: [], diagnostics: [], note: 'complete',
  }),
};

describe('real profiles', () => {
  it('a FastAPI and Flask project: one sentence naming every route once', async () => {
    const map = await projectMapOf({ 'api/main.py': FASTAPI_FILE, 'web/app.py': FLASK_FILE });
    expect(warningFor(map)).toEqual([
      'Route protection analysis reads JavaScript and TypeScript handlers only, so it did not follow the code of ' +
        '5 Python routes, and a missing login, permission, input-validation, rate-limit or CSRF check on them can go ' +
        'unreported; only checks that match Python code by pattern examined them: GET /data at "web/app.py:4", ' +
        'POST /data at "web/app.py:4", POST /login at "api/main.py:9", GET /report at "web/app.py:8", ' +
        'GET /users at "api/main.py:5".',
    ]);
  }, 60_000);

  it('an Express handler passed by reference is not located and is said; an inline one is found and is not', async () => {
    const map = await projectMapOf({
      'src/server.js':
        "const express = require('express');\n" +
        "const controller = require('./controller');\n" +
        'const app = express();\n' +
        "app.get('/inline', (req, res) => res.send('ok'));\n" +
        "app.post('/by-reference', controller.create);\n",
      'src/controller.js': 'exports.create = (req, res) => res.send("ok");\n',
    });
    expect(warningFor(map)).toEqual([
      'The handler code of 1 route could not be located, so route protection analysis did not follow it, and a ' +
        'missing login, permission, input-validation, rate-limit or CSRF check on it can go unreported: ' +
        'POST /by-reference at "src/server.js:5".',
    ]);
  }, 60_000);

  it('THE REPORT: the sentence is in the warnings, and moves no status', async () => {
    const report = await scanProject(await project({ 'api/main.py': FASTAPI_FILE }), { dependencyScanner: completeAudit });
    const said = report.warnings.filter((w) => w.startsWith('Route protection analysis reads JavaScript and TypeScript'));
    expect(said).toHaveLength(1);
    expect(said[0]).toContain(' the code of 2 Python routes, ');
    expect(report.codeScanStatus).toBe('complete');
  }, 120_000);
});
