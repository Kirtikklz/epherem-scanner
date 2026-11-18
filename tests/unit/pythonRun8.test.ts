import { copyFile, mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { MockDependencyVulnerabilityScanner } from '../../src/dependency-audit/dependencyAudit.js';
import { crossSiteScripting } from '../../src/rules/basic/xss.js';
import { databaseDeleteWithoutOwnershipCheck } from '../../src/rules/contextual/databaseDeleteWithoutOwnershipCheck.js';
import { scanProject } from '../../src/scanProject.js';
import { bindingsOf, functionAt } from '../../src/shared/pythonBindings.js';
import { pythonOrmDeletes } from '../../src/shared/pythonDelete.js';
import {
  MAX_PY_FILE_CHARS,
  MAX_PY_LINE_CHARS,
  preparePythonReader,
  pythonReaderStats,
  pythonReaderTesting,
  readPythonTree,
  releasePythonReader,
  type PyFallbackReason,
} from '../../src/shared/pythonParser.js';
import { memoryContext } from './helpers.js';

type Files = [string, string][];
const py = (...lines: string[]): string => `${lines.join('\n')}\n`;
const file = (content: string, name = 'pkg/mod.py'): { path: string; content: string } => ({ path: name, content });
const fallbackOf = (content: string): PyFallbackReason | undefined => readPythonTree(file(content)).fallback;

const budgets = { ...pythonReaderTesting.budgets };
afterEach(() => {
  Object.assign(pythonReaderTesting.budgets, budgets);
  pythonReaderTesting.failNext = false;
});

describe('the Python reader', () => {
  beforeAll(async () => { pythonReaderTesting.reset(); await preparePythonReader(); });
  afterAll(() => { releasePythonReader(); pythonReaderTesting.reset(); });

  it('reads a file into a tree: node types, fields, text (non-ASCII too) and 1-based lines', () => {
    const read = readPythonTree(file(py('label = "é😀"', 'def shelve(box, *, size=1):', '    return box')));
    expect(read.fallback).toBeUndefined();
    const tree = read.tree!;
    expect(tree.root.type).toBe('module');
    const fn = tree.find((n) => n.type === 'function_definition')[0]!;
    expect(fn.child('name')!.text).toBe('shelve');
    expect(fn.line).toBe(2);
    expect(fn.endLine).toBe(3);
    const literal = tree.find((n) => n.type === 'string')[0]!;
    expect(literal.text).toBe('"é😀"');
    expect(functionAt(tree, 3)!.same(fn)).toBe(true);
  });

  it('the same entry object is read once', () => {
    const entry = file(py('a = 1'));
    expect(readPythonTree(entry).tree).toBe(readPythonTree(entry).tree);
  });

  it('each pathological file falls back: very large, one long line, very deep nesting, and a file that does not parse', () => {
    expect(fallbackOf('x = 1\n'.repeat(Math.ceil((MAX_PY_FILE_CHARS + 1) / 6)))).toBe('too-large');
    expect(fallbackOf(`blob_text = "${'a'.repeat(MAX_PY_LINE_CHARS + 1)}"\n`)).toBe('long-line');
    expect(['parse-error', 'too-deep']).toContain(fallbackOf(`x = ${'['.repeat(3000)}${']'.repeat(3000)}\n`));
    expect(fallbackOf(py('def shelve(:', '    pass'))).toBe('parse-error');
    expect(fallbackOf(py('call(1, 2'))).toBe('parse-error');
    expect(fallbackOf(py('x = [[1], [2]]', 'def shelve():', '    pass'))).toBeUndefined();
  });

  it('every budget falls back: nodes, depth, parse time and the scan total', () => {
    const body = py('def shelve(a, b):', '    return [a, b, (a + b) * 2]');
    pythonReaderTesting.budgets.nodes = 10;
    expect(fallbackOf(body)).toBe('too-many-nodes');
    Object.assign(pythonReaderTesting.budgets, budgets);
    pythonReaderTesting.budgets.depth = 4;
    expect(fallbackOf(body)).toBe('too-deep');
    Object.assign(pythonReaderTesting.budgets, budgets);
    pythonReaderTesting.budgets.parseMs = -1;
    expect(fallbackOf('total = total + 1\n'.repeat(20_000))).toBe('too-slow');
    Object.assign(pythonReaderTesting.budgets, budgets);
    pythonReaderTesting.budgets.scanNodes = 0;
    expect(fallbackOf(body)).toBe('scan-budget');
    Object.assign(pythonReaderTesting.budgets, budgets);
    expect(fallbackOf(body)).toBeUndefined();
  });

  it('the cached trees are capped: past the cap the oldest is dropped and read again', () => {
    const first = file(py('a = 1'));
    const second = file(py('b = 2'));
    const tree = readPythonTree(first).tree;
    pythonReaderTesting.budgets.cachedNodes = 1;
    readPythonTree(second);
    expect(readPythonTree(first).tree).not.toBe(tree);
  });

  it('the runtime works in the capped memory this module hands it', () => {
    readPythonTree(file(py('def shelve(a):', '    return a')));
    expect(pythonReaderTesting.wasmMemoryWritten()).toBe(true);
  });

  it('the stats name each fallback and its reason', () => {
    const before = pythonReaderStats().fallbacks['parse-error'];
    readPythonTree(file('def (:\n', 'pkg/broken_one.py'));
    const after = pythonReaderStats();
    expect(after.fallbacks['parse-error']).toBe(before + 1);
    expect(after.fellBack.some((f) => f.path === 'pkg/broken_one.py' && f.reason === 'parse-error') || after.fellBack.length === 20).toBe(true);
  });
});

describe('the Python reader: preparing, failing and releasing', () => {
  afterEach(() => { pythonReaderTesting.setAssetDir(undefined); pythonReaderTesting.reset(); });

  it('a reader nobody prepared falls back as not-ready, and a rule still runs', () => {
    pythonReaderTesting.reset();
    expect(fallbackOf(py('a = 1'))).toBe('not-ready');
    expect(() => databaseDeleteWithoutOwnershipCheck.run(memoryContext(lockerApp(['g.tenant = 1'])))).not.toThrow();
  });

  it('a parser failure switches the reader off for the process; later files fall back; nothing throws', async () => {
    pythonReaderTesting.reset();
    expect(await preparePythonReader()).toBe(true);
    pythonReaderTesting.failNext = true;
    expect(fallbackOf(py('a = 1'))).toBe('parser-failure');
    expect(fallbackOf(py('b = 2'))).toBe('not-ready');
    expect(await preparePythonReader()).toBe(false);
    releasePythonReader();
    releasePythonReader();
  });

  it('assets that are missing leave every file to fall back, and prepare says so', async () => {
    pythonReaderTesting.reset();
    pythonReaderTesting.setAssetDir(await mkdtemp(path.join(tmpdir(), 'epherem-no-reader-')));
    expect(await preparePythonReader()).toBe(false);
    expect(fallbackOf(py('a = 1'))).toBe('not-ready');
    releasePythonReader();
  });

  it('loads from the layout copy-assets builds: a .cjs runtime in a "type": "module" package', async () => {
    const pkg = await mkdtemp(path.join(tmpdir(), 'epherem-dist-layout-'));
    const dir = path.join(pkg, 'python-reader');
    await mkdir(dir, { recursive: true });
    await writeFile(path.join(pkg, 'package.json'), '{"type":"module"}\n', 'utf8');
    const from = path.join(path.dirname(createRequire(import.meta.url).resolve('@vscode/tree-sitter-wasm/package.json')), 'wasm');
    await copyFile(path.join(from, 'tree-sitter.js'), path.join(dir, 'tree-sitter.cjs'));
    await copyFile(path.join(from, 'tree-sitter.wasm'), path.join(dir, 'tree-sitter.wasm'));
    await copyFile(path.join(from, 'tree-sitter-python.wasm'), path.join(dir, 'tree-sitter-python.wasm'));
    pythonReaderTesting.reset();
    pythonReaderTesting.setAssetDir(dir);
    expect(await preparePythonReader()).toBe(true);
    expect(fallbackOf(py('a = 1'))).toBeUndefined();
    releasePythonReader();
    await copyFile(path.join(from, 'tree-sitter.js'), path.join(dir, 'tree-sitter.js'));
    await rm(path.join(dir, 'tree-sitter.cjs'));
    pythonReaderTesting.reset();
    pythonReaderTesting.setAssetDir(dir);
    expect(await preparePythonReader()).toBe(false);
    releasePythonReader();
  });

  it('never fetches anything: the runtime and grammar are read from disk', async () => {
    pythonReaderTesting.reset();
    const real = globalThis.fetch;
    let fetched = 0;
    globalThis.fetch = (() => { fetched += 1; throw new Error('no network'); }) as typeof fetch;
    try {
      expect(await preparePythonReader()).toBe(true);
      expect(fallbackOf(py('a = 1'))).toBeUndefined();
    } finally {
      globalThis.fetch = real;
      releasePythonReader();
    }
    expect(fetched).toBe(0);
  });

  it('the last release frees the parser: a later read falls back until the reader is prepared again', async () => {
    pythonReaderTesting.reset();
    await preparePythonReader();
    await preparePythonReader();
    releasePythonReader();
    expect(fallbackOf(py('a = 1'))).toBeUndefined();
    releasePythonReader();
    expect(fallbackOf(py('a = 2'))).toBe('not-ready');
  });

  it('a scan of a Python project completes whether or not the reader can load', async () => {
    const root = await mkdtemp(path.join(tmpdir(), 'epherem-reader-scan-'));
    await mkdir(path.join(root, 'site'), { recursive: true });
    for (const [rel, content] of lockerApp(['payload = request.get_json()', 'g.tenant = payload.get("tenant")'])) {
      await mkdir(path.dirname(path.join(root, rel)), { recursive: true });
      await writeFile(path.join(root, rel), content, 'utf8');
    }
    const scan = async (): Promise<string[]> => (await scanProject(root, { dependencyScanner: new MockDependencyVulnerabilityScanner() }))
      .findings.filter((f) => f.ruleId === 'database_delete_without_ownership_check').map((f) => `${f.filePath}:${f.lineStart}`);
    pythonReaderTesting.reset();
    expect(await scan()).toEqual(['site/lockers.py:9']);
    expect(fallbackOf(py('after = 1'))).toBe('not-ready');
    pythonReaderTesting.reset();
    pythonReaderTesting.setAssetDir(await mkdtemp(path.join(tmpdir(), 'epherem-no-reader-')));
    expect(await scan()).toEqual([]);
  });
});

describe('binding sites, read wide', () => {
  beforeAll(async () => { pythonReaderTesting.reset(); await preparePythonReader(); });
  afterAll(() => { releasePythonReader(); pythonReaderTesting.reset(); });

  it('every kind of binding counts; a nested function\'s parameter and a read do not', () => {
    const forms = [
      'member = 1', 'member: int = 1', 'member += 1', 'member, other = 1, 2', '(other, *member) = 1, 2', 'for member in rows: pass',
      'with open(p) as member: pass', 'try:\n        pass\n    except E as member:\n        pass', 'if (member := 1): pass', 'del member',
      'global member', 'import member', 'from m import other as member', 'def member(): pass', 'class member: pass',
      'match x:\n        case [member]:\n            pass', 'match x:\n        case P(k=member):\n            pass', '[member for member in rows]',
    ];
    for (const form of forms) {
      const tree = readPythonTree(file(py('def view(member):', `    ${form}`))).tree!;
      expect(bindingsOf(functionAt(tree, 1)!, 'member').length, form).toBeGreaterThan(0);
    }
    for (const form of ['print(member)', 'member.x = 1', 'member[0] = 1', 'fn = lambda member: member', 'def inner(member):\n        return member', 'match x:\n        case P(member=1):\n            pass']) {
      const tree = readPythonTree(file(py('def view(member):', `    ${form}`))).tree!;
      expect(bindingsOf(functionAt(tree, 1)!, 'member'), form).toEqual([]);
    }
  });
});

function lockerApp(assign: string[], gateHead: string[] = []): Files {
  return [
    ['site/lockers.py', py(
      'from flask import Blueprint, abort, g, request',
      'from flask_login import login_required',
      'from . import db',
      'from .models import Locker',
      'bp = Blueprint("lockers", __name__)',
      '@bp.delete("/<int:locker_id>")',
      '@login_required',
      'def clear_locker(locker_id):',
      '    Locker.query.filter_by(id=locker_id, tenant_id=g.tenant).delete()',
    )],
    ['site/gate.py', py(
      'from flask import abort, g, request, session',
      ...gateHead,
      'def load_tenant():',
      ...assign.map((line) => `    ${line}`),
    )],
  ];
}

const verdicts = (files: Files, filePath: string): string[] => {
  const context = memoryContext(files);
  const entry = context.fileMap.entries.find((e) => e.path === filePath)!;
  return pythonOrmDeletes(context, entry).map((s) => `${s.line}:${s.owned ? 'owned' : 'reported'}`);
};

describe('job 8: g.<name> is the caller only when every assignment is proven not to come from the request', () => {
  beforeAll(async () => { pythonReaderTesting.reset(); await preparePythonReader(); });
  afterAll(() => { releasePythonReader(); pythonReaderTesting.reset(); });

  it('a value read from the body into a local, then copied into g, is a client value: the delete reports', () => {
    expect(verdicts(lockerApp(['payload = request.get_json()', 'g.tenant = payload.get("tenant")']), 'site/lockers.py')).toEqual(['9:reported']);
    expect(verdicts(lockerApp(['g.tenant = request.args.get("tenant")']), 'site/lockers.py')).toEqual(['9:reported']);
    expect(verdicts(lockerApp(['g.tenant = Tenant.query.get(session["tenant_id"])']), 'site/lockers.py')).toEqual(['9:owned']);
  });

  it('a helper the reader does not open is not proof: unclassified, never owned', () => {
    expect(verdicts(lockerApp(['g.tenant = fetch_tenant()']), 'site/lockers.py')).toEqual([]);
    expect(verdicts(lockerApp(['claims = read_claims()', 'g.tenant = Tenant.query.get(claims["sub"])']), 'site/lockers.py')).toEqual([]);
  });

  it('a token the code verifies with a key and then looks a row up by is the caller; an unverified decode is not', () => {
    const head = ['import jwt', 'SECRET = "k"'];
    const through = (decode: string): string[] => verdicts(lockerApp([
      'token = request.headers.get("Authorization", "")',
      `claims = ${decode}`,
      'g.tenant = Tenant.query.filter_by(id=claims["sub"]).first()',
    ], head), 'site/lockers.py');
    expect(through('jwt.decode(token, SECRET, algorithms=["HS256"])')).toEqual(['9:owned']);
    expect(through('jwt.decode(token, options={"verify_signature": False})')).toEqual([]);
    expect(through('jwt.decode(token, SECRET, algorithms=["HS256"], options={"verify_signature": False})')).toEqual([]);
    expect(through('jwt.decode(token, SECRET)')).toEqual([]);
    expect(through('jwt.decode(token, SECRET, algorithms=["none"])')).toEqual([]);
    expect(through('jwt.decode(token, None, algorithms=["HS256"])')).toEqual([]);
    expect(verdicts(lockerApp([
      'token = request.headers.get("Authorization", "")',
      'claims = jwt.decode(token, SECRET, algorithms=["HS256"])',
      'g.tenant = Tenant.query.filter_by(id=claims["sub"]).first()',
    ], ['from .tokens import jwt', 'SECRET = "k"']), 'site/lockers.py')).toEqual([]);
  });

  it('one unproven assignment anywhere withdraws the credit; a tuple target, setattr or a file that does not parse too', () => {
    const owned = 'g.tenant = Tenant.query.get(session["tenant_id"])';
    expect(verdicts([...lockerApp([owned]), ['site/other.py', py('from flask import g', 'def elsewhere():', '    g.tenant = fetch_tenant()')]], 'site/lockers.py')).toEqual([]);
    expect(verdicts([...lockerApp([owned]), ['site/other.py', py('from flask import g', 'def elsewhere():', '    g.tenant, x = fetch_tenant(), 1')]], 'site/lockers.py')).toEqual([]);
    expect(verdicts([...lockerApp([owned]), ['site/other.py', py('from flask import g', 'def elsewhere():', '    setattr(g, "x", 1)')]], 'site/lockers.py')).toEqual([]);
    expect(verdicts([...lockerApp([owned]), ['site/other.py', py('from flask import g', 'def elsewhere(:', '    g.tenant = 1')]], 'site/lockers.py')).toEqual([]);
    expect(verdicts(lockerApp([owned]), 'site/lockers.py')).toEqual(['9:owned']);
  });

  it('a loader parameter is not proof, even when the loader also assigns it a proven value', () => {
    const files = (head: string): Files => lockerApp([]).map(([p, c]) => [p, p === 'site/gate.py'
      ? py('from flask import g, session', `def load_tenant(${head}):`, '    if not tenant_id:', '        tenant_id = session["tenant_id"]', '    g.tenant = Tenant.query.get(tenant_id)')
      : c]);
    expect(verdicts(files('tenant_id=None'), 'site/lockers.py')).toEqual([]);
    expect(verdicts(lockerApp(['tenant_id = session["tenant_id"]', 'g.tenant = Tenant.query.get(tenant_id)']), 'site/lockers.py')).toEqual(['9:owned']);
  });

  it('a local also bound some other way (with-as) is not proof', () => {
    expect(verdicts(lockerApp(['tenant_id = session["tenant_id"]', 'with pick() as tenant_id:', '    pass', 'g.tenant = Tenant.query.get(tenant_id)']), 'site/lockers.py')).toEqual([]);
  });

  it('a handler file that does not parse gets no g credit, though the loader proves it', () => {
    const files = lockerApp(['g.tenant = Tenant.query.get(session["tenant_id"])'])
      .map(([p, c]): [string, string] => [p, p === 'site/lockers.py' ? `${c}def broken(:\n    pass\n` : c]);
    expect(verdicts(files, 'site/lockers.py')).toEqual([]);
  });

  it('a local the gate rebinds from the request is followed through every binding', () => {
    expect(verdicts(lockerApp(['tenant = Tenant.query.get(session["tenant_id"])', 'if not tenant:', '    tenant = request.args.get("t")', 'g.tenant = tenant']), 'site/lockers.py')).toEqual([]);
  });
});

const FASTAPI_HEAD = [
  'from fastapi import APIRouter, Depends, HTTPException',
  'from fastapi.security import OAuth2PasswordBearer',
  'from sqlalchemy.orm import Session',
  'from .models import Locker, Tenant',
  'from .database import get_db',
  'router = APIRouter()',
  'bearer = OAuth2PasswordBearer(tokenUrl="token")',
  'def signed_in(token: str = Depends(bearer), db: Session = Depends(get_db)):',
  '    who = db.get(Account, token)',
  '    if who is None:',
  '        raise HTTPException(status_code=401)',
  '    return who',
  '@router.delete("/lockers/{locker_id}")',
  'def clear_locker(locker_id: int, other_id: int = 0, member=Depends(signed_in), db: Session = Depends(get_db)):',
];
const fastapi = (...body: string[]): Files => [['svc/lockers.py', py(...FASTAPI_HEAD, ...body)]];
const fastVerdicts = (...body: string[]): string[] => verdicts(fastapi(...body), 'svc/lockers.py');

describe('job 8: a guard parameter or caller alias the handler rebinds is no longer the caller', () => {
  beforeAll(async () => { pythonReaderTesting.reset(); await preparePythonReader(); });
  afterAll(() => { releasePythonReader(); pythonReaderTesting.reset(); });

  const filtered = '    locker = db.query(Locker).filter(Locker.id == locker_id, Locker.tenant_id == member.id).first()';
  it('the parameter credits the filter; rebound before the delete, it does not', () => {
    expect(fastVerdicts(filtered, '    db.delete(locker)')).toEqual(['16:owned']);
    expect(fastVerdicts('    member = db.get(Tenant, other_id)', filtered, '    db.delete(locker)')).toEqual([]);
  });

  it('any binding on any path counts: a branch, a loop after the delete, with-as, a tuple, a walrus', () => {
    for (const rebind of [
      ['    if other_id:', '        member = db.get(Tenant, other_id)'],
      [],
      ['    with lock() as member:', '        pass'],
      ['    member, _ = db.get(Tenant, other_id), 1'],
      ['    if (member := db.get(Tenant, other_id)):', '        pass'],
    ]) {
      const after = rebind.length === 0 ? ['    for member in []:', '        pass'] : [];
      expect(fastVerdicts(...rebind, filtered, '    db.delete(locker)', ...after), rebind.join(' ') || 'loop after').toEqual([]);
    }
  });

  it('an alias of the caller credits; an alias rebound anywhere does not', () => {
    const aliasFilter = filtered.replace('member.id', 'me.id');
    expect(fastVerdicts('    me = member', aliasFilter, '    db.delete(locker)')).toEqual(['17:owned']);
    expect(fastVerdicts('    me = member', aliasFilter, '    db.delete(locker)', '    me = db.get(Tenant, other_id)')).toEqual([]);
  });

  it("flask_login's current_user rebound in the handler is not the caller", () => {
    const files = (extra: string[]): Files => [['site/lockers.py', py(
      'from flask import Blueprint',
      'from flask_login import current_user, login_required',
      'from . import db',
      'from .models import Locker, Tenant',
      'bp = Blueprint("lockers", __name__)',
      '@bp.delete("/<int:locker_id>")',
      '@login_required',
      'def clear_locker(locker_id):',
      ...extra,
      '    Locker.query.filter_by(id=locker_id, tenant_id=current_user.id).delete()',
    )]];
    expect(verdicts(files([]), 'site/lockers.py')).toEqual(['9:owned']);
    expect(verdicts(files(['    current_user = Tenant.query.get(locker_id)']), 'site/lockers.py')).toEqual([]);
  });

  it('without the reader, a guard parameter is no credit: the same delete is unclassified, never owned', () => {
    pythonReaderTesting.reset();
    expect(fastVerdicts(filtered, '    db.delete(locker)')).toEqual([]);
  });
});

describe('job 8: an owner check that refuses the owner is no ownership proof', () => {
  beforeAll(async () => { pythonReaderTesting.reset(); await preparePythonReader(); });
  afterAll(() => { releasePythonReader(); pythonReaderTesting.reset(); });

  const checked = (condition: string): string[] => fastVerdicts(
    '    locker = db.get(Locker, locker_id)',
    `    if ${condition}:`,
    '        raise HTTPException(status_code=403)',
    '    db.delete(locker)',
  );
  it('refusing when the attribute equals the caller reports; refusing when it differs is owned', () => {
    expect(checked('locker.tenant_id == member.id')).toEqual(['18:reported']);
    expect(checked('member.id == locker.tenant_id')).toEqual(['18:reported']);
    expect(checked('(locker.tenant_id == member.id)')).toEqual(['18:reported']);
    expect(checked('locker.tenant_id != member.id')).toEqual([]);
  });

  it('a condition with anything else in it stays as before (unread): a second test, or another operator', () => {
    expect(checked('locker.tenant_id == member.id and locker.shared')).toEqual([]);
    expect(checked('locker.tenant_id is member.id')).toEqual([]);
    expect(checked('locker.tenant_id == member.id == other_id')).toEqual([]);
  });

  it('a check that only returns, without refusing, is not read as refusing the owner', () => {
    expect(fastVerdicts(
      '    locker = db.get(Locker, locker_id)',
      '    if locker.tenant_id == member.id:',
      '        return {"kept": True}',
      '    db.delete(locker)',
    )).toEqual([]);
  });

  it('without the reader the inverted check keeps its old reading: unclassified', () => {
    pythonReaderTesting.reset();
    expect(checked('locker.tenant_id == member.id')).toEqual([]);
  });

  it('the rule reports the inverted check through the full rule too', async () => {
    pythonReaderTesting.reset();
    await preparePythonReader();
    const found = databaseDeleteWithoutOwnershipCheck.run(memoryContext(fastapi(
      '    locker = db.get(Locker, locker_id)',
      '    if locker.tenant_id == member.id:',
      '        raise HTTPException(status_code=403)',
      '    db.delete(locker)',
    ))).map((f) => `${f.filePath}:${f.lineStart}`);
    expect(found).toEqual(['svc/lockers.py:18']);
  });
});

describe('job 8: a model base is followed through its file\'s imports', () => {
  beforeAll(async () => { pythonReaderTesting.reset(); await preparePythonReader(); });
  afterAll(() => { releasePythonReader(); pythonReaderTesting.reset(); });

  const page = '<html><body><p>{{ thing.blurb|safe }}</p></body></html>\n';
  const APP_DB: [string, string] = ['app/__init__.py', py('from flask_sqlalchemy import SQLAlchemy', 'db = SQLAlchemy()')];
  const view = py(
    'from flask import render_template',
    'from .models import Card',
    'def open_card(card_no):',
    '    thing = Card.query.get_or_404(card_no)',
    '    return render_template("card.html", thing=thing)',
  );
  const lines = (models: string, extra: Files = []): string[] => crossSiteScripting.run(memoryContext([
    APP_DB, ['app/models.py', models], ['app/views.py', view], ['app/templates/card.html', page],
    ['app/notes.py', py('from app import db', 'class Note(db.Model):', '    blurb = db.Column(db.Text)')], ...extra,
  ])).filter((f) => f.filePath.endsWith('.html')).map((f) => `${f.filePath}:${f.lineStart}`);

  it('a base the file imports from a library, sharing a project class\'s name, is not that class', () => {
    const shelf: Files = [['app/shelf.py', py('from app import db', 'class Shelf(db.Model):', '    code = db.Column(db.Integer)')]];
    expect(lines(py('from app import db', 'from .shelf import Shelf', 'class Card(Shelf):', '    code = db.Column(db.Integer)'), shelf)).toEqual([]);
    expect(lines(py('from app import db', 'from vendor.records import Shelf', 'class Card(Shelf):', '    code = db.Column(db.Integer)'), shelf)).toEqual(['app/templates/card.html:1']);
  });

  it('a library root counts only when the import names that library', () => {
    expect(lines(py('from app import db', 'class Card(db.Model):', '    code = db.Column(db.Integer)'))).toEqual([]);
    expect(lines(py('from sqlalchemy.orm import DeclarativeBase', 'class Card(DeclarativeBase):', '    code = 1'))).toEqual([]);
    expect(lines(py('from mylib import DeclarativeBase', 'class Card(DeclarativeBase):', '    code = 1'))).toEqual(['app/templates/card.html:1']);
    expect(lines(py('from .extensions import db', 'class Card(db.Model):', '    code = 1'), [['app/extensions.py', py('db = make_db()')]])).toEqual(['app/templates/card.html:1']);
    expect(lines(py('from .extensions import db', 'class Card(db.Model):', '    code = 1'), [['app/extensions.py', py('from mylib import Database', 'db = Database()')]])).toEqual(['app/templates/card.html:1']);
    expect(lines(py('from .extensions import db', 'class Card(db.Model):', '    code = 1'), [['app/extensions.py', py('from flask_sqlalchemy import SQLAlchemy', 'db = SQLAlchemy(model_class=Base)')]])).toEqual(['app/templates/card.html:1']);
    expect(lines(py('from .extensions import db', 'class Card(db.Model):', '    code = 1'), [['app/extensions.py', py('from flask_sqlalchemy import SQLAlchemy', 'db = SQLAlchemy()')]])).toEqual([]);
  });

  it('a base bound inside a try, bound twice, or in a file that does not parse is unproven', () => {
    const shelf: Files = [['app/shelf.py', py('from app import db', 'class Shelf(db.Model):', '    code = db.Column(db.Integer)')]];
    expect(lines(py('from app import db', 'try:', '    from .shelf import Shelf', 'except ImportError:', '    Shelf = object', 'class Card(Shelf):', '    code = 1'), shelf)).toEqual(['app/templates/card.html:1']);
    expect(lines(py('from app import db', 'try:', '    from .shelf import Shelf', 'except ImportError:', '    pass', 'class Card(Shelf):', '    code = 1'), shelf)).toEqual(['app/templates/card.html:1']);
    expect(lines(py('from app import db', 'from .shelf import Shelf', 'class Card(Shelf):', '    code = 1'), shelf)).toEqual([]);
    expect(lines(py('from app import db', 'from .shelf import Shelf', 'from .other import Shelf', 'class Card(Shelf):', '    code = 1'), shelf)).toEqual(['app/templates/card.html:1']);
    expect(lines(py('from app import db', 'from .shelf import Shelf', 'class Card(Shelf):', '    code = 1', 'def broken(:', '    pass'), shelf)).toEqual(['app/templates/card.html:1']);
  });

  it('without the reader no base is followed: the name-only gate decides', () => {
    pythonReaderTesting.reset();
    expect(lines(py('from app import db', 'class Card(db.Model):', '    code = db.Column(db.Integer)'))).toEqual(['app/templates/card.html:1']);
  });
});
