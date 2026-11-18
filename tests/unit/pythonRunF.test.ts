import { describe, expect, it } from 'vitest';
import { openRedirect } from '../../src/rules/basic/openRedirect.js';
import { verboseErrorResponse } from '../../src/rules/basic/verboseErrorResponse.js';
import { crossSiteScripting } from '../../src/rules/basic/xss.js';
import { databaseDeleteWithoutOwnershipCheck } from '../../src/rules/contextual/databaseDeleteWithoutOwnershipCheck.js';
import { pythonHasBranches, pythonUrlHeadFixed } from '../../src/shared/pythonFlow.js';
import { pythonSqlTakesNothingFromOutside } from '../../src/shared/pythonSql.js';
import type { Finding, RuleContext } from '../../src/shared/types.js';
import { memoryContext } from './helpers.js';

type Files = [string, string][];
const py = (...lines: string[]): string => `${lines.join('\n')}\n`;
const rows = (rule: { run: (context: RuleContext) => Finding[] }, files: Files): Finding[] => rule.run(memoryContext(files));
const lines = (findings: Finding[]): number[] => findings.map((f) => f.lineStart).sort((a, b) => a - b);

describe('job F: a Flask redirect with a program-written head', () => {
  const go = (destination: string): number[] => lines(rows(openRedirect, [['app/main.py', py(
    'from flask import Flask, request, redirect',
    'app = Flask(__name__)',
    '@app.get("/go")',
    'def go():',
    `    return redirect(${destination})`,
  )]]));

  it('an f-string or a concatenation that opens with /items/ is not reported', () => {
    expect(go('f"/items/{request.args.get(\'next\')}"')).toEqual([]);
    expect(go('"/items/" + request.args.get("next", "")')).toEqual([]);
  });

  it('a bare "/" head, an f-string whose head is the request, or an absolute URL the request picks still reports', () => {
    expect(go('f"/{request.args.get(\'next\')}"')).toEqual([5]);
    expect(go('"/" + request.args.get("next", "")')).toEqual([5]);
    expect(go('f"{request.args.get(\'host\')}/items"')).toEqual([5]);
    expect(go('f"//{request.args.get(\'host\')}/items"')).toEqual([5]);
  });

  it('a fixed head on one arm of a conditional, or before an `or`, does not vouch for the other', () => {
    expect(go('f"/items/{request.args.get(\'id\')}" if request.args.get("id") else request.args.get("next")')).toEqual([5]);
    expect(go('"/items/" + request.args.get("id") or request.args.get("next")')).toEqual([5]);
    expect(go('"/items/" + request.args.get("id") and request.args.get("next")')).toEqual([5]);
  });

  it('the branch test reads only the top level, outside brackets and strings', () => {
    expect(pythonHasBranches('f"/items/{a if b else c}"')).toBe(false);
    expect(pythonHasBranches('"/items/" + pick(a or b)')).toBe(false);
    expect(pythonHasBranches('"if or else"')).toBe(false);
    expect(pythonHasBranches('a if b else c')).toBe(true);
    expect(pythonHasBranches('a or b')).toBe(true);
    expect(pythonHasBranches('lambda: a')).toBe(true);
  });

  it('the head test: fixed paths and hosts only', () => {
    expect(pythonUrlHeadFixed('f"/items/{x}"')).toBe(true);
    expect(pythonUrlHeadFixed('f"https://api.example/{x}"')).toBe(true);
    expect(pythonUrlHeadFixed('f"/{x}"')).toBe(false);
    expect(pythonUrlHeadFixed('f"/\\\\{x}"')).toBe(false);
    expect(pythonUrlHeadFixed('f"{base}/x"')).toBe(false);
    expect(pythonUrlHeadFixed('x')).toBe(false);
    expect(pythonUrlHeadFixed('f"/items/{x}" if c else y')).toBe(false);
    expect(pythonUrlHeadFixed('')).toBe(false);
  });
});

describe('job F: a validation message written on the lines below `raise X(`', () => {
  const view = (raise: string[], extra: string[] = []): Files => [['app/main.py', py(
    'from flask import Flask, request, jsonify',
    'app = Flask(__name__)',
    ...extra,
    'def parse_code(text):',
    '    if not text.isalnum():',
    ...raise,
    '    return text.upper()',
    '@app.post("/codes")',
    'def make_code():',
    '    data = request.get_json()',
    '    try:',
    '        code = parse_code("abc")',
    '    except ValueError as e:',
    '        return jsonify({"error": str(e)}), 400',
    '    return jsonify({"code": code})',
  )]];

  it('a literal or an f-string on the next lines is the app\'s own message', () => {
    expect(rows(verboseErrorResponse, view(['        raise ValueError(', '            "code must be letters and digits"', '        )']))).toEqual([]);
    expect(rows(verboseErrorResponse, view(['        raise ValueError(', '            f"not a code: {text!r}"', '        )']))).toEqual([]);
    expect(rows(verboseErrorResponse, view(['        raise ValueError(', '            "code must be "', '            "letters and digits",', '        )']))).toEqual([]);
  });

  it('a name, a call or an operator in the brackets is not', () => {
    expect(rows(verboseErrorResponse, view(['        raise ValueError(', '            text', '        )'])).length).toBe(1);
    expect(rows(verboseErrorResponse, view(['        raise ValueError(', '            describe(text)', '        )'])).length).toBe(1);
    expect(rows(verboseErrorResponse, view(['        raise ValueError(', '            "bad: " + text', '        )'])).length).toBe(1);
    expect(rows(verboseErrorResponse, view(['        raise ValueError(', '        )'])).length).toBe(1);
    expect(rows(verboseErrorResponse, view(['        raise ValueError(text,', '            "more")'])).length).toBe(1);
  });

  it('the deeper read is bounded: past 200 defs nothing is proved', () => {
    const chain: string[] = [];
    for (let i = 0; i < 205; i += 1) chain.push(`def step_${i}(text):`, `    return step_${i + 1}(text)`);
    chain.push('def step_205(text):', '    return text');
    const calls = ['        raise ValueError("code must be letters and digits")', '    step_0(text)'];
    expect(rows(verboseErrorResponse, view(calls, chain)).length).toBe(1);
    const short = chain.slice(-6).map((line) => line.replace('step_203', 'step_0'));
    expect(rows(verboseErrorResponse, view(calls, short))).toEqual([]);
  });

  it('a project function the helper names that raises a handled class without a written message withdraws the credit', () => {
    const deeper = ['def check_text(text):', '    if not text:', '        raise ValueError(text)', '    return text'];
    const calls = ['        raise ValueError("code must be letters and digits")', '    check_text(text)'];
    expect(rows(verboseErrorResponse, view(calls, deeper)).length).toBe(1);
    const passed = ['        raise ValueError("code must be letters and digits")', '    run(check_text, text)'];
    expect(rows(verboseErrorResponse, view(passed, deeper)).length).toBe(1);
    const twoDown = [...deeper, 'def tidy(text):', '    return check_text(text)'];
    const viaTidy = ['        raise ValueError("code must be letters and digits")', '    tidy(text)'];
    expect(rows(verboseErrorResponse, view(viaTidy, twoDown)).length).toBe(1);
    const reraise = ['def check_text(text):', '    try:', '        return text.strip()', '    except AttributeError:', '        raise'];
    expect(rows(verboseErrorResponse, view(calls, reraise)).length).toBe(1);
  });

  it('a deeper function whose raises are all written keeps the credit', () => {
    const deeper = ['def check_text(text):', '    if not text:', '        raise ValueError("text is required")', '    return text'];
    const calls = ['        raise ValueError("code must be letters and digits")', '    check_text(text)'];
    expect(rows(verboseErrorResponse, view(calls, deeper))).toEqual([]);
  });
});

describe('job F: a plain SQL delete that takes nothing from outside its function', () => {
  const app = (helper: string[], call: string): Files => [['app/main.py', py(
    'import sqlite3, time',
    'from flask import Flask, request, jsonify, session, abort',
    'app = Flask(__name__)',
    'KEEP_SECONDS = 7 * 86400  # a week',
    'def get_db():',
    '    return sqlite3.connect("app.db")',
    ...helper,
    '@app.post("/tidy")',
    'def tidy():',
    '    if not session.get("uid"):',
    '        abort(401)',
    `    ${call}`,
    '    return jsonify(ok=True)',
  )]];
  const count = (helper: string[], call = 'prune(get_db())'): number => rows(databaseDeleteWithoutOwnershipCheck, app(helper, call)).length;

  it('values only the clock and constants chose are not reported', () => {
    expect(count(['def prune(db):', '    now = time.time()', '    db.execute("DELETE FROM nonces WHERE expires_at < ?", (now - KEEP_SECONDS,))'])).toBe(0);
    expect(count(['def prune(db):', '    db.execute("DELETE FROM nonces WHERE expires_at < ?", [int(time.time()) - 3600])'])).toBe(0);
  });

  it('attempt 2: a fixed WHERE is quiet only because no request reaches it', () => {
    const fixed = ['def prune(db):', '    db.execute("DELETE FROM flags WHERE key IN (\'a\', \'b\')")'];
    expect(count(fixed, 'pass')).toBe(0);
    expect(count(fixed)).toBe(1);
  });

  it('a value from a parameter, a request, or a binding the reader does not follow still reports', () => {
    expect(count(['def prune(db, record_id):', '    db.execute("DELETE FROM items WHERE id = ?", (record_id,))'], 'prune(get_db(), request.args.get("id"))')).toBe(1);
    expect(count(['def prune(db, record_id):', '    cutoff = record_id', '    db.execute("DELETE FROM items WHERE id < ?", (cutoff,))'], 'prune(get_db(), request.args.get("id"))')).toBe(1);
    expect(count(['def prune(db, record_id):', '    db.execute("DELETE FROM items WHERE id = ?", record_id)'], 'prune(get_db(), request.args.get("id"))')).toBe(1);
    expect(count(['def prune(db, when):', '    now = time.time()', '    if when:', '        now = when', '    db.execute("DELETE FROM nonces WHERE expires_at < ?", (now,))'], 'prune(get_db(), request.args.get("t"))')).toBe(1);
    expect(count(['def prune(db, when):', '    now = time.time()', '    if when: now = when', '    db.execute("DELETE FROM nonces WHERE expires_at < ?", (now,))'], 'prune(get_db(), request.args.get("t"))')).toBe(1);
    expect(count(['def prune(db, now):', '    db.execute("DELETE FROM nonces WHERE expires_at < ?", (now,))'], 'prune(get_db(), request.args.get("t"))')).toBe(1);
    expect(count(['def prune(db, when):', '    now = time.time()', '    now -= when', '    db.execute("DELETE FROM nonces WHERE expires_at < ?", (now,))'], 'prune(get_db(), request.args.get("t"))')).toBe(1);
    expect(count(['def prune(db, rows):', '    for now in rows:', '        db.execute("DELETE FROM nonces WHERE expires_at < ?", (now,))'], 'prune(get_db(), request.json)')).toBe(1);
    expect(count(['def prune(db, record_id):', '    db.execute("DELETE FROM items WHERE id = " + record_id)'], 'prune(get_db(), request.args.get("id"))')).toBe(1);
    expect(count(['def prune(db, record_id):', '    db.execute("DELETE FROM nonces WHERE id = " + record_id + " AND expires_at < ?", (time.time(),))'], 'prune(get_db(), request.args.get("id"))')).toBe(1);
    expect(count(['def prune(db, now):', '    if not now:', '        now = time.time()', '    db.execute("DELETE FROM nonces WHERE expires_at < ?", (now,))'], 'prune(get_db(), request.args.get("t"))')).toBe(1);
    expect(count(['def prune(db, source):', '    now = time.time()', '    with source.open() as now:', '        db.execute("DELETE FROM nonces WHERE expires_at < ?", (now,))'], 'prune(get_db(), request.files["f"])')).toBe(1);
    expect(count(['def prune(db, days):', '    cut = datetime.now(timezone.utc) - timedelta(days=days)', '    db.execute("DELETE FROM nonces WHERE expires_at < ?", (cut,))'], 'prune(get_db(), request.args.get("d"))')).toBe(1);
    expect(count(['def prune(db):', '    now = time.time()', '    db.execute("DELETE FROM nonces WHERE expires_at < ?", now)'])).toBe(1);
  });

  it('timedelta and datetime readings with code-chosen arguments are the clock', () => {
    expect(count(['def prune(db):', '    cut = datetime.now(timezone.utc) - timedelta(days=30)', '    db.execute("DELETE FROM nonces WHERE expires_at < ?", (cut.isoformat(),))'])).toBe(1);
    expect(count(['def prune(db):', '    cut = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()', '    db.execute("DELETE FROM nonces WHERE expires_at < ?", (cut,))'])).toBe(1);
    expect(count(['def prune(db):', '    cut = datetime.now(timezone.utc) - timedelta(days=30)', '    db.execute("DELETE FROM nonces WHERE expires_at < ?", (cut,))'])).toBe(0);
  });

  it('a placeholder with nothing bound, a keyword argument, or a third argument is not proved', () => {
    expect(count(['def prune(db):', '    db.execute("DELETE FROM items WHERE id = ?")'])).toBe(1);
    expect(count(['def prune(db):', '    db.execute("DELETE FROM items WHERE id < :cut", params={"cut": 1})'])).toBe(1);
    expect(count(['def prune(db):', '    db.execute("DELETE FROM items WHERE id < ?", (time.time(),), 5)'])).toBe(1);
  });

  it('the SQL literal must be the first argument of an execute call', () => {
    const at = (code: string): boolean => pythonSqlTakesNothingFromOutside(code, code.indexOf('DELETE'));
    expect(at(py('def f(db):', '    db.execute("DELETE FROM a WHERE b < ?", (time.time(),))'))).toBe(true);
    expect(at(py('def f(db):', '    db.execute("DELETE FROM a WHERE b < ?", [time.time() - 60])'))).toBe(true);
    expect(at(py('def f(db):', '    db.executemany("DELETE FROM a WHERE b < ?", (time.time(),))'))).toBe(true);
    expect(at(py('def f(db):', '    db.executemany("DELETE FROM a WHERE b < ?", [(time.time(),)])'))).toBe(false);
    expect(at(py('def f(db):', '    q = "DELETE FROM a WHERE b < ?"', '    db.execute(q, (time.time(),))'))).toBe(false);
    expect(at(py('def f(db):', '    log("DELETE FROM a WHERE b < ?", (time.time(),))'))).toBe(false);
    expect(at(py('db.execute("DELETE FROM a WHERE b < ?", (time.time(),))'))).toBe(false);
    expect(at(py('def f(db):', '    db.execute("DELETE FROM a WHERE b = 1")'))).toBe(false);
    expect(at(py('def f(db):', '    db.execute("DELETE FROM a WHERE b = ?", [1])'))).toBe(false);
    expect(at(py('def f(db):', '    db.executemany("DELETE FROM a WHERE b = ?", (2,))'))).toBe(false);
  });
});

describe('job F, attempt 2: a signed-in route that removes shared rows by a fixed condition', () => {
  const route = (...body: string[]): number => rows(databaseDeleteWithoutOwnershipCheck, [['app/main.py', py(
    'import sqlite3, time',
    'from flask import Flask, request, jsonify, session, abort',
    'app = Flask(__name__)',
    'KEEP_SECONDS = 7 * 86400',
    'STARTED = time.time()',
    'def get_db():',
    '    return sqlite3.connect("app.db")',
    '@app.post("/clear")',
    'def clear():',
    '    if not session.get("uid"):',
    '        abort(401)',
    '    db = get_db()',
    ...body.map((l) => `    ${l}`),
    '    db.commit()',
    '    return jsonify(ok=True)',
  )]]).length;

  it('a fixed WHERE with nothing bound reports: every signed-in user wipes every user\'s rows', () => {
    expect(route('db.execute("DELETE FROM tasks WHERE done = 1")')).toBe(1);
  });

  it('a placeholder bound only to constants reports', () => {
    expect(route('db.execute("DELETE FROM tasks WHERE done = ?", (1,))')).toBe(1);
    expect(route('db.execute("DELETE FROM tasks WHERE done = ?", [KEEP_SECONDS])')).toBe(1);
  });

  it('the clock-bound retention twin stays quiet', () => {
    expect(route('now = time.time()', 'db.execute("DELETE FROM nonces WHERE expires_at < ?", (now - KEEP_SECONDS,))')).toBe(0);
    expect(route('now = time.time()', 'now = now - KEEP_SECONDS', 'db.execute("DELETE FROM nonces WHERE expires_at < ?", (now,))')).toBe(0);
  });

  it('a clock reading on only some paths, or held by a module constant, is not proved', () => {
    expect(route('now = time.time()', 'if request.args.get("all"):', '    now = 0', 'db.execute("DELETE FROM nonces WHERE expires_at < ?", (now,))')).toBe(1);
    expect(route('db.execute("DELETE FROM nonces WHERE expires_at < ?", (time.time() if request.args.get("all") else 0,))')).toBe(1);
    expect(route('db.execute("DELETE FROM nonces WHERE expires_at < ?", (STARTED,))')).toBe(1);
  });

  it('a parameter given a constant when empty is still the caller\'s, beside a clock reading', () => {
    expect(rows(databaseDeleteWithoutOwnershipCheck, [['app/main.py', py(
      'import sqlite3, time',
      'from flask import Flask, request, jsonify, session, abort',
      'app = Flask(__name__)',
      'def prune(db, when):',
      '    if not when:',
      '        when = 0',
      '    now = time.time()',
      '    db.execute("DELETE FROM nonces WHERE expires_at < ?", (now - when,))',
      '@app.post("/tidy")',
      'def tidy():',
      '    if not session.get("uid"):',
      '        abort(401)',
      '    prune(sqlite3.connect("app.db"), request.args.get("t"))',
      '    return jsonify(ok=True)',
    )]]).length).toBe(1);
  });
});

describe('job F: an element given back its own markup, renumbered', () => {
  const page = (script: string[]): Files => [
    ['app.py', py('from flask import Flask', 'app = Flask(__name__)')],
    ['templates/page.html', ['<html><body><div id="box"></div><script>', ...script, '</script></body></html>', ''].join('\n')],
  ];
  const xss = (script: string[]): number => rows(crossSiteScripting, page(script)).length;

  it('the same element\'s innerHTML with a computed number put in is inert', () => {
    expect(xss(['function addRow(box, total) {', '  const n = parseInt(total.value);', '  const row = box.firstElementChild.cloneNode(true);', '  row.innerHTML = row.innerHTML.replace(/row-(\\d+)-/g, `row-${n}-`);', '}'])).toBe(0);
    expect(xss(['function addRow(row) {', "  row.innerHTML = row.innerHTML.replace(/__prefix__/g, 'new-1');", '}'])).toBe(0);
  });

  it('a group reference, a typed value, markup in the replacement, or another element\'s markup is not', () => {
    expect(xss(['function decode(box) {', '  box.innerHTML = box.innerHTML.replace(/&lt;(b)&gt;/g, `<$1>`);', '}'])).toBe(1);
    expect(xss(['function decode(box) {', "  box.innerHTML = box.innerHTML.replace(/x/g, '$&');", '}'])).toBe(1);
    expect(xss(['function rename(box, input) {', '  box.innerHTML = box.innerHTML.replace(/row-(\\d+)-/g, `row-${input.value}-`);', '}'])).toBe(1);
    expect(xss(['function bold(box) {', "  box.innerHTML = box.innerHTML.replace(/x/g, '<b>x</b>');", '}'])).toBe(1);
    expect(xss(['function copy(box, other) {', '  const n = parseInt(other.dataset.n);', '  box.innerHTML = other.innerHTML.replace(/x/g, `${n}`);', '}'])).toBe(1);
    expect(xss(['function swap(box) {', '  box.innerHTML = box.innerHTML.replace(/x/g, (m) => m);', '}'])).toBe(1);
    expect(xss(['function swap(box, label) {', '  box.innerHTML = box.innerHTML.replace(/x/g, label);', '}'])).toBe(1);
    expect(xss(['function swap(box, label) {', "  box.innerHTML = box.innerHTML.replace(/x/g, '1', label);", '}'])).toBe(1);
  });

  it('a local that only ever holds a computed number is inert; one written again, or shadowed, is not', () => {
    expect(xss(['function show(box, data) {', '  const shown = parseInt(data.count);', '  box.innerHTML = `<b>${shown}</b> items`;', '}'])).toBe(0);
    expect(xss(['function show(box, data) {', '  let shown = parseInt(data.count);', '  shown = data.label;', '  box.innerHTML = `<b>${shown}</b>`;', '}'])).toBe(1);
    expect(xss(['function show(box, data) {', '  let shown = parseInt(data.count);', '  shown += data.label;', '  box.innerHTML = `<b>${shown}</b>`;', '}'])).toBe(1);
    expect(xss(['const shown = parseInt(document.body.dataset.n);', 'function show(box, shown) {', '  box.innerHTML = `<b>${shown}</b>`;', '}'])).toBe(1);
    expect(xss(['const shown = parseInt(document.body.dataset.n);', 'const show = (box, shown) => { box.innerHTML = `<b>${shown}</b>`; };'])).toBe(1);
    expect(xss(['function show(box, data) {', '  const shown = data.count;', '  box.innerHTML = `<b>${shown}</b>`;', '}'])).toBe(1);
    expect(xss(['function a(box, data) { const shown = parseInt(data.n); }', 'function b(box, data) { const shown = data.label; box.innerHTML = `<b>${shown}</b>`; }'])).toBe(1);
    expect(xss(['function show(box, data) {', '  let shown = parseInt(data.count);', '  for (shown of data.labels) {}', '  box.innerHTML = `<b>${shown}</b>`;', '}'])).toBe(1);
  });

  it('a JavaScript-only project keeps today\'s behaviour (the credit is scoped to projects with Python)', () => {
    const js: Files = [['public/page.html', ['<html><body><script>', 'function addRow(row, total) {', '  const n = parseInt(total.value);', '  row.innerHTML = row.innerHTML.replace(/row-(\\d+)-/g, `row-${n}-`);', '}', '</script></body></html>', ''].join('\n')]];
    expect(rows(crossSiteScripting, js).length).toBe(1);
  });
});
