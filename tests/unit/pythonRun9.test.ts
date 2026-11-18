import { describe, expect, it } from 'vitest';
import { pythonDependencyAliases, pythonValueReaches } from '../../src/shared/pythonFlow.js';
import { sqlInjection } from '../../src/rules/basic/sqlInjection.js';
import { pathTraversal } from '../../src/rules/basic/pathTraversal.js';
import { serverSideRequestForgery } from '../../src/rules/basic/ssrf.js';
import { openRedirect } from '../../src/rules/basic/openRedirect.js';
import { verboseErrorResponse } from '../../src/rules/basic/verboseErrorResponse.js';
import type { ScanRule } from '../../src/shared/types.js';
import { memoryContext } from './helpers.js';

const py = (...lines: string[]): string => `${lines.join('\n')}\n`;

const FASTAPI = ['from fastapi import APIRouter, Depends, Query', 'router = APIRouter()', ''];

function reaches(code: string, opts: Parameters<typeof pythonValueReaches>[3] = {}): boolean {
  const at = code.lastIndexOf('sink(');
  if (at < 0) throw new Error('no sink');
  const open = at + 4;
  let depth = 0;
  let close = open;
  for (let i = open; i < code.length; i += 1) {
    if (code[i] === '(') depth += 1;
    if (code[i] === ')') { depth -= 1; if (depth === 0) { close = i; break; } }
  }
  return pythonValueReaches(code, open + 1, close, opts);
}

function lines(rule: ScanRule, files: [string, string][], file: string): number[] {
  return rule.run(memoryContext(files)).filter((f) => f.filePath === file).map((f) => f.lineStart).sort((a, b) => a - b);
}

describe('job 9: sources', () => {
  const direct = ['request.args["w"]', 'request.form.get("w")', 'request.values["w"]', 'request.json["w"]', 'request.get_json()["w"]',
    'request.GET.get("w")', 'request.POST["w"]', 'request.data["w"]', 'request.query_params.get("w")', 'self.request.query_params["w"]',
    'request.files["w"].filename'];
  for (const source of direct) {
    it(`${source} is a source`, () => {
      expect(reaches(py('def view(request):', `    colour = ${source}`, '    sink(colour)'))).toBe(true);
    });
  }
  it('strict twin: request.user and request.method are not sources', () => {
    expect(reaches(py('def view(request):', '    colour = request.user.username', '    sink(colour)'))).toBe(false);
    expect(reaches(py('def view(request):', '    colour = request.method', '    sink(colour)'))).toBe(false);
  });

  it('a FastAPI route parameter is a source', () => {
    expect(reaches(py(...FASTAPI, '@router.get("/w")', 'def view(colour: str):', '    sink(colour)'))).toBe(true);
    expect(reaches(py(...FASTAPI, '@router.get("/w")', 'def view(colour: str = Query("red")):', '    sink(colour)'))).toBe(true);
  });
  it('a FastAPI body model parameter is a source, and so are its fields', () => {
    expect(reaches(py(...FASTAPI, 'class Shape(BaseModel):', '    link: str', '', '@router.post("/w")', 'async def view(shape: Shape):', '    sink(str(shape.link))'))).toBe(true);
  });
  it('strict twin: the same function without a route decorator has no parameter sources', () => {
    expect(reaches(py(...FASTAPI, 'def view(colour: str):', '    sink(colour)'))).toBe(false);
  });
  it('strict twin: a Flask view parameter is not a FastAPI source', () => {
    expect(reaches(py('from flask import Blueprint', 'bp = Blueprint("w", __name__)', '@bp.get("/<colour>")', 'def view(colour):', '    sink(colour)'))).toBe(false);
  });
  it('a dependency, a framework object or a converted type is not a parameter source', () => {
    const route = (param: string): string => py(...FASTAPI, '@router.get("/w/{n}")', `def view(${param}):`, '    sink(colour)');
    expect(reaches(route('colour: str = Depends(load)'))).toBe(false);
    expect(reaches(route('colour: Annotated[str, Depends(load)]'))).toBe(false);
    expect(reaches(route('colour: Request'))).toBe(false);
    expect(reaches(route('colour: int'))).toBe(false);
    expect(reaches(route('colour: Optional[int] = None'))).toBe(false);
    expect(reaches(route('colour: str'))).toBe(true);
  });
  it('an Annotated dependency alias is not a source, in this module or anywhere in the project', () => {
    const local = py(...FASTAPI, 'Painter = Annotated[object, Depends(load)]', '', '@router.get("/w")', 'def view(colour: Painter):', '    sink(colour.base)');
    expect(reaches(local)).toBe(false);
    const route = py(...FASTAPI, '@router.get("/w")', 'def view(colour: Painter):', '    sink(colour.base)');
    const deps = py('from typing import Annotated', 'from fastapi import Depends', 'Painter = Annotated[object, Depends(load)]');
    const aliases = pythonDependencyAliases([{ extension: '.py', content: deps }, { extension: '.py', content: route }]);
    expect(reaches(route, { aliases })).toBe(false);
    expect(reaches(route)).toBe(true);
  });
});

describe('job 9: steps', () => {
  const SRC = '    colour = request.args["w"]';
  const step = (...body: string[]): boolean => reaches(py('def view():', SRC, ...body));
  it('assignment, chained and tuple assignment, annotation', () => {
    expect(step('    shade = colour', '    sink(shade)')).toBe(true);
    expect(step('    a = b = colour', '    sink(b)')).toBe(true);
    expect(step('    a, b = colour, 1', '    sink(a)')).toBe(true);
    expect(step('    shade: str = colour', '    sink(shade)')).toBe(true);
  });
  it('augmented assignment', () => {
    expect(step('    shade = "x"', '    shade += colour', '    sink(shade)')).toBe(true);
  });
  it('f-strings, %, .format, + and join', () => {
    expect(step('    sink(f"a {colour} b")')).toBe(true);
    expect(step('    sink("a %s" % colour)')).toBe(true);
    expect(step('    sink("a {}".format(colour))')).toBe(true);
    expect(step('    sink("a " + colour)')).toBe(true);
    expect(step('    sink(",".join([colour, "x"]))')).toBe(true);
  });
  it('a method on a followed value, str(), os.path.join and Path', () => {
    expect(step('    sink(colour.strip().lower())')).toBe(true);
    expect(step('    sink(str(colour))')).toBe(true);
    expect(step('    sink(os.path.join(BASE, colour))')).toBe(true);
    expect(step('    sink(Path(BASE) / colour)')).toBe(true);
  });
  it('a for target over a followed value', () => {
    expect(step('    for part in colour.split(","):', '        sink(part)')).toBe(true);
  });
  it('a multi-line header whose closing parenthesis is in column 0', () => {
    expect(reaches(py(...FASTAPI, '@router.get("/w")', 'def view(', '    colour: str,', '    other: int = 1,', '):', '    sink(f"{colour}")'))).toBe(true);
  });
  it('strict twins: what is not followed keeps today\'s behaviour (no claim)', () => {
    expect(step('    sink(clean(colour))')).toBe(false);
    expect(step('    self.shade = colour', '    sink(self.shade)')).toBe(false);
    expect(step('    sink(lambda: colour)')).toBe(false);
    expect(step('    sink(SHADES[colour])')).toBe(false);
    expect(step('    shade = "1" if colour == "a" else "0"', '    sink(shade)')).toBe(false);
  });
  it('a straight-line re-binding to a literal ends the flow; one inside a branch does not', () => {
    expect(step('    colour = "red"', '    sink(colour)')).toBe(false);
    expect(step('    if ready:', '        colour = "red"', '    sink(colour)')).toBe(true);
  });
  it('an allow-list choice carries only its else side', () => {
    expect(step('    shade = colour if colour in ALLOWED else "red"', '    sink(shade)')).toBe(false);
    expect(step('    shade = colour if colour in ALLOWED else colour', '    sink(shade)')).toBe(true);
  });
  it('a nested def has its own scope', () => {
    expect(reaches(py('def view():', '    def inner():', '        colour = request.args["w"]', '    sink(colour)'))).toBe(false);
  });
});

describe('job 9: head mode (where the request or browser goes)', () => {
  const SRC = '    colour = request.args["w"]';
  const head = (expr: string): boolean => reaches(py('def view():', SRC, `    sink(${expr})`), { head: true });
  it('a value in the head is followed', () => {
    expect(head('colour')).toBe(true);
    expect(head('f"{colour}/x"')).toBe(true);
    expect(head('f"https://{colour}/x"')).toBe(true);
    expect(head('"http://" + colour')).toBe(true);
  });
  it('strict twins: a value only after a fixed head is not', () => {
    expect(head('f"{BASE}/{colour}"')).toBe(false);
    expect(head('f"/items/{colour}"')).toBe(false);
    expect(head('f"https://api.example.org/{colour}"')).toBe(false);
    expect(head('BASE + "/x/" + colour')).toBe(false);
    expect(head('f"//{colour}"')).toBe(true);
  });
  it('attempt 2: a head of one bare "/" (or "/" then "\\") is not fixed', () => {
    expect(head('f"/{colour}"')).toBe(true);
    expect(head('"/" + colour')).toBe(true);
    expect(head('f"/\\\\{colour}"')).toBe(true);
    expect(head('f"/i/{colour}"')).toBe(false);
  });
  it('an assignment carries the head, and += never moves it', () => {
    expect(reaches(py('def view():', SRC, '    target = f"{BASE}/{colour}"', '    target += colour', '    sink(target)'), { head: true })).toBe(false);
    expect(reaches(py('def view():', SRC, '    target = f"{colour}/x"', '    sink(target)'), { head: true })).toBe(true);
  });
});

describe('job 9: a check the reader cannot judge keeps today\'s behaviour', () => {
  const SRC = '    colour = request.args["w"]';
  it('a sink inside a block whose condition passes the value to a project function', () => {
    expect(reaches(py('def view():', SRC, '    if colour and allowed(colour):', '        sink(colour)'))).toBe(false);
    expect(reaches(py('def view():', SRC, '    if not allowed(colour):', '        raise Refused()', '    sink(colour)'))).toBe(false);
  });
  it('strict twins: a method, a module function, a builtin, or a call on another value is not such a check', () => {
    expect(reaches(py('def view():', SRC, '    if colour.startswith("/"):', '        sink(colour)'))).toBe(true);
    expect(reaches(py('def view():', SRC, '    if os.path.exists(colour):', '        sink(colour)'))).toBe(true);
    expect(reaches(py('def view():', SRC, '    if len(colour) < 9:', '        sink(colour)'))).toBe(true);
    expect(reaches(py('def view():', SRC, '    if allowed(other):', '        sink(colour)'))).toBe(true);
    expect(reaches(py('def view():', SRC, '    if not allowed(colour):', '        log(colour)', '    sink(colour)'))).toBe(true);
  });
});

describe('job 9: sql_injection', () => {
  const FILE = 'app/views.py';
  const view = (...body: string[]): [string, string][] => [[FILE, py('from django.db import connection', '', 'def report(request):', '    shade = request.GET.get("shade", "")', ...body)]];
  it('cursor.execute with % on a followed value reports', () => {
    expect(lines(sqlInjection, view('    with connection.cursor() as cursor:', '        cursor.execute("SELECT id FROM paint WHERE shade = \'%s\'" % shade)'), FILE)).toEqual([6]);
  });
  it('strict twin: the value passed as a bound parameter does not', () => {
    expect(lines(sqlInjection, view('    with connection.cursor() as cursor:', '        cursor.execute("SELECT id FROM paint WHERE shade = %s", (shade,))'), FILE)).toEqual([]);
  });
  it('a session execute of SQLAlchemy text() on an f-string reports', () => {
    expect(lines(sqlInjection, view('    rows = db.session.execute(', '        text(f"SELECT id FROM paint WHERE shade = \'{shade}\'")', '    )'), FILE)).toEqual([5]);
  });
  it('strict twin: text() with a bound name does not', () => {
    expect(lines(sqlInjection, view('    rows = db.session.execute(', '        text("SELECT id FROM paint WHERE shade = :shade"), {"shade": shade}', '    )'), FILE)).toEqual([]);
  });
  it('a QuerySet .extra(where=[...]) built from a followed value reports', () => {
    expect(lines(sqlInjection, view('    return Paint.objects.filter(owner=request.user).extra(where=[f"shade = \'{shade}\'"])'), FILE)).toEqual([5]);
  });
  it('strict twin: .extra with params does not', () => {
    expect(lines(sqlInjection, view('    return Paint.objects.extra(where=["shade = %s"], params=[shade])'), FILE)).toEqual([]);
  });
  it('a manager method given SQL text built from a followed value reports', () => {
    expect(lines(sqlInjection, view('    return Paint.objects.custom_query(f"SELECT id FROM paint WHERE shade = \'{shade}\'")'), FILE)).toEqual([5]);
  });
  it('strict twin: a manager method given a non-SQL string does not', () => {
    expect(lines(sqlInjection, view('    return Paint.objects.label_for(f"shade {shade}")'), FILE)).toEqual([]);
  });
  it('a FastAPI str parameter in an f-string reports; an int parameter does not', () => {
    const route = (param: string): [string, string][] => [['app/api.py', py(...FASTAPI, '@router.get("/paint")', `def lookup(${param}):`, '    return conn.execute(f"SELECT id FROM paint WHERE shade = \'{shade}\'").fetchall()')]];
    expect(lines(sqlInjection, route('shade: str'), 'app/api.py')).toEqual([6]);
    expect(lines(sqlInjection, route('shade: int'), 'app/api.py')).toEqual([]);
  });
});

describe('job 9: path_traversal', () => {
  const FILE = 'app/files.py';
  it('FileResponse of a followed path reports', () => {
    expect(lines(pathTraversal, [[FILE, py(...FASTAPI, 'from fastapi.responses import FileResponse', '@router.get("/f/{fname}")', 'async def fetch(fname: str):', '    return FileResponse(f"{ROOT}/{fname}")')]], FILE)).toEqual([7]);
  });
  it('strict twin: FileResponse of a path with no followed value does not', () => {
    expect(lines(pathTraversal, [[FILE, py(...FASTAPI, 'from fastapi.responses import FileResponse', '@router.get("/f/{fname}")', 'async def fetch(fname: str):', '    return FileResponse(f"{ROOT}/fixed.pdf")')]], FILE)).toEqual([]);
  });
  it('a secure_filename() in the neighbouring function no longer credits a followed path', () => {
    const file = py(
      'from flask import request, send_file',
      'from werkzeug.utils import secure_filename',
      'def put_one():',
      '    f = request.files["f"]',
      '    f.save(os.path.join(ROOT, secure_filename(f.filename)))',
      '',
      'def get_one():',
      '    fname = request.args["fname"]',
      '    return send_file(os.path.join(ROOT, fname))',
    );
    expect(lines(pathTraversal, [[FILE, file]], FILE)).toEqual([9]);
  });
  it('strict twin: secure_filename() in the same function still credits', () => {
    const file = py(
      'from flask import request, send_file',
      'from werkzeug.utils import secure_filename',
      'def get_one():',
      '    fname = secure_filename(request.args["fname"])',
      '    return send_file(os.path.join(ROOT, fname))',
    );
    expect(lines(pathTraversal, [[FILE, file]], FILE)).toEqual([]);
  });
  it('an is_relative_to() check that refuses credits the followed path', () => {
    const route = (check: string): [string, string][] => [[FILE, py(...FASTAPI, 'from fastapi.responses import FileResponse', '@router.get("/f/{fname}")', 'async def fetch(fname: str):',
      '    target = (ROOT / fname).resolve()', check, '        raise HTTPException(status_code=404)', '    return FileResponse(target)')]];
    expect(lines(pathTraversal, route('    if not target.is_relative_to(ROOT):'), FILE)).toEqual([]);
    expect(lines(pathTraversal, route('    if not target.is_file():'), FILE)).toEqual([10]);
  });
});

describe('job 9: ssrf', () => {
  const FILE = 'app/fetch.py';
  it('a client object\'s get() on a followed URL reports', () => {
    const file = py(...FASTAPI, 'import httpx', '@router.post("/peek")', 'async def peek(link: str):', '    async with httpx.AsyncClient(timeout=5) as client:', '        resp = await client.get(link)', '    return resp.text');
    expect(lines(serverSideRequestForgery, [[FILE, file]], FILE)).toEqual([8]);
  });
  it('strict twin: the same client on a fixed URL does not', () => {
    const file = py(...FASTAPI, 'import httpx', '@router.post("/peek")', 'async def peek(link: str):', '    async with httpx.AsyncClient(timeout=5) as client:', '        resp = await client.get("https://api.example.org/status")', '    return resp.text');
    expect(lines(serverSideRequestForgery, [[FILE, file]], FILE)).toEqual([]);
  });
  it('requests.get of a Django POST value reports; a value only in the path after a fixed host does not', () => {
    const view = (url: string): [string, string][] => [[FILE, py('import requests', 'def pull(request):', '    link = request.POST["link"]', `    return requests.get(${url}, timeout=5)`)]];
    expect(lines(serverSideRequestForgery, view('link'), FILE)).toEqual([4]);
    expect(lines(serverSideRequestForgery, view('f"{API_BASE}/items/{link}"'), FILE)).toEqual([]);
  });
  it('a host allow-list check on the same parsed URL that refuses credits it', () => {
    const view = (check: string): [string, string][] => [[FILE, py('import requests', 'def pull(request):', '    link = request.POST["link"]', '    parsed = urlparse(link)', check, '        return HttpResponseBadRequest("no")', '    return requests.get(link, timeout=5)')]];
    expect(lines(serverSideRequestForgery, view('    if parsed.hostname not in ALLOWED_HOSTS:'), FILE)).toEqual([]);
    expect(lines(serverSideRequestForgery, view('    if not parsed.hostname:'), FILE)).toEqual([7]);
  });
});

describe('job 9: open_redirect', () => {
  const FILE = 'app/auth.py';
  it('RedirectResponse(url=<FastAPI parameter>) reports', () => {
    const file = py(...FASTAPI, 'from fastapi.responses import RedirectResponse', '@router.get("/after")', 'async def after(dest: str = Query("/home")):', '    return RedirectResponse(url=dest, status_code=303)');
    expect(lines(openRedirect, [[FILE, file]], FILE)).toEqual([7]);
  });
  it('strict twin: a RedirectResponse to a fixed relative path with the value in its tail does not', () => {
    const file = py(...FASTAPI, 'from fastapi.responses import RedirectResponse', '@router.get("/after")', 'async def after(dest: str = Query("/home")):', '    return RedirectResponse(url=f"/home/{dest}", status_code=303)');
    expect(lines(openRedirect, [[FILE, file]], FILE)).toEqual([]);
  });
  it('HttpResponseRedirect of request.GET reports; redirect(name or default) reports', () => {
    expect(lines(openRedirect, [[FILE, py('def done(request):', '    return HttpResponseRedirect(request.GET["dest"])')]], FILE)).toEqual([2]);
    expect(lines(openRedirect, [[FILE, py('from flask import redirect, request, url_for', 'def done():', '    dest = request.args.get("dest")', '    return redirect(dest or url_for("home"))')]], FILE)).toEqual([4]);
  });
  it('url_has_allowed_host_and_scheme with a block that re-binds credits it', () => {
    const view = (check: string): [string, string][] => [[FILE, py('def done(request):', '    dest = request.POST.get("dest", "")', check, '        dest = "/"', '    return HttpResponseRedirect(dest)')]];
    expect(lines(openRedirect, view('    if not url_has_allowed_host_and_scheme(dest, allowed_hosts={request.get_host()}):'), FILE)).toEqual([]);
    expect(lines(openRedirect, view('    if not dest.startswith("/"):'), FILE)).toEqual([5]);
  });
  it('strict twin of the twin: startswith("/") with no re-binding reports', () => {
    expect(lines(openRedirect, [[FILE, py('def done(request):', '    dest = request.POST.get("dest", "")', '    if not dest.startswith("/"):', '        log(dest)', '    return HttpResponseRedirect(dest)')]], FILE)).toEqual([5]);
  });
  it('an allow-list membership test that refuses credits it', () => {
    expect(lines(openRedirect, [[FILE, py('def done(request):', '    dest = request.GET["dest"]', '    if dest not in ALLOWED:', '        return HttpResponseBadRequest("no")', '    return HttpResponseRedirect(dest)')]], FILE)).toEqual([]);
  });
});

describe('job 9 (carried from review 6b): PYTHON_LEAK reads the name and the module', () => {
  const FILE = 'app/errors.py';
  const run = (...body: string[]): number[] => lines(verboseErrorResponse, [[FILE, py('from flask import jsonify', 'import traceback', '', 'def handler(account):', ...body)]], FILE);
  it('str(<name>) of a value the function bound by assignment is not an exception message', () => {
    expect(run('    email = account.email', '    return jsonify({"error": str(email)}), 400')).toEqual([]);
  });
  it('strict twin: str(<name>) bound by except ... as is still reported', () => {
    expect(run('    try:', '        account.refresh()', '    except Exception as email:', '        return jsonify({"error": str(email)}), 500')).toEqual([8]);
  });
  it('strict twin: a parameter is not provably anything, and keeps counting', () => {
    expect(lines(verboseErrorResponse, [[FILE, py('from flask import jsonify', '', 'def on_error(exc):', '    return jsonify({"error": str(exc)}), 500')]], FILE)).toEqual([4]);
  });
  it('the word traceback in a key is not a traceback when the value is proved', () => {
    expect(run('    rid = "static"', '    return jsonify({"traceback_id": rid}), 500')).toEqual([]);
    expect(lines(verboseErrorResponse, [[FILE, py('from flask import jsonify, request', '', 'def handler():', '    rid = request.args.get("rid")', '    return jsonify({"traceback_id": rid}), 500')]], FILE)).toEqual([]);
  });
  it('strict twin: a value from a call is not proved, so the word traceback still reports', () => {
    expect(run('    rid = new_id()', '    return jsonify({"traceback_id": rid}), 500')).toEqual([6]);
  });
  it('strict twins: the traceback module called here, or bound to a name passed here, is', () => {
    expect(run('    return jsonify({"trace": traceback.format_exc()}), 500')).toEqual([5]);
    expect(run('    tb = traceback.format_exc()', '    return jsonify({"traceback": tb}), 500')).toEqual([6]);
  });
});

describe('job 9, attempt 2: silence needs proof that the value is not an exception (review 9)', () => {
  const FILE = 'app/failures.py';
  const run = (...body: string[]): number[] => lines(verboseErrorResponse, [[FILE, py('from flask import jsonify', 'import traceback', '', 'def handler(account):', ...body)]], FILE);
  const caught = ['    try:', '        account.refresh()', '    except Exception as caught:'];
  it('an alias of the caught exception reports', () => {
    expect(run(...caught, '        exc_held = caught', '        return jsonify({"error": str(exc_held)}), 500')).toEqual([9]);
  });
  it('a helper\'s result over the caught exception reports', () => {
    expect(run(...caught, '        exc_text = summarise(caught)', '        return jsonify({"error": str(exc_text)}), 500')).toEqual([9]);
  });
  it('a loop target reports', () => {
    expect(run('    for entry in account.failures:', '        return jsonify({"error": str(entry)}), 500')).toEqual([6]);
  });
  it('a traceback joined across two lines reports', () => {
    expect(run('    try:', '        account.refresh()', '    except Exception:', '        trace_text = "".join(', '            traceback.format_stack())',
      '        return jsonify({"traceback": trace_text}), 500')).toEqual([10]);
  });
  it('a traceback built by a helper reports', () => {
    expect(run(...caught, '        trace_text = summarise(caught)', '        return jsonify({"traceback": trace_text}), 500')).toEqual([9]);
  });
  it('one unproved binding among proved ones reports', () => {
    expect(run('    exc_label = account.label', ...caught, '        exc_label = caught.args', '    return jsonify({"error": str(exc_label)}), 500')).toEqual([10]);
  });
  it('an attribute of an alias of the caught exception reports', () => {
    expect(run(...caught, '        exc_held = caught', '        exc_label = exc_held.args', '        return jsonify({"error": str(exc_label)}), 500')).toEqual([10]);
  });
  it('strict twins: literals, an f-string of proved names, and an attribute of a non-exception are proved', () => {
    expect(run('    code = 7', '    exc_label = f"failed with {code}"', '    return jsonify({"error": str(exc_label)}), 400')).toEqual([]);
    expect(run('    exc_label = "E-" + account.code', '    return jsonify({"error": str(exc_label)}), 400')).toEqual([]);
    expect(run('    exc_label = "{} {}".format("failed", 7)', '    return jsonify({"error": str(exc_label)}), 400')).toEqual([]);
    expect(run('    exc_label = "failed: %s" % (account.code,)', '    return jsonify({"error": str(exc_label)}), 400')).toEqual([]);
  });
  it('an f-string, a .format, a % or a + that reads the caught exception reports', () => {
    const leak = (rhs: string): number[] => run(...caught, `        exc_label = ${rhs}`, '        return jsonify({"error": str(exc_label)}), 500');
    expect(leak('f"failed: {caught}"')).toEqual([9]);
    expect(leak('"failed: {}".format(caught)')).toEqual([9]);
    expect(leak('"failed: %s" % caught')).toEqual([9]);
    expect(leak('"failed: " + caught.args[0]')).toEqual([9]);
  });
  it('a bare name as the whole right-hand side is not proof, even of a literal', () => {
    expect(run('    exc_first = "fixed"', '    exc_label = exc_first', '    return jsonify({"error": str(exc_label)}), 400')).toEqual([7]);
  });
  it('a parameter is not proof, even when the only assignment is a literal', () => {
    expect(lines(verboseErrorResponse, [[FILE, py('from flask import jsonify', '', 'def on_error(exc_in, flag):', '    if flag:', '        exc_in = "hidden"',
      '    return jsonify({"error": str(exc_in)}), 500')]], FILE)).toEqual([6]);
  });
  const proved = '    exc_label = "fixed"';
  it('a loop target is not proof', () => {
    expect(run(proved, '    for exc_label in account.failures:', '        return jsonify({"error": str(exc_label)}), 500')).toEqual([7]);
  });
  it('a binding only below the use is not proof', () => {
    expect(run('    if account.flag:', '        return jsonify({"error": str(exc_label)}), 500', '    exc_label = "late"')).toEqual([6]);
  });
  it('a with target and a walrus are not proof', () => {
    expect(run(proved, '    with account.open() as exc_label:', '        return jsonify({"error": str(exc_label)}), 400')).toEqual([7]);
    expect(run(proved, '    if (exc_label := account.problem):', '        return jsonify({"error": str(exc_label)}), 400')).toEqual([7]);
  });
  it('an import, an augmented and a tuple target are not proof', () => {
    expect(run(proved, '    if account.flag:', '        from app.state import exc_label', '    return jsonify({"error": str(exc_label)}), 400')).toEqual([8]);
    expect(run(proved, '    exc_label += account.note', '    return jsonify({"error": str(exc_label)}), 400')).toEqual([7]);
    expect(run(proved, '    exc_label, = account.errors', '    return jsonify({"error": str(exc_label)}), 400')).toEqual([7]);
  });
  it('the bare word traceback: a direct call, an f-string, or a value after the call on the line reports', () => {
    expect(run('    rid = "static"', '    return jsonify({"traceback_id": rid.upper()}), 500')).toEqual([6]);
    expect(run(...caught, '        trace_text = summarise(caught)', '        return jsonify({"traceback": f"{trace_text}"}), 500')).toEqual([9]);
    expect(run('    rid = new_id()', '    return jsonify(ok=False), 500, {"X-traceback-id": rid}')).toEqual([6]);
  });
  it('the bare word traceback in a call whose arguments are not read reports', () => {
    const pad = 'x'.repeat(4100);
    expect(run('    rid = "static"', `    return jsonify({"traceback_id": rid, "pad": "${pad}"}), 500`)).toEqual([6]);
  });
});

describe('job 9, attempt 2: a bare "/" is not a fixed URL head', () => {
  const FILE = 'app/hop.py';
  const route = (target: string): [string, string][] => [[FILE, py(...FASTAPI, 'from fastapi.responses import RedirectResponse', '@router.get("/hop")', 'async def hop(q: str):', `    return RedirectResponse(${target})`)]];
  it('RedirectResponse(f"/{q}") and RedirectResponse("/" + q) report', () => {
    expect(lines(openRedirect, route('f"/{q}"'), FILE)).toEqual([7]);
    expect(lines(openRedirect, route('"/" + q'), FILE)).toEqual([7]);
  });
  it('strict twin: f"/items/{q}" stays silent', () => {
    expect(lines(openRedirect, route('f"/items/{q}"'), FILE)).toEqual([]);
    expect(lines(openRedirect, route('"/items/" + q'), FILE)).toEqual([]);
  });
});

describe('job 9: isolating tests (each path on its own)', () => {
  it('sql: the pattern pass alone reports a followed value (a receiver only it reads)', () => {
    const FILE = 'app/pool.py';
    expect(lines(sqlInjection, [[FILE, py('def report(request):', '    shade = request.GET.get("shade", "")', '    return pool.execute(f"SELECT id FROM paint WHERE rank = {shade}")')]], FILE)).toEqual([3]);
  });
  it('sql: strict twin: an execute() on something that is not a database is not read', () => {
    const FILE = 'app/jobs.py';
    expect(lines(sqlInjection, [[FILE, py('def report(request):', '    shade = request.GET.get("shade", "")', '    return pipeline.execute(f"SELECT id FROM paint WHERE shade = \'{shade}\'")')]], FILE)).toEqual([]);
  });
  it('path: open() of a FastAPI parameter reports through the follower alone', () => {
    const FILE = 'app/open.py';
    expect(lines(pathTraversal, [[FILE, py(...FASTAPI, '@router.get("/f/{fname}")', 'async def fetch(fname: str):', '    return open(f"{ROOT}/{fname}").read()')]], FILE)).toEqual([6]);
  });
  it('path: strict twin: FileResponse reports only a followed path, not a request read nearby', () => {
    const FILE = 'app/near.py';
    expect(lines(pathTraversal, [[FILE, py('from flask import request', 'def fetch():', '    note(request.args["fname"])', '    return FileResponse(f"{ROOT}/fixed.pdf")')]], FILE)).toEqual([]);
  });
  it('path: an os.path.commonpath() check that refuses credits the followed path', () => {
    const FILE = 'app/common.py';
    const route = (check: string): [string, string][] => [[FILE, py(...FASTAPI, '@router.get("/f/{fname}")', 'async def fetch(fname: str):',
      '    target = os.path.join(ROOT, fname)', check, '        raise HTTPException(status_code=404)', '    return FileResponse(target)')]];
    expect(lines(pathTraversal, route('    if os.path.commonpath([ROOT, target]) != ROOT:'), FILE)).toEqual([]);
    expect(lines(pathTraversal, route('    if not os.path.isfile(target):'), FILE)).toEqual([9]);
  });
  it('ssrf: strict twin: a client object reports only a followed URL, not a request read nearby', () => {
    const FILE = 'app/client.py';
    const file = py('import httpx', 'def pull(request):', '    note(request.args["link"])', '    with httpx.Client() as client:', '        return client.get(STATUS_URL)');
    expect(lines(serverSideRequestForgery, [[FILE, file]], FILE)).toEqual([]);
  });
  it('redirect: strict twin: a response class reports only a followed destination', () => {
    const FILE = 'app/back.py';
    expect(lines(openRedirect, [[FILE, py('def back(request):', '    return HttpResponseRedirect(request.headers.get("referer"))')]], FILE)).toEqual([]);
  });
  it('redirect: a value only after a config head is not followed into the head', () => {
    const FILE = 'app/cfg.py';
    expect(lines(openRedirect, [[FILE, py(...FASTAPI, '@router.get("/after")', 'async def after(dest: str):', '    return RedirectResponse(url=f"{settings.APP_URL}/{dest}")')]], FILE)).toEqual([]);
    expect(lines(openRedirect, [[FILE, py(...FASTAPI, '@router.get("/after")', 'async def after(dest: str):', '    return RedirectResponse(url=f"{dest}/landing")')]], FILE)).toEqual([6]);
  });
  it('verbose: the nearest binding decides: an except after an assignment still counts', () => {
    const FILE = 'app/late.py';
    expect(lines(verboseErrorResponse, [[FILE, py('from flask import jsonify', 'def handler(account):', '    email = account.email', '    try:', '        account.refresh()',
      '    except Exception as email:', '        return jsonify({"error": str(email)}), 500')]], FILE)).toEqual([7]);
  });
});
