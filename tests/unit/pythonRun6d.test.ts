import { describe, expect, it } from 'vitest';
import { pythonRouteGuard } from '../../src/shared/pythonGuards.js';
import { unsafeFileUpload } from '../../src/rules/basic/unsafeFileUpload.js';
import { crossSiteScripting } from '../../src/rules/basic/xss.js';
import { databaseDeleteWithoutOwnershipCheck } from '../../src/rules/contextual/databaseDeleteWithoutOwnershipCheck.js';
import { verboseErrorResponse } from '../../src/rules/basic/verboseErrorResponse.js';
import { missingRateLimit } from '../../src/rules/contextual/missingRateLimit.js';
import { sqlInjection } from '../../src/rules/basic/sqlInjection.js';
import { openRedirect } from '../../src/rules/basic/openRedirect.js';
import { innerHtmlValueIsInert } from '../../src/shared/inertMarkup.js';
import { pythonUploadFacts } from '../../src/shared/pythonUpload.js';
import type { Finding, RuleContext } from '../../src/shared/types.js';
import { memoryContext } from './helpers.js';

type Files = [string, string][];

const py = (...lines: string[]): string => `${lines.join('\n')}\n`;

function guard(dependency: string): string | undefined {
  const files: Files = [
    ['app/db.py', py('def get_db():', '    yield object()')],
    ['app/auth.py', dependency],
    ['app/routes.py', py(
      'from fastapi import APIRouter, Depends',
      'from .auth import get_current_user',
      'router = APIRouter()',
      '',
      '@router.delete("/entries/{entry_id}")',
      'def delete_entry(entry_id: int, user=Depends(get_current_user)):',
      '    db.delete(entry_id)',
      '    db.commit()',
    )],
  ];
  const context = memoryContext(files);
  const route = context.projectMap.apiRoutes.find((candidate) => candidate.routePath === '/entries/{entry_id}');
  if (route === undefined) throw new Error('no route');
  return pythonRouteGuard(context, route)?.level;
}

const HEAD = [
  'from fastapi import HTTPException, Request',
  'def authenticate(value):',
  '    return value == "expected"',
  'def get_current_user(request: Request):',
  '    sent = request.headers.get("X-Access")',
];
const REFUSAL = ['    if not sent or not authenticate(sent):', '        raise HTTPException(status_code=401)'];
const END = ['    return {"id": 1}'];

const ONE_LINE_EXITS: [string, string[]][] = [
  ['if', ['    if request.query_params.get("preview"): return None']],
  ['elif', ['    if request.method == "OPTIONS":', '        pass', '    elif request.query_params.get("preview"): return None']],
  ['else', ['    if request.method == "GET":', '        pass', '    else: return None']],
  ['try', ['    try: return request.state.member', '    except AttributeError:', '        pass']],
  ['except', ['    try:', '        marker = request.state.member', '    except AttributeError: return None']],
  ['finally', ['    try:', '        marker = request.state.member', '    finally: return None']],
  ['for', ['    for hint in request.query_params.keys(): return None']],
  ['while', ['    while request.query_params.get("preview"): return None']],
  ['with', ['    with open("bypass.flag") as handle: return None']],
  ['if (yield)', ['    if request.query_params.get("preview"): yield None']],
];

describe('an exit on its block header\'s line is an exit (the fail-closed one-line fix)', () => {
  for (const [kind, exit] of ONE_LINE_EXITS) {
    it(`${kind}: the exit before the refusal leaves a caller through; after it, the guard counts`, () => {
      expect(guard(py(...HEAD, ...exit, ...REFUSAL, ...END))).toBeUndefined();
      expect(guard(py(...HEAD, ...REFUSAL, ...exit, ...END))).toBe('auth');
    });
  }

  it('an elif one-liner after a refusal in its own if branch is not covered by it', () => {
    const body = [
      '    kind, _, value = request.headers.get("X-Access", "").partition(" ")',
      '    if kind and kind != "v1":',
      '        raise HTTPException(status_code=401)',
      '    elif not value: return None',
      '    if not authenticate(value):',
      '        raise HTTPException(status_code=401)',
      ...END,
    ];
    expect(guard(py(...HEAD.slice(0, 4), ...body))).toBeUndefined();
    expect(guard(py(...HEAD.slice(0, 4),
      '    kind, _, value = request.headers.get("X-Access", "").partition(" ")',
      '    if not value:',
      '        raise HTTPException(status_code=401)',
      '    if kind and kind != "v1": return None',
      '    if not authenticate(value):',
      '        raise HTTPException(status_code=401)',
      ...END))).toBe('auth');
  });
});

const rows = (rule: { run: (context: RuleContext) => Finding[] }, files: Files): Finding[] => rule.run(memoryContext(files));
const lines = (findings: Finding[]): number[] => findings.map((finding) => finding.lineStart).sort((a, b) => a - b);

const FLASK_APP = py(
  'from flask import Flask',
  'app = Flask(__name__)',
);

describe('unsafe_file_upload on Python', () => {
  const view = (body: string[], extra: string[] = [], config = FLASK_APP): Files => [
    ['web/app.py', config],
    ['web/views.py', py(
      'import os',
      'import tempfile',
      'from flask import Blueprint, abort, request',
      'bp = Blueprint("files", __name__)',
      'STORE = "/srv/files"',
      'PERMITTED = {"png", "jpg"}',
      ...extra,
      '@bp.route("/files", methods=["POST"])',
      'def put_file():',
      ...body,
      '    return "ok"',
    )],
  ];
  const CAP = py('from flask import Flask', 'app = Flask(__name__)', 'app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024');
  const SAVE = ['    f = request.files["doc"]', '    f.save(os.path.join(STORE, "x.png"))'];
  const stored = (files: Files): boolean | undefined => {
    const entry = memoryContext(files).fileMap.entries.find((candidate) => candidate.path.endsWith('views.py'));
    if (entry === undefined) throw new Error('no view');
    const line = (entry.content ?? '').split('\n').findIndex((text) => text.includes('request.files')) + 1;
    return pythonUploadFacts(entry, line)?.stored;
  };

  it('a helper whose body tests membership, plus the app-wide cap, clears a stored upload; a helper that tests nothing does not', () => {
    const checks = ['def ext_ok(name):', '    return "." in name and name.rsplit(".", 1)[1].lower() in PERMITTED'];
    const body = ['    f = request.files["doc"]', '    if not ext_ok(f.filename):', '        abort(400)', '    f.save(os.path.join(STORE, "x.png"))'];
    expect(rows(unsafeFileUpload, view(body, checks, CAP))).toEqual([]);
    const lax = ['def ext_ok(name):', '    return True'];
    expect(rows(unsafeFileUpload, view(body, lax, CAP)).length).toBeGreaterThan(0);
  });

  it('the allow-list check must govern the store: a check whose block neither refuses nor holds the save is not credited', () => {
    const governed = ['    f = request.files["doc"]', '    ext = f.filename.rsplit(".", 1)[-1]', '    if ext not in PERMITTED:', '        abort(400)', '    f.save(os.path.join(STORE, "x.png"))'];
    expect(rows(unsafeFileUpload, view(governed, [], CAP))).toEqual([]);
    const logged = governed.map((line) => line === '        abort(400)' ? '        print("odd type")' : line);
    expect(rows(unsafeFileUpload, view(logged, [], CAP)).length).toBeGreaterThan(0);
  });

  it('a dict lookup that refuses on a miss, and a size compared after seek/tell, are credited', () => {
    const body = [
      '    f = request.files["doc"]',
      '    suffix = os.path.splitext(f.filename)[1].lower()',
      '    kind = KINDS.get(suffix)',
      '    if kind is None:',
      '        abort(400)',
      '    f.seek(0, os.SEEK_END)',
      '    size = f.tell()',
      '    if size > 1000000:',
      '        abort(413)',
      '    f.save(os.path.join(STORE, "x" + kind))',
    ];
    const kinds = ['KINDS = {".png": ".png"}'];
    expect(rows(unsafeFileUpload, view(body, kinds))).toEqual([]);
    const noSize = body.filter((line) => !/size|seek|413/.test(line));
    expect(rows(unsafeFileUpload, view(noSize, kinds)).map((f) => f.evidence).join(' ')).toContain('a size limit');
  });

  it('an upload only read into memory is reported (no "not stored" credit), though the reader sees nothing kept; saving it keeps it', () => {
    const parsed = ['    f = request.files["doc"]', '    text = f.read().decode("utf-8")', '    rows = text.splitlines()'];
    expect(rows(unsafeFileUpload, view(parsed)).length).toBeGreaterThan(0);
    expect(stored(view(parsed))).toBe(false);
    expect(rows(unsafeFileUpload, view(SAVE)).length).toBeGreaterThan(0);
    expect(stored(view(SAVE))).toBe(true);
  });

  it('a save into a temporary file is reported; the reader sees nothing kept unless the temporary copy is handed to the project\'s own code or moved on', () => {
    const temp = ['    f = request.files["doc"]', '    with tempfile.NamedTemporaryFile(delete=False) as tmp:', '        f.save(tmp.name)', '    data = open(tmp.name).read()'];
    expect(rows(unsafeFileUpload, view(temp)).length).toBeGreaterThan(0);
    expect(stored(view(temp))).toBe(false);
    const kept = [...temp, '    keep_copy(tmp.name, STORE)'];
    const helper = ['def keep_copy(src, dest):', '    os.replace(src, dest)'];
    expect(rows(unsafeFileUpload, view(kept, helper)).length).toBeGreaterThan(0);
    expect(stored(view(kept, helper))).toBe(true);
    const moved = [...temp, '    os.replace(tmp.name, os.path.join(STORE, "x"))'];
    expect(rows(unsafeFileUpload, view(moved)).length).toBeGreaterThan(0);
    expect(stored(view(moved))).toBe(true);
  });

  it('a file object handed to code the reader cannot see counts as stored', () => {
    const handed = ['    f = request.files["doc"]', '    storage_backend.put(f)'];
    expect(rows(unsafeFileUpload, view(handed)).length).toBeGreaterThan(0);
    expect(stored(view(handed))).toBe(true);
  });

  it('the bytes read from the file, written with write_bytes, are stored', () => {
    const body = ['    f = request.files["doc"]', '    data = f.read()', '    Path(STORE, "x.png").write_bytes(data)'];
    expect(rows(unsafeFileUpload, view(body, ['from pathlib import Path'])).length).toBeGreaterThan(0);
    expect(stored(view(body, ['from pathlib import Path']))).toBe(true);
    for (const write of ['    Path(STORE, "x").write_text(data.decode())', '    out = open(os.path.join(STORE, "x"), "wb")\n    out.writelines([data])']) {
      expect(rows(unsafeFileUpload, view(['    f = request.files["doc"]', '    data = f.read()', write], ['from pathlib import Path'])).length).toBeGreaterThan(0);
      expect(stored(view(['    f = request.files["doc"]', '    data = f.read()', write], ['from pathlib import Path']))).toBe(true);
    }
    for (const kept of ['    record.blob = data', '    cache["doc"] = data']) {
      expect(rows(unsafeFileUpload, view(['    f = request.files["doc"]', '    data = f.read()', kept])).length).toBeGreaterThan(0);
      expect(stored(view(['    f = request.files["doc"]', '    data = f.read()', kept]))).toBe(true);
    }
  });

  it('an attribute of the file (its stream) handed to a storage client is stored', () => {
    const body = ['    f = request.files["doc"]', '    s3.upload_fileobj(f.stream, "bucket", "x.png")'];
    expect(rows(unsafeFileUpload, view(body)).length).toBeGreaterThan(0);
    expect(stored(view(body))).toBe(true);
    const wrapped = ['    f = request.files["doc"]', '    buf = io.BytesIO(f.read())', '    s3.upload_fileobj(buf, "bucket", "x.png")'];
    expect(rows(unsafeFileUpload, view(wrapped, ['import io'])).length).toBeGreaterThan(0);
    expect(stored(view(wrapped, ['import io']))).toBe(true);
  });

  it('strict twin: bytes only parsed in memory (json, yaml, csv, hashing) are reported, though the reader sees nothing kept in them or in what the parse returns', () => {
    const parsed = [
      '    f = request.files["doc"]',
      '    body = f.read()',
      '    digest = hashlib.sha256(body).hexdigest()',
      '    settings = json.loads(body.decode("utf-8"))',
      '    rows = list(csv.DictReader(io.StringIO(body.decode("utf-8"))))',
      '    apply_settings(settings, len(rows), digest)',
    ];
    const imports = ['import csv', 'import hashlib', 'import io', 'import json'];
    expect(rows(unsafeFileUpload, view(parsed, imports)).length).toBeGreaterThan(0);
    expect(stored(view(parsed, imports))).toBe(false);
    expect(rows(unsafeFileUpload, view([...parsed, '    archive.put(body)'], imports)).length).toBeGreaterThan(0);
    expect(stored(view([...parsed, '    archive.put(body)'], imports))).toBe(true);
  });

  it('a write of the bytes into a temporary file is reported, though the reader sees nothing kept (decision 4)', () => {
    const temp = ['    f = request.files["doc"]', '    data = f.read()', '    with tempfile.NamedTemporaryFile() as tmp:', '        tmp.write(data)'];
    expect(rows(unsafeFileUpload, view(temp)).length).toBeGreaterThan(0);
    expect(stored(view(temp))).toBe(false);
  });

  it('the bytes read straight onto a record\'s attribute, then added to a session, are stored', () => {
    const body = ['    f = request.files["doc"]', '    record = Record(owner="me")', '    record.payload = f.read()', '    session.add(record)'];
    expect(rows(unsafeFileUpload, view(body)).length).toBeGreaterThan(0);
    expect(stored(view(body))).toBe(true);
    expect(rows(unsafeFileUpload, view(['    f = request.files["doc"]', '    record.payload += f.read()'])).length).toBeGreaterThan(0);
    expect(stored(view(['    f = request.files["doc"]', '    record.payload += f.read()']))).toBe(true);
  });

  it('the stream\'s bytes read straight into a key named from the file are stored', () => {
    const body = ['    f = request.files["doc"]', '    by_name[secure_filename(f.filename)] = f.stream.read()'];
    expect(rows(unsafeFileUpload, view(body, ['from werkzeug.utils import secure_filename'])).length).toBeGreaterThan(0);
    expect(stored(view(body, ['from werkzeug.utils import secure_filename']))).toBe(true);
  });

  it('kept bytes are stored whatever the target or line shape: an annotated attribute, a nested key, a right-hand side on the next lines', () => {
    for (const kept of [
      ['    record.payload: bytes = f.read()'],
      ['    by_name[keys[0]] = f.read()'],
      ['    record.payload = (', '        f.read()', '    )'],
      ['    record.payload = \\', '        f.read()'],
      ['    return (', '        f.read()', '    )'],
    ]) {
      expect(rows(unsafeFileUpload, view(['    f = request.files["doc"]', ...kept])).length, kept.join(' / ')).toBeGreaterThan(0);
      expect(stored(view(['    f = request.files["doc"]', ...kept])), kept.join(' / ')).toBe(true);
    }
    const meta = view(['    f = request.files["doc"]', '    record.meta = json.loads(', '        f.read()', '    )'], ['import json']);
    expect(rows(unsafeFileUpload, meta).length).toBeGreaterThan(0);
    expect(stored(meta)).toBe(false);
  });

  it('returning the bytes read from the file stores them', () => {
    const body = ['    f = request.files["doc"]', '    return f.read()'];
    expect(rows(unsafeFileUpload, view(body)).length).toBeGreaterThan(0);
    expect(stored(view(body))).toBe(true);
  });

  it('strict twin: a length or a parse of the bytes kept on a record is not the content (reported all the same)', () => {
    const body = ['    f = request.files["doc"]', '    record.count = len(f.read())', '    record.meta = json.loads(f.read())'];
    expect(rows(unsafeFileUpload, view(body, ['import json'])).length).toBeGreaterThan(0);
    expect(stored(view(body, ['import json']))).toBe(false);
    const label = view(['    f = request.files["doc"]', '    record.label = f.filename'], []);
    expect(rows(unsafeFileUpload, label).length).toBeGreaterThan(0);
    expect(stored(label)).toBe(false);
  });

  it('the bytes kept on a temporary file\'s attribute are reported, though the reader sees nothing kept; on any other record it sees them kept', () => {
    const temp = ['    f = request.files["doc"]', '    with tempfile.SpooledTemporaryFile() as tmp:', '        tmp.payload = f.read()'];
    expect(rows(unsafeFileUpload, view(temp)).length).toBeGreaterThan(0);
    expect(stored(view(temp))).toBe(false);
    const onRecord = view(temp.map((line) => line.replace('tmp.payload', 'record.payload')));
    expect(rows(unsafeFileUpload, onRecord).length).toBeGreaterThan(0);
    expect(stored(onRecord)).toBe(true);
  });

  const UNKNOWN_STORE_SHAPES: [string, string[]][] = [
    ['a tuple target', ['    entry = Entry()', '    entry.content, entry.size = f.read(), 0']],
    ['a chained target', ['    held = entry.content = f.read()']],
    ['a module global', ['    global LATEST_UPLOAD', '    LATEST_UPLOAD = f.read()']],
    ['a yield', ['    yield f.read()']],
  ];
  for (const [shape, kept] of UNKNOWN_STORE_SHAPES) {
    it(`bytes kept through ${shape} are reported`, () => {
      expect(rows(unsafeFileUpload, view(['    f = request.files["doc"]', ...kept])).length).toBeGreaterThan(0);
    });
  }

  it('os.path.join(STORE, x.filename) on a stored record is not an upload; on a request file it is', () => {
    const record = ['    for attachment in entry.attachments.all():', '        os.remove(os.path.join(STORE, attachment.filename))'];
    const files = (header: string[]): Files => [['web/app.py', FLASK_APP], ['web/views.py', py(
      'import os',
      'from flask import request',
      'STORE = "/srv"',
      ...header,
      ...record,
      'def take():',
      '    attachment = request.files["doc"]',
      '    attachment.save(os.path.join(STORE, attachment.filename))',
    )]];
    expect(lines(rows(unsafeFileUpload, files(['def tidy():', '    entry = Entry.query.get(1)'])))).toEqual([9, 10]);
    expect(lines(rows(unsafeFileUpload, files(['def tidy(entry):'])))).toEqual([6, 8, 9]);
  });

  it('a stored record\'s file removed beside an unchecked upload is not reported; the upload is', () => {
    const files: Files = [['web/app.py', FLASK_APP], ['web/views.py', py(
      'import os',
      'from flask import request',
      'STORE = "/srv"',
      'def replace_doc():',
      '    entry = Entry.query.get(1)',
      '    f = request.files["doc"]',
      '    for attachment in entry.attachments.all():',
      '        os.remove(os.path.join(STORE, attachment.filename))',
      '    f.save(os.path.join(STORE, "x"))',
    )]];
    expect(lines(rows(unsafeFileUpload, files))).toEqual([6]);
  });

  it('request.files in a module docstring (no enclosing function) is prose', () => {
    const files: Files = [['web/app.py', FLASK_APP], ['web/notes.py', py(
      '"""This module documents how views read request.files for uploads."""',
      'from flask import request',
      'LIMIT = 3',
    )]];
    expect(rows(unsafeFileUpload, files)).toEqual([]);
  });

  it('request.files in a docstring or a comment is prose', () => {
    const files: Files = [['web/app.py', FLASK_APP], ['web/check.py', py(
      'from flask import request',
      'def check(f):',
      '    """f: the uploaded file object (from request.files)."""',
      '    # request.files is read by the caller',
      '    return f is not None',
    )]];
    expect(rows(unsafeFileUpload, files)).toEqual([]);
  });

  it('JavaScript is read exactly as before (the Python arm never runs on it)', () => {
    const files: Files = [['server.js', [
      "const express = require('express');",
      "const multer = require('multer');",
      "const upload = multer({ dest: 'uploads/' });",
      "app.post('/up', upload.single('doc'), (req, res) => res.send('ok'));",
      '',
    ].join('\n')]];
    expect(rows(unsafeFileUpload, files).length).toBeGreaterThan(0);
  });
});

describe('xss: inert markup in a Python project\'s pages', () => {
  const page = (script: string[], withPython = true): Files => [
    ...(withPython ? [['app.py', FLASK_APP] as [string, string]] : []),
    ['templates/page.html', ['<html><body><div id="box"></div><script>', ...script, '</script></body></html>', ''].join('\n')],
  ];
  const ESC_ALL = "function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;'); }";
  const ESC_TWO = "function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;'); }";

  it('constant markup chosen by a condition is inert; the same with a fetched value in a branch is not', () => {
    expect(rows(crossSiteScripting, page(["box.innerHTML = data.flag ? '<span class=\"on\">On</span>' : '';"]))).toEqual([]);
    expect(rows(crossSiteScripting, page(["box.innerHTML = data.flag ? '<span>' + data.label + '</span>' : '';"])).length).toBeGreaterThan(0);
  });

  const inert = (script: string[]): boolean => {
    const content = script.join('\n');
    const at = content.indexOf('.innerHTML');
    return innerHtmlValueIsInert(content, at, '.innerHTML =');
  };

  it('a value through a helper that escapes &, < and > is inert in text and in a quoted attribute', () => {
    expect(inert([ESC_ALL, "box.innerHTML = '<b title=\"' + esc(data.title) + '\">' + esc(data.label) + '</b>';"])).toBe(true);
    expect(rows(crossSiteScripting, page([ESC_ALL, "box.innerHTML = '<b title=\"' + esc(data.title) + '\">' + esc(data.label) + '</b>';"]))).toEqual([]);
  });

  it('an escaper that misses >, or an escaped value in an event handler, a URL or style attribute, an unquoted attribute or a script element, is not inert', () => {
    expect(inert([ESC_TWO, "box.innerHTML = '<b>' + esc(data.label) + '</b>';"])).toBe(false);
    expect(inert([ESC_ALL, "box.innerHTML = '<button onclick=\"go(\\'' + esc(data.label) + '\\')\">Go</button>';"])).toBe(false);
    expect(inert([ESC_ALL, "box.innerHTML = '<a href=\"' + esc(data.link) + '\">open</a>';"])).toBe(false);
    expect(inert([ESC_ALL, "box.innerHTML = '<b style=\"' + esc(data.css) + '\">x</b>';"])).toBe(false);
    expect(inert([ESC_ALL, "box.innerHTML = '<b title=' + esc(data.title) + '>x</b>';"])).toBe(false);
    expect(inert([ESC_ALL, "box.innerHTML = '<script>var v = \"' + esc(data.v) + '\";</script>';"])).toBe(false);
    expect(inert(['function esc(s) { return String(s); }', "box.innerHTML = '<b>' + esc(data.label) + '</b>';"])).toBe(false);
  });

  const ESC_THREE = "function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }";
  const ESC_SQ = "function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/'/g,'&#39;'); }";

  it('an escaper lacking the double quote is not inert in title="…"; with &quot; it is', () => {
    const dq = "box.innerHTML = '<b title=\"' + esc(data.title) + '\">x</b>';";
    expect(inert([ESC_THREE, dq])).toBe(false);
    expect(inert([ESC_ALL, dq])).toBe(true);
    expect(rows(crossSiteScripting, page([ESC_ALL, dq]))).toEqual([]);
    expect(inert([ESC_THREE, "box.innerHTML = '<b>' + esc(data.label) + '</b>';"])).toBe(true);
  });

  it('an escaper lacking the single quote is not inert in title=\'…\'; with &#39; it is', () => {
    const sq = "box.innerHTML = \"<b title='\" + esc(data.title) + \"'>x</b>\";";
    expect(inert([ESC_ALL, sq])).toBe(false);
    expect(inert([ESC_SQ, sq])).toBe(true);
  });

  it('a conditional whose branches leave the markup in different contexts is not inert', () => {
    expect(inert([ESC_ALL, "box.innerHTML = (data.flag ? '<b title=\"' : '<b>') + esc(data.label) + '</b>';"])).toBe(false);
  });

  it('computed numbers and a constant table are inert; a server number is not', () => {
    expect(rows(crossSiteScripting, page(["box.innerHTML = '<i>' + data.items.length + '</i> ' + Math.round(data.share * 100) + '%';"]))).toEqual([]);
    expect(rows(crossSiteScripting, page(["var HINTS = { a: '<i>Type more</i>', b: '<i>None</i>' };", "box.innerHTML = '<p>' + HINTS[data.tab] + '</p>';"]))).toEqual([]);
    expect(rows(crossSiteScripting, page(["box.innerHTML = '<i>' + data.count + '</i>';"])).length).toBeGreaterThan(0);
  });

  it('a constant table written to later is not constant', () => {
    expect(rows(crossSiteScripting, page(["var HINTS = { a: '<i>x</i>' };", 'HINTS.a = data.label;', "box.innerHTML = '<p>' + HINTS[data.tab] + '</p>';"])).length).toBeGreaterThan(0);
  });

  it('the credit applies only in a project with Python sources (the JavaScript baseline does not move)', () => {
    expect(rows(crossSiteScripting, page(["box.innerHTML = data.flag ? '<span class=\"on\">On</span>' : '';"], false)).length).toBeGreaterThan(0);
  });
});

describe('database_delete_without_ownership_check: Python code no request reaches', () => {
  const app = (extra: string[], route: string[]): Files => [['srv/app.py', py(
    'import sqlite3',
    'from functools import wraps',
    'from flask import Flask, abort, jsonify',
    'from flask_login import current_user, login_required',
    'app = Flask(__name__)',
    'def get_db():',
    '    return sqlite3.connect("x.db")',
    'def staff_only(f):',
    '    @wraps(f)',
    '    def wrapper(*args, **kwargs):',
    '        if not current_user.is_authenticated or not current_user.is_admin:',
    '            abort(403)',
    '        return f(*args, **kwargs)',
    '    return wrapper',
    'def sweep_expired(cutoff):',
    '    get_db().execute("DELETE FROM entries WHERE id=?", (cutoff,))',
    ...extra,
    ...route,
  )]];
  const OPEN = ['@app.route("/entries/<int:entry_id>", methods=["DELETE"])', '@login_required', 'def entry_delete(entry_id):'];

  it('a janitor no route calls is not reported; once a signed-in route calls it, it is', () => {
    expect(rows(databaseDeleteWithoutOwnershipCheck, app([], [...OPEN, '    return jsonify(ok=True)']))).toEqual([]);
    expect(rows(databaseDeleteWithoutOwnershipCheck, app([], [...OPEN, '    sweep_expired(entry_id)', '    return jsonify(ok=True)'])).length).toBeGreaterThan(0);
  });

  it('a delete reached only through a route a refusing admin guard protects is not reported; behind sign-in alone it is', () => {
    const adminRoute = ['@app.route("/entries/<int:entry_id>", methods=["DELETE"])', '@staff_only', 'def entry_delete(entry_id):', '    sweep_expired(entry_id)', '    return jsonify(ok=True)'];
    expect(rows(databaseDeleteWithoutOwnershipCheck, app([], adminRoute))).toEqual([]);
    const lax = app([], adminRoute).map(([p, c]) => [p, c.replace(' or not current_user.is_admin', '')] as [string, string]);
    expect(rows(databaseDeleteWithoutOwnershipCheck, lax).length).toBeGreaterThan(0);
  });

  it('a view registered with add_url_rule inside an app factory is reachable', () => {
    const factory = ['def create_app():', '    app.add_url_rule("/entries/<int:cutoff>", view_func=sweep_expired, methods=["DELETE"])', '    return app'];
    expect(rows(databaseDeleteWithoutOwnershipCheck, app(factory, [...OPEN, '    return jsonify(ok=True)'])).length).toBeGreaterThan(0);
  });

  it('a FastAPI handler registered with router.add_api_route inside a function is reachable', () => {
    const files: Files = [['api/main.py', py(
      'import sqlite3',
      'from fastapi import APIRouter, FastAPI',
      'app = FastAPI()',
      'router = APIRouter()',
      'def get_db():',
      '    return sqlite3.connect("x.db")',
      'async def wipe_entry(entry_id: int):',
      '    get_db().execute("DELETE FROM entries WHERE id=?", (entry_id,))',
      '    return {"ok": True}',
      '@app.get("/health")',
      'async def health():',
      '    return {"ok": True}',
      'def mount_routes():',
      '    router.add_api_route("/entries/{entry_id}", wipe_entry, methods=["DELETE"])',
      '    app.include_router(router)',
      'mount_routes()',
    )]];
    expect(rows(databaseDeleteWithoutOwnershipCheck, files).length).toBeGreaterThan(0);
    const unnamed = files.map(([p, c]) => [p, c.replace('router.add_api_route("/entries/{entry_id}", wipe_entry, methods=["DELETE"])', 'pass')] as [string, string]);
    expect(rows(databaseDeleteWithoutOwnershipCheck, unnamed)).toEqual([]);
  });

  it('a thread target named in a route is reachable', () => {
    expect(rows(databaseDeleteWithoutOwnershipCheck, app(['import threading'], [...OPEN, '    threading.Thread(target=sweep_expired, args=(entry_id,)).start()', '    return jsonify(ok=True)'])).length).toBeGreaterThan(0);
  });

  it('a decorated def that is not a route (a socket handler, a task) counts as reachable', () => {
    const socket = ['@socketio.on("purge")', 'def on_purge(entry_id):', '    sweep_expired(entry_id)'];
    expect(rows(databaseDeleteWithoutOwnershipCheck, app(socket, [...OPEN, '    return jsonify(ok=True)'])).length).toBeGreaterThan(0);
  });

  it('a Django project gets no answer (its views have no routes yet), so the delete is reported', () => {
    const files = app([], [...OPEN, '    return jsonify(ok=True)']);
    files.push(['web/views.py', py('from django.http import JsonResponse', 'def ping(request):', '    return JsonResponse({})')]);
    expect(rows(databaseDeleteWithoutOwnershipCheck, files).length).toBeGreaterThan(0);
  });
});

describe('verbose_error_response: a message the application wrote', () => {
  const view = (helper: string[], body: string[], decorator = '@login_required'): Files => [['srv/app.py', py(
    'from functools import wraps',
    'from flask import Flask, abort, jsonify, request',
    'from flask_login import current_user, login_required',
    'app = Flask(__name__)',
    'def staff_only(f):',
    '    @wraps(f)',
    '    def wrapper(*args, **kwargs):',
    '        if not current_user.is_authenticated or not current_user.is_admin:',
    '            abort(403)',
    '        return f(*args, **kwargs)',
    '    return wrapper',
    ...helper,
    '@app.route("/settings", methods=["POST"])',
    decorator,
    'def settings_save():',
    ...body,
    '    return jsonify(ok=True)',
  )]];
  const VALIDATOR = ['def check_days(value):', '    if value < 1:', '        raise ValueError("days must be at least 1")', '    return value'];
  const TRY = ['    try:', '        days = check_days(5)', '    except ValueError as e:', '        return jsonify(error=str(e)), 400'];

  it('str(e) of a ValueError only the project\'s own validator raises, with a written message, is not a leak', () => {
    expect(rows(verboseErrorResponse, view(VALIDATOR, TRY))).toEqual([]);
  });

  it('a validator raising with a passed-through message, a library call in the try, or except Exception is still a leak', () => {
    const passed = VALIDATOR.map((line) => line.replace('raise ValueError("days must be at least 1")', 'raise ValueError(value)'));
    expect(rows(verboseErrorResponse, view(passed, TRY)).length).toBe(1);
    const parsed = TRY.map((line) => line.replace('check_days(5)', 'check_days(int(request.args["d"]))'));
    expect(rows(verboseErrorResponse, view(VALIDATOR, parsed)).length).toBe(1);
    const broad = TRY.map((line) => line.replace('except ValueError', 'except Exception'));
    expect(rows(verboseErrorResponse, view(VALIDATOR, broad)).length).toBe(1);
    const ownBroad = VALIDATOR.map((line) => line.replace('raise ValueError(', 'raise Exception('));
    expect(rows(verboseErrorResponse, view(ownBroad, broad)).length).toBe(1);
    const mixed = [...VALIDATOR, 'def check_label(value):', '    if not value:', '        raise ValueError(value)', '    return value'];
    const both = ['    try:', '        days = check_days(5)', '        label = check_label("")', '    except ValueError as e:', '        return jsonify(error=str(e)), 400'];
    expect(rows(verboseErrorResponse, view(mixed, both)).length).toBe(1);
    const reraised = [...VALIDATOR.slice(0, 3), '    try:', '        return int(value)', '    except KeyError:', '        raise'];
    expect(rows(verboseErrorResponse, view(reraised, TRY)).length).toBe(1);
  });

  it('error text behind a refusing admin guard is reported at low severity, wording unchanged; behind sign-in only it keeps its severity', () => {
    const leak = ['    try:', '        open("/etc/x").read()', '    except OSError as e:', '        return jsonify(error=str(e)), 500'];
    const admin = rows(verboseErrorResponse, view([], leak, '@staff_only'));
    const signedIn = rows(verboseErrorResponse, view([], leak));
    expect(admin.map((f) => f.severity)).toEqual(['low']);
    expect(signedIn.map((f) => f.severity)).toEqual(['medium']);
    expect(admin[0]?.userExplanation).toBe(signedIn[0]?.userExplanation);
    expect(admin[0]?.technicalExplanation).toBe(signedIn[0]?.technicalExplanation);
    const lax = view([], leak, '@staff_only').map(([p, c]) => [p, c.replace(' or not current_user.is_admin', '')] as [string, string]);
    expect(rows(verboseErrorResponse, lax).map((f) => f.severity)).toEqual(['medium']);
  });
});

describe('missing_rate_limit on Python routes', () => {
  const app = (route: string, extra: string[] = [], decorators: string[] = [], body: string[] = []): Files => [['srv/app.py', py(
    'from flask import Flask, jsonify',
    ...extra,
    'app = Flask(__name__)',
    `@app.route("${route}", methods=["POST"])`,
    ...decorators,
    'def handler():',
    ...body,
    '    return jsonify(ok=True)',
  )]];

  it('a path parameter named session or token is not a sign-in word; a /session segment is', () => {
    expect(rows(missingRateLimit, app('/runs/<session_id>/edit'))).toEqual([]);
    expect(rows(missingRateLimit, app('/pay/<token>'))).toEqual([]);
    expect(rows(missingRateLimit, app('/api/session')).length).toBe(1);
  });

  it('reset after a draft is not a password reset; /auth/reset and /reset/<code> are', () => {
    expect(rows(missingRateLimit, app('/drafts/<int:n>/reset'))).toEqual([]);
    expect(rows(missingRateLimit, app('/auth/reset')).length).toBe(1);
    expect(rows(missingRateLimit, app('/reset/<code>')).length).toBe(1);
  });

  it('@x.limit on the view counts when x is a flask_limiter Limiter; a local class of that name does not', () => {
    const limiter = ['from flask_limiter import Limiter', 'from flask_limiter.util import get_remote_address', 'limiter = Limiter(get_remote_address)'];
    expect(rows(missingRateLimit, app('/login', limiter, ['@limiter.limit("5 per minute")']))).toEqual([]);
    const local = ['class Limiter:', '    def __init__(self, *a):', '        pass', '    def limit(self, *a):', '        return lambda f: f', 'limiter = Limiter(None)'];
    expect(rows(missingRateLimit, app('/login', local, ['@limiter.limit("5 per minute")'])).length).toBe(1);
  });

  it('a handler that answers 429 itself is limited; one that never does is not', () => {
    const counted = ['    if too_many():', '        return jsonify(error="slow down"), 429'];
    expect(rows(missingRateLimit, app('/login', ['def too_many():', '    return False'], [], counted))).toEqual([]);
    expect(rows(missingRateLimit, app('/login', ['def too_many():', '    return False'], [], ['    too_many()'])).length).toBe(1);
  });

  it('an app-wide middleware counts only when its class answers 429', () => {
    const fastapi = (status: number): Files => [
      ['api/main.py', py(
        'from fastapi import FastAPI',
        'from .limits import Throttle',
        'from .auth import router',
        'app = FastAPI()',
        'app.add_middleware(Throttle)',
        'app.include_router(router)',
      )],
      ['api/limits.py', py(
        'from starlette.middleware.base import BaseHTTPMiddleware',
        'from starlette.responses import JSONResponse',
        'class Throttle(BaseHTTPMiddleware):',
        '    async def dispatch(self, request, call_next):',
        '        if over_budget(request):',
        `            return JSONResponse({"detail": "slow"}, status_code=${status})`,
        '        return await call_next(request)',
        'def over_budget(request):',
        '    return False',
      )],
      ['api/auth.py', py('from fastapi import APIRouter', 'router = APIRouter()', '@router.post("/login")', 'def login():', '    return {}')],
    ];
    expect(rows(missingRateLimit, fastapi(429))).toEqual([]);
    expect(rows(missingRateLimit, fastapi(400)).length).toBe(1);
  });

  it('a route written in a docstring registers nothing', () => {
    const files: Files = [['srv/deps.py', py(
      '"""Usage:',
      '',
      '    @router.post("/login")',
      '    def login(): ...',
      '"""',
      'from fastapi import APIRouter',
      'router = APIRouter()',
    )]];
    expect(memoryContext(files).projectMap.apiRoutes).toEqual([]);
    expect(rows(missingRateLimit, files)).toEqual([]);
    const flask: Files = [['srv/views.py', py(
      'from flask import Blueprint',
      'bp = Blueprint("a", __name__)',
      'def helper():',
      '    """Example:',
      '        @bp.route("/login", methods=["POST"])',
      '    """',
      '# @bp.route("/signup", methods=["POST"])',
      '@bp.route("/reset-password", methods=["POST"])',
      'def reset():',
      '    return ""',
    )]];
    expect(memoryContext(flask).projectMap.apiRoutes.map((route) => route.routePath)).toEqual(['/reset-password']);
  });
});

describe('sql_injection: f-string SQL from constant fragments, values bound', () => {
  const view = (body: string[]): Files => [['srv/app.py', py(
    'import sqlite3',
    'from flask import Flask, jsonify, request',
    'app = Flask(__name__)',
    'COLUMNS = "id, label"',
    '@app.route("/rows")',
    'def list_rows():',
    '    db = sqlite3.connect("x.db")',
    '    node = request.args.get("node")',
    '    cond, params = [], []',
    '    if node:',
    '        cond.append("node = ?"); params.append(node)',
    ...body,
    '    return jsonify(ok=True)',
  )]];

  it('a WHERE built from typed fragments, with params bound, is not reported', () => {
    expect(rows(sqlInjection, view([
      '    clause_text = ("WHERE " + " AND ".join(cond)) if cond else ""',
      '    db.execute(f"SELECT {COLUMNS} FROM entries {clause_text}", params)',
    ]))).toEqual([]);
    expect(rows(sqlInjection, view([
      '    sets = ", ".join(f"{k}=?" for k in ("label", "node"))',
      '    db.execute(f"UPDATE entries SET {sets} WHERE id=?", params)',
    ]))).toEqual([]);
  });

  it('a fragment carrying a request value, keys from a dict built elsewhere, or no bound values, is reported', () => {
    expect(rows(sqlInjection, view([
      '    cond.append(f"{request.args.get(\'col\')} = ?")',
      '    clause_text = "WHERE " + " AND ".join(cond)',
      '    db.execute(f"SELECT * FROM entries {clause_text}", params)',
    ])).length).toBe(1);
    expect(rows(sqlInjection, view([
      '    fields = request.get_json()',
      '    sets = ", ".join(f"{k}=?" for k in fields)',
      '    db.execute(f"UPDATE entries SET {sets} WHERE id=?", params)',
    ])).length).toBe(1);
    expect(rows(sqlInjection, view([
      '    clause_text = ("WHERE " + " AND ".join(cond)) if cond else ""',
      '    db.execute(f"SELECT * FROM entries {clause_text}")',
    ])).length).toBe(1);
  });
});

describe('open_redirect: back to the URL just requested', () => {
  const view = (target: string): Files => [['srv/app.py', py(
    'from flask import Flask, redirect, request',
    'app = Flask(__name__)',
    '@app.route("/docs", methods=["POST"])',
    'def docs():',
    `    return redirect(${target})`,
  )]];

  it('redirect(request.url) is not an open redirect; a query parameter is', () => {
    expect(rows(openRedirect, view('request.url'))).toEqual([]);
    expect(rows(openRedirect, view('request.args.get("next")')).length).toBe(1);
  });
});
