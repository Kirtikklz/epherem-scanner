import { describe, expect, it } from 'vitest';
import { unsafeFileUpload } from '../../src/rules/basic/unsafeFileUpload.js';
import { fastapiUploads } from '../../src/shared/pythonUpload.js';
import type { Finding, RuleContext } from '../../src/shared/types.js';
import { memoryContext } from './helpers.js';

type Files = [string, string][];
const py = (...lines: string[]): string => `${lines.join('\n')}\n`;
const rows = (files: Files): Finding[] => unsafeFileUpload.run(memoryContext(files) as RuleContext);
const missing = (files: Files): string[] => rows(files).map((f) => /missing: ([^)]*)/.exec(f.evidence ?? '')?.[1] ?? '');

const HEAD = [
  'import os',
  'import io',
  'import csv',
  'import json',
  'import shutil',
  'from fastapi import APIRouter, File, HTTPException, UploadFile',
  '',
  'router = APIRouter()',
  'FOLDER = "/srv/blobs"',
  'KINDS = {".png", ".jpg"}',
  'MEDIA = ["image/png", "image/jpeg"]',
  'LIMIT = 5 * 1024 * 1024',
];
const route = (params: string, body: string[], extra: string[] = []): Files => [
  ['app/blobs.py', py(...HEAD, ...extra, '@router.post("/blobs")', `async def put_blob(${params}):`, ...body, '    return {"ok": True}')],
];
const SAVE = ['    with open(os.path.join(FOLDER, "x.bin"), "wb") as out:', '        shutil.copyfileobj(incoming.file, out)'];
const EXT = ['    ext = os.path.splitext(incoming.filename or "")[1].lower()', '    if ext not in KINDS:', '        raise HTTPException(status_code=400, detail="type")'];
const SIZE = ['    if incoming.size is None or incoming.size > LIMIT:', '        raise HTTPException(status_code=413, detail="size")'];
const BOTH = 'allowed file types, a size limit';

describe('job G: a FastAPI upload parameter is an upload', () => {
  it('an unchecked UploadFile saved to disk reports, at the parameter, missing both', () => {
    const found = rows(route('incoming: UploadFile = File(...)', SAVE));
    expect(found.map((f) => [f.lineStart, f.severity])).toEqual([[14, 'high']]);
    expect(missing(route('incoming: UploadFile = File(...)', SAVE))).toEqual([BOTH]);
  });

  it('a list of uploads, a bytes parameter and an Annotated one are uploads too', () => {
    expect(missing(route('blobs: list[UploadFile]', ['    for incoming in blobs:', ...SAVE.map((l) => `    ${l}`)]))).toEqual([BOTH]);
    expect(missing(route('data: bytes = File(...)', ['    with open(os.path.join(FOLDER, "x.bin"), "wb") as out:', '        out.write(data)']))).toEqual([BOTH]);
    expect(missing(route('incoming: Annotated[UploadFile, File()]', SAVE, ['from typing import Annotated']))).toEqual([BOTH]);
  });

  it('only a route\'s parameter counts, in a file importing fastapi: a helper reached from the route is read through it', () => {
    const helper = [['app/blobs.py', py(...HEAD, 'def keep(incoming: UploadFile):', ...SAVE, '', '@router.post("/blobs")', 'async def put_blob(incoming: UploadFile):', '    keep(incoming)', '    return {"ok": True}')]] as Files;
    expect(rows(helper).map((f) => f.lineStart)).toEqual([18]);
    const unrouted = [['app/blobs.py', py(...HEAD, 'async def put_blob(incoming: UploadFile):', ...SAVE)]] as Files;
    expect(rows(unrouted)).toEqual([]);
    const noImport = route('incoming: UploadFile', SAVE).map(([p, t]) => [p, t.replace('from fastapi import', 'from somewhere import')]) as Files;
    expect(rows(noImport)).toEqual([]);
  });
});

describe('job G: the allow-list and size credits, each with its twin', () => {
  it('an extension allow-list and a size check before the write clear it; each alone leaves the other missing', () => {
    expect(rows(route('incoming: UploadFile', [...EXT, ...SIZE, ...SAVE]))).toEqual([]);
    expect(missing(route('incoming: UploadFile', [...EXT, ...SAVE]))).toEqual(['a size limit']);
    expect(missing(route('incoming: UploadFile', [...SIZE, ...SAVE]))).toEqual(['allowed file types']);
  });

  it('the declared content type against a fixed list, and len() of the bytes read, are credited', () => {
    const body = [
      '    if incoming.content_type not in MEDIA:', '        raise HTTPException(status_code=415, detail="type")',
      '    payload = await incoming.read()', '    if len(payload) > LIMIT:', '        raise HTTPException(status_code=413, detail="size")',
      '    with open(os.path.join(FOLDER, "x.bin"), "wb") as out:', '        out.write(payload)',
    ];
    expect(rows(route('incoming: UploadFile', body))).toEqual([]);
    expect(rows(route('incoming: UploadFile', ['    kind = incoming.content_type', '    if kind not in MEDIA:', ...body.slice(1)]))).toEqual([]);
    expect(missing(route('incoming: UploadFile', ['    kind = incoming.content_type', '    if kind not in other_kinds():', ...body.slice(1)]))).toEqual(['allowed file types']);
  });

  it('a check that does not refuse (it only logs) still reports', () => {
    const logged = EXT.map((l) => l.includes('raise') ? '        print("odd type")' : l);
    expect(missing(route('incoming: UploadFile', [...logged, ...SIZE, ...SAVE]))).toEqual(['allowed file types']);
    const loggedSize = SIZE.map((l) => l.includes('raise') ? '        print("big")' : l);
    expect(missing(route('incoming: UploadFile', [...EXT, ...loggedSize, ...SAVE]))).toEqual(['a size limit']);
  });

  it('a check made after the file is written still reports', () => {
    expect(missing(route('incoming: UploadFile', [...SAVE, ...EXT, ...SIZE]))).toEqual([BOTH]);
    expect(missing(route('incoming: UploadFile', [...EXT, ...SAVE, ...SIZE]))).toEqual(['a size limit']);
  });

  it('a check holding the write must let the file through: "not in the list" holding the save is not a credit', () => {
    const name = '    ext = os.path.splitext(incoming.filename or "")[1].lower()';
    const inside = SAVE.map((l) => `    ${l}`);
    expect(rows(route('incoming: UploadFile', [name, ...SIZE, '    if ext in KINDS:', ...inside]))).toEqual([]);
    expect(missing(route('incoming: UploadFile', [name, ...SIZE, '    if ext not in KINDS:', ...inside]))).toEqual(['allowed file types']);
    const read = ['    payload = await incoming.read()', name, '    if ext not in KINDS:', '        raise HTTPException(status_code=400, detail="type")'];
    const write = ['        with open(os.path.join(FOLDER, "x.bin"), "wb") as out:', '            out.write(payload)'];
    expect(rows(route('incoming: UploadFile', [...read, '    if len(payload) <= LIMIT:', ...write]))).toEqual([]);
    expect(missing(route('incoming: UploadFile', [...read, '    if len(payload) > LIMIT:', ...write]))).toEqual(['a size limit']);
  });

  it('the list must be fixed: an attribute or a computed list is not credited; a literal in the condition is', () => {
    const name = '    ext = os.path.splitext(incoming.filename or "")[1].lower()';
    const refuse = '        raise HTTPException(status_code=400, detail="type")';
    expect(missing(route('incoming: UploadFile', [name, '    if ext not in settings.KINDS:', refuse, ...SIZE, ...SAVE], ['from .config import settings']))).toEqual(['allowed file types']);
    expect(missing(route('incoming: UploadFile', [name, '    if ext not in OPEN:', refuse, ...SIZE, ...SAVE], ['OPEN = load_kinds()']))).toEqual(['allowed file types']);
    expect(missing(route('incoming: UploadFile', [name, '    if ext not in OPEN:', refuse, ...SIZE, ...SAVE], ['OPEN = {k for k in KINDS}']))).toEqual(['allowed file types']);
    expect(rows(route('incoming: UploadFile', [name, '    if ext not in {".png", ".gif"}:', refuse, ...SIZE, ...SAVE]))).toEqual([]);
    expect(rows(route('incoming: UploadFile', [name, '    if ext not in OPEN:', refuse, ...SIZE, ...SAVE], ['OPEN = frozenset({".png", ".gif"})']))).toEqual([]);
  });

  it('every binding of the list counts: rebound to something computed, it is not fixed; a binding inside another def is not this one\'s', () => {
    const name = '    ext = os.path.splitext(incoming.filename or "")[1].lower()';
    const refuse = '        raise HTTPException(status_code=400, detail="type")';
    const body = [name, '    if ext not in OPEN:', refuse, ...SIZE, ...SAVE];
    expect(missing(route('incoming: UploadFile', body, ['OPEN = {".png"}', 'OPEN = load_kinds()']))).toEqual(['allowed file types']);
    expect(rows(route('incoming: UploadFile', body, ['OPEN = {".png"}', 'def elsewhere():', '    OPEN = load_kinds()', '    return OPEN']))).toEqual([]);
  });

  it('a dict read that refuses on a miss counts only when the dict is fixed', () => {
    const body = ['    ext = os.path.splitext(incoming.filename or "")[1].lower()', '    kind = SUFFIXES.get(ext)', '    if kind is None:', '        raise HTTPException(status_code=400, detail="type")', ...SIZE, ...SAVE];
    expect(rows(route('incoming: UploadFile', body, ['SUFFIXES = {".png": "image/png"}']))).toEqual([]);
    expect(missing(route('incoming: UploadFile', body, ['SUFFIXES = load_table()']))).toEqual(['allowed file types']);
    const typed = ['    suffix = SUFFIXES.get(incoming.content_type or "")', '    if suffix is None:', '        raise HTTPException(status_code=415, detail="type")', ...SIZE, ...SAVE];
    expect(rows(route('incoming: UploadFile', typed, ['SUFFIXES = {"image/png": ".png"}']))).toEqual([]);
    expect(missing(route('incoming: UploadFile', typed, ['SUFFIXES = load_table()']))).toEqual(['allowed file types']);
  });

  it('the name\'s ending against written suffixes is a type check; against a computed one, or only logged, it is not', () => {
    const name = '    label = os.path.basename(incoming.filename or "")';
    const refuse = '        raise HTTPException(status_code=400, detail="type")';
    expect(rows(route('incoming: UploadFile', [name, '    if not label.lower().endswith((".png", ".gif")):', refuse, ...SIZE, ...SAVE]))).toEqual([]);
    expect(rows(route('incoming: UploadFile', [name, '    if not (label and label.endswith(".png")):', refuse, ...SIZE, ...SAVE]))).toEqual([]);
    expect(missing(route('incoming: UploadFile', [name, '    if not label.endswith(wanted()):', refuse, ...SIZE, ...SAVE]))).toEqual(['allowed file types']);
    expect(missing(route('incoming: UploadFile', [name, '    if not label.endswith(".png"):', '        print("odd")', ...SIZE, ...SAVE]))).toEqual(['allowed file types']);
  });

  it('a check helper counts only when its body tests membership against a fixed list', () => {
    const body = ['    if not looks_fine(incoming.filename):', '        raise HTTPException(status_code=400, detail="type")', ...SIZE, ...SAVE];
    expect(rows(route('incoming: UploadFile', body, ['def looks_fine(name):', '    return os.path.splitext(name)[1].lower() in KINDS']))).toEqual([]);
    expect(missing(route('incoming: UploadFile', body, ['def looks_fine(name):', '    return True']))).toEqual(['allowed file types']);
    expect(missing(route('incoming: UploadFile', body, ['def looks_fine(name):', '    return os.path.splitext(name)[1].lower() in settings.KINDS']))).toEqual(['allowed file types']);
  });

  it('a signature table: the bytes compared with each entry of a fixed collection, refused on a miss, is a type check', () => {
    const table = ['MARKS = {', '    "png": b"\\x89PNG",', '    "gif": b"GIF8",', '}', 'def sort_out(head):', '    for kind, mark in MARKS.items():', '        if head.startswith(mark):', '            return kind', '    return None'];
    const body = [
      '    payload = await incoming.read(LIMIT + 1)', '    if len(payload) > LIMIT:', '        raise HTTPException(status_code=413, detail="size")',
      '    kind = sort_out(payload)', '    if kind is None:', '        raise HTTPException(status_code=415, detail="type")',
      '    with open(os.path.join(FOLDER, "x." + kind), "wb") as out:', '        out.write(payload)',
    ];
    expect(rows(route('incoming: UploadFile', body, table))).toEqual([]);
    const looks = table.map((l) => l.includes('startswith') ? '        if mark:' : l);
    expect(missing(route('incoming: UploadFile', body, looks))).toEqual(['allowed file types']);
    const loaded = table.map((l, i) => i === 0 ? 'MARKS = load_marks()' : i < 4 ? '' : l);
    expect(missing(route('incoming: UploadFile', body, loaded))).toEqual(['allowed file types']);
    const logged = body.map((l) => l.includes('status_code=415') ? '        print("odd")' : l);
    expect(missing(route('incoming: UploadFile', logged, table))).toEqual(['allowed file types']);
    const held = [...body.slice(0, 4), '    if kind is None:', '        with open(os.path.join(FOLDER, "x.bin"), "wb") as out:', '            out.write(payload)'];
    expect(missing(route('incoming: UploadFile', held, table))).toEqual(['allowed file types']);
  });

  it('a helper handed the file that checks it counts from the line that calls it, not after a write', () => {
    const helper = ['def vet(item):', '    if os.path.splitext(item.filename)[1].lower() not in KINDS:', '        raise HTTPException(status_code=400, detail="type")'];
    expect(rows(route('incoming: UploadFile', ['    vet(incoming)', ...SIZE, ...SAVE], helper))).toEqual([]);
    expect(missing(route('incoming: UploadFile', [...SIZE, ...SAVE, '    vet(incoming)'], helper))).toEqual(['allowed file types']);
  });
});

describe('job G: only parsed in memory, where proved', () => {
  it('bytes read straight into json, or into csv through io.StringIO, are not reported', () => {
    expect(rows(route('incoming: UploadFile', ['    rows = json.loads(await incoming.read())', '    print(len(rows))']))).toEqual([]);
    expect(rows(route('incoming: UploadFile', ['    print(incoming.filename, incoming.content_type)', '    await incoming.seek(0)', '    rows = json.loads(await incoming.read())', '    await incoming.close()']))).toEqual([]);
    expect(rows(route('incoming: UploadFile', ['    got = await incoming.read()', '    reader = csv.DictReader(io.StringIO(got.decode("utf-8")))', '    print(sum(1 for _ in reader))']))).toEqual([]);
    expect(rows(route('data: bytes = File(...)', ['    rows = json.loads(data)', '    print(len(rows))']))).toEqual([]);
  });

  it('any other use of the bytes is not proved: kept, transformed, or the file object handed on', () => {
    expect(missing(route('incoming: UploadFile', ['    got = await incoming.read()', '    rows = json.loads(got)', '    archive.put(got)']))).toEqual([BOTH]);
    expect(missing(route('incoming: UploadFile', ['    got = await incoming.read()', '    text = got.decode("utf-8").upper()']))).toEqual([BOTH]);
    expect(missing(route('incoming: UploadFile', ['    rows = json.loads(await incoming.read())', '    archive.put(incoming)']))).toEqual([BOTH]);
    expect(missing(route('incoming: UploadFile', ['    got = await incoming.read()', '    got = got + b"!"', '    rows = json.loads(got)']))).toEqual([BOTH]);
    expect(missing(route('blobs: list[UploadFile]', ['    for incoming in blobs:', '        rows = json.loads(await incoming.read())']))).toEqual([BOTH]);
  });

  it('reading the bytes is not proof: an upload read into memory and not parsed reports', () => {
    expect(missing(route('incoming: UploadFile', ['    got = await incoming.read()']))).toEqual([BOTH]);
    const read = fastapiUploads(memoryContext(route('incoming: UploadFile', ['    got = await incoming.read()'])).fileMap.entries[0]!);
    expect(read.map((u) => [u.name, u.inMemory, u.facts.stored])).toEqual([['incoming', false, false]]);
  });
});

describe('job G: one row per handler', () => {
  it('when an older sink already reports in the def, the parameter adds no second row', () => {
    const files: Files = [['app/blobs.py', py(...HEAD, '@router.post("/blobs")', 'async def put_blob(request, upfile: UploadFile):', '    form = await request.form()', '    with open(os.path.join(FOLDER, upfile.filename), "wb") as out:', '        shutil.copyfileobj(upfile.file, out)', '    return {"ok": True}')]];
    expect(rows(files).map((f) => f.lineStart)).toEqual([16]);
  });
});

describe('job G, attempt 2: a deny-list is not an allow-list', () => {
  const name = '    ext = os.path.splitext(incoming.filename or "")[1].lower()';
  const refuse = '        raise HTTPException(status_code=400, detail="type")';
  const SHUNNED = ['SHUNNED = {".exe", ".php", ".sh"}'];

  it('a fixed set of bad extensions, refused, reports; the allow-list twin is silent', () => {
    expect(missing(route('incoming: UploadFile', [name, '    if ext in SHUNNED:', refuse, ...SIZE, ...SAVE], SHUNNED))).toEqual(['allowed file types']);
    expect(rows(route('incoming: UploadFile', [name, '    if ext not in KINDS:', refuse, ...SIZE, ...SAVE], SHUNNED))).toEqual([]);
  });

  it('a written tuple of bad extensions reports; a written tuple of good ones, refused on a miss, is silent', () => {
    expect(missing(route('incoming: UploadFile', [name, '    if ext in (".exe", ".php"):', refuse, ...SIZE, ...SAVE]))).toEqual(['allowed file types']);
    expect(rows(route('incoming: UploadFile', [name, '    if ext not in (".png", ".jpg"):', refuse, ...SIZE, ...SAVE]))).toEqual([]);
  });

  it('bad content types, refused, report; good ones refused on a miss are silent', () => {
    expect(missing(route('incoming: UploadFile', ['    if incoming.content_type in {"text/html", "application/x-php"}:', refuse, ...SIZE, ...SAVE]))).toEqual(['allowed file types']);
    expect(rows(route('incoming: UploadFile', ['    if incoming.content_type not in {"image/png", "image/jpeg"}:', refuse, ...SIZE, ...SAVE]))).toEqual([]);
  });

  it('a name ending in a bad suffix, refused, reports; not ending in a good one, refused, is silent', () => {
    expect(missing(route('incoming: UploadFile', ['    if incoming.filename.endswith(".exe"):', refuse, ...SIZE, ...SAVE]))).toEqual(['allowed file types']);
    expect(rows(route('incoming: UploadFile', ['    if not incoming.filename.endswith(".png"):', refuse, ...SIZE, ...SAVE]))).toEqual([]);
  });

  it('a check helper: `if not allowed(f)` refused counts, `if blocked(f)` refused does not, whatever its body', () => {
    const helper = ['def kind_ok(label):', '    return os.path.splitext(label)[1].lower() in KINDS'];
    expect(rows(route('incoming: UploadFile', ['    if not kind_ok(incoming.filename):', refuse, ...SIZE, ...SAVE], helper))).toEqual([]);
    expect(missing(route('incoming: UploadFile', ['    if kind_ok(incoming.filename):', refuse, ...SIZE, ...SAVE], helper))).toEqual(['allowed file types']);
  });

  it('the helper must say yes to what is on its list: a `not in` body, or one that branches, is not read', () => {
    const call = ['    if not kind_ok(incoming.filename):', refuse, ...SIZE, ...SAVE];
    expect(missing(route('incoming: UploadFile', call, [...SHUNNED, 'def kind_ok(label):', '    return os.path.splitext(label)[1].lower() not in SHUNNED']))).toEqual(['allowed file types']);
    expect(missing(route('incoming: UploadFile', call, ['def kind_ok(label):', '    if os.path.splitext(label)[1].lower() in KINDS:', '        return True', '    return False']))).toEqual(['allowed file types']);
  });

  it('a block holding the write must let no miss in, even when it also returns', () => {
    const inside = ['    if ext not in KINDS:', ...SAVE.map((l) => `    ${l}`), '        return {"saved": True}'];
    expect(missing(route('incoming: UploadFile', [name, ...SIZE, ...inside]))).toEqual(['allowed file types']);
  });

  it('and / or / not are read; a test whose polarity cannot be read is not credited', () => {
    expect(rows(route('incoming: UploadFile', [name, '    if ext not in KINDS or incoming.size > LIMIT:', refuse, ...SAVE]))).toEqual([]);
    expect(rows(route('incoming: UploadFile', [name, '    if not (ext in KINDS and incoming.size <= LIMIT):', refuse, ...SAVE]))).toEqual([]);
    expect(missing(route('incoming: UploadFile', [name, '    if ext not in KINDS and incoming.size > LIMIT:', refuse, ...SAVE]))).toEqual([BOTH]);
    expect(missing(route('incoming: UploadFile', [name, '    if (ext not in KINDS) if incoming.size else False:', refuse, ...SIZE, ...SAVE]))).toEqual(['allowed file types']);
  });
});

describe('job G, attempt 2: a minimum is not a cap', () => {
  const big = '        raise HTTPException(status_code=413, detail="size")';

  it('a refused size test counts only when it says too big', () => {
    expect(missing(route('incoming: UploadFile', [...EXT, '    if incoming.size < LIMIT:', big, ...SAVE]))).toEqual(['a size limit']);
    expect(missing(route('incoming: UploadFile', [...EXT, '    if LIMIT > incoming.size:', big, ...SAVE]))).toEqual(['a size limit']);
    expect(missing(route('incoming: UploadFile', [...EXT, '    if incoming.size == LIMIT:', big, ...SAVE]))).toEqual(['a size limit']);
    for (const test of ['incoming.size > LIMIT', 'incoming.size >= LIMIT', 'LIMIT < incoming.size', 'not incoming.size <= LIMIT']) {
      expect(rows(route('incoming: UploadFile', [...EXT, `    if ${test}:`, big, ...SAVE]))).toEqual([]);
    }
  });

  it('a size test holding the write still counts when it lets only the small in, a chain included', () => {
    const read = ['    payload = await incoming.read()', ...EXT];
    const write = ['        with open(os.path.join(FOLDER, "x.bin"), "wb") as out:', '            out.write(payload)'];
    expect(rows(route('incoming: UploadFile', [...read, '    if 0 < len(payload) <= LIMIT:', ...write]))).toEqual([]);
    expect(missing(route('incoming: UploadFile', [...read, '    if 0 < len(payload) >= LIMIT:', ...write]))).toEqual(['a size limit']);
  });
});

describe('job G, attempt 2: a sniffed or looked-up kind counts only as "nothing matched"', () => {
  const table = ['MARKS = {', '    "png": b"\\x89PNG",', '    "gif": b"GIF8",', '}', 'BARRED = ("exe", "elf")', 'def sort_out(head):', '    for kind, mark in MARKS.items():', '        if head.startswith(mark):', '            return kind', '    return None'];
  const body = (test: string): string[] => [
    '    payload = await incoming.read(LIMIT + 1)', '    if len(payload) > LIMIT:', '        raise HTTPException(status_code=413, detail="size")',
    '    kind = sort_out(payload)', `    if ${test}:`, '        raise HTTPException(status_code=415, detail="type")',
    '    with open(os.path.join(FOLDER, "x.bin"), "wb") as out:', '        out.write(payload)',
  ];

  it('`not kind` and `kind not in <fixed list>` refused are silent', () => {
    expect(rows(route('incoming: UploadFile', body('not kind'), table))).toEqual([]);
    expect(rows(route('incoming: UploadFile', body('kind not in ("png", "gif")'), table))).toEqual([]);
  });

  it('`kind == ...`, `kind in BARRED` and `kind is not None` refused report', () => {
    expect(missing(route('incoming: UploadFile', body('kind == "exe"'), table))).toEqual(['allowed file types']);
    expect(missing(route('incoming: UploadFile', body('kind in BARRED'), table))).toEqual(['allowed file types']);
    expect(missing(route('incoming: UploadFile', body('kind is not None'), table))).toEqual(['allowed file types']);
  });

  it('a fixed dict read: refused when it is found reports; refused when it is not is silent', () => {
    const read = ['    ext = os.path.splitext(incoming.filename or "")[1].lower()', '    kind = SUFFIXES.get(ext)'];
    const refused = '        raise HTTPException(status_code=400, detail="type")';
    expect(missing(route('incoming: UploadFile', [...read, '    if kind is not None:', refused, ...SIZE, ...SAVE], ['SUFFIXES = {".exe": "x"}']))).toEqual(['allowed file types']);
    expect(rows(route('incoming: UploadFile', [...read, '    if not kind:', refused, ...SIZE, ...SAVE], ['SUFFIXES = {".png": "x"}']))).toEqual([]);
  });
});

describe('job G, attempt 2: a route decorator over several lines', () => {
  const file = (decorator: string[]): Files => [['app/blobs.py', py(...HEAD, ...decorator, 'async def put_blob(incoming: UploadFile):', ...SAVE, '    return {"ok": True}')]];

  it('is read as a route, its upload parameter reported', () => {
    expect(rows(file(['@router.post(', '    "/blobs",', '    status_code=201,', ')'])).map((f) => f.lineStart)).toEqual([17]);
    expect(rows(file(['@router.post("/blobs")', '@functools.lru_cache(', '    maxsize=1,', ')'])).map((f) => f.lineStart)).toEqual([17]);
  });

  it('a decorator over several lines that is not a route stays out, and so does a call that is not a decorator', () => {
    expect(rows(file(['@functools.lru_cache(', '    maxsize=1,', ')']))).toEqual([]);
    expect(rows(file(['router.post(', '    "/blobs",', ')']))).toEqual([]);
  });
});

describe('job G, attempt 2: what each part of a test may be', () => {
  const name = '    ext = os.path.splitext(incoming.filename or "")[1].lower()';
  const refuse = '        raise HTTPException(status_code=400, detail="type")';
  const big = '        raise HTTPException(status_code=413, detail="size")';

  it('the list is the whole right-hand side: a fixed list joined to a computed one is not fixed', () => {
    expect(missing(route('incoming: UploadFile', [name, '    if ext not in KINDS | load_kinds():', refuse, ...SIZE, ...SAVE]))).toEqual(['allowed file types']);
    expect(missing(route('incoming: UploadFile', [name, '    if ext not in (".png", ".jpg") + tuple(load_kinds()):', refuse, ...SIZE, ...SAVE]))).toEqual(['allowed file types']);
  });

  it('the left-hand side must be the file\'s name or type: another value against the list is not a check of the file', () => {
    expect(missing(route('incoming: UploadFile', ['    mode = pick_mode()', '    if mode not in KINDS:', refuse, ...SIZE, ...SAVE]))).toEqual(['allowed file types']);
    const helper = ['def kind_ok(label):', '    return os.path.splitext(label)[1].lower() in KINDS'];
    expect(missing(route('incoming: UploadFile', ['    if not kind_ok(pick_mode()):', refuse, ...SIZE, ...SAVE], helper))).toEqual(['allowed file types']);
  });

  it('a helper is read only as the whole part: its answer compared with something else says nothing', () => {
    const helper = ['def kind_ok(label):', '    return os.path.splitext(label)[1].lower() in KINDS'];
    expect(missing(route('incoming: UploadFile', ['    if not kind_ok(incoming.filename) == lenient():', refuse, ...SIZE, ...SAVE], helper))).toEqual(['allowed file types']);
  });

  it('a one-line check that does not refuse says nothing', () => {
    expect(missing(route('incoming: UploadFile', [name, '    if ext not in KINDS: print("odd")', ...SIZE, ...SAVE]))).toEqual(['allowed file types']);
  });

  it('a conditional expression says nothing', () => {
    expect(missing(route('incoming: UploadFile', [name, '    if ext if incoming.size else incoming.filename not in KINDS:', refuse, ...SIZE, ...SAVE]))).toEqual(['allowed file types']);
  });

  it('a size test needs the size on exactly one side, compared by < or >', () => {
    expect(missing(route('incoming: UploadFile', [...EXT, '    if LIMIT == incoming.size:', big, ...SAVE]))).toEqual(['a size limit']);
    expect(missing(route('incoming: UploadFile', [...EXT, '    if 0 < LIMIT:', big, ...SAVE]))).toEqual(['a size limit']);
  });

  it('a sniffed kind holding the write is not a credit, whichever way round', () => {
    const table = ['MARKS = {', '    "png": b"\\x89PNG",', '}', 'def sort_out(head):', '    for kind, mark in MARKS.items():', '        if head.startswith(mark):', '            return kind', '    return None'];
    const body = [
      '    payload = await incoming.read(LIMIT + 1)', '    if len(payload) > LIMIT:', '        raise HTTPException(status_code=413, detail="size")',
      '    kind = sort_out(payload)', '    if kind:', '        with open(os.path.join(FOLDER, "x.bin"), "wb") as out:', '            out.write(payload)',
    ];
    expect(missing(route('incoming: UploadFile', body, table))).toEqual(['allowed file types']);
  });

  it('a def right after a route\'s body is not decorated by it', () => {
    const files: Files = [['app/blobs.py', py(...HEAD, '@router.post("/ping")', 'async def ping():', '    return {"ok": True}', 'async def put_blob(incoming: UploadFile):', ...SAVE)]];
    expect(rows(files)).toEqual([]);
  });
});
