import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { brokenAccessControl } from '../../src/rules/contextual/brokenAccessControl.js';
import { databaseDeleteWithoutOwnershipCheck } from '../../src/rules/contextual/databaseDeleteWithoutOwnershipCheck.js';
import { memoryContext } from './helpers.js';
import { preparePythonReader, releasePythonReader } from '../../src/shared/pythonParser.js';

beforeAll(async () => { await preparePythonReader(); });
afterAll(() => { releasePythonReader(); });

type Files = [string, string][];
const py = (...lines: string[]): string => `${lines.join('\n')}\n`;
const edits = (files: Files): string[] =>
  brokenAccessControl.run(memoryContext(files)).map((f) => `${f.filePath}:${f.lineStart}`).sort();
const at = (files: Files, path: string, needle: string): string => {
  const lines = (files.find(([p]) => p === path)?.[1] ?? '').split('\n');
  const index = lines.findIndex((line) => line.includes(needle));
  if (index < 0) throw new Error(`no line with ${needle}`);
  return `${path}:${index + 1}`;
};

const FASTAPI_HEAD = [
  'from fastapi import APIRouter, Depends, HTTPException',
  'from fastapi.security import OAuth2PasswordBearer',
  'from sqlalchemy import update',
  'from sqlalchemy.orm import Session',
  'from .models import Kite, Pilot',
  'from .database import get_db',
  'router = APIRouter()',
  'bearer = OAuth2PasswordBearer(tokenUrl="token")',
  'def pilot_in(token: str = Depends(bearer), db: Session = Depends(get_db)):',
  '    who = db.get(Pilot, token)',
  '    if who is None:',
  '        raise HTTPException(status_code=401)',
  '    return who',
];
const KITES = 'air/kites.py';
const fastapi = (...body: string[]): Files => [[KITES, py(...FASTAPI_HEAD, ...body)]];
const ROUTE = '@router.patch("/kites/{kite_id}")';
const SIGNATURE = 'def retitle(kite_id: int, name: str, flier_id: int = 0, who=Depends(pilot_in), db: Session = Depends(get_db)):';

describe('broken_access_control: SQLAlchemy edits in FastAPI', () => {
  it('a row fetched by id alone, written and committed, reports at the fetch; fetched with the caller in the filter it is owned', () => {
    const byId = fastapi(ROUTE, SIGNATURE, '    kite = db.get(Kite, kite_id)', '    kite.name = name', '    db.commit()');
    expect(edits(byId)).toEqual([at(byId, KITES, 'kite = db.get(')]);
    expect(edits(fastapi(ROUTE, SIGNATURE,
      '    kite = db.query(Kite).filter(Kite.id == kite_id, Kite.flier_id == who.id).first()',
      '    kite.name = name',
      '    db.commit()',
    ))).toEqual([]);
  });

  it('the owner value taken from the request is not the caller', () => {
    const files = fastapi(ROUTE, SIGNATURE,
      '    kite = db.query(Kite).filter(Kite.id == kite_id, Kite.flier_id == flier_id).first()',
      '    kite.name = name',
      '    db.commit()',
    );
    expect(edits(files)).toEqual([at(files, KITES, 'kite = db.query(')]);
  });

  it('a write persists only through a commit after it: no commit, or a commit before the write only, is no edit', () => {
    expect(edits(fastapi(ROUTE, SIGNATURE, '    kite = db.get(Kite, kite_id)', '    kite.name = name', '    return kite'))).toEqual([]);
    expect(edits(fastapi(ROUTE, SIGNATURE, '    kite = db.get(Kite, kite_id)', '    db.commit()', '    kite.name = name', '    return kite'))).toEqual([]);
    const sessionCommit = fastapi(ROUTE, SIGNATURE, '    kite = db.get(Kite, kite_id)', '    kite.name = name', '    db.session.commit()');
    expect(edits(sessionCommit)).toEqual([at(sessionCommit, KITES, 'kite = db.get(')]);
    const asyncCommit = fastapi(ROUTE, SIGNATURE.replace('def ', 'async def '), '    kite = await db.get(Kite, kite_id)', '    kite.name = name', '    await db.commit()');
    expect(edits(asyncCommit)).toEqual([at(asyncCommit, KITES, 'kite = await db.get(')]);
  });

  it('a commit on something that is not a database session does not make the write persist', () => {
    expect(edits(fastapi(ROUTE, SIGNATURE, '    kite = db.get(Kite, kite_id)', '    kite.name = name', '    journal.commit()'))).toEqual([]);
  });

  it('a commit in another handler does not make this write persist', () => {
    expect(edits(fastapi(ROUTE, SIGNATURE, '    kite = db.get(Kite, kite_id)', '    kite.name = name', '    return kite',
      '@router.post("/kites/flush")',
      'def flush(who=Depends(pilot_in), db: Session = Depends(get_db)):',
      '    db.commit()',
    ))).toEqual([]);
  });

  it('augmented writes, item writes and setattr are writes too', () => {
    const augmented = fastapi(ROUTE, SIGNATURE, '    kite = db.get(Kite, kite_id)', '    kite.flights += 1', '    db.commit()');
    expect(edits(augmented)).toEqual([at(augmented, KITES, 'kite = db.get(')]);
    const item = fastapi(ROUTE, SIGNATURE, '    kite = db.get(Kite, kite_id)', '    kite.extras["tail"] = name', '    db.commit()');
    expect(edits(item)).toEqual([at(item, KITES, 'kite = db.get(')]);
    const viaSetattr = fastapi(ROUTE, SIGNATURE, '    kite = db.get(Kite, kite_id)', '    for key, value in {"name": name}.items():', '        setattr(kite, key, value)', '    db.commit()');
    expect(edits(viaSetattr)).toEqual([at(viaSetattr, KITES, 'kite = db.get(')]);
  });

  it('a check before the commit: against the caller it is a credit, against a client value none, against an unread value unclassified', () => {
    const route = (other: string): Files => fastapi(ROUTE, SIGNATURE,
      '    kite = db.get(Kite, kite_id)',
      '    kite.name = name',
      `    if kite.flier_id != ${other}:`,
      '        raise HTTPException(status_code=403)',
      '    db.commit()',
    );
    expect(edits(route('who.id'))).toEqual([]);
    expect(edits(route('flier_id'))).toEqual([at(route('flier_id'), KITES, 'kite = db.get(')]);
    expect(edits(route('crew_lead(who)'))).toEqual([]);
  });

  it('a core update(...).where(...) by id alone reports; with the caller it is owned; the values written are no constraint', () => {
    const byId = fastapi(ROUTE, SIGNATURE, '    db.execute(update(Kite).where(Kite.id == kite_id).values(name=name))', '    db.commit()');
    expect(edits(byId)).toEqual([at(byId, KITES, 'db.execute(update(')]);
    expect(edits(fastapi(ROUTE, SIGNATURE, '    db.execute(update(Kite).where(Kite.id == kite_id, Kite.flier_id == who.id).values(name=name))'))).toEqual([]);
    const ownerWritten = fastapi(ROUTE, SIGNATURE, '    db.execute(update(Kite).where(Kite.id == kite_id).values(flier_id=who.id))');
    expect(edits(ownerWritten)).toEqual([at(ownerWritten, KITES, 'db.execute(update(')]);
  });

  it('a project function named update is not the sqlalchemy core update', () => {
    const files: Files = [[KITES, py(...FASTAPI_HEAD.map((l) => (l === 'from sqlalchemy import update' ? 'from .writes import update' : l)),
      ROUTE, SIGNATURE, '    db.execute(update(Kite).where(Kite.id == kite_id).values(name=name))')]];
    expect(edits(files)).toEqual([]);
  });

  it('a query .update({...}) by id alone reports; with the caller it is owned; an owner in the payload is no constraint', () => {
    const byId = fastapi(ROUTE, SIGNATURE, '    db.query(Kite).filter(Kite.id == kite_id).update({"name": name})', '    db.commit()');
    expect(edits(byId)).toEqual([at(byId, KITES, 'db.query(Kite)')]);
    expect(edits(fastapi(ROUTE, SIGNATURE, '    db.query(Kite).filter(Kite.id == kite_id, Kite.flier_id == who.id).update({"name": name})'))).toEqual([]);
    const ownerWritten = fastapi(ROUTE, SIGNATURE, '    db.query(Kite).filter(Kite.id == kite_id).update({"flier_id": who.id})');
    expect(edits(ownerWritten)).toEqual([at(ownerWritten, KITES, 'db.query(Kite)')]);
  });

  it('.update(...) on a local a recognised fetch bound is judged by that fetch; on a dict it is no edit', () => {
    const query = fastapi(ROUTE, SIGNATURE, '    rows = db.query(Kite).filter(Kite.id == kite_id)', '    rows.update({"name": name})');
    expect(edits(query)).toEqual([at(query, KITES, 'rows.update(')]);
    expect(edits(fastapi(ROUTE, SIGNATURE, '    rows = db.query(Kite).filter(Kite.id == kite_id, Kite.flier_id == who.id)', '    rows.update({"name": name})'))).toEqual([]);
    expect(edits(fastapi(ROUTE, SIGNATURE, '    patch = {"id": kite_id}', '    patch.update({"name": name})', '    db.commit()'))).toEqual([]);
  });

  it('an object the route builds itself is not someone else\'s record; one fetched in another branch still is unclassified', () => {
    expect(edits(fastapi(ROUTE, SIGNATURE, '    kite = Kite(name=name, flier_id=who.id)', '    kite.name = name', '    db.add(kite)', '    db.commit()'))).toEqual([]);
    expect(edits(fastapi(ROUTE, SIGNATURE,
      '    if kite_id == 0:',
      '        kite = Kite(name=name, flier_id=who.id)',
      '    else:',
      '        kite = db.get(Kite, kite_id)',
      '    kite.name = name',
      '    db.commit()',
    ))).toEqual([]);
  });

  it('the caller\'s own row is not someone else\'s record', () => {
    expect(edits(fastapi(ROUTE, SIGNATURE, '    who.nickname = name', '    db.commit()'))).toEqual([]);
    expect(edits(fastapi(ROUTE, SIGNATURE, '    me = db.get(Pilot, who.id)', '    me.nickname = name', '    db.commit()'))).toEqual([]);
    const other = fastapi(ROUTE, SIGNATURE, '    me = db.get(Pilot, flier_id)', '    me.nickname = name', '    db.commit()');
    expect(edits(other)).toEqual([at(other, KITES, 'me = db.get(')]);
  });

  it('only a guarded route is judged: an open route, a helper and an admin-only route are not; the sign-in twin is', () => {
    expect(edits(fastapi(ROUTE, 'def retitle(kite_id: int, name: str, db: Session = Depends(get_db)):', '    kite = db.get(Kite, kite_id)', '    kite.name = name', '    db.commit()'))).toEqual([]);
    expect(edits(fastapi('def tidy(kite_id: int, name: str, db: Session):', '    kite = db.get(Kite, kite_id)', '    kite.name = name', '    db.commit()'))).toEqual([]);
    const route = (guard: string): Files => fastapi(
      'def crew_only(who=Depends(pilot_in)):',
      '    if not who.is_admin:',
      '        raise HTTPException(status_code=403)',
      '    return who',
      ROUTE,
      `def retitle(kite_id: int, name: str, who=Depends(${guard}), db: Session = Depends(get_db)):`,
      '    kite = db.get(Kite, kite_id)',
      '    kite.name = name',
      '    db.commit()',
    );
    expect(edits(route('crew_only'))).toEqual([]);
    expect(edits(route('pilot_in'))).toEqual([at(route('pilot_in'), KITES, 'kite = db.get(')]);
  });

  it('two writes of one fetched object report one line', () => {
    const files = fastapi(ROUTE, SIGNATURE, '    kite = db.get(Kite, kite_id)', '    kite.name = name', '    db.commit()', '    kite.flights = 0', '    db.commit()');
    expect(edits(files)).toEqual([at(files, KITES, 'kite = db.get(')]);
  });
});

const SPOOLS = 'mill/spools.py';
const flaskApp = (head: string[], body: string[]): Files => [[SPOOLS, py(
  'from flask import Blueprint, abort, request',
  ...head,
  'from . import db',
  'from .models import Spool',
  'bp = Blueprint("spools", __name__)',
  ...body,
)]];
const FLASK_LOGIN = ['from flask_login import current_user, login_required'];
const FLASK_ROUTE = ['@bp.post("/<int:spool_id>/wind")', '@login_required', 'def wind(spool_id):'];

describe('broken_access_control: Flask-SQLAlchemy edits', () => {
  it('db.get_or_404 by id alone, written and committed, reports at the fetch; filter_by with current_user is owned', () => {
    const byId = flaskApp(FLASK_LOGIN, [...FLASK_ROUTE, '    spool = db.get_or_404(Spool, spool_id)', '    spool.colour = request.form["colour"]', '    db.session.commit()']);
    expect(edits(byId)).toEqual([at(byId, SPOOLS, 'spool = db.get_or_404(')]);
    expect(edits(flaskApp(FLASK_LOGIN, [...FLASK_ROUTE,
      '    spool = Spool.query.filter_by(id=spool_id, winder_id=current_user.id).first_or_404()',
      '    spool.colour = request.form["colour"]',
      '    db.session.commit()',
    ]))).toEqual([]);
    const firstOnly = flaskApp(FLASK_LOGIN, [...FLASK_ROUTE, '    spool = Spool.query.filter_by(id=spool_id).first()', '    spool.colour = request.form["colour"]', '    db.session.commit()']);
    expect(edits(firstOnly)).toEqual([at(firstOnly, SPOOLS, 'spool = Spool.query')]);
  });

  it('an exit check refusing a stranger is a credit; one refusing the owner proves nothing', () => {
    const route = (op: string): Files => flaskApp(FLASK_LOGIN, [...FLASK_ROUTE,
      '    spool = db.session.get(Spool, spool_id)',
      `    if spool.winder_id ${op} current_user.id:`,
      '        abort(403)',
      '    spool.colour = request.form["colour"]',
      '    db.session.commit()',
    ]);
    expect(edits(route('!='))).toEqual([]);
    expect(edits(route('=='))).toEqual([at(route('=='), SPOOLS, 'spool = db.session.get(')]);
  });

  it('a write and commit inside an if requiring the caller are owned; inside an if on something else they report', () => {
    const route = (condition: string): Files => flaskApp(FLASK_LOGIN, [...FLASK_ROUTE,
      '    spool = db.session.get(Spool, spool_id)',
      `    if ${condition}:`,
      '        spool.colour = request.form["colour"]',
      '        db.session.commit()',
    ]);
    expect(edits(route('spool.winder_id == current_user.id'))).toEqual([]);
    expect(edits(route('request.method == "POST"'))).toEqual([at(route('request.method == "POST"'), SPOOLS, 'spool = db.session.get(')]);
  });

  it('a query update by id alone reports once; with current_user it is owned, and the record loop does not judge the line again', () => {
    const byId = flaskApp(FLASK_LOGIN, [...FLASK_ROUTE, '    Spool.query.filter_by(id=spool_id).update({"colour": request.form["colour"]})', '    db.session.commit()']);
    expect(edits(byId)).toEqual([at(byId, SPOOLS, 'Spool.query.filter_by(id=spool_id).update(')]);
    expect(edits(flaskApp(FLASK_LOGIN, [...FLASK_ROUTE, '    Spool.query.filter_by(id=spool_id, winder_id=current_user.id).update({"colour": request.form["colour"]})']))).toEqual([]);
  });

  it('a dict update on the request body is no edit', () => {
    expect(edits(flaskApp(FLASK_LOGIN, [...FLASK_ROUTE, '    changes = dict(request.form)', '    changes.update({"spool": spool_id})', '    db.session.commit()']))).toEqual([]);
  });

  it('the signed-in user\'s own row is not someone else\'s record, nor is a local only ever set to it', () => {
    expect(edits(flaskApp(FLASK_LOGIN, [...FLASK_ROUTE, '    current_user.nickname = request.form["n"]', '    db.session.commit()']))).toEqual([]);
    expect(edits(flaskApp(FLASK_LOGIN, [...FLASK_ROUTE, '    me = current_user', '    me.nickname = request.form["n"]', '    db.session.commit()']))).toEqual([]);
  });

  it('a route with no sign-in is left to api_mutation_without_auth', () => {
    expect(edits(flaskApp(FLASK_LOGIN, ['@bp.post("/<int:spool_id>/wind")', 'def wind(spool_id):',
      '    spool = db.get_or_404(Spool, spool_id)', '    spool.colour = request.form["colour"]', '    db.session.commit()']))).toEqual([]);
  });
});

const BADGES = 'lanyard/views.py';
const djangoView = (...body: string[]): Files => [[BADGES, py(
  'from django.contrib.auth.decorators import login_required',
  'from django.shortcuts import get_object_or_404, redirect',
  'from .models import Badge',
  '@login_required',
  'def relabel(request, pk):',
  ...body,
  '    return redirect("badges")',
)], ['site/settings.py', py('ROOT_URLCONF = "lanyard.urls"')], ['lanyard/urls.py', py(
  'from django.urls import path',
  'from . import views',
  'urlpatterns = [path("badges/<int:pk>/relabel", views.relabel)]',
)]];

describe('broken_access_control: Django ORM edits', () => {
  it('get_object_or_404 by pk alone, written and saved, reports at the fetch; with holder=request.user it is owned', () => {
    const byId = djangoView('    badge = get_object_or_404(Badge, pk=pk)', '    badge.label = request.POST["label"]', '    badge.save()');
    expect(edits(byId)).toEqual([at(byId, BADGES, 'badge = get_object_or_404(')]);
    expect(edits(djangoView('    badge = get_object_or_404(Badge, pk=pk, holder=request.user)', '    badge.label = request.POST["label"]', '    badge.save()'))).toEqual([]);
  });

  it('objects.get(pk=...) is a fetch by a request id; a custom manager method is unread', () => {
    const byId = djangoView('    badge = Badge.objects.get(pk=pk)', '    badge.label = request.POST["label"]', '    badge.save(update_fields=["label"])');
    expect(edits(byId)).toEqual([at(byId, BADGES, 'badge = Badge.objects.get(')]);
    expect(edits(djangoView('    badge = Badge.objects.mine(request).get(pk=pk)', '    badge.label = request.POST["label"]', '    badge.save()'))).toEqual([]);
  });

  it('only the edited object\'s own save makes the write persist', () => {
    expect(edits(djangoView('    badge = get_object_or_404(Badge, pk=pk)', '    badge.label = request.POST["label"]', '    request.user.save()'))).toEqual([]);
  });

  it('a queryset update by pk alone reports; scoped to request.user it is owned; the owner written is no constraint', () => {
    const byId = djangoView('    Badge.objects.filter(pk=pk).update(label=request.POST["label"])');
    expect(edits(byId)).toEqual([at(byId, BADGES, 'Badge.objects.filter(pk=pk).update(')]);
    expect(edits(djangoView('    Badge.objects.filter(pk=pk, holder=request.user).update(label=request.POST["label"])'))).toEqual([]);
    const ownerWritten = djangoView('    Badge.objects.filter(pk=pk).update(holder=request.user)');
    expect(edits(ownerWritten)).toEqual([at(ownerWritten, BADGES, 'Badge.objects.filter(pk=pk).update(')]);
  });

  it('request.user\'s own row and an object the view builds are not someone else\'s record', () => {
    expect(edits(djangoView('    request.user.first_name = request.POST["first"]', '    request.user.save()'))).toEqual([]);
    expect(edits(djangoView('    badge = Badge(label=request.POST["label"], holder=request.user)', '    badge.label = request.POST["label"]', '    badge.save()'))).toEqual([]);
  });
});

describe('broken_access_control: supabase-py updates', () => {
  it('an update chain by id alone reports; an .eq on the caller is owned', () => {
    const route = (eq: string): Files => fastapi('from .supa import supabase', ROUTE, SIGNATURE,
      `    supabase.table("kites").update({"name": name}).eq("id", kite_id)${eq}.execute()`);
    expect(edits(route(''))).toEqual([at(route(''), KITES, 'supabase.table(')]);
    expect(edits(route('.eq("flier_id", flier_id)'))).toEqual([at(route(''), KITES, 'supabase.table(')]);
    expect(edits(route('.eq("flier_id", who.id)'))).toEqual([]);
  });

  it('an update chain on a Flask request id reports; with current_user it is owned', () => {
    const route = (eq: string): Files => flaskApp(['from flask_login import current_user, login_required', 'from .supa import supabase'], [...FLASK_ROUTE,
      `    supabase.table("spools").update({"colour": "red"}).eq("id", request.json["id"])${eq}.execute()`]);
    expect(edits(route(''))).toEqual([at(route(''), SPOOLS, 'supabase.table(')]);
    expect(edits(route('.eq("winder_id", current_user.id)'))).toEqual([]);
  });
});

describe('broken_access_control: who the caller is, on edits', () => {
  it('a FastAPI parameter whose dependency proves a guard is the caller; a value from get_db is not', () => {
    const route = (other: string): Files => fastapi(ROUTE, SIGNATURE,
      '    if kite_id > 100:',
      `        kite = db.query(Kite).filter(Kite.id == kite_id, Kite.flier_id == ${other}).first()`,
      '    else:',
      '        kite = db.get(Kite, kite_id)',
      '    kite.name = name',
      '    db.commit()',
    );
    expect(edits(route('who.id'))).toEqual([at(route('who.id'), KITES, 'kite = db.get(')]);
    expect(edits(route('db.id'))).toEqual([]);
  });

  it('flask_login\'s current_user is the caller', () => {
    const route = (other: string): Files => flaskApp(FLASK_LOGIN, [...FLASK_ROUTE,
      '    if spool_id > 100:',
      `        spool = Spool.query.filter_by(id=spool_id, winder_id=${other}).first_or_404()`,
      '    else:',
      '        spool = db.get_or_404(Spool, spool_id)',
      '    spool.colour = request.form["colour"]',
      '    db.session.commit()',
    ]);
    expect(edits(route('current_user.id'))).toEqual([at(route('current_user.id'), SPOOLS, 'spool = db.get_or_404(')]);
    expect(edits(route('pick_winder()'))).toEqual([]);
  });

  it('Django\'s request.user is the caller', () => {
    const view = (holder: string): Files => djangoView(
      '    if pk > 100:',
      `        badge = get_object_or_404(Badge, pk=pk, holder=${holder})`,
      '    else:',
      '        badge = get_object_or_404(Badge, pk=pk)',
      '    badge.label = request.POST["label"]',
      '    badge.save()',
    );
    expect(edits(view('request.user'))).toEqual([at(view('request.user'), BADGES, 'badge = get_object_or_404(Badge, pk=pk)')]);
    expect(edits(view('request.session_holder'))).toEqual([]);
  });

  it('an object edit names the last fetch before the write', () => {
    const files = fastapi(ROUTE, SIGNATURE,
      '    if kite_id > 100:',
      '        kite = db.get(Kite, kite_id)',
      '    else:',
      '        kite = db.get(Kite, flier_id)',
      '    kite.name = name',
      '    db.commit()',
    );
    expect(edits(files)).toEqual([at(files, KITES, 'kite = db.get(Kite, flier_id)')]);
  });

  it('a lookup the reader does not recognise as the database is not judged', () => {
    expect(edits(fastapi(ROUTE, SIGNATURE, '    kite = registry.get(Kite, kite_id)', '    kite.name = name', '    db.commit()'))).toEqual([]);
    const recognised = fastapi(ROUTE, SIGNATURE, '    kite = db.session.get(Kite, kite_id)', '    kite.name = name', '    db.commit()');
    expect(edits(recognised)).toEqual([at(recognised, KITES, 'kite = db.session.get(')]);
  });

  it('a comparison at the start of a statement is not a write', () => {
    expect(edits(fastapi(ROUTE, SIGNATURE, '    kite = db.get(Kite, kite_id)', '    kite.flights == 0 or abort_flight()', '    db.commit()'))).toEqual([]);
  });

  it('a returning(...) on a core update names columns to give back, not rows', () => {
    const files = fastapi(ROUTE, SIGNATURE, '    db.execute(update(Kite).where(Kite.id == kite_id).values(name=name).returning(Kite.id))');
    expect(edits(files)).toEqual([at(files, KITES, 'db.execute(update(')]);
  });
});

describe('the delete rule and the update rule each read their own sites', () => {
  const deletes = (files: Files): string[] =>
    databaseDeleteWithoutOwnershipCheck.run(memoryContext(files)).map((f) => `${f.filePath}:${f.lineStart}`).sort();
  const updatesOnly = fastapi(ROUTE, SIGNATURE,
    '    db.execute(update(Kite).where(Kite.id == kite_id).values(name=name))',
    '    db.query(Kite).filter(Kite.id == kite_id).update({"name": name})',
    '    kite = db.get(Kite, kite_id)',
    '    kite.name = name',
    '    db.commit()',
    'def tidy(db, kite):',
    '    db.delete(kite)',
  );
  const deletesOnly: Files = [[KITES, py(...FASTAPI_HEAD.map((l) => (l === 'from sqlalchemy import update' ? 'from sqlalchemy import delete' : l)),
    '@router.delete("/kites/{kite_id}")',
    SIGNATURE,
    '    db.execute(delete(Kite).where(Kite.id == kite_id))',
    '    kite = db.get(Kite, kite_id)',
    '    db.delete(kite)',
    '    db.commit()',
  )]];

  it('the delete rule reports no update, and broken_access_control no delete', () => {
    expect(deletes(updatesOnly)).toEqual([]);
    expect(edits(deletesOnly)).toEqual([]);
    expect(edits(updatesOnly).length).toBe(3);
    expect(deletes(deletesOnly).length).toBe(2);
  });
});
