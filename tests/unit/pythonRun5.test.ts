import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { databaseDeleteWithoutOwnershipCheck } from '../../src/rules/contextual/databaseDeleteWithoutOwnershipCheck.js';
import { sqlInjection } from '../../src/rules/basic/sqlInjection.js';
import { memoryContext } from './helpers.js';
import { preparePythonReader, releasePythonReader } from '../../src/shared/pythonParser.js';

beforeAll(async () => { await preparePythonReader(); });
afterAll(() => { releasePythonReader(); });

type Files = [string, string][];
const py = (...lines: string[]): string => `${lines.join('\n')}\n`;
const deletes = (files: Files): string[] =>
  databaseDeleteWithoutOwnershipCheck.run(memoryContext(files)).map((f) => `${f.filePath}:${f.lineStart}`).sort();
const injections = (files: Files): string[] =>
  sqlInjection.run(memoryContext(files)).map((f) => `${f.filePath}:${f.lineStart}`).sort();

const FASTAPI_HEAD = [
  'from fastapi import APIRouter, Depends, HTTPException',
  'from fastapi.security import OAuth2PasswordBearer',
  'from sqlalchemy.orm import Session',
  'from .models import Parcel',
  'from .database import get_db',
  'router = APIRouter()',
  'bearer = OAuth2PasswordBearer(tokenUrl="token")',
  'def signed_in(token: str = Depends(bearer), db: Session = Depends(get_db)):',
  '    who = db.get(Account, token)',
  '    if who is None:',
  '        raise HTTPException(status_code=401)',
  '    return who',
];
const fastapi = (...body: string[]): Files => [['svc/parcels.py', py(...FASTAPI_HEAD, ...body)]];

describe('database_delete_without_ownership_check: SQLAlchemy deletes in FastAPI', () => {
  it('db.delete of a row fetched by id alone reports; fetched with the caller in the filter is owned', () => {
    expect(deletes(fastapi(
      '@router.delete("/parcels/{parcel_id}")',
      'def drop_parcel(parcel_id: int, who=Depends(signed_in), db: Session = Depends(get_db)):',
      '    parcel = db.get(Parcel, parcel_id)',
      '    db.delete(parcel)',
      '    db.commit()',
    ))).toEqual(['svc/parcels.py:16']);
    expect(deletes(fastapi(
      '@router.delete("/parcels/{parcel_id}")',
      'def drop_parcel(parcel_id: int, who=Depends(signed_in), db: Session = Depends(get_db)):',
      '    parcel = (',
      '        db.query(Parcel)',
      '        .filter(Parcel.id == parcel_id, Parcel.sender_id == who.id)',
      '        .first()',
      '    )',
      '    db.delete(parcel)',
    ))).toEqual([]);
  });

  it('the owner value taken from the request is not the caller', () => {
    expect(deletes(fastapi(
      '@router.delete("/parcels/{parcel_id}")',
      'def drop_parcel(parcel_id: int, sender_id: int, who=Depends(signed_in), db: Session = Depends(get_db)):',
      '    parcel = db.query(Parcel).filter(Parcel.id == parcel_id, Parcel.sender_id == sender_id).first()',
      '    db.delete(parcel)',
    ))).toEqual(['svc/parcels.py:16']);
  });

  it('a check against the caller is a credit; against a client value it is none; against an unread value it is unclassified', () => {
    const route = (other: string): Files => fastapi(
      '@router.delete("/parcels/{parcel_id}")',
      'def drop_parcel(parcel_id: int, sender_id: int = 0, who=Depends(signed_in), db: Session = Depends(get_db)):',
      '    parcel = db.get(Parcel, parcel_id)',
      `    if parcel.sender_id != ${other}:`,
      '        raise HTTPException(status_code=403)',
      '    db.delete(parcel)',
    );
    expect(deletes(route('who.id'))).toEqual([]);
    expect(deletes(route('sender_id'))).toEqual(['svc/parcels.py:18']);
    expect(deletes(route('db.id'))).toEqual([]);
  });

  it('a parameter is the caller only when its own dependency proves a guard (seen where one fetch is owned and another is not)', () => {
    const route = (other: string): Files => fastapi(
      '@router.delete("/parcels/{parcel_id}")',
      'def drop_parcel(parcel_id: int, who=Depends(signed_in), db: Session = Depends(get_db)):',
      '    if parcel_id > 100:',
      `        parcel = db.query(Parcel).filter(Parcel.id == parcel_id, Parcel.sender_id == ${other}).first()`,
      '    else:',
      '        parcel = db.get(Parcel, parcel_id)',
      '    db.delete(parcel)',
    );
    expect(deletes(route('who.id'))).toEqual(['svc/parcels.py:19']);
    expect(deletes(route('db.id'))).toEqual([]);
  });

  it('an if that wraps the delete: equal to the caller is a credit, equal to an unread value unclassified, a client value none', () => {
    const route = (other: string): Files => fastapi(
      '@router.delete("/parcels/{parcel_id}")',
      'def drop_parcel(parcel_id: int, sender_id: int = 0, who=Depends(signed_in), db: Session = Depends(get_db)):',
      '    parcel = db.get(Parcel, parcel_id)',
      `    if parcel is not None and parcel.sender_id == ${other}:`,
      '        db.delete(parcel)',
    );
    expect(deletes(route('who.id'))).toEqual([]);
    expect(deletes(route('allowed_sender(who)'))).toEqual([]);
    expect(deletes(route('sender_id'))).toEqual(['svc/parcels.py:17']);
  });

  it('a client id already used to fetch a row the handler checks is unread from then on', () => {
    const route = (...check: string[]): Files => fastapi(
      '@router.delete("/parcels/{parcel_id}/labels/{label_id}")',
      'def drop_label(parcel_id: int, label_id: int, who=Depends(signed_in), db: Session = Depends(get_db)):',
      '    parcel = db.get(Parcel, parcel_id)',
      ...check,
      '    label = db.get(Label, label_id)',
      '    if label.parcel_id != parcel_id:',
      '        raise HTTPException(status_code=404)',
      '    db.delete(label)',
    );
    expect(deletes(route('    if parcel.route not in who.routes():', '        return {"error": "no"}'))).toEqual([]);
    expect(deletes(route('    if parcel.sender_id != who.id:', '        raise HTTPException(status_code=403)'))).toEqual([]);
    expect(deletes(route())).toEqual(['svc/parcels.py:19']);
  });

  it('a check that exits on an unread test of the object leaves the delete unclassified; one on a literal does not', () => {
    const route = (...check: string[]): Files => fastapi(
      '@router.delete("/parcels/{parcel_id}")',
      'def drop_parcel(parcel_id: int, who=Depends(signed_in), db: Session = Depends(get_db)):',
      '    parcel = db.get(Parcel, parcel_id)',
      ...check,
      '    db.delete(parcel)',
    );
    expect(deletes(route('    if parcel.route not in who.routes():', '        return {"error": "no"}'))).toEqual([]);
    expect(deletes(route('    if not may_remove(who, parcel):', '        return {"error": "no"}'))).toEqual([]);
    expect(deletes(route('    if parcel.state != "draft":', '        raise HTTPException(status_code=409)'))).toEqual(['svc/parcels.py:18']);
    expect(deletes(route('    if parcel is None:', '        raise HTTPException(status_code=404)'))).toEqual(['svc/parcels.py:18']);
  });

  it('a scope the reader cannot read keeps the behaviour from before job 5 (no new finding)', () => {
    const route = (...body: string[]): Files => fastapi(
      '@router.delete("/parcels/{parcel_id}")',
      'def drop_parcel(parcel_id: int, who=Depends(signed_in), db: Session = Depends(get_db)):',
      ...body,
    );
    expect(deletes(route('    db.query(Parcel).filter(Parcel.id == parcel_id, Parcel.sender_id == db.id).delete()'))).toEqual([]);
    expect(deletes(route('    route_id = pick_route(who)', '    db.query(Parcel).filter(Parcel.id == parcel_id, Parcel.route_id == route_id).delete()'))).toEqual([]);
    expect(deletes(route('    db.query(Parcel).visible_to(who).filter(Parcel.id == parcel_id).delete()'))).toEqual([]);
    expect(deletes(route('    db.query(Parcel).filter(Parcel.id.in_(pending_ids(parcel_id))).delete()'))).toEqual([]);
    expect(deletes(route('    db.query(Parcel).delete()'))).toEqual([]);
    expect(deletes(route('    db.query(Parcel).filter(Parcel.id == parcel_id, Parcel.state == "draft").delete()'))).toEqual(['svc/parcels.py:15']);
    expect(deletes(route('    route_id = int(parcel_id)', '    db.query(Parcel).filter(Parcel.route_id == route_id).delete()'))).toEqual(['svc/parcels.py:16']);
  });

  it('a query delete with the caller in its filter is owned; without it, it reports', () => {
    expect(deletes(fastapi(
      '@router.delete("/parcels/{parcel_id}")',
      'def drop_parcel(parcel_id: int, who=Depends(signed_in), db: Session = Depends(get_db)):',
      '    db.query(Parcel).filter(Parcel.id == parcel_id, Parcel.sender_id == who.id).delete()',
    ))).toEqual([]);
    expect(deletes(fastapi(
      '@router.delete("/parcels/{parcel_id}")',
      'def drop_parcel(parcel_id: int, who=Depends(signed_in), db: Session = Depends(get_db)):',
      '    db.query(Parcel).filter(Parcel.id == parcel_id).delete()',
    ))).toEqual(['svc/parcels.py:15']);
  });

  it('a tie inside or_(...) is no credit (unread); and_(...) is read', () => {
    expect(deletes(fastapi(
      'from sqlalchemy import or_',
      '@router.delete("/parcels/{parcel_id}")',
      'def drop_parcel(parcel_id: int, who=Depends(signed_in), db: Session = Depends(get_db)):',
      '    parcel = db.query(Parcel).filter(or_(Parcel.id == parcel_id, Parcel.sender_id == who.id)).first()',
      '    if parcel.sender_id != parcel_id:',
      '        raise HTTPException(status_code=403)',
      '    db.delete(parcel)',
    ))).toEqual([]);
    expect(deletes(fastapi(
      'from sqlalchemy import and_',
      '@router.delete("/parcels/{parcel_id}")',
      'def drop_parcel(parcel_id: int, who=Depends(signed_in), db: Session = Depends(get_db)):',
      '    db.query(Parcel).filter(and_(Parcel.id == parcel_id, Parcel.state == "draft")).delete()',
    ))).toEqual(['svc/parcels.py:16']);
    expect(deletes(fastapi(
      'from sqlalchemy import and_',
      '@router.delete("/parcels/{parcel_id}")',
      'def drop_parcel(parcel_id: int, who=Depends(signed_in), db: Session = Depends(get_db)):',
      '    db.query(Parcel).filter(and_(Parcel.id == parcel_id, Parcel.sender_id == who.id)).delete()',
    ))).toEqual([]);
  });

  it('a core delete(...).where(...) with the caller is owned; without it, it reports', () => {
    expect(deletes(fastapi(
      'from sqlalchemy import delete',
      '@router.delete("/parcels/{parcel_id}")',
      'def drop_parcel(parcel_id: int, who=Depends(signed_in), db: Session = Depends(get_db)):',
      '    db.execute(delete(Parcel).where(Parcel.id == parcel_id, Parcel.sender_id == who.id))',
    ))).toEqual([]);
    expect(deletes(fastapi(
      'from sqlalchemy import delete',
      '@router.delete("/parcels/{parcel_id}")',
      'def drop_parcel(parcel_id: int, who=Depends(signed_in), db: Session = Depends(get_db)):',
      '    db.execute(delete(Parcel).where(Parcel.id == parcel_id))',
    ))).toEqual(['svc/parcels.py:16']);
  });

  it('an object from session.execute(select(...).where(...)) carries its where clause', () => {
    const route = (where: string): Files => fastapi(
      'from sqlalchemy import select',
      '@router.delete("/parcels/{parcel_id}")',
      'def drop_parcel(parcel_id: int, who=Depends(signed_in), db: Session = Depends(get_db)):',
      `    parcel = db.execute(select(Parcel).where(${where})).scalar_one()`,
      '    db.delete(parcel)',
    );
    expect(deletes(route('Parcel.id == parcel_id, Parcel.sender_id == who.id'))).toEqual([]);
    expect(deletes(route('Parcel.id == parcel_id'))).toEqual(['svc/parcels.py:17']);
  });

  it('a check before the delete that refuses another owner is a credit; one that does not refuse is not', () => {
    const route = (...check: string[]): Files => fastapi(
      '@router.delete("/parcels/{parcel_id}")',
      'def drop_parcel(parcel_id: int, who=Depends(signed_in), db: Session = Depends(get_db)):',
      '    parcel = db.get(Parcel, parcel_id)',
      ...check,
      '    db.delete(parcel)',
    );
    expect(deletes(route('    if parcel is None or parcel.sender_id != who.id:', '        raise HTTPException(status_code=403)'))).toEqual([]);
    expect(deletes(route('    if parcel.sender_id != who.id:', '        print("someone else")'))).toEqual(['svc/parcels.py:18']);
    expect(deletes(route('    if parcel.sender_id != parcel_id:', '        raise HTTPException(status_code=403)'))).toEqual(['svc/parcels.py:18']);
    expect(deletes(route('    if parcel_id > 10:', '        if parcel.sender_id != who.id:', '            raise HTTPException(status_code=403)'))).toEqual(['svc/parcels.py:19']);
  });

  it('a local that only ever holds the caller is the caller', () => {
    const route = (alias: string): Files => fastapi(
      '@router.delete("/parcels/{parcel_id}")',
      'def drop_parcel(parcel_id: int, sender: int = 0, who=Depends(signed_in), db: Session = Depends(get_db)):',
      `    mine = ${alias}`,
      '    db.query(Parcel).filter(Parcel.id == parcel_id, Parcel.sender_id == mine).delete()',
    );
    expect(deletes(route('who.id'))).toEqual([]);
    expect(deletes(route('sender'))).toEqual(['svc/parcels.py:16']);
  });

  it('an object the reader cannot classify keeps the behaviour from before job 5 (no new finding)', () => {
    const route = (fetch: string): Files => fastapi(
      '@router.delete("/parcels/{parcel_id}")',
      'def drop_parcel(parcel_id: int, who=Depends(signed_in), db: Session = Depends(get_db)):',
      `    parcel = ${fetch}`,
      '    db.delete(parcel)',
    );
    expect(deletes(route('fetch_parcel(parcel_id)'))).toEqual([]);
    expect(deletes(route('db.get(Parcel, parcel_id)'))).toEqual(['svc/parcels.py:16']);
    expect(deletes(fastapi(
      '@router.delete("/parcels/{parcel_id}")',
      'def drop_parcel(parcel_id: int, who=Depends(signed_in), db: Session = Depends(get_db)):',
      '    parcel = db.get(Parcel, parcel_id)',
      '    for parcel in pending(parcel_id):',
      '        pass',
      '    db.delete(parcel)',
    ))).toEqual([]);
  });

  it('a .get on something that is not a database session is not a fetch', () => {
    const route = (fetch: string): Files => fastapi(
      '@router.delete("/parcels/{parcel_id}")',
      'def drop_parcel(parcel_id: int, who=Depends(signed_in), db: Session = Depends(get_db)):',
      `    parcel = ${fetch}`,
      '    db.delete(parcel)',
    );
    expect(deletes(route('registry.get(Parcel, parcel_id)'))).toEqual([]);
    expect(deletes(route('db.session.get(Parcel, parcel_id)'))).toEqual(['svc/parcels.py:16']);
  });

  it('a route behind a proven admin guard is not judged; the same route behind a sign-in guard is', () => {
    const route = (guard: string): Files => fastapi(
      'def staff_only(who=Depends(signed_in)):',
      '    if not who.is_admin:',
      '        raise HTTPException(status_code=403)',
      '    return who',
      '@router.delete("/parcels/{parcel_id}")',
      `def drop_parcel(parcel_id: int, who=Depends(${guard}), db: Session = Depends(get_db)):`,
      '    parcel = db.get(Parcel, parcel_id)',
      '    db.delete(parcel)',
    );
    expect(deletes(route('staff_only'))).toEqual([]);
    expect(deletes(route('signed_in'))).toEqual(['svc/parcels.py:20']);
  });

  it('only a guarded route is judged: an open route is left to api_mutation_without_auth, and a helper to no one', () => {
    expect(deletes(fastapi(
      '@router.delete("/parcels/{parcel_id}")',
      'def drop_parcel(parcel_id: int, db: Session = Depends(get_db)):',
      '    parcel = db.get(Parcel, parcel_id)',
      '    db.delete(parcel)',
    ))).toEqual([]);
    expect(deletes(fastapi(
      'def tidy(parcel_id: int, db: Session):',
      '    parcel = db.get(Parcel, parcel_id)',
      '    db.delete(parcel)',
    ))).toEqual([]);
  });
});

const flaskApp = (head: string[], body: string[], extra: Files = []): Files => [['site/boxes.py', py(
  'from flask import Blueprint, abort, g, request',
  ...head,
  'from . import db',
  'from .models import Lamp',
  'bp = Blueprint("lamps", __name__)',
  ...body,
)], ...extra];
const FLASK_LOGIN = ['from flask_login import current_user, login_required'];

describe('database_delete_without_ownership_check: Flask-SQLAlchemy deletes', () => {
  it('flask_login current_user in filter_by is owned; a fetch by id alone reports', () => {
    expect(deletes(flaskApp(FLASK_LOGIN, [
      '@bp.delete("/<int:lamp_id>")',
      '@login_required',
      'def unplug(lamp_id):',
      '    lamp = Lamp.query.filter_by(id=lamp_id, keeper_id=current_user.id).first_or_404()',
      '    db.session.delete(lamp)',
    ]))).toEqual([]);
    expect(deletes(flaskApp(FLASK_LOGIN, [
      '@bp.delete("/<int:lamp_id>")',
      '@login_required',
      'def unplug(lamp_id):',
      '    lamp = db.session.get(Lamp, lamp_id)',
      '    db.session.delete(lamp)',
    ]))).toEqual(['site/boxes.py:10']);
  });

  it('a current_user that is not flask_login\'s is not the caller (seen where one fetch is owned and another is not)', () => {
    const route = (head: string[]): Files => flaskApp(head, [
      '@bp.delete("/<int:lamp_id>")',
      '@login_required',
      'def unplug(lamp_id):',
      '    if lamp_id > 100:',
      '        lamp = Lamp.query.filter_by(id=lamp_id, keeper_id=current_user.id).first_or_404()',
      '    else:',
      '        lamp = db.session.get(Lamp, lamp_id)',
      '    db.session.delete(lamp)',
    ]);
    expect(deletes(route(FLASK_LOGIN))).toEqual(['site/boxes.py:13']);
    expect(deletes(route(['from flask_login import login_required', 'from .people import current_user']))).toEqual([]);
  });

  it('the owner from the JSON body is not the caller', () => {
    expect(deletes(flaskApp(FLASK_LOGIN, [
      '@bp.delete("/<int:lamp_id>")',
      '@login_required',
      'def unplug(lamp_id):',
      '    Lamp.query.filter_by(id=lamp_id, keeper_id=request.json["keeper"]).delete()',
    ]))).toEqual(['site/boxes.py:9']);
  });

  it('g.<name> is the caller when the project sets it from a value proven not to come from the request', () => {
    const guard = (value: string): Files => [['site/gate.py', py(
      'from functools import wraps',
      'from flask import abort, g, request, session',
      'def keeper_required(view):',
      '    @wraps(view)',
      '    def wrapper(*args, **kwargs):',
      '        claims = read_token()',
      `        g.keeper = ${value}`,
      '        if g.keeper is None:',
      '            abort(401)',
      '        return view(*args, **kwargs)',
      '    return wrapper',
    )]];
    const route = (value: string, house = 'g.keeper.house_id'): Files => flaskApp(['from .gate import keeper_required'], [
      '@bp.delete("/<int:lamp_id>")',
      '@keeper_required',
      'def unplug(lamp_id):',
      '    if lamp_id > 100:',
      `        lamp = Lamp.query.filter_by(id=lamp_id, house_id=${house}).first_or_404()`,
      '    else:',
      '        lamp = db.get_or_404(Lamp, lamp_id)',
      '    db.session.delete(lamp)',
    ], guard(value));
    expect(deletes(route('Keeper.query.get(session["keeper_id"])'))).toEqual(['site/boxes.py:13']);
    expect(deletes(route('find_keeper(claims)'))).toEqual([]);
    expect(deletes(route('find_keeper(request.headers.get("X-Keeper"))'))).toEqual([]);
    expect(deletes(route('Keeper.query.get(session["keeper_id"])', 'request.json["house"]'))).toEqual(['site/boxes.py:13']);
  });

  it('a filter on g.<name> alone is owned; the same filter on a body value reports', () => {
    const files = (house: string, keeper = 'Keeper.query.get(session["keeper_id"])'): Files => flaskApp([], [
      '@bp.delete("/<int:lamp_id>")',
      '@keeper_required',
      'def unplug(lamp_id):',
      `    Lamp.query.filter_by(id=lamp_id, house_id=${house}).delete()`,
    ], [['site/gate.py', py(
      'from flask import abort, g, session',
      'def keeper_required(view):',
      '    def wrapper(*args, **kwargs):',
      `        g.keeper = ${keeper}`,
      '        if g.keeper is None:',
      '            abort(401)',
      '        return view(*args, **kwargs)',
      '    return wrapper',
    )]]);
    expect(deletes(files('g.keeper.house_id').map(([p, c]) => [p, p === 'site/boxes.py' ? c.replace('from . import db', 'from . import db\nfrom .gate import keeper_required') : c]))).toEqual([]);
    expect(deletes(files('request.json["house"]').map(([p, c]) => [p, p === 'site/boxes.py' ? c.replace('from . import db', 'from . import db\nfrom .gate import keeper_required') : c]))).toEqual(['site/boxes.py:9']);
    expect(deletes(files('g.keeper.house_id', 'read_keeper()').map(([p, c]) => [p, p === 'site/boxes.py' ? c.replace('from . import db', 'from . import db\nfrom .gate import keeper_required') : c]))).toEqual([]);
  });
});

const djangoView = (...body: string[]): Files => [['shelf/views.py', py(
  'from django.contrib.auth.decorators import login_required',
  'from django.shortcuts import get_object_or_404, redirect',
  'from .models import Ticket',
  '@login_required',
  'def void_ticket(request, pk):',
  ...body,
  '    return redirect("tickets")',
)], ['proj/settings.py', py('ROOT_URLCONF = "shelf.urls"')], ['shelf/urls.py', py(
  'from django.urls import path',
  'from . import views',
  'urlpatterns = [path("tickets/<int:pk>/void", views.void_ticket)]',
)]];

describe('database_delete_without_ownership_check: Django ORM deletes', () => {
  it('objects.filter(...).delete() by pk alone reports; with owner=request.user it is owned', () => {
    expect(deletes(djangoView('    Ticket.objects.filter(pk=pk).delete()'))).toEqual(['shelf/views.py:6']);
    expect(deletes(djangoView('    Ticket.objects.filter(pk=pk, holder=request.user).delete()'))).toEqual([]);
  });

  it('request.user is the caller (seen where one fetch is owned and another is not)', () => {
    const view = (holder: string): Files => djangoView(
      '    if pk > 100:',
      `        ticket = get_object_or_404(Ticket, pk=pk, holder=${holder})`,
      '    else:',
      '        ticket = get_object_or_404(Ticket, pk=pk)',
      '    ticket.delete()',
    );
    expect(deletes(view('request.user'))).toEqual(['shelf/views.py:10']);
    expect(deletes(view('request.session_holder'))).toEqual([]);
  });

  it('a holder taken from the POST body is not the caller', () => {
    expect(deletes(djangoView('    Ticket.objects.filter(pk=pk, holder_id=request.POST["holder"]).delete()'))).toEqual(['shelf/views.py:6']);
  });

  it('get_object_or_404 with the caller is owned; without it, obj.delete() reports', () => {
    expect(deletes(djangoView('    ticket = get_object_or_404(Ticket, pk=pk, holder=request.user)', '    ticket.delete()'))).toEqual([]);
    expect(deletes(djangoView('    ticket = get_object_or_404(Ticket, pk=pk)', '    ticket.delete()'))).toEqual(['shelf/views.py:7']);
    expect(deletes(djangoView('    get_object_or_404(Ticket, pk=pk, holder__team__lead=request.user).delete()'))).toEqual([]);
    expect(deletes(djangoView('    get_object_or_404(Ticket, pk=pk).delete()'))).toEqual(['shelf/views.py:6']);
  });

  it('objects.get(...).delete() reads its keywords; a Q(...) argument is unread', () => {
    expect(deletes(djangoView('    Ticket.objects.get(pk=pk, holder=request.user).delete()'))).toEqual([]);
    expect(deletes(djangoView('    Ticket.objects.get(pk=pk, voided=False).delete()'))).toEqual(['shelf/views.py:6']);
    expect(deletes(djangoView('    Ticket.objects.get(Q(pk=pk) | Q(holder=request.user)).delete()'))).toEqual([]);
  });

  it('a queryset from a custom manager method, or a parent the reader does not follow, is unread', () => {
    expect(deletes(djangoView('    ticket = get_object_or_404(Ticket.objects.mine(request), pk=pk)', '    ticket.delete()'))).toEqual([]);
    expect(deletes(djangoView('    shelf = pick_shelf(request)', '    Ticket.objects.filter(pk=pk, shelf=shelf).delete()'))).toEqual([]);
    expect(deletes(djangoView('    Ticket.objects.all().delete()'))).toEqual([]);
    expect(deletes(djangoView('    ticket = get_object_or_404(Ticket.objects.all(), pk=pk)', '    ticket.delete()'))).toEqual([]);
  });

  it('an obj.delete() on a name no fetch bound is unclassified', () => {
    expect(deletes(djangoView('    ticket = build_ticket(pk)', '    ticket.delete()'))).toEqual([]);
  });
});

describe('database_delete_without_ownership_check: supabase-py deletes', () => {
  const route = (eq: string): Files => fastapi(
    'from .supa import supabase',
    '@router.delete("/parcels/{parcel_id}")',
    'def drop_parcel(parcel_id: int, sender_id: int = 0, who=Depends(signed_in)):',
    `    supabase.table("parcels").delete().eq("id", parcel_id)${eq}.execute()`,
  );
  it('a line the Python reader judged is not judged again by the older chain branch', () => {
    const files = fastapi(
      'from .supa import supabase',
      '@router.delete("/parcels/{parcel_id}")',
      'def drop_parcel(parcel_id: int, sender_id: int = 0, who=Depends(signed_in)):',
      '    supabase.table("parcels").delete().eq("id", parcel_id).eq("sender_id", sender_id).execute()',
      'def tidy(db, parcel):',
      '    db.delete(parcel)',
    );
    expect(deletes(files)).toEqual(['svc/parcels.py:16']);
  });

  it('an .eq on the caller is owned; an .eq on a client value reports', () => {
    expect(deletes(route('.eq("sender_id", who.id)'))).toEqual([]);
    expect(deletes(route('.eq("sender_id", sender_id)'))).toEqual(['svc/parcels.py:16']);
    expect(deletes(route(''))).toEqual(['svc/parcels.py:16']);
  });
});

describe('sql_injection: SQLAlchemy text() given an f-string', () => {
  const route = (query: string): Files => fastapi(
    'from sqlalchemy import text',
    '@router.get("/parcels")',
    'def find_parcels(term: str, who=Depends(signed_in), db: Session = Depends(get_db)):',
    `    return db.execute(${query}).all()`,
  );
  it('an f-string with a request value fires; bound parameters do not', () => {
    expect(injections(route('text(f"SELECT * FROM parcels WHERE label = \'{term}\'")'))).toEqual(['svc/parcels.py:16']);
    expect(injections(route('text("SELECT * FROM parcels WHERE label = :term"), {"term": term}'))).toEqual([]);
  });
  it('text() built apart from the execute call fires too', () => {
    expect(injections(fastapi(
      'from sqlalchemy import text',
      '@router.get("/parcels")',
      'def find_parcels(term: str, who=Depends(signed_in), db: Session = Depends(get_db)):',
      '    query = text(f"SELECT * FROM parcels WHERE label = \'{term}\'")',
      '    return db.execute(query).all()',
    ))).toEqual(['svc/parcels.py:17']);
  });
});
