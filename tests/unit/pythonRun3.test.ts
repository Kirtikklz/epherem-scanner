import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiMutationWithoutAuth } from '../../src/rules/contextual/apiMutationWithoutAuth.js';
import { missingRateLimit } from '../../src/rules/contextual/missingRateLimit.js';
import { crossSiteScripting } from '../../src/rules/basic/xss.js';
import { pythonRouteGuard } from '../../src/shared/pythonGuards.js';
import { pythonRouteIsSensitive } from '../../src/shared/pythonRateLimit.js';
import type { ApiRoute } from '../../src/shared/types.js';
import { memoryContext } from './helpers.js';
import { preparePythonReader, releasePythonReader } from '../../src/shared/pythonParser.js';

beforeAll(async () => { await preparePythonReader(); });
afterAll(() => { releasePythonReader(); });

type Files = [string, string][];
const py = (...lines: string[]): string => `${lines.join('\n')}\n`;

function pyRoutes(files: Files): ApiRoute[] {
  return memoryContext(files).projectMap.apiRoutes.filter((route) => route.filePath.endsWith('.py'));
}
const paths = (files: Files): string[] => pyRoutes(files).map((route) => `${route.framework} ${route.methods.join(',')} ${route.routePath}`).sort();

describe('route decorators the per-file arms missed', () => {
  it('a FastAPI router bound under any name is read; an object bound to something else is not', () => {
    const files: Files = [['svc/widgets.py', py(
      'from fastapi import APIRouter',
      'widgets_router = APIRouter()',
      '@widgets_router.post("/widgets")',
      'def add_widget():',
      '    return {}',
    )]];
    expect(paths(files)).toEqual(['fastapi POST /widgets']);
    const other: Files = [['svc/widgets.py', py(
      'from types import SimpleNamespace',
      'helpers = SimpleNamespace()',
      '@helpers.post("/widgets")',
      'def add_widget():',
      '    return {}',
    )]];
    expect(paths(other)).toEqual([]);
  });

  it("Flask 2's @bp.post and @app.get are Flask routes; @app.get on a FastAPI app stays FastAPI", () => {
    const flask: Files = [['shop/views.py', py(
      'from flask import Blueprint, Flask',
      'app = Flask(__name__)',
      'parts = Blueprint("parts", __name__)',
      '@parts.post("/parts")',
      'def add_part():',
      '    return ""',
      '@app.get("/health")',
      'def health():',
      '    return ""',
    )]];
    expect(paths(flask)).toEqual(['flask GET /health', 'flask POST /parts']);
    const fastapi: Files = [['shop/views.py', py(
      'from fastapi import FastAPI',
      'app = FastAPI()',
      '@app.get("/health")',
      'def health():',
      '    return ""',
    )]];
    expect(paths(fastapi)).toEqual(['fastapi GET /health']);
  });

  it('a blueprint imported from the package that creates it is followed', () => {
    const files: Files = [
      ['shop/__init__.py', py('from flask import Blueprint', 'counter = Blueprint("counter", __name__, url_prefix="/counter")')],
      ['shop/routes.py', py('from . import counter', '@counter.get("/tally")', 'def tally():', '    return ""')],
      ['run.py', py('from flask import Flask', 'from shop import counter', 'app = Flask(__name__)', 'app.register_blueprint(counter)')],
    ];
    expect(paths(files)).toEqual(['flask GET /counter/tally']);
  });
});

describe('FastAPI prefixes', () => {
  const orders = py(
    'from fastapi import APIRouter',
    'router = APIRouter(prefix="/orders")',
    '@router.get("/{order_no}")',
    'def show_order(order_no: int):',
    '    return {}',
  );

  it('APIRouter(prefix=) and include_router(prefix=) are joined up to the app, through a nested router', () => {
    const files: Files = [
      ['api/orders.py', orders],
      ['api/v2.py', py('from fastapi import APIRouter', 'from . import orders', 'v2 = APIRouter(prefix="/v2")', 'v2.include_router(orders.router, prefix="/shop")')],
      ['api/main.py', py('from fastapi import FastAPI', 'from .v2 import v2', 'app = FastAPI()', 'app.include_router(v2, prefix="/api")')],
    ];
    const [route] = pyRoutes(files);
    expect(route?.routePath).toBe('/api/v2/shop/orders/{order_no}');
    expect(route?.declaredPath).toBe('/{order_no}');
  });

  it('a prefix bound once to a literal is read; one bound twice, an f-string, two mounts that disagree, a sub-app or no mount keeps the old path', () => {
    const main = (body: string): Files => [['api/orders.py', orders], ['api/main.py', py('from fastapi import FastAPI', 'from . import orders', 'app = FastAPI()', body)]];
    expect(pyRoutes(main(py('base = "/api"', 'app.include_router(orders.router, prefix=base)')))[0]?.routePath).toBe('/api/orders/{order_no}');
    expect(pyRoutes(main(py('base = "/api"', 'base = "/v9"', 'app.include_router(orders.router, prefix=base)')))[0]?.routePath).toBe('/{order_no}');
    expect(pyRoutes(main(py('ver = 2', 'app.include_router(orders.router, prefix=f"/v{ver}")')))[0]?.routePath).toBe('/{order_no}');
    expect(pyRoutes(main(py('app.include_router(orders.router, prefix="/a")', 'app.include_router(orders.router, prefix="/b")')))[0]?.routePath).toBe('/{order_no}');
    expect(pyRoutes(main(py('app.include_router(orders.router, prefix="/a")', 'app.include_router(orders.router, prefix="/a")')))[0]?.routePath).toBe('/a/orders/{order_no}');
    expect(pyRoutes(main(py('outer = FastAPI()', 'app.include_router(orders.router)', 'outer.mount("/sub", app)')))[0]?.routePath).toBe('/{order_no}');
    expect(pyRoutes(main(''))[0]?.routePath).toBe('/{order_no}');
  });
});

describe('Flask prefixes', () => {
  it('register_blueprint(url_prefix=) replaces the blueprint\'s own, and nested blueprints join', () => {
    const files: Files = [
      ['site/parts.py', py('from flask import Blueprint', 'parts = Blueprint("parts", __name__, url_prefix="/own")', '@parts.route("/list")', 'def list_parts():', '    return ""')],
      ['site/__init__.py', py(
        'from flask import Blueprint, Flask',
        'def create_app():',
        '    app = Flask(__name__)',
        '    from .parts import parts',
        '    group = Blueprint("group", __name__)',
        '    group.register_blueprint(parts, url_prefix="/inner")',
        '    app.register_blueprint(group, url_prefix="/outer")',
        '    return app',
      )],
    ];
    expect(paths(files)).toEqual(['flask GET /outer/inner/list']);
  });

  it('a blueprint registered under a computed prefix keeps its old path', () => {
    const files: Files = [
      ['site/parts.py', py('from flask import Blueprint', 'parts = Blueprint("parts", __name__)', '@parts.route("/list")', 'def list_parts():', '    return ""')],
      ['site/app.py', py('from flask import Flask', 'from .parts import parts', 'import os', 'app = Flask(__name__)', 'app.register_blueprint(parts, url_prefix=os.environ["BASE"])')],
    ];
    expect(paths(files)).toEqual(['flask GET /list']);
  });
});

const MIDDLEWARE_ON = py(
  'ROOT_URLCONF = "proj.urls"',
  'MIDDLEWARE = [',
  '    "django.contrib.sessions.middleware.SessionMiddleware",',
  '    "django.contrib.auth.middleware.AuthenticationMiddleware",',
  '    "django.contrib.auth.middleware.LoginRequiredMiddleware",',
  ']',
);
const MIDDLEWARE_OFF = MIDDLEWARE_ON.replace('    "django.contrib.auth.middleware.LoginRequiredMiddleware",\n', '');
const PROJ_URLS = py(
  'from django.urls import include, path, re_path',
  'from shelf import views',
  'urlpatterns = [',
  '    path("shelf/", include("shelf.urls")),',
  '    re_path(r"^legacy/(?P<code>[0-9]+)/$", views.legacy_code),',
  ']',
);
const SHELF_URLS = py(
  'from django.urls import path',
  'from . import views',
  'urlpatterns = [',
  '    path("crates/<int:pk>/", views.crate_detail),',
  '    path("crates/new/", views.CrateCreate.as_view()),',
  '    path("open/", views.open_page),',
  ']',
);
const SHELF_VIEWS = py(
  'from django.contrib.auth.decorators import login_not_required',
  'from django.views.decorators.http import require_POST',
  'from django.views.generic import CreateView, View',
  'from .models import db',
  '',
  '@require_POST',
  'def crate_detail(request, pk):',
  '    db.delete(pk)',
  '    return None',
  '',
  'def legacy_code(request, code):',
  '    return None',
  '',
  '@login_not_required',
  'def open_page(request):',
  '    db.delete(1)',
  '    return None',
  '',
  'class CrateCreate(CreateView):',
  '    def get(self, request):',
  '        return None',
);
const djangoApp = (settings: string, views = SHELF_VIEWS, extra: Files = []): Files => [
  ['proj/settings.py', settings],
  ['proj/urls.py', PROJ_URLS],
  ['shelf/urls.py', SHELF_URLS],
  ['shelf/views.py', views],
  ['shelf/models.py', py('db = object()')],
  ...extra,
];
const routeAt = (files: Files, routePath: string, method: string): ApiRoute | undefined =>
  pyRoutes(files).find((route) => route.routePath === routePath && route.methods.includes(method));
const djangoGuard = (files: Files, routePath: string, method: string): string | undefined => {
  const context = memoryContext(files);
  const route = context.projectMap.apiRoutes.find((candidate) => candidate.routePath === routePath && candidate.methods.includes(method));
  if (route === undefined) throw new Error(`no route ${routePath}: ${context.projectMap.apiRoutes.map((r) => r.routePath).join(', ')}`);
  return pythonRouteGuard(context, route)?.level;
};

describe('Django URLconf', () => {
  it('ROOT_URLCONF → path / re_path / include, each resolved to its function or class view', () => {
    expect(paths(djangoApp(MIDDLEWARE_OFF))).toEqual([
      'django GET /shelf/crates/new/',
      'django GET,POST /legacy/(?P<code>[0-9]+)/',
      'django GET,POST /shelf/open/',
      'django POST /shelf/crates/<int:pk>/',
      'django POST /shelf/crates/new/',
    ].sort());
    const detail = routeAt(djangoApp(MIDDLEWARE_OFF), '/shelf/crates/<int:pk>/', 'POST');
    expect(detail?.line).toBe(7);
    expect(detail?.declaredPath).toBe('/crates/<int:pk>/');
  });

  it('no ROOT_URLCONF, a computed route or a view the reader cannot find registers nothing', () => {
    expect(paths(djangoApp(MIDDLEWARE_OFF.replace('ROOT_URLCONF = "proj.urls"\n', '')))).toEqual([]);
    const computed = SHELF_URLS.replace('path("open/", views.open_page)', 'path(f"{views.BASE}/", views.open_page)')
      .replace('path("crates/new/", views.CrateCreate.as_view())', 'path("crates/new/", views.missing_view)');
    const files = djangoApp(MIDDLEWARE_OFF).map(([file, content]): [string, string] => [file, file === 'shelf/urls.py' ? computed : content]);
    expect(paths(files)).toEqual(['django GET,POST /legacy/(?P<code>[0-9]+)/', 'django POST /shelf/crates/<int:pk>/']);
  });

  it('DRF router register(...) gives a viewset its list, detail and @action routes', () => {
    const files: Files = [
      ['proj/settings.py', py('ROOT_URLCONF = "proj.urls"')],
      ['proj/urls.py', py(
        'from django.urls import include, path',
        'from rest_framework.routers import DefaultRouter',
        'from shelf.api import ParcelViewSet',
        'router = DefaultRouter()',
        'router.register(r"parcels", ParcelViewSet, basename="parcel")',
        'urlpatterns = [path("api/", include(router.urls))]',
      )],
      ['shelf/api.py', py(
        'from rest_framework import viewsets',
        'from rest_framework.decorators import action',
        'class ParcelViewSet(viewsets.ModelViewSet):',
        '    def destroy(self, request, pk=None):',
        '        return None',
        '    @action(detail=True, methods=["post"], url_path="ship-now")',
        '    def ship(self, request, pk=None):',
        '        return None',
      )],
    ];
    expect(paths(files)).toEqual([
      'django DELETE /api/parcels/{pk}/',
      'django GET,POST,PUT,PATCH /api/parcels/',
      'django POST /api/parcels/{pk}/ship-now/',
    ].sort());
  });
});

describe('Django LoginRequiredMiddleware (carried from review 6e)', () => {
  it('credits sign-in on a plain view when settings list the class; a project without it stays unguarded', () => {
    expect(djangoGuard(djangoApp(MIDDLEWARE_ON), '/shelf/crates/<int:pk>/', 'POST')).toBe('auth');
    expect(djangoGuard(djangoApp(MIDDLEWARE_OFF), '/shelf/crates/<int:pk>/', 'POST')).toBeUndefined();
    expect(djangoGuard(djangoApp(MIDDLEWARE_ON), '/shelf/crates/new/', 'GET')).toBe('auth');
  });

  it('@login_not_required, a URLconf wrap and method_decorator(login_not_required) opt out', () => {
    expect(djangoGuard(djangoApp(MIDDLEWARE_ON), '/shelf/open/', 'GET')).toBeUndefined();
    const wrapped = SHELF_URLS.replace('views.crate_detail)', 'login_not_required(views.crate_detail))')
      .replace('from . import views', 'from django.contrib.auth.decorators import login_not_required\nfrom . import views');
    const files = djangoApp(MIDDLEWARE_ON).map(([file, content]): [string, string] => [file, file === 'shelf/urls.py' ? wrapped : content]);
    expect(djangoGuard(files, '/shelf/crates/<int:pk>/', 'POST')).toBeUndefined();
    const exempt = SHELF_VIEWS.replace('class CrateCreate(CreateView):', '@method_decorator(login_not_required, name="dispatch")\nclass CrateCreate(CreateView):')
      .replace('from .models import db', 'from django.utils.decorators import method_decorator\nfrom .models import db');
    expect(djangoGuard(djangoApp(MIDDLEWARE_ON, exempt), '/shelf/crates/new/', 'GET')).toBeUndefined();
  });

  it('a commented-out entry, a project class of that name, a removal, or a second settings module without it is no credit', () => {
    const commented = MIDDLEWARE_ON.replace('    "django.contrib.auth.middleware.LoginRequiredMiddleware",', '    # "django.contrib.auth.middleware.LoginRequiredMiddleware",');
    expect(djangoGuard(djangoApp(commented), '/shelf/crates/<int:pk>/', 'POST')).toBeUndefined();
    const own = MIDDLEWARE_ON.replace('"django.contrib.auth.middleware.LoginRequiredMiddleware"', '"proj.middleware.LoginRequiredMiddleware"');
    expect(djangoGuard(djangoApp(own), '/shelf/crates/<int:pk>/', 'POST')).toBeUndefined();
    const removed = `${MIDDLEWARE_ON}MIDDLEWARE.remove("django.contrib.auth.middleware.LoginRequiredMiddleware")\n`;
    expect(djangoGuard(djangoApp(removed), '/shelf/crates/<int:pk>/', 'POST')).toBeUndefined();
    const production: Files = [['proj/production.py', py('from .settings import *', 'MIDDLEWARE = ["django.contrib.auth.middleware.AuthenticationMiddleware"]')]];
    expect(djangoGuard(djangoApp(MIDDLEWARE_ON, SHELF_VIEWS, production), '/shelf/crates/<int:pk>/', 'POST')).toBeUndefined();
    const inherits: Files = [['proj/production.py', py('from .settings import *', 'DEBUG = False')]];
    expect(djangoGuard(djangoApp(MIDDLEWARE_ON, SHELF_VIEWS, inherits), '/shelf/crates/<int:pk>/', 'POST')).toBe('auth');
  });

  it('is not credited on a DRF view, a subclass of a Django view marked exempt, or an unreadable base', () => {
    const drf = SHELF_VIEWS.replace('class CrateCreate(CreateView):', 'from rest_framework.views import APIView\nclass CrateCreate(APIView):');
    expect(djangoGuard(djangoApp(MIDDLEWARE_ON, drf), '/shelf/crates/new/', 'GET')).toBeUndefined();
    const signIn = SHELF_VIEWS.replace('class CrateCreate(CreateView):', 'from django.contrib.auth.views import LoginView\nclass CrateCreate(LoginView):');
    expect(djangoGuard(djangoApp(MIDDLEWARE_ON, signIn), '/shelf/crates/new/', 'GET')).toBeUndefined();
    const thirdParty = SHELF_VIEWS.replace('class CrateCreate(CreateView):', 'from braces.views import CsrfExemptMixin\nclass CrateCreate(CsrfExemptMixin, View):');
    expect(djangoGuard(djangoApp(MIDDLEWARE_ON, thirdParty), '/shelf/crates/new/', 'GET')).toBeUndefined();
    const plain = SHELF_VIEWS.replace('class CrateCreate(CreateView):', 'class CrateCreate(View):');
    expect(djangoGuard(djangoApp(MIDDLEWARE_ON, plain), '/shelf/crates/new/', 'GET')).toBe('auth');
    const unseen = SHELF_VIEWS.replace('class CrateCreate(CreateView):', 'class CrateCreate(UnseenBase, View):');
    expect(djangoGuard(djangoApp(MIDDLEWARE_ON, unseen), '/shelf/crates/new/', 'GET')).toBeUndefined();
    const apiView = SHELF_VIEWS.replace('@require_POST\ndef crate_detail', '@api_view(["POST"])\ndef crate_detail')
      .replace('from .models import db', 'from rest_framework.decorators import api_view\nfrom .models import db');
    expect(djangoGuard(djangoApp(MIDDLEWARE_ON, apiView), '/shelf/crates/<int:pk>/', 'POST')).toBeUndefined();
  });

  it('a module-level view after a class is not in that class; a refusing check in the view body counts', () => {
    const after = SHELF_VIEWS.replace('@require_POST\ndef crate_detail(request, pk):',
      'from django.contrib.auth.mixins import LoginRequiredMixin\nclass Guarded(LoginRequiredMixin, View):\n    template_name = "x.html"\n\ndef crate_detail(request, pk):');
    expect(djangoGuard(djangoApp(MIDDLEWARE_OFF, after), '/shelf/crates/<int:pk>/', 'GET')).toBeUndefined();
    const checked = SHELF_VIEWS.replace('def crate_detail(request, pk):\n',
      'def crate_detail(request, pk):\n    if not request.user.is_authenticated:\n        return HttpResponse(status=401)\n');
    expect(djangoGuard(djangoApp(MIDDLEWARE_OFF, checked), '/shelf/crates/<int:pk>/', 'POST')).toBe('auth');
  });

  it('api_mutation_without_auth: the middleware covers a view that writes; without it the write is reported', () => {
    const reported = (files: Files): string[] => apiMutationWithoutAuth.run(memoryContext(files)).map((f) => `${f.filePath}:${f.lineStart}`);
    expect(reported(djangoApp(MIDDLEWARE_OFF))).toEqual(['shelf/views.py:8']);
    const onlyGuarded = SHELF_VIEWS.replace('    db.delete(1)\n', '');
    expect(reported(djangoApp(MIDDLEWARE_ON, onlyGuarded))).toEqual([]);
    expect(reported(djangoApp(MIDDLEWARE_ON))).toEqual(['shelf/views.py:16']);
  });
});

describe('rate-limit words read from the route\'s own path', () => {
  const route = (routePath: string, declaredPath?: string): ApiRoute => ({
    filePath: 'svc/a.py', framework: 'fastapi', routePath, methods: ['POST'], line: 1, ...(declaredPath !== undefined ? { declaredPath } : {}),
  });
  it('a router prefix does not make its routes sensitive, unless the full path ends in a sensitive segment', () => {
    expect(pythonRouteIsSensitive(route('/api/auths/status', '/status'))).toBe(false);
    expect(pythonRouteIsSensitive(route('/api/auth/', '/'))).toBe(true);
    expect(pythonRouteIsSensitive(route('/api/knowledge/{n}/reset', '/{n}/reset'))).toBe(true);
    expect(pythonRouteIsSensitive(route('/api/login'))).toBe(true);
  });
  it('"author" is not "auth"', () => {
    expect(pythonRouteIsSensitive(route('/books/by-author/{name}'))).toBe(false);
    expect(pythonRouteIsSensitive(route('/books/authorize'))).toBe(true);
  });
  it('missing_rate_limit reports the router root that is a sign-in endpoint', () => {
    const files: Files = [
      ['svc/signin.py', py('from fastapi import APIRouter', 'router = APIRouter(prefix="/auth")', '@router.post("/")', 'def sign_in():', '    return {}')],
      ['svc/main.py', py('from fastapi import FastAPI', 'from . import signin', 'app = FastAPI()', 'app.include_router(signin.router)')],
    ];
    expect(missingRateLimit.run(memoryContext(files)).map((f) => `${f.filePath}:${f.lineStart}`)).toEqual(['svc/signin.py:3']);
  });
});

const MODELS = py(
  'from app import db',
  'class Entry(db.Model):',
  '    body = db.Column(db.Text)',
  'class Note2(db.Model):',
  '    summary = db.Column(db.Text)',
  '    def save(self):',
  '        self.summary = bleach.clean(self.summary)',
  'class EntryForm:',
  '    caption = "x"',
);
const PAGE = '<html><body><div>{{ thing.body|safe }}</div></body></html>\n';
const APP_DB: [string, string] = ['app/__init__.py', py('from flask_sqlalchemy import SQLAlchemy', 'db = SQLAlchemy()')];
const xssLines = (files: Files): string[] => crossSiteScripting.run(memoryContext(files.some(([p]) => p === APP_DB[0]) ? files : [...files, APP_DB]))
  .filter((f) => f.filePath.endsWith('.html') || f.filePath.endsWith('.py')).map((f) => `${f.filePath}:${f.lineStart}`);
const view = (binding: string): string => py(
  'from flask import render_template',
  'from .models import Entry, EntryForm',
  'def show(entry_no):',
  `    thing = ${binding}`,
  '    return render_template("page.html", thing=thing)',
);

describe('xss stored-field gate tied to a proven receiver (carried item 1)', () => {
  it('a query result of a model that declares the column is reported', () => {
    expect(xssLines([['app/models.py', MODELS], ['app/views.py', view('Entry.query.get(entry_no)')], ['app/templates/page.html', PAGE]]))
      .toEqual(['app/templates/page.html:1']);
  });
  it('a proven non-model receiver is not, though another class declares a column of that name', () => {
    const page = PAGE.replace('thing.body', 'thing.summary');
    expect(xssLines([['app/models.py', MODELS], ['app/views.py', view('EntryForm()')], ['app/templates/page.html', page]])).toEqual([]);
    expect(xssLines([['app/models.py', MODELS], ['app/views.py', view('entry_no')], ['app/templates/page.html', page]]))
      .toEqual(['app/templates/page.html:1']);
  });
  it('a macro parameter, a {% set %} or a template another one includes is unproven and keeps today\'s gate', () => {
    const files = (page: string, extra: Files = []): Files => [['app/models.py', MODELS], ['app/views.py', view('EntryForm()')], ['app/templates/page.html', page], ...extra];
    const macro = '<html><body>{% macro show(thing) %}<div>{{ thing.summary|safe }}</div>{% endmacro %}</body></html>\n';
    expect(xssLines(files(macro))).toEqual(['app/templates/page.html:1']);
    const reset = '<html><body>{% set thing = other %}<div>{{ thing.summary|safe }}</div></body></html>\n';
    expect(xssLines(files(reset))).toEqual(['app/templates/page.html:1']);
    const included = PAGE.replace('thing.body', 'thing.summary');
    expect(xssLines(files(included, [['app/templates/outer.html', '<html>{% include "page.html" %}</html>\n']]))).toEqual(['app/templates/page.html:1']);
    const other: Files = [['app/other.py', py('from flask import render_template', 'def pick(name):', '    return render_template(name, thing=None)')]];
    expect(xssLines(files(included, other))).toEqual(['app/templates/page.html:1']);
  });

  it('a view parameter rebound only on one branch is not proven', () => {
    const page = PAGE.replace('thing.body', 'thing.summary');
    const branchy = py(
      'from flask import render_template',
      'from .models import EntryForm',
      'def show(thing, fresh):',
      '    if fresh:',
      '        thing = EntryForm()',
      '    return render_template("page.html", thing=thing)',
    );
    expect(xssLines([['app/models.py', MODELS], ['app/views.py', branchy], ['app/templates/page.html', page]])).toEqual(['app/templates/page.html:1']);
  });
});

describe('sanitiser credit tied to the receiver (carried item 2)', () => {
  const page = PAGE.replace('thing.body', 'thing.summary');
  it("credits the proven class's own sanitising save(), not another class's", () => {
    const viewOf = (binding: string): string => view(binding).replace('Entry, EntryForm', 'Entry, EntryForm, Note2');
    expect(xssLines([['app/models.py', MODELS], ['app/views.py', viewOf('Note2.query.get(entry_no)')], ['app/templates/page.html', page]])).toEqual([]);
    const models = MODELS.replace('    body = db.Column(db.Text)', '    body = db.Column(db.Text)\n    summary = db.Column(db.Text)');
    expect(xssLines([['app/models.py', models], ['app/views.py', viewOf('Entry.query.get(entry_no)')], ['app/templates/page.html', page]]))
      .toEqual(['app/templates/page.html:1']);
    expect(xssLines([['app/models.py', MODELS], ['app/views.py', view('entry_no')], ['app/templates/page.html', page]]))
      .toEqual(['app/templates/page.html:1']);
  });
  it('mark_safe: a value cleaned earlier in the same function is credited; one cleaned elsewhere is not', () => {
    const pyView = (clean: string): string => py(
      'from django.utils.safestring import mark_safe',
      'from .models import Entry',
      'def show(request, entry_no):',
      '    shown = Entry.objects.get(pk=entry_no)',
      clean,
      '    return mark_safe(shown.body)',
    );
    expect(xssLines([['app/models.py', MODELS], ['app/views.py', pyView('    shown.body = bleach.clean(shown.body)')]])).toEqual([]);
    expect(xssLines([['app/models.py', MODELS], ['app/views.py', pyView('    other = bleach.clean(shown.body)')]])).toEqual(['app/views.py:6']);
  });
});

describe('xss: a proven receiver reads the columns of every base (attempt 2, FIX 1)', () => {
  const page = '<html><body><p>{{ thing.blurb|safe }}</p></body></html>\n';
  const flaskModels = (card: string, extra = ''): string => py(
    'from app import db',
    'class BlurbBits:',
    '    blurb = db.Column(db.Text)',
    card,
    'class Tag(db.Model):',
    '    label = db.Column(db.String(40))',
    extra,
  );
  const flaskView = (model: string): string => py(
    'from flask import render_template',
    'from .models import Card, Tag',
    'def open_card(card_no):',
    `    thing = ${model}.query.get_or_404(card_no)`,
    '    return render_template("card.html", thing=thing)',
  );
  const CARD = 'class Card(BlurbBits, db.Model):\n    id = db.Column(db.Integer)';
  const flask = (card: string, model = 'Card'): string[] =>
    xssLines([['app/models.py', flaskModels(card)], ['app/views.py', flaskView(model)], ['app/templates/card.html', page]]);
  const tagWith = (models: string, extra: Files = []): string[] =>
    xssLines([['app/models.py', models], ['app/views.py', flaskView('Tag')], ['app/templates/card.html', page], ...extra]);

  it('Flask: a column on a mixin, or two levels up, is the proven class\'s column', () => {
    expect(flask(CARD)).toEqual(['app/templates/card.html:1']);
    expect(flask('class Middle(BlurbBits):\n    pass\nclass Card(Middle, db.Model):\n    id = db.Column(db.Integer)')).toEqual(['app/templates/card.html:1']);
    expect(flask('class Card(db.Model):\n    blurb = db.Column(db.Text)')).toEqual(['app/templates/card.html:1']);
    expect(flask(CARD, 'Tag')).toEqual([]);
  });

  it('Flask: library roots end the chain; a declarative_base name and a DeclarativeBase subclass are roots', () => {
    const declarative: Files = [['app/base.py', py('from sqlalchemy.orm import declarative_base', 'Root = declarative_base()')]];
    const tagOn = (base: string, from = 'base'): string => flaskModels(CARD).replace('class Tag(db.Model):', `from .${from} import ${base}\nclass Tag(${base}):`);
    expect(tagWith(tagOn('Root'), declarative)).toEqual([]);
    const rooted: Files = [['app/root.py', py('from sqlalchemy.orm import DeclarativeBase', 'class Rooted(DeclarativeBase):', '    pass')]];
    expect(tagWith(tagOn('Rooted', 'root'), rooted)).toEqual([]);
    const rebound: Files = [['app/base.py', py('from sqlalchemy.orm import declarative_base', 'Root = declarative_base()', 'Root = vendor_base()')]];
    expect(tagWith(tagOn('Root'), rebound)).toEqual(['app/templates/card.html:1']);
    expect(tagWith(tagOn('Root'), [...declarative, ['app/other.py', py('Root = 1')]])).toEqual(['app/templates/card.html:1']);
    expect(tagWith(flaskModels(CARD).replace('class Tag(db.Model):', 'from sqlalchemy.orm import DeclarativeBase as Footing\nclass Tag(Footing):'))).toEqual(['app/templates/card.html:1']);
  });

  it('Flask: a base the reader cannot follow leaves the receiver unproven, so the name-only gate reports', () => {
    const tagOn = (header: string, extra: Files = []): string[] => tagWith(flaskModels(CARD).replace('class Tag(db.Model):', header), extra);
    expect(tagOn('class Tag(VendorRecord, db.Model):')).toEqual(['app/templates/card.html:1']);
    expect(tagOn('class Tag(db.Model, metaclass=Registry):')).toEqual(['app/templates/card.html:1']);
    expect(tagOn('class Tag(make_base(), db.Model):')).toEqual(['app/templates/card.html:1']);
    expect(tagOn('class Tag[T](db.Model):')).toEqual(['app/templates/card.html:1']);
    const twice: Files = [['app/a.py', py('class Twin:', '    pass')], ['app/b.py', py('class Twin:', '    pass')]];
    expect(tagOn('class Tag(Twin, db.Model):', twice)).toEqual(['app/templates/card.html:1']);
    expect(tagOn('from .a import Twin\nclass Tag(Twin, db.Model):', twice)).toEqual(['app/templates/card.html:1']);
    expect(tagOn('from .a import Twin\nclass Tag(Twin, db.Model):', twice.slice(0, 1))).toEqual([]);
    expect(tagOn('class Tag(Twin, db.Model):', twice.slice(0, 1))).toEqual(['app/templates/card.html:1']);
  });

  it('Flask: a leaf the chain binds as anything but a stored column is unproven', () => {
    const shapes = [
      '    @property\n    def blurb(self):\n        return self.label',
      '    @hybrid_property\n    def blurb(self):\n        return self.label',
      '    blurb = synonym("label")',
      '    blurb = column_property(label + "")',
    ];
    for (const shape of shapes) {
      const models = flaskModels(CARD).replace('    label = db.Column(db.String(40))', `    label = db.Column(db.String(40))\n${shape}`);
      expect(tagWith(models)).toEqual(['app/templates/card.html:1']);
    }
    const viaBase = py(
      'from app import db',
      'class BlurbBits:',
      '    blurb = db.Column(db.Text)',
      'class Shaped:',
      '    blurb = synonym("label")',
      'class Tag(Shaped, db.Model):',
      '    label = db.Column(db.String(40))',
    );
    expect(tagWith(viaBase)).toEqual(['app/templates/card.html:1']);
    expect(tagWith(viaBase.replace('    blurb = synonym("label")', '    tone = synonym("label")'))).toEqual([]);
  });

  it('Flask: an attribute only a method sets, or a column a nested class declares, is unproven', () => {
    const tagged = (body: string): string[] =>
      tagWith(flaskModels(CARD).replace('    label = db.Column(db.String(40))', `    label = db.Column(db.String(40))\n${body}`));
    expect(tagged('    def refresh(self):\n        self.blurb = self.label')).toEqual(['app/templates/card.html:1']);
    expect(tagged('    class Snapshot:\n        blurb = db.Column(db.Text)')).toEqual(['app/templates/card.html:1']);
    expect(tagged('    def refresh(self):\n        self.tone = self.label')).toEqual([]);
  });

  const djangoModels = (crate: string): string => py(
    'from django.db import models',
    'class Shelved(models.Model):',
    '    blurb = models.TextField()',
    '    class Meta:',
    '        abstract = True',
    crate,
    'class Bin(models.Model):',
    '    code = models.IntegerField()',
  );
  const djangoView = (model: string): string => py(
    'from django.shortcuts import get_object_or_404, render',
    'from .models import Bin, Crate',
    'def crate_page(request, pk):',
    `    crate = get_object_or_404(${model}, pk=pk)`,
    '    return render(request, "shelf/crate.html", {"crate": crate})',
  );
  const djangoPage = '<html><body><p>{{ crate.blurb|safe }}</p></body></html>\n';
  const CRATE = 'class Crate(Shelved):\n    code = models.CharField(max_length=9)';
  const djangoLines = (models: string, model: string): string[] =>
    xssLines([['shelf/models.py', models], ['shelf/views.py', djangoView(model)], ['shelf/templates/shelf/crate.html', djangoPage]]);

  it('Django: a column on an abstract base is the proven model\'s column', () => {
    expect(djangoLines(djangoModels(CRATE), 'Crate')).toEqual(['shelf/templates/shelf/crate.html:1']);
    expect(djangoLines(djangoModels('class Crate(models.Model):\n    blurb = models.TextField()'), 'Crate')).toEqual(['shelf/templates/shelf/crate.html:1']);
    expect(djangoLines(djangoModels(CRATE), 'Bin')).toEqual([]);
  });

  it('Django: an unfollowable base or a non-column leaf keeps the name-only gate', () => {
    const base = djangoModels(CRATE);
    expect(djangoLines(base.replace('class Bin(models.Model):', 'class Bin(AbstractUser):'), 'Bin')).toEqual(['shelf/templates/shelf/crate.html:1']);
    expect(djangoLines(base.replace('    code = models.IntegerField()', '    code = models.IntegerField()\n    def blurb(self):\n        return str(self.code)'), 'Bin'))
      .toEqual(['shelf/templates/shelf/crate.html:1']);
    expect(djangoLines(base, 'Bin')).toEqual([]);
  });

  const selfModels = (crate: string): string => py(
    'from django.utils.safestring import mark_safe',
    djangoModels(crate).replace('class Bin(models.Model):', 'class Bin(models.Model):\n    def shown(self):\n        return mark_safe(self.blurb)'),
  );
  const selfLines = (models: string): string[] => xssLines([['shelf/models.py', models]]);
  const METHOD = '    def shown(self):\n        return mark_safe(self.blurb)';

  it('mark_safe(self.<inherited column>) is reported; a chain without the column is not', () => {
    const crateOnly = (crate: string): string => py('from django.utils.safestring import mark_safe', djangoModels(crate));
    expect(selfLines(crateOnly(`${CRATE}\n${METHOD}`))).toEqual(['shelf/models.py:10']);
    expect(selfLines(crateOnly(`class Crate(models.Model):\n    blurb = models.TextField()\n${METHOD}`))).toEqual(['shelf/models.py:10']);
    expect(selfLines(selfModels(CRATE))).toEqual([]);
  });

  it('mark_safe(self.x): an unfollowable base or a non-column leaf keeps the name-only gate', () => {
    const base = selfModels(CRATE);
    expect(selfLines(base.replace('class Bin(models.Model):', 'class Bin(VendorRecord, models.Model):'))).toEqual(['shelf/models.py:11']);
    expect(selfLines(base.replace('    code = models.IntegerField()', '    code = models.IntegerField()\n    blurb = column_property(code)'))).toEqual(['shelf/models.py:11']);
    expect(selfLines(base)).toEqual([]);
  });
});

describe('LoginRequiredMiddleware: only a top-level element of the list counts (attempt 2, FIX 2)', () => {
  const LOGIN = '"django.contrib.auth.middleware.LoginRequiredMiddleware"';
  const settings = (value: string): string => py('ROOT_URLCONF = "proj.urls"', 'BASE = ["django.contrib.auth.middleware.AuthenticationMiddleware"]', `MIDDLEWARE = ${value}`);
  const guard = (value: string): string | undefined => djangoGuard(djangoApp(settings(value)), '/shelf/crates/<int:pk>/', 'POST');

  it('a comprehension that filters the class out is no credit; the plain list is', () => {
    expect(guard(`[m for m in BASE + [${LOGIN}] if m != ${LOGIN}]`)).toBeUndefined();
    expect(guard(`BASE + [${LOGIN}]`)).toBe('auth');
  });

  it('a filter(...) or list(...) call, or a conditional, is no credit; a tuple display and a + of displays are', () => {
    expect(guard(`list(filter(lambda m: m != ${LOGIN}, BASE + [${LOGIN}]))`)).toBeUndefined();
    expect(guard(`list(BASE + [${LOGIN}])`)).toBeUndefined();
    expect(guard(`BASE + [${LOGIN}] if DEBUG else BASE`)).toBeUndefined();
    expect(guard(`(${LOGIN},)`)).toBe('auth');
    expect(guard(`[${LOGIN}] + ["django.middleware.common.CommonMiddleware"]`)).toBe('auth');
    expect(guard(`[[${LOGIN}]]`)).toBeUndefined();
  });

  it('the list is read on the code view: a bracket inside a string or a comment is not structure', () => {
    expect(guard(`["odd]name", ${LOGIN}]`)).toBe('auth');
    expect(guard(`[  # was: ]\n    ${LOGIN},\n]`)).toBe('auth');
    expect(guard(`[\n    # ${LOGIN},\n]`)).toBeUndefined();
  });

  it('a call beside a display, or a literal in plain brackets, is no credit', () => {
    expect(guard(`[${LOGIN}] + list(BASE)`)).toBeUndefined();
    expect(guard(`[${LOGIN}] + BASE`)).toBe('auth');
    expect(guard(`(${LOGIN})`)).toBeUndefined();
  });
});
