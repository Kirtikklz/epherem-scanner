import { describe, expect, it } from 'vitest';
import { isNonProductionCodePath, isPythonTestModule, mayVouchForProject, pathSuggestsNonProduction } from '../../src/input/fileFilters.js';
import { debugModeEnabled } from '../../src/rules/basic/debugModeEnabled.js';
import { hardcodedSecret } from '../../src/rules/basic/hardcodedSecret.js';
import { insecureCookies } from '../../src/rules/basic/insecureCookies.js';
import { serverSideRequestForgery } from '../../src/rules/basic/ssrf.js';
import { databaseDeleteWithoutOwnershipCheck } from '../../src/rules/contextual/databaseDeleteWithoutOwnershipCheck.js';
import { missingWebhookVerification } from '../../src/rules/contextual/missingWebhookVerification.js';
import type { Finding, RuleContext, ScanRule } from '../../src/shared/types.js';
import { memoryContext } from './helpers.js';

type Files = [string, string][];
const py = (...lines: string[]): string => `${lines.join('\n')}\n`;
const run = (rule: ScanRule, files: Files): Finding[] => rule.run(memoryContext(files) as RuleContext);
const at = (rule: ScanRule, files: Files): string[] => run(rule, files).map((f) => `${f.filePath}:${f.lineStart}`);

const KEY = 'Zq8xK2mV9tLp4RwN7bYc3HdF6sJg1QeA';

describe('job M, 1: a Python test module is a test file for hardcoded_secret', () => {
  const secret = (path: string): Files => [
    ['requirements.txt', 'flask==3.0.0\n'],
    [path, py('def test_login(client):', `    api_token = "${KEY}"`, '    assert client.post("/x", headers={"t": api_token})')],
  ];

  it('pytest and Django test module names are recognised by filename only', () => {
    for (const path of ['app/test_login.py', 'app/login_test.py', 'app/tests.py', 'app/tests_login.py', 'app/login_tests.py', 'conftest.py', 'cfg/settings/test.py', 'test.py']) {
      expect(isPythonTestModule(path), path).toBe(true);
    }
    for (const path of ['app/testimonials.py', 'app/contests.py', 'app/latest.py', 'app/tests/helpers.py', 'app/test_login.ts', 'app/attest.py']) {
      expect(isPythonTestModule(path), path).toBe(false);
    }
  });

  it('the credit side refuses them; the finding filter and the adjudicator veto do not move', () => {
    expect(mayVouchForProject('app/test_login.py')).toBe(false);
    expect(mayVouchForProject('app/service.py')).toBe(true);
    expect(isNonProductionCodePath('app/test_login.py')).toBe(false);
    expect(pathSuggestsNonProduction('app/test_login.py')).toBe(false);
  });

  it('a key in a Python test module is not reported; the same key in a production module is', () => {
    expect(at(hardcodedSecret, secret('app/service.py'))).toEqual(['app/service.py:2']);
    for (const path of ['app/test_login.py', 'app/login_test.py', 'app/tests.py', 'app/tests_login.py', 'conftest.py']) {
      expect(at(hardcodedSecret, secret(path)), path).toEqual([]);
    }
    expect(at(hardcodedSecret, secret('app/testimonials.py'))).toEqual(['app/testimonials.py:2']);
  });
});

const DJANGO: Files = [
  ['requirements.txt', 'django==5.0.0\n'],
  ['manage.py', py('import os', 'os.environ.setdefault("DJANGO_SETTINGS_MODULE", "site_cfg.settings")')],
  ['site_cfg/settings.py', py('INSTALLED_APPS = ["notes"]', 'ROOT_URLCONF = "site_cfg.urls"')],
  ['site_cfg/urls.py', py('from django.urls import path', 'from notes import views', 'urlpatterns = [path("n/<int:pk>/", views.show)]')],
  ['notes/views.py', py('from django.http import HttpResponse', 'def show(request, pk):', '    return HttpResponse("ok")')],
];
const RAW_DELETE = ['        with connection.cursor() as cur:', '            cur.execute("DELETE FROM notes_note WHERE id = %s", [pk])'];
const COMMAND = py('from django.core.management.base import BaseCommand', 'from django.db import connection', 'class Command(BaseCommand):', '    def handle(self, *args, **opts):', '        pk = opts.get("pk")', ...RAW_DELETE);
const withFiles = (base: Files, extra: Files): Files => [...base.filter(([p]) => !extra.some(([q]) => q === p)), ...extra];

describe('job M, 2: deletes no request reaches', () => {
  const deletes = (files: Files): string[] => at(databaseDeleteWithoutOwnershipCheck, files);

  it('a raw delete in a view reports; the same delete in a Python test module does not', () => {
    const view = withFiles(DJANGO, [['notes/views.py', py('from django.db import connection', 'from django.http import HttpResponse', 'def show(request, pk):', '    if True:', ...RAW_DELETE.map((l) => l.slice(4)), '    return HttpResponse("ok")')]]);
    expect(deletes(view)).toEqual(['notes/views.py:6']);
    const test = withFiles(DJANGO, [['notes/test_sweep.py', py('from django.db import connection', 'def test_sweep(pk=1):', '    if True:', ...RAW_DELETE.map((l) => l.slice(4)))]]);
    expect(deletes(test)).toEqual([]);
  });

  it('a management command nothing else runs is not reported', () => {
    expect(deletes(withFiles(DJANGO, [['notes/management/commands/sweep_notes.py', COMMAND]]))).toEqual([]);
  });

  it('a command a view calls with call_command, or imports, still reports', () => {
    const called = withFiles(DJANGO, [
      ['notes/management/commands/sweep_notes.py', COMMAND],
      ['notes/views.py', py('from django.core.management import call_command', 'from django.http import HttpResponse', 'def show(request, pk):', '    call_command("sweep_notes", pk=pk)', '    return HttpResponse("ok")')],
    ]);
    expect(deletes(called)).toEqual(['notes/management/commands/sweep_notes.py:7']);
    const imported = withFiles(DJANGO, [
      ['notes/management/commands/sweep_notes.py', COMMAND],
      ['notes/views.py', py('from django.http import HttpResponse', 'from notes.management.commands.sweep_notes import Command', 'def show(request, pk):', '    Command().handle(pk=pk)', '    return HttpResponse("ok")')],
    ]);
    expect(deletes(imported)).toEqual(['notes/management/commands/sweep_notes.py:7']);
  });

  it('a test that calls the command does not make it reachable', () => {
    const tested = withFiles(DJANGO, [
      ['notes/management/commands/sweep_notes.py', COMMAND],
      ['notes/tests.py', py('from django.core.management import call_command', 'def test_sweep():', '    call_command("sweep_notes", pk=1)')],
    ]);
    expect(deletes(tested)).toEqual([]);
  });

  it('the path alone is not evidence: no Command class, or a base that is not a command, reports', () => {
    const noClass = py('from django.db import connection', 'def handle(pk):', '    if True:', ...RAW_DELETE.map((l) => l.slice(4)));
    expect(deletes(withFiles(DJANGO, [['notes/management/commands/sweep_notes.py', noClass]]))).toEqual(['notes/management/commands/sweep_notes.py:5']);
    const notCommand = COMMAND.replace('class Command(BaseCommand):', 'class Command(object):');
    expect(deletes(withFiles(DJANGO, [['notes/management/commands/sweep_notes.py', notCommand]]))).toEqual(['notes/management/commands/sweep_notes.py:7']);
    expect(deletes(withFiles(DJANGO, [['notes/tools/commands/sweep_notes.py', COMMAND]]))).toEqual(['notes/tools/commands/sweep_notes.py:7']);
  });
});

const hook = (body: string[], extra: string[] = []): Files => [
  ['requirements.txt', 'flask==3.0.0\n'],
  ['app/hooks.py', py('import hmac', 'import hashlib', 'import os', 'import stripe', 'from flask import Flask, request, abort', 'from .store import record_payment', '', 'app = Flask(__name__)', ...extra, '', '@app.post("/webhook/stripe")', 'def stripe_webhook():', '    payload = request.get_data()', '    sig = request.headers.get("Stripe-Signature", "")', ...body, '    return "", 200')],
  ['app/store.py', py('def record_payment(event):', '    return event')],
];
const MAC = '    mac = hmac.new(os.environ["WH_SECRET"].encode(), payload, hashlib.sha256).hexdigest()';

describe('job M, 3: webhook checks in Python', () => {
  const hooks = (files: Files): number => run(missingWebhookVerification, files).length;

  it('an unverified handler reports', () => {
    expect(hooks(hook(['    record_payment(request.get_json())']))).toBe(1);
  });

  it('the provider SDK\'s raising verify, before the work, is credited; after the work it is not', () => {
    expect(hooks(hook(['    event = stripe.Webhook.construct_event(payload, sig, os.environ["WH_SECRET"])', '    record_payment(event)']))).toBe(0);
    expect(hooks(hook(['    record_payment(request.get_json())', '    stripe.Webhook.construct_event(payload, sig, os.environ["WH_SECRET"])']))).toBe(1);
  });

  it('a compare_digest is credited only when an if acts on it and refuses', () => {
    expect(hooks(hook([MAC, '    if not hmac.compare_digest(mac, sig):', '        abort(401)', '    record_payment(request.get_json())']))).toBe(0);
    expect(hooks(hook([MAC, '    ok = hmac.compare_digest(mac, sig)', '    print(ok)', '    record_payment(request.get_json())']))).toBe(1);
    expect(hooks(hook([MAC, '    if not hmac.compare_digest(mac, sig):', '        print("bad")', '    record_payment(request.get_json())']))).toBe(1);
  });

  it('feeding the MAC with update() is part of the check, not work done first', () => {
    expect(hooks(hook(['    mac = hmac.new(os.environ["WH_SECRET"].encode(), digestmod=hashlib.sha256)', '    mac.update(payload)', '    if not hmac.compare_digest(mac.hexdigest(), sig):', '        abort(401)', '    record_payment(request.get_json())']))).toBe(0);
  });

  it('a helper that refuses inside is credited; one that returns a compare needs the handler\'s own refusing if', () => {
    const refuses = ['def check_sig(body, given):', MAC.replace('payload', 'body'), '    if not hmac.compare_digest(mac, given):', '        abort(401)'];
    expect(hooks(hook(['    check_sig(payload, sig)', '    record_payment(request.get_json())'], refuses))).toBe(0);
    const returns = ['def sig_ok(body, given):', MAC.replace('payload', 'body'), '    return hmac.compare_digest(mac, given)'];
    expect(hooks(hook(['    if not sig_ok(payload, sig):', '        abort(401)', '    record_payment(request.get_json())'], returns))).toBe(0);
    expect(hooks(hook(['    sig_ok(payload, sig)', '    record_payment(request.get_json())'], returns))).toBe(1);
  });

  it('a helper\'s name is never a credit', () => {
    expect(hooks(hook(['    if not verify_signature(payload, sig):', '        abort(401)', '    record_payment(request.get_json())'], ['def verify_signature(body, given):', '    return True']))).toBe(1);
  });

  it('a stub webhook route in a Python test module is not reported; the same stub elsewhere is', () => {
    const stub = py('import stripe', 'from flask import Flask, request', 'stub = Flask("stub")', '@stub.post("/webhook/stripe")', 'def fake_stripe_webhook():', '    payload = request.get_json()', '    record_payment(payload)', '    return "", 200');
    const verified = hook(['    event = stripe.Webhook.construct_event(payload, sig, os.environ["WH_SECRET"])', '    record_payment(event)']);
    expect(at(missingWebhookVerification, [...verified, ['app/test_hooks.py', stub]])).toEqual([]);
    expect(at(missingWebhookVerification, [...verified, ['app/stub_hooks.py', stub]])).toEqual(['app/stub_hooks.py:6']);
  });
});

const fetcher = (head: string[], body: string[], deps = 'flask==3.0.0\n'): Files => [
  ['requirements.txt', deps],
  ['app/client.py', py('import os', 'import requests', 'from flask import Flask, request', ...head, '', 'app = Flask(__name__)', '', '@app.get("/proxy")', 'def proxy():', '    item = request.args.get("item")', ...body)],
];

describe('job M, 4: an outgoing request to a configured base URL', () => {
  const ssrf = (files: Files): number => run(serverSideRequestForgery, files).length;

  it('a request URL reports', () => {
    expect(ssrf(fetcher([], ['    return requests.get(request.args["url"]).text']))).toBe(1);
  });

  it('an environment base with a path after it is not caller-controlled', () => {
    expect(ssrf(fetcher(['BASE = os.environ["UPSTREAM_URL"]'], ['    return requests.get(f"{BASE}/items/{item}").text']))).toBe(0);
    expect(ssrf(fetcher(['BASE = os.getenv("UPSTREAM_URL", "https://api.example.com").rstrip("/")'], ['    return requests.get(BASE + "/items/" + item).text']))).toBe(0);
    expect(ssrf(fetcher([], ['    return requests.get(f"{os.environ[\'UPSTREAM_URL\']}/items/{item}").text']))).toBe(0);
  });

  it('a self attribute assigned only from the environment is credited; one assigned from a parameter is not', () => {
    const cls = (init: string, args: string): string[] => ['class Upstream:', `    def __init__(${args}):`, `        self.root_url = ${init}`, '    def get(self, item):', '        return requests.get(f"{self.root_url}/items/{item}").text'];
    expect(ssrf(fetcher(cls('os.environ.get("UPSTREAM_URL", "")', 'self'), ['    return Upstream().get(item)']))).toBe(0);
    expect(ssrf(fetcher(cls('base', 'self, base'), ['    return Upstream(request.args["base"]).get(item)']))).toBe(1);
  });

  it('the host must end where the config value ends', () => {
    expect(ssrf(fetcher(['BASE = os.environ["UPSTREAM_URL"]'], ['    return requests.get(f"{BASE}{item}").text']))).toBe(1);
    expect(ssrf(fetcher(['BASE = os.environ["UPSTREAM_URL"]'], ['    return requests.get(BASE + item).text']))).toBe(1);
  });

  it('a name is not a fact: config.x and a settings object from elsewhere still report', () => {
    expect(ssrf(fetcher(['from .conf import config'], ['    return requests.get(f"{config.base}/items/{item}").text']))).toBe(1);
    expect(ssrf(fetcher(['from .conf import settings'], ['    return requests.get(f"{settings.UPSTREAM_URL}/items/{item}").text']))).toBe(1);
  });

  it('Django settings, proven by their import, are credited unless the name is bound again', () => {
    expect(ssrf(fetcher(['from django.conf import settings'], ['    return requests.get(f"{settings.UPSTREAM_URL}/items/{item}").text'], 'django==5.0.0\n'))).toBe(0);
    expect(ssrf(fetcher(['from django.conf import settings'], ['    settings = request.args', '    return requests.get(f"{settings.UPSTREAM_URL}/items/{item}").text'], 'django==5.0.0\n'))).toBe(1);
  });

  it('a name assigned from the request anywhere in the file is not credited', () => {
    expect(ssrf(fetcher(['BASE = os.environ["UPSTREAM_URL"]'], ['    global BASE', '    BASE = request.args["b"]', '    return requests.get(f"{BASE}/items/{item}").text']))).toBe(1);
    expect(ssrf(fetcher(['BASE = os.environ["UPSTREAM_URL"]'], ['    BASE = request.args["b"]', '    return requests.get(f"{BASE}/items/{item}").text']))).toBe(1);
  });

  it('a request in a Python test module is not reported; the same code elsewhere is', () => {
    const fake = py('import requests', 'from flask import request', 'def fake_proxy():', '    return requests.get(request.args["url"]).text');
    expect(at(serverSideRequestForgery, [...fetcher([], ['    return "x"']), ['app/test_client.py', fake]])).toEqual([]);
    expect(at(serverSideRequestForgery, [...fetcher([], ['    return "x"']), ['app/fake_client.py', fake]])).toEqual(['app/fake_client.py:4']);
  });
});

describe('job M, 5: DEBUG=True in a Python app\'s example configuration', () => {
  const debug = (files: Files): string[] => at(debugModeEnabled, files);

  it('.env.example, .env.sample and .env.template under a Python manifest are not reported', () => {
    expect(debug([['requirements.txt', 'flask==3.0.0\n'], ['app.py', ''], ['.env.example', 'DEBUG=True\n']])).toEqual([]);
    expect(debug([['pyproject.toml', '[project]\nname = "x"\n'], ['app/main.py', ''], ['deploy/.env.sample', 'FLASK_DEBUG=1\n']])).toEqual([]);
    expect(debug([['manage.py', ''], ['site_cfg/.env.template', 'DJANGO_DEBUG=True\n']])).toEqual([]);
  });

  it('without a Python manifest above it, a real env file, or a sibling folder\'s manifest, it still reports', () => {
    expect(debug([['package.json', '{"name":"x"}'], ['.env.example', 'DEBUG=True\n']])).toEqual(['.env.example:1']);
    expect(debug([['requirements.txt', 'flask==3.0.0\n'], ['app.py', ''], ['.env.production', 'DEBUG=True\n']])).toEqual(['.env.production:1']);
    expect(debug([['api/requirements.txt', 'flask==3.0.0\n'], ['api/app.py', ''], ['web/.env.example', 'DEBUG=True\n']])).toEqual(['web/.env.example:1']);
  });

  it('only the Flask/Django probe is skipped there', () => {
    expect(debug([['requirements.txt', 'flask==3.0.0\n'], ['app.py', ''], ['.env.example', 'NODE_ENV="development"\n']])).toEqual(['.env.example:1']);
  });
});

const cookie = (extra: string[], call: string): Files => [
  ['requirements.txt', 'flask==3.0.0\n'],
  ['app/auth.py', py('from flask import Flask, make_response', 'from .cfg import cookie_opts', '', 'app = Flask(__name__)', ...extra, '', '@app.post("/login")', 'def login():', '    resp = make_response("ok")', `    ${call}`, '    return resp')],
  ['app/cfg.py', py('def cookie_opts():', '    return {"httponly": True, "secure": True, "samesite": "Lax"}')],
];

describe('job M, 6: cookie flags passed as **kwargs', () => {
  const cookies = (files: Files): string[] => run(insecureCookies, files).map((f) => `${f.severity} ${/missing: ([^)]*)/.exec(f.evidence ?? '')?.[1] ?? ''}`);

  it('no flags at all still reports high', () => {
    expect(cookies(cookie([], 'resp.set_cookie("session", "v")'))).toEqual(['high HttpOnly, Secure, SameSite']);
  });

  it('a same-file helper returning the flags, or a dict bound once, supplies them', () => {
    expect(cookies(cookie(['def cookie_kwargs():', '    return {"httponly": True, "secure": True, "samesite": "Lax"}'], 'resp.set_cookie("session", "v", **cookie_kwargs())'))).toEqual([]);
    expect(cookies(cookie(['OPTS = dict(httponly=True, secure=True, samesite="Lax")'], 'resp.set_cookie("session", "v", **OPTS)'))).toEqual([]);
    expect(cookies(cookie(['def cookie_kwargs():', '    return {', '        "httponly": True,', '        "secure": True,', '        "samesite": "Lax",', '    }'], 'resp.set_cookie("session", "v", **cookie_kwargs())'))).toEqual([]);
  });

  it('a flag the helper switches off is still missing, at full severity', () => {
    expect(cookies(cookie(['def cookie_kwargs():', '    return {"httponly": False, "secure": True, "samesite": "Lax"}'], 'resp.set_cookie("session", "v", **cookie_kwargs())'))).toEqual(['high HttpOnly']);
  });

  it('a helper with a branch that returns something else is not read', () => {
    const branchy = ['def cookie_kwargs(prod):', '    if prod:', '        return {"httponly": True, "secure": True, "samesite": "Lax"}', '    return base_opts()'];
    expect(cookies(cookie(branchy, 'resp.set_cookie("session", "v", **cookie_kwargs(True))'))).toEqual(['medium HttpOnly, Secure, SameSite']);
  });

  it('a spread this file cannot read keeps the finding, rated no higher than medium', () => {
    expect(cookies(cookie([], 'resp.set_cookie("session", "v", **cookie_opts())'))).toEqual(['medium HttpOnly, Secure, SameSite']);
    expect(cookies(cookie(['OPTS = {}', 'OPTS["httponly"] = True'], 'resp.set_cookie("session", "v", **OPTS)'))).toEqual(['medium HttpOnly, Secure, SameSite']);
  });

  it('JavaScript cookies do not move', () => {
    const js: Files = [['package.json', '{"name":"x","dependencies":{"express":"4.0.0"}}'], ['server.js', 'app.post("/login", (req, res) => { res.cookie("session", "v", { secure: true }); res.end(); });\n']];
    expect(cookies(js)).toEqual(['high HttpOnly, SameSite']);
  });
});

describe('job M: twins for each guard (deliberate breaks)', () => {
  const deletes = (files: Files): string[] => at(databaseDeleteWithoutOwnershipCheck, files);
  const hooks = (files: Files): number => run(missingWebhookVerification, files).length;
  const ssrf = (files: Files): number => run(serverSideRequestForgery, files).length;
  const debug = (files: Files): string[] => at(debugModeEnabled, files);
  const cookies = (files: Files): string[] => run(insecureCookies, files).map((f) => `${f.severity} ${/missing: ([^)]*)/.exec(f.evidence ?? '')?.[1] ?? ''}`);

  it('an ORM delete in a guarded stub route of a Python test module is not judged; in a production module it is', () => {
    const route = py('from flask import Flask', 'from flask_login import login_required', 'from .models import Note, db', 'app = Flask(__name__)', '@app.post("/notes/<int:note_id>/delete")', '@login_required', 'def drop(note_id):', '    Note.query.filter_by(id=note_id).delete()', '    db.session.commit()', '    return "ok"');
    const base: Files = [['requirements.txt', 'flask==3.0.0\nflask-login==0.6.3\n'], ['app/models.py', py('from flask_sqlalchemy import SQLAlchemy', 'db = SQLAlchemy()', 'class Note(db.Model):', '    id = db.Column(db.Integer, primary_key=True)', '    owner_id = db.Column(db.Integer)')]];
    expect(deletes([...base, ['app/notes.py', route]])).toEqual(['app/notes.py:8']);
    expect(deletes([...base, ['app/test_notes.py', route]])).toEqual([]);
  });

  it('another management command that runs the command does not make it reachable', () => {
    const other = py('from django.core.management import call_command', 'from django.core.management.base import BaseCommand', 'class Command(BaseCommand):', '    def handle(self, *args, **opts):', '        call_command("sweep_notes", pk=1)');
    expect(deletes(withFiles(DJANGO, [['notes/management/commands/sweep_notes.py', COMMAND], ['notes/management/commands/nightly.py', other]]))).toEqual([]);
  });

  it('each provider SDK verify that raises is credited', () => {
    for (const call of [
      '    stripe.WebhookSignature.verify_header(payload, sig, os.environ["WH_SECRET"])',
      '    Webhook(os.environ["WH_SECRET"]).verify(payload, dict(request.headers))',
    ]) {
      expect(hooks(hook([call, '    record_payment(request.get_json())'])), call).toBe(0);
    }
  });

  it('a compare with no HMAC behind it is not a signature check', () => {
    expect(hooks(hook(['    if sig != os.environ["WH_TOKEN"]:', '        abort(401)', '    record_payment(request.get_json())']))).toBe(1);
  });

  it('a returned compare acted on without not, or with a block that does not refuse, is not credited', () => {
    const returns = ['def sig_ok(body, given):', MAC.replace('payload', 'body'), '    return hmac.compare_digest(mac, given)'];
    expect(hooks(hook(['    if sig_ok(payload, sig):', '        return "", 204', '    record_payment(request.get_json())'], returns))).toBe(1);
    expect(hooks(hook(['    if not sig_ok(payload, sig):', '        print("bad")', '    record_payment(request.get_json())'], returns))).toBe(1);
  });

  it('every def of a helper\'s name must verify', () => {
    const files = hook(['    check_sig(payload, sig)', '    record_payment(request.get_json())'], ['def check_sig(body, given):', MAC.replace('payload', 'body'), '    if not hmac.compare_digest(mac, given):', '        abort(401)']);
    expect(hooks(files)).toBe(0);
    expect(hooks([...files, ['app/legacy.py', py('def check_sig(body, given):', '    return None')]])).toBe(1);
  });

  it('an update on a name not bound to a MAC is work done before the check', () => {
    expect(hooks(hook(['    orders = Order.objects.filter(ref=1)', '    orders.update(paid=True)', '    stripe.Webhook.construct_event(payload, sig, os.environ["WH_SECRET"])']))).toBe(1);
  });

  it('a parameter of the same name, a name never assigned, or a tuple target is not credited', () => {
    expect(ssrf(fetcher(['BASE = os.environ["UPSTREAM_URL"]', 'def fetch_item(BASE, item):', '    return requests.get(f"{BASE}/items/{item}").text'], ['    return fetch_item(request.args["b"], item)']))).toBe(1);
    expect(ssrf(fetcher(['class Upstream(Base):', '    def get(self, item):', '        return requests.get(f"{self.root_url}/items/{item}").text'], ['    return Upstream().get(item)']))).toBe(1);
    expect(ssrf(fetcher(['BASE = os.environ["UPSTREAM_URL"]'], ['    BASE, other = request.args["b"], 1', '    return requests.get(f"{BASE}/items/{item}").text']))).toBe(1);
  });

  it('an environment value with a fixed-host literal fallback, and a URL built into a name first, are credited', () => {
    expect(ssrf(fetcher(['BASE = os.environ.get("UPSTREAM_URL") or "https://api.example.com"'], ['    return requests.get(f"{BASE}/items/{item}").text']))).toBe(0);
    expect(ssrf(fetcher(['BASE = os.environ.get("UPSTREAM_URL") or request_base()'], ['    return requests.get(f"{BASE}/items/{item}").text']))).toBe(1);
    expect(ssrf(fetcher(['BASE = os.environ["UPSTREAM_URL"]'], ['    url = f"{BASE}/items/{item}"', '    return requests.get(url).text']))).toBe(0);
  });

  it('example files are named by their last suffix, and only a manifest in the file\'s own folder or above counts', () => {
    expect(debug([['requirements.txt', 'flask==3.0.0\n'], ['app.py', ''], ['.env.example.local', 'DEBUG=True\n']])).toEqual([]);
    expect(debug([['requirements.txt', 'flask==3.0.0\n'], ['app.py', ''], ['.env.examples', 'DEBUG=True\n']])).toEqual(['.env.examples:1']);
  });

  it('a keyword the call names itself cannot come from an unread spread', () => {
    expect(cookies(cookie([], 'resp.set_cookie("session", "v", httponly=False, **cookie_opts())'))).toEqual(['high HttpOnly, Secure, SameSite']);
  });

  it('two defs of the helper, or a name assigned twice, are not read', () => {
    const twoDefs = ['if True:', '    def cookie_kwargs():', '        return {"httponly": True, "secure": True, "samesite": "Lax"}', 'else:', '    def cookie_kwargs():', '        return {"httponly": False}'];
    expect(cookies(cookie(twoDefs, 'resp.set_cookie("session", "v", **cookie_kwargs())'))).toEqual(['medium HttpOnly, Secure, SameSite']);
    expect(cookies(cookie(['OPTS = dict(httponly=True, secure=True, samesite="Lax")', 'OPTS = {}'], 'resp.set_cookie("session", "v", **OPTS)'))).toEqual(['medium HttpOnly, Secure, SameSite']);
  });
});

describe('job M: twins for each guard (deliberate breaks), part 2', () => {
  const deletes = (files: Files): string[] => at(databaseDeleteWithoutOwnershipCheck, files);
  const hooks = (files: Files): number => run(missingWebhookVerification, files).length;

  it('a view importing the command module by name reaches it', () => {
    const imported = withFiles(DJANGO, [
      ['notes/management/commands/sweep_notes.py', COMMAND],
      ['notes/views.py', py('from django.http import HttpResponse', 'from notes.management.commands import sweep_notes', 'def show(request, pk):', '    sweep_notes.Command().handle(pk=pk)', '    return HttpResponse("ok")')],
    ]);
    expect(deletes(imported)).toEqual(['notes/management/commands/sweep_notes.py:7']);
  });

  it('a compare that is not an if condition is not credited, even beside an abort', () => {
    expect(hooks(hook([MAC, '    ok = hmac.compare_digest(mac, sig) if mac else abort(400)', '    print(ok)', '    record_payment(request.get_json())']))).toBe(1);
  });
});

describe('job M: configured-host twins where the unknown value is not a followed request value', () => {
  const ssrf = (files: Files): number => run(serverSideRequestForgery, files).length;

  it('a host extended by an unknown value reports, in an f-string or a concatenation', () => {
    expect(ssrf(fetcher(['BASE = os.environ["UPSTREAM_URL"]'], ['    extra = load_suffix()', '    return requests.get(f"{BASE}{extra}", params={"q": item}).text']))).toBe(1);
    expect(ssrf(fetcher(['BASE = os.environ["UPSTREAM_URL"]'], ['    extra = load_suffix()', '    return requests.get(BASE + extra, params={"q": item}).text']))).toBe(1);
  });

  it('a name also assigned from an unknown value, or as a tuple target, reports', () => {
    expect(ssrf(fetcher(['BASE = os.environ["UPSTREAM_URL"]'], ['    BASE = load_base()', '    return requests.get(f"{BASE}/items/{item}").text']))).toBe(1);
    expect(ssrf(fetcher(['BASE = os.environ["UPSTREAM_URL"]'], ['    BASE, other = load_pair()', '    return requests.get(f"{BASE}/items/{item}").text']))).toBe(1);
  });

  it('a fallback that is not a fixed-host literal reports', () => {
    expect(ssrf(fetcher(['BASE = os.environ.get("UPSTREAM_URL") or "api.internal"'], ['    return requests.get(f"{BASE}/items/{item}").text']))).toBe(1);
  });

  it('Django settings bound again to an unknown value report', () => {
    expect(ssrf(fetcher(['from django.conf import settings'], ['    settings = load_settings()', '    return requests.get(f"{settings.UPSTREAM_URL}/items/{item}").text'], 'django==5.0.0\n'))).toBe(1);
  });
});

describe('job M, attempt 2: a webhook check must decide, and come before the body is used', () => {
  const hooks = (files: Files): number => run(missingWebhookVerification, files).length;
  const LOGS = ['    if sig != mac:', '        print("mismatch")'];

  it('a presence or emptiness test is not a signature check, even beside an HMAC that only logs', () => {
    for (const presence of ['    if sig == "":', '    if sig == None:', '    if None == sig:', '    if sig is None:', '    if not sig:', '    if sig != None and sig == "":', '    if mac == "":']) {
      expect(hooks(hook([MAC, presence, '        abort(400)', ...LOGS, '    record_payment(request.get_json())'])), presence).toBe(1);
    }
  });

  it('an equality against a computed digest that refuses is credited', () => {
    expect(hooks(hook([MAC, '    if sig != mac:', '        abort(401)', '    record_payment(request.get_json())']))).toBe(0);
    expect(hooks(hook(['    if hmac.new(os.environ["WH_SECRET"].encode(), payload, hashlib.sha256).hexdigest() != sig:', '        abort(401)', '    record_payment(request.get_json())']))).toBe(0);
    expect(hooks(hook(['    expected = "sha256=" + hmac.new(os.environ["WH_SECRET"].encode(), payload, hashlib.sha256).hexdigest()', '    if sig is None or sig != expected:', '        abort(401)', '    record_payment(request.get_json())']))).toBe(0);
  });

  it('a name bound to something else as well, or a signature word alone, is not a digest', () => {
    expect(hooks(hook([MAC, '    if sig:', '        mac = sig', '    if sig != mac:', '        abort(401)', '    record_payment(request.get_json())']))).toBe(1);
    expect(hooks(hook([MAC, '    signature = request.headers.get("X-Sig")', '    if sig != signature:', '        abort(401)', '    record_payment(request.get_json())']))).toBe(1);
  });

  it('a plain hash of the body, with no HMAC in the handler, is not a signature check', () => {
    expect(hooks(hook(['    expected = hashlib.sha256(payload).hexdigest()', '    if sig != expected:', '        abort(401)', '    record_payment(request.get_json())']))).toBe(1);
  });

  it('a call whose name says it acts is work before the check even when it is not given the body', () => {
    expect(hooks(hook(['    record_payment(request.args.get("id"))', '    stripe.Webhook.construct_event(payload, sig, os.environ["WH_SECRET"])']))).toBe(1);
  });

  it('a verify inside a try whose except goes on is not a check', () => {
    const verify = '        stripe.Webhook.construct_event(payload, sig, os.environ["WH_SECRET"])';
    for (const handlers of [
      ['    except Exception:', '        pass'],
      ['    except Exception as e:', '        print(e)'],
      ['    except ValueError:', '        return "", 400', '    except Exception:', '        pass'],
      ['    finally:', '        return "", 200'],
      ['    except Exception:', '        abort(400)', '    else:', '        print("ok")', '    finally:', '        return "", 200'],
    ]) {
      expect(hooks(hook(['    try:', verify, ...handlers, '    record_payment(request.get_json())'])), handlers.join('|')).toBe(1);
    }
  });

  it('a verify inside a try whose every except refuses is a check', () => {
    const verify = '        stripe.Webhook.construct_event(payload, sig, os.environ["WH_SECRET"])';
    for (const handlers of [
      ['    except Exception:', '        return "", 400'],
      ['    except ValueError:', '        abort(400)', '    except Exception:', '        raise'],
      ['    except Exception:', '        abort(400)', '    else:', '        print("ok")'],
      ['    finally:', '        print("done")'],
    ]) {
      expect(hooks(hook(['    try:', verify, ...handlers, '    record_payment(request.get_json())'])), handlers.join('|')).toBe(0);
    }
  });

  it('a helper whose verify is swallowed does not verify; one whose except refuses does', () => {
    const helper = (handler: string): string[] => ['def check_sig(body, given):', '    try:', '        stripe.Webhook.construct_event(body, given, os.environ["WH_SECRET"])', '    except Exception:', handler];
    expect(hooks(hook(['    check_sig(payload, sig)', '    record_payment(request.get_json())'], helper('        pass')))).toBe(1);
    expect(hooks(hook(['    check_sig(payload, sig)', '    record_payment(request.get_json())'], helper('        abort(400)')))).toBe(0);
  });

  it('any call given the request body before the check is work, whatever its name', () => {
    const verify = '    stripe.Webhook.construct_event(payload, sig, os.environ["WH_SECRET"])';
    for (const work of [
      ['    mark_paid(request.json)'],
      ['    mark_paid(request.get_json())'],
      ['    mark_paid(request.data)'],
      ['    data = request.get_json()', '    mark_paid(data)'],
      ['    mark_paid(payload)'],
      ['    event = json.loads(payload)', '    mark_paid(event)'],
      ['    mark_paid(', '        request.json,', '    )'],
      ['    mark_paid(json.loads(payload))'],
    ]) {
      expect(hooks(hook([...work, verify, '    record_payment(request.get_json())'])), work.join('|')).toBe(1);
    }
  });

  it('the check\'s own calls may take the body first', () => {
    const verify = '    stripe.Webhook.construct_event(payload, sig, os.environ["WH_SECRET"])';
    for (const check of [
      ['    data = json.loads(payload)'],
      ['    digest = hashlib.sha256(payload).hexdigest()', '    log_digest(digest)'],
      ['    mac = hmac.new(os.environ["WH_SECRET"].encode(), bytes(payload), hashlib.sha256)'],
      ['    mac = hmac.new(os.environ["WH_SECRET"].encode(), digestmod=hashlib.sha256)', '    mac.update(payload)'],
      ['    kind = request.headers.get("X-Kind")', '    mark_seen(kind)'],
    ]) {
      expect(hooks(hook([...check, verify, '    record_payment(request.get_json())'])), check.join('|')).toBe(0);
    }
    expect(hooks(hook(['    event = stripe.Webhook.construct_event(request.data, sig, os.environ["WH_SECRET"])', '    record_payment(event)']))).toBe(0);
    expect(hooks(hook(['    event = Webhook(os.environ["WH_SECRET"]).verify(request.data, dict(request.headers))', '    record_payment(event)']))).toBe(0);
  });
});

describe('job M, attempt 2: a command reached in ways the search cannot read is reached', () => {
  const deletes = (files: Files): string[] => at(databaseDeleteWithoutOwnershipCheck, files);
  const view = (...body: string[]): [string, string] => ['notes/views.py', py('from django.core.management import call_command', 'from django.http import HttpResponse', 'NAME = "sweep_notes"', 'def show(request, pk):', ...body, '    return HttpResponse("ok")')];

  it('call_command with a name that is not a string literal reaches every command', () => {
    for (const call of [['    call_command(NAME, pk=pk)'], ['    call_command(f"sweep_{NAME}", pk=pk)'], ['    call_command(*[NAME])'], ['    call_command(', '        NAME, pk=pk)']]) {
      expect(deletes(withFiles(DJANGO, [['notes/management/commands/sweep_notes.py', COMMAND], view(...call)])), call.join('|')).toEqual(['notes/management/commands/sweep_notes.py:7']);
    }
  });

  it('a literal name of another command, or a nameless call in a test or another command, does not', () => {
    expect(deletes(withFiles(DJANGO, [['notes/management/commands/sweep_notes.py', COMMAND], view('    call_command("migrate")')]))).toEqual([]);
    expect(deletes(withFiles(DJANGO, [['notes/management/commands/sweep_notes.py', COMMAND], ['notes/tests.py', py('from django.core.management import call_command', 'NAME = "sweep_notes"', 'def test_sweep():', '    call_command(NAME, pk=1)')]]))).toEqual([]);
    const nightly = py('from django.core.management import call_command', 'from django.core.management.base import BaseCommand', 'class Command(BaseCommand):', '    def handle(self, *args, **opts):', '        for name in opts["names"]:', '            call_command(name)');
    expect(deletes(withFiles(DJANGO, [['notes/management/commands/sweep_notes.py', COMMAND], ['notes/management/commands/nightly.py', nightly]]))).toEqual([]);
  });

  it('a test-named module that production code imports is a caller; one only tests import is not', () => {
    const runner = py('from django.core.management import call_command', 'def run_sweep(pk):', '    call_command("sweep_notes", pk=pk)');
    const importer: [string, string] = ['notes/views.py', py('from django.http import HttpResponse', 'from .test_helpers import run_sweep', 'def show(request, pk):', '    run_sweep(pk)', '    return HttpResponse("ok")')];
    expect(deletes(withFiles(DJANGO, [['notes/management/commands/sweep_notes.py', COMMAND], ['notes/test_helpers.py', runner], importer]))).toEqual(['notes/management/commands/sweep_notes.py:7']);
    const grouped: [string, string] = ['notes/views.py', py('from django.http import HttpResponse', 'from . import (', '    forms,', '    test_helpers,', ')', 'def show(request, pk):', '    test_helpers.run_sweep(pk)', '    return HttpResponse("ok")')];
    expect(deletes(withFiles(DJANGO, [['notes/management/commands/sweep_notes.py', COMMAND], ['notes/test_helpers.py', runner], grouped]))).toEqual(['notes/management/commands/sweep_notes.py:7']);
    const testImporter: [string, string] = ['notes/test_views.py', py('from .test_helpers import run_sweep', 'def test_sweep():', '    run_sweep(1)')];
    expect(deletes(withFiles(DJANGO, [['notes/management/commands/sweep_notes.py', COMMAND], ['notes/test_helpers.py', runner], testImporter]))).toEqual([]);
  });
});
