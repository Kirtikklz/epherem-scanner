import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { csrfProtection } from '../../src/rules/contextual/csrfProtection.js';
import { crossSiteScripting } from '../../src/rules/basic/xss.js';
import { dangerousCorsWildcard } from '../../src/rules/basic/dangerousCorsWildcard.js';
import { debugModeEnabled } from '../../src/rules/basic/debugModeEnabled.js';
import { hardcodedSecret } from '../../src/rules/basic/hardcodedSecret.js';
import { insecureCookies } from '../../src/rules/basic/insecureCookies.js';
import { unsafeDynamicCode } from '../../src/rules/basic/unsafeDynamicCode.js';
import { verboseErrorResponse } from '../../src/rules/basic/verboseErrorResponse.js';
import { weakJwtHandling } from '../../src/rules/basic/weakJwtHandling.js';
import { RULE_REGISTRY } from '../../src/rules/ruleRegistry.js';
import { isPythonNonProductionSetting, pythonCallArguments } from '../../src/shared/pythonSettings.js';
import type { Finding, ScanRule } from '../../src/shared/types.js';
import { memoryContext } from './helpers.js';
import { preparePythonReader, releasePythonReader } from '../../src/shared/pythonParser.js';

beforeAll(async () => { await preparePythonReader(); });
afterAll(() => { releasePythonReader(); });

const run = (rule: ScanRule, files: [string, string][]): Finding[] => rule.run(memoryContext(files));
const lines = (...body: string[]): string => `${body.join('\n')}\n`;
const at = (findings: Finding[]): string[] => findings.map((f) => `${f.filePath}:${f.lineStart}`);

describe('shared/pythonSettings: the frameworks\' own non-production conventions', () => {
  const config = lines(
    'class BaseConfig:',
    '    SECRET = 1',
    '',
    'class DevelopmentConfig(BaseConfig):',
    '    DEBUG = True',
    '',
    'class TestingConfig(BaseConfig):',
    '    DEBUG = True',
    '',
    'class LiveConfig(BaseConfig):',
    '    DEBUG = True',
    '',
    'class DevOpsConfig(BaseConfig):',
    '    DEBUG = True',
  );
  const indexOfLine = (text: string, line: number): number => text.split('\n').slice(0, line - 1).join('\n').length + 1 + 4;

  it('a development or testing config class is not production; any other class is', () => {
    expect(isPythonNonProductionSetting('shop/config.py', config, indexOfLine(config, 5))).toBe(true);
    expect(isPythonNonProductionSetting('shop/config.py', config, indexOfLine(config, 8))).toBe(true);
    expect(isPythonNonProductionSetting('shop/config.py', config, indexOfLine(config, 11))).toBe(false);
    expect(isPythonNonProductionSetting('shop/config.py', config, indexOfLine(config, 14))).toBe(false);
  });

  it('a settings module named for an environment, or a test module, is not production', () => {
    const flat = 'DEBUG = True\n';
    for (const path of ['site/settings/local.py', 'site/settings/dev.py', 'site/local_settings.py', 'site/settings_test.py', 'app/tests/test_views.py', 'conftest.py']) {
      expect(isPythonNonProductionSetting(path, flat, 0), path).toBe(true);
    }
    for (const path of ['site/settings.py', 'site/settings/production.py', 'site/config.py', 'site/local.py', 'tests/config.py', 'tests/fixtures/settings.py']) {
      expect(isPythonNonProductionSetting(path, flat, 0), path).toBe(false);
    }
  });

  it('Django\'s override_settings(...) is test-only', () => {
    const text = '@override_settings(DEBUG=True)\ndef test_x(): pass\n';
    expect(isPythonNonProductionSetting('hc/views.py', text, text.indexOf('DEBUG'))).toBe(true);
    expect(isPythonNonProductionSetting('hc/views.py', 'X = dict(DEBUG=True)\n', 9)).toBe(false);
  });

  it('pythonCallArguments reads to the balanced close and steps over strings', () => {
    const text = 'f(a, int(b), ")", c=1) + 2';
    expect(pythonCallArguments(text, 1)).toBe('a, int(b), ")", c=1');
    expect(pythonCallArguments('f(a, (b', 1)).toBeUndefined();
  });
});

describe('debug_mode_enabled on Python', () => {
  it('FastAPI(debug=True) and Starlette(debug=True) are reported; FastAPI() is not', () => {
    expect(at(run(debugModeEnabled, [['api/main.py', 'from fastapi import FastAPI\napp = FastAPI(title="x", debug=True)\n']]))).toEqual(['api/main.py:2']);
    expect(at(run(debugModeEnabled, [['api/main.py', 'app = Starlette(debug=True, routes=[])\n']]))).toEqual(['api/main.py:1']);
    expect(run(debugModeEnabled, [['api/main.py', 'app = FastAPI(title="x")\n']])).toEqual([]);
  });

  it('DEBUG = True in a development config class is silent; in a production class it fires', () => {
    const source = lines('class DevelopmentConfig:', '    DEBUG = True', '', 'class ProductionConfig:', '    DEBUG = True');
    expect(at(run(debugModeEnabled, [['shop/config.py', source]]))).toEqual(['shop/config.py:5']);
  });

  it('a Django local settings module is silent; the main settings module fires', () => {
    expect(run(debugModeEnabled, [['site/settings/local.py', 'DEBUG = True\n']])).toEqual([]);
    expect(at(run(debugModeEnabled, [['site/settings.py', 'DEBUG = True\n']]))).toEqual(['site/settings.py:1']);
  });
});

describe('insecure_cookies on Python', () => {
  it('set_cookie is read to its balanced close, so flags after a nested call count', () => {
    const source = lines(
      'def login(resp, token, ts):',
      '    resp.set_cookie("token", token, expires=datetime.fromtimestamp(ts), httponly=True, secure=COOKIE_SECURE, samesite="lax")',
    );
    expect(run(insecureCookies, [['app/auth.py', source]])).toEqual([]);
  });

  it('httponly=False is a missing HttpOnly, and secure=True alone does not hide it', () => {
    const source = lines(
      'def login(resp, token):',
      '    resp.set_cookie(',
      '        "token",',
      '        token,',
      '        httponly=False,',
      '        secure=True,',
      '        samesite="lax",',
      '    )',
    );
    const findings = run(insecureCookies, [['app/auth.py', source]]);
    expect(at(findings)).toEqual(['app/auth.py:2']);
    expect(findings[0]?.evidence).toContain('(missing: HttpOnly)');
  });

  it('a refresh cookie is a session cookie', () => {
    const source = 'def login(resp, user):\n    resp.set_cookie("app_refresh", mint(user), max_age=3600)\n';
    expect(at(run(insecureCookies, [['app/views.py', source]]))).toEqual(['app/views.py:2']);
  });

  it('SESSION_COOKIE_SECURE = False fires in production settings, not in a development config', () => {
    expect(at(run(insecureCookies, [['site/settings/production.py', 'SESSION_COOKIE_SECURE = False\n']]))).toEqual(['site/settings/production.py:1']);
    expect(run(insecureCookies, [['site/settings/dev.py', 'SESSION_COOKIE_SECURE = False\n']])).toEqual([]);
    const flask = lines('class DevelopmentConfig:', '    SESSION_COOKIE_SECURE = False');
    expect(run(insecureCookies, [['shop/config.py', flask]])).toEqual([]);
  });
});

describe('unsafe_dynamic_code: a method called eval is not Python\'s eval', () => {
  it('redis.eval and model.eval() are silent in Python; eval(expr) fires', () => {
    const source = lines('def renew(self):', '    return self.redis.eval(SCRIPT, 1, self.key)', '', 'def calc(expr):', '    return eval(expr)');
    expect(at(run(unsafeDynamicCode, [['app/lock.py', source]]))).toEqual(['app/lock.py:5']);
  });

  it('JavaScript keeps reading window.eval(x) as eval', () => {
    expect(at(run(unsafeDynamicCode, [['web/run.js', 'export function go(x) { return window.eval(x); }\n']]))).toEqual(['web/run.js:1']);
  });
});

describe('verbose_error_response on Python', () => {
  const errors = lines('class QuotaError(Exception):', '    pass');

  it('DRF Response( with str(exc) is reported', () => {
    const view = lines('def post(self, request):', '    try:', '        save()', '    except IntegrityError as exc:', '        return Response({"error": str(exc)}, status=409)');
    expect(at(run(verboseErrorResponse, [['api/views.py', view]]))).toEqual(['api/views.py:5']);
  });

  it('the message of an exception class the project defines is silent', () => {
    const view = lines('def post():', '    try:', '        save()', '    except QuotaError as e:', '        raise HTTPException(status_code=400, detail=str(e))');
    expect(run(verboseErrorResponse, [['api/errors.py', errors], ['api/views.py', view]])).toEqual([]);
  });

  it('except Exception, a standard-library type, and a mixed tuple keep firing', () => {
    for (const caught of ['Exception', 'ValueError', '(QuotaError, OSError)']) {
      const view = lines('def post():', '    try:', '        save()', `    except ${caught} as e:`, '        raise HTTPException(status_code=400, detail=str(e))');
      expect(at(run(verboseErrorResponse, [['api/errors.py', errors], ['api/views.py', view]])), caught).toEqual(['api/views.py:5']);
    }
  });

  it('a project-defined class still fires when the traceback goes out with it', () => {
    const view = lines('def post():', '    try:', '        save()', '    except QuotaError as e:', '        return jsonify(error=str(e), trace=traceback.format_exc()), 400');
    expect(at(run(verboseErrorResponse, [['api/errors.py', errors], ['api/views.py', view]]))).toEqual(['api/views.py:5']);
  });

  it('HTTPException is credited only when the project raises it itself', () => {
    const view = lines('def post():', '    try:', '        check()', '    except HTTPException as e:', '        return JSONResponse(status_code=400, content={"detail": str(e)})');
    expect(at(run(verboseErrorResponse, [['api/views.py', view]]))).toEqual(['api/views.py:5']);
    const raiser = 'def check():\n    raise HTTPException(status_code=403, detail="no")\n';
    expect(run(verboseErrorResponse, [['api/views.py', view], ['api/guards.py', raiser]])).toEqual([]);
  });

  it('an exception handler typed with a project class is silent; one typed Exception fires', () => {
    const handler = (type: string): string =>
      lines(`async def handle(request, exc: ${type}):`, '    return JSONResponse(status_code=400, content={"detail": str(exc)})');
    expect(run(verboseErrorResponse, [['api/errors.py', errors], ['api/main.py', handler('QuotaError')]])).toEqual([]);
    expect(at(run(verboseErrorResponse, [['api/errors.py', errors], ['api/main.py', handler('Exception')]]))).toEqual(['api/main.py:2']);
  });

  it('a multi-line call is read to its balanced close: a traceback two lines down fires', () => {
    const view = lines(
      'def post():',
      '    try:',
      '        save()',
      '    except Exception:',
      '        return JSONResponse(',
      '            status_code=500,',
      '            content={"trace": traceback.format_exc()},',
      '        )',
    );
    expect(at(run(verboseErrorResponse, [['api/views.py', view]]))).toEqual(['api/views.py:5']);
  });

  it('a multi-line call carrying a project-defined exception\'s message is silent; an unknown one fires', () => {
    const view = (caught: string): string => lines(
      'def post():',
      '    try:',
      '        save()',
      `    except ${caught} as e:`,
      '        return JSONResponse(',
      '            status_code=400,',
      '            content={"detail": str(e)},',
      '        )',
    );
    expect(run(verboseErrorResponse, [['api/errors.py', errors], ['api/views.py', view('QuotaError')]])).toEqual([]);
    expect(at(run(verboseErrorResponse, [['api/errors.py', errors], ['api/views.py', view('Exception')]]))).toEqual(['api/views.py:5']);
  });

  it('a positional detail, HTTPException(400, str(error)), is read like detail=', () => {
    const view = lines('def post():', '    try:', '        save()', '    except ValueError as error:', '        raise HTTPException(400, str(error)) from error');
    expect(at(run(verboseErrorResponse, [['api/views.py', view]]))).toEqual(['api/views.py:5']);
  });

  it('str(exc) used only as a .get( lookup key is silent; given as the default it fires', () => {
    const view = (lookup: string): string => lines(
      'def post():',
      '    try:',
      '        save()',
      '    except ValueError as exc:',
      '        fixed = {"Too large": "The upload is too large."}',
      `        raise HTTPException(502, ${lookup}) from None`,
    );
    expect(run(verboseErrorResponse, [['api/views.py', view('fixed.get(str(exc), "Invalid response.")')]])).toEqual([]);
    expect(run(verboseErrorResponse, [['api/views.py', view('fixed.get(str(exc))')]])).toEqual([]);
    expect(at(run(verboseErrorResponse, [['api/views.py', view('fixed.get("x", str(exc))')]]))).toEqual(['api/views.py:6']);
  });

  it('a responding call with no exception in its arguments is silent, even with one on a later line', () => {
    const view = lines(
      'def post():',
      '    try:',
      '        save()',
      '    except Exception as e:',
      '        log.error(str(e))',
      '        return JSONResponse(status_code=500, content={"detail": "failed"})',
      '    x = str(e)',
    );
    expect(run(verboseErrorResponse, [['api/views.py', view]])).toEqual([]);
  });
});

describe('weak_jwt_handling on Python: the algorithm taken from the token', () => {
  it('algorithms from get_unverified_header is reported; a fixed list is not', () => {
    const bad = lines('def read(token):', '    header = jwt.get_unverified_header(token)', '    return jwt.decode(token, KEY, algorithms=[header["alg"]])');
    const findings = run(weakJwtHandling, [['app/tokens.py', bad]]);
    expect(at(findings)).toEqual(['app/tokens.py:3']);
    expect(findings[0]?.title).toBe("JWT algorithm taken from the token's own header");
    const good = lines('def read(token):', '    header = jwt.get_unverified_header(token)', '    return jwt.decode(token, KEY, algorithms=["HS256"])');
    expect(run(weakJwtHandling, [['app/tokens.py', good]])).toEqual([]);
  });

  it('verify_exp False is reported as ignored expiry; a decode that keeps it is not', () => {
    const source = lines('def read(token):', '    return jwt.decode(token, KEY, algorithms=["HS256"], options={"verify_exp": False})');
    const findings = run(weakJwtHandling, [['app/tokens.py', source]]);
    expect(at(findings)).toEqual(['app/tokens.py:2']);
    expect(findings[0]?.title).toBe('JWT verification ignores token expiration');
    const kept = lines('def read(token):', '    return jwt.decode(token, KEY, algorithms=["HS256"], options={"verify_exp": True})');
    expect(run(weakJwtHandling, [['app/tokens.py', kept]])).toEqual([]);
  });

  it('verify_exp False outside the decode call\'s own arguments is not read', () => {
    const source = lines('OPTS = {"verify_exp": False}', 'def read(token):', '    return jwt.decode(token, KEY, algorithms=["HS256"])');
    expect(run(weakJwtHandling, [['app/tokens.py', source]])).toEqual([]);
  });
});

describe('hardcoded_secret: Django\'s key format', () => {
  it('a startproject-style SECRET_KEY is reported; one read from the environment is not', () => {
    const key = 'django-insecure-' + 'w7#k2q!v9m@x4p$z8r&t3b^n5c*e1h6j0l(a)s-d+f=g_y';
    const findings = run(hardcodedSecret, [['site/settings.py', `SECRET_KEY = "${key}"\n`]]);
    expect(at(findings)).toEqual(['site/settings.py:1']);
    expect(findings[0]?.title).toContain('Django SECRET_KEY');
    expect(findings[0]?.evidence).not.toContain('w7#k2q');
    expect(run(hardcodedSecret, [['site/settings.py', 'SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]\n']])).toEqual([]);
  });
});

describe('dangerous_cors_wildcard on Python', () => {
  it('flask-cors origins="*" with supports_credentials is the reflected, critical form', () => {
    const findings = run(dangerousCorsWildcard, [['app/__init__.py', 'CORS(app, origins="*", supports_credentials=True)\n']]);
    expect(at(findings)).toEqual(['app/__init__.py:1']);
    expect(findings[0]?.severity).toBe('critical');
    expect(findings[0]?.title).toBe('CORS allows all origins with credentials');
  });

  it('flask-cors origins="*" without credentials is the low, literal form; an allowlist is silent', () => {
    const findings = run(dangerousCorsWildcard, [['app/__init__.py', 'CORS(app, origins="*")\n']]);
    expect(findings.map((f) => f.severity)).toEqual(['low']);
    expect(run(dangerousCorsWildcard, [['app/__init__.py', 'CORS(app, origins=["https://a.example"], supports_credentials=True)\n']])).toEqual([]);
  });

  it('django-cors-headers allow-all with credentials fires in settings, not in a local settings module', () => {
    const settings = 'CORS_ALLOW_ALL_ORIGINS = True\nCORS_ALLOW_CREDENTIALS = True\n';
    const findings = run(dangerousCorsWildcard, [['site/settings.py', settings]]);
    expect(at(findings)).toEqual(['site/settings.py:1']);
    expect(findings[0]?.severity).toBe('critical');
    expect(run(dangerousCorsWildcard, [['site/settings/local.py', settings]])).toEqual([]);
  });

  it('Starlette CORSMiddleware allow_origins=["*"] with allow_credentials=True is the reflected, critical form', () => {
    const source = lines('app.add_middleware(', '    CORSMiddleware,', '    allow_origins=["*"],', '    allow_credentials=True,', ')');
    const findings = run(dangerousCorsWildcard, [['api/main.py', source]]);
    expect(at(findings)).toEqual(['api/main.py:3']);
    expect(findings[0]?.severity).toBe('critical');
    expect(findings[0]?.title).toBe('CORS allows all origins with credentials');
  });

  it('Starlette CORSMiddleware without credentials is the low form; an allowlist, or a wildcard outside its call, is silent', () => {
    const literal = lines('app.add_middleware(CORSMiddleware, allow_origins=["*"])');
    expect(run(dangerousCorsWildcard, [['api/main.py', literal]]).map((f) => f.severity)).toEqual(['low']);
    const allowlist = lines('app.add_middleware(', '    CORSMiddleware,', '    allow_origins=["https://a.example"],', '    allow_credentials=True,', ')');
    expect(run(dangerousCorsWildcard, [['api/main.py', allowlist]])).toEqual([]);
    const outside = lines('ORIGINS = dict(allow_origins=["*"])', 'app.add_middleware(CORSMiddleware, allow_origins=ALLOWED, allow_credentials=True)');
    expect(run(dangerousCorsWildcard, [['api/main.py', outside]])).toEqual([]);
  });
});

describe('missing_csrf_protection on Python', () => {
  it('declares Python in the registry', () => {
    expect(RULE_REGISTRY.find((rule) => rule.ruleId === 'missing_csrf_protection')?.languages).toContain('python');
  });

  it('WTF_CSRF_ENABLED = False fires in a base config, not in a testing config or a test module', () => {
    const config = lines('class BaseConfig:', '    WTF_CSRF_ENABLED = False', '', 'class TestingConfig(BaseConfig):', '    WTF_CSRF_ENABLED = False');
    expect(at(run(csrfProtection, [['shop/config.py', config]]))).toEqual(['shop/config.py:2']);
    expect(run(csrfProtection, [['tests/test_forms.py', 'app.config["WTF_CSRF_ENABLED"] = False\n']])).toEqual([]);
    expect(at(run(csrfProtection, [['shop/app.py', 'app.config["WTF_CSRF_ENABLED"] = False\n']]))).toEqual(['shop/app.py:1']);
  });

  it('@csrf_exempt on a session-backed view fires; on a webhook with no session it does not', () => {
    const views = lines(
      '@login_required',
      '@csrf_exempt',
      'def grade(request, pk):',
      '    return save(pk)',
      '',
      '@csrf_exempt',
      'def update(request):',
      '    request.user.profile.save()',
      '',
      '@csrf_exempt',
      '@require_POST',
      'def hook(request):',
      '    verify(request.body)',
    );
    expect(at(run(csrfProtection, [['school/views.py', views]]))).toEqual(['school/views.py:2', 'school/views.py:6']);
  });
});

describe('xss on Python templates: a stored text field marked safe', () => {
  const models = lines(
    'class Post(db.Model):',
    '    body = db.Column(db.Text, nullable=False)',
    '    title = db.Column(db.String(200))',
    '',
    '    @property',
    '    def body_html(self):',
    '        return bleach.clean(markdown.markdown(self.body), tags=TAGS)',
  );
  const page = (expr: string): string => `<article>\n  {{ ${expr} }}\n</article>\n`;

  it('a stored field rendered |safe fires', () => {
    expect(at(run(crossSiteScripting, [['app/models.py', models], ['app/templates/show.html', page('post.body|safe')]]))).toEqual(['app/templates/show.html:2']);
  });

  it('a property built by a sanitiser, a sanitising filter, and a value that is not stored are silent', () => {
    for (const expr of ['post.body_html|safe', 'post.body|bleach|safe', 'item|safe', 'post.summary|safe']) {
      expect(run(crossSiteScripting, [['app/models.py', models], ['app/templates/show.html', page(expr)]]), expr).toEqual([]);
    }
  });

  it('a stored field the model cleans on save is credited in a template', () => {
    const cleaned = lines(
      'from app import db',
      'class Post(db.Model):',
      '    body = db.Column(db.Text, nullable=False)',
      '',
      '    def save(self):',
      '        self.body = bleach.clean(self.body, tags=TAGS)',
    );
    const view = lines('from flask import render_template', 'from .models import Post', 'def show(n):', '    return render_template("show.html", post=Post.query.get(n))');
    expect(run(crossSiteScripting, [['app/__init__.py', lines('from flask_sqlalchemy import SQLAlchemy', 'db = SQLAlchemy()')], ['app/models.py', cleaned], ['app/views.py', view], ['app/templates/show.html', page('post.body|safe')]])).toEqual([]);
  });

  it('a template with no HTML element renders text and is silent', () => {
    expect(run(crossSiteScripting, [['app/models.py', models], ['app/templates/sms.html', 'New post: {{ post.body|safe }}\n']])).toEqual([]);
  });

  it('a project with no Python is not read this way', () => {
    expect(run(crossSiteScripting, [['site/templates/show.html', page('post.body|safe')]])).toEqual([]);
  });

  it('mark_safe over a stored field fires; over a sanitised one or a count it does not', () => {
    const django = lines('class Submission(models.Model):', '    feedback = models.TextField(blank=True)');
    const tags = lines(
      'def box(s):',
      '    return mark_safe(f"<p>{s.feedback}</p>")',
      '',
      'def clean_box(s):',
      '    return mark_safe(bleach.clean(s.feedback))',
      '',
      'def count(total, done):',
      '    return mark_safe(f"{total} <i>{done} done</i>")',
    );
    expect(at(run(crossSiteScripting, [['school/models.py', django], ['school/templatetags/tags.py', tags]]))).toEqual(['school/templatetags/tags.py:2']);
  });

  it('a stored field the model cleans on save is credited', () => {
    const django = lines(
      'from django.db import models',
      'class Submission(models.Model):',
      '    feedback = models.TextField(blank=True)',
      '',
      '    def save(self, *args, **kwargs):',
      '        self.feedback = bleach.clean(self.feedback, tags=TAGS)',
      '        super().save(*args, **kwargs)',
    );
    const tags = lines('from school.models import Submission', 'def box(n):', '    s = Submission.objects.get(pk=n)', '    return mark_safe(f"<p>{s.feedback}</p>")');
    expect(run(crossSiteScripting, [['school/models.py', django], ['school/templatetags/tags.py', tags]])).toEqual([]);
  });
});
