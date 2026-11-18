import { describe, expect, it } from 'vitest';
import { apiMutationWithoutAuth } from '../../src/rules/contextual/apiMutationWithoutAuth.js';
import { publicAdminRouteHint } from '../../src/rules/basic/publicAdminRouteHint.js';
import { djangoViewGuard, maskPython, pythonRouteGuard } from '../../src/shared/pythonGuards.js';
import type { RuleContext } from '../../src/shared/types.js';
import { memoryContext } from './helpers.js';

type Files = [string, string][];

function guardAt(files: Files, routePath: string, method?: string): string | undefined {
  const context = memoryContext(files);
  const route = context.projectMap.apiRoutes.find((candidate) =>
    candidate.routePath === routePath && (method === undefined || candidate.methods.includes(method)));
  if (route === undefined) throw new Error(`no route ${routePath}; routes: ${context.projectMap.apiRoutes.map((r) => r.routePath).join(', ')}`);
  return pythonRouteGuard(context, route)?.level;
}

const py = (...lines: string[]): string => `${lines.join('\n')}\n`;

const REFUSING_USER = py(
  'from fastapi import Depends, HTTPException',
  'from .db import get_db',
  '',
  'def get_current_user(token: str = "", db=Depends(get_db)):',
  '    user = db.lookup(token)',
  '    if user is None:',
  '        raise HTTPException(status_code=401, detail="Not signed in")',
  '    return user',
);
const PERMISSIVE_USER = py(
  'from fastapi import Depends',
  'from .db import get_db',
  '',
  'def get_current_user(token: str = "", db=Depends(get_db)):',
  '    return db.lookup(token)',
);
const DB = py('def get_db():', '    yield object()');

function fastapiRoute(signature: string, extra = ''): Files {
  return [
    ['app/db.py', DB],
    ['app/routes.py', py(
      'from fastapi import APIRouter, Depends',
      'from .auth import get_current_user',
      'from .db import get_db',
      extra,
      'router = APIRouter()',
      '',
      '@router.delete("/items/{item_id}")',
      `def delete_item(${signature}):`,
      '    db.delete(item_id)',
      '    db.commit()',
    )],
  ];
}

describe('FastAPI dependencies on the route', () => {
  it('Depends(x) counts when x raises 401, and not when x never refuses (a name is never a credit)', () => {
    const signature = 'item_id: int, user=Depends(get_current_user), db=Depends(get_db)';
    expect(guardAt([...fastapiRoute(signature), ['app/auth.py', REFUSING_USER]], '/items/{item_id}')).toBe('auth');
    expect(guardAt([...fastapiRoute(signature), ['app/auth.py', PERMISSIVE_USER]], '/items/{item_id}')).toBeUndefined();
    const notFound = REFUSING_USER.replace('status_code=401', 'status_code=404');
    expect(guardAt([...fastapiRoute(signature), ['app/auth.py', notFound]], '/items/{item_id}')).toBeUndefined();
  });

  it('Security(x) and a dotted module dependency (auth.get_current_user) are read the same way', () => {
    const files: Files = [
      ['app/db.py', DB],
      ['app/auth.py', REFUSING_USER],
      ['app/routes.py', py(
        'from fastapi import APIRouter, Security',
        'from . import auth',
        'router = APIRouter()',
        '',
        '@router.post("/a")',
        'def a(user=Security(auth.get_current_user)):',
        '    pass',
      )],
    ];
    expect(guardAt(files, '/a')).toBe('auth');
  });

  it('an optional-user dependency (no token: return None) is not a guard, whatever it refuses later', () => {
    const optional = py(
      'from fastapi import HTTPException',
      'def get_current_user(token: str = ""):',
      '    if token is None:',
      '        return None',
      '    if token != "ok":',
      '        raise HTTPException(status_code=401)',
      '    return token',
    );
    expect(guardAt([...fastapiRoute('item_id: int, user=Depends(get_current_user)'), ['app/auth.py', optional]], '/items/{item_id}')).toBeUndefined();
  });

  describe('an anonymous caller must be refused (an optional user written positively is no guard)', () => {
    const route = (dependency: string): string | undefined =>
      guardAt([...fastapiRoute('item_id: int, user=Depends(get_current_user)'), ['app/auth.py', dependency]], '/items/{item_id}');
    const head = ['from fastapi import Header, HTTPException', 'def get_current_user(authorization: str = Header(None)):'];
    const checkBadToken = [
      '        if authorization != "ok":',
      '            raise HTTPException(status_code=401)',
      '        return {"id": 1}',
    ];
    const STRICT = py(...head, '    if not authorization:', '        raise HTTPException(status_code=401)', ...checkBadToken.map((line) => line.slice(4)));

    it('the strict twin (no header: 401) is a guard', () => {
      expect(route(STRICT)).toBe('auth');
    });

    it('if authorization: ... 401 ...; then an unconditional return None is not', () => {
      expect(route(py(...head, '    if authorization:', ...checkBadToken, '    return None'))).toBeUndefined();
      expect(route(py(...head, '    if authorization is not None:', ...checkBadToken, '    return None'))).toBeUndefined();
      expect(route(py(
        'from fastapi import HTTPException, Request',
        'def get_current_user(request: Request):',
        '    if request.headers.get("Authorization"):',
        '        if request.headers.get("Authorization") != "ok":',
        '            raise HTTPException(status_code=401)',
        '        return {"id": 1}',
        '    return None',
      ))).toBeUndefined();
    });

    it('the same body falling off the end (an implicit None) is not', () => {
      expect(route(py(...head, '    if authorization:', ...checkBadToken))).toBeUndefined();
    });

    it('else: return None is not, and neither is a refusal in the else of a missing-credential test', () => {
      expect(route(py(...head, '    if authorization:', ...checkBadToken, '    else:', '        return None'))).toBeUndefined();
      expect(route(py(
        ...head,
        '    if authorization is None:',
        '        user = None',
        '    else:',
        '        if authorization != "ok":',
        '            raise HTTPException(status_code=401)',
        '        user = {"id": 1}',
        '    return user',
      ))).toBeUndefined();
    });

    it('a helper called only when a credential was sent proves nothing; called always, it does', () => {
      const helper = (body: string[]): string => py(
        'from fastapi import Header, HTTPException',
        'def decode_or_401(raw):',
        '    if raw != "ok":',
        '        raise HTTPException(status_code=401)',
        '    return {"id": 1}',
        'def get_current_user(authorization: str = Header(None)):',
        ...body,
      );
      expect(route(helper(['    if authorization:', '        return decode_or_401(authorization)', '    return None']))).toBeUndefined();
      expect(route(helper(['    return decode_or_401(authorization)']))).toBe('auth');
    });

    it('a positive check with an unconditional refusal after it is still a guard', () => {
      expect(route(py(...head, '    if authorization:', ...checkBadToken, '    raise HTTPException(status_code=401)'))).toBe('auth');
    });

    it('the configuration switch stays credited beside a positive credential check', () => {
      const switched = py(
        'from fastapi import Header, HTTPException',
        'from .config import settings',
        'def get_current_user(authorization: str = Header(None)):',
        '    if not settings.SIGN_IN_ENABLED:',
        '        return None',
        '    if authorization:',
        '        if authorization != "ok":',
        '            raise HTTPException(status_code=401)',
        '        return {"id": 1}',
        '    raise HTTPException(status_code=401)',
      );
      expect(route(switched)).toBe('auth');
    });
  });

  it('a guard a configuration switch turns off is still a guard (the conditional-guard decision)', () => {
    const conditional = py(
      'from fastapi import HTTPException',
      'from .config import settings',
      'def get_current_user(token: str = ""):',
      '    if not settings.SIGN_IN_ENABLED:',
      '        return None',
      '    if token is None:',
      '        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)',
      '    return token',
    );
    expect(guardAt([...fastapiRoute('item_id: int, user=Depends(get_current_user)'), ['app/auth.py', conditional]], '/items/{item_id}')).toBe('auth');
    const sectioned = conditional.replace('settings.SIGN_IN_ENABLED', 'settings.session.enabled');
    expect(guardAt([...fastapiRoute('item_id: int, user=Depends(get_current_user)'), ['app/auth.py', sectioned]], '/items/{item_id}')).toBe('auth');
  });

  it('a 401 raised inside try and swallowed by a broad except is fail-open, not a guard', () => {
    const swallowing = py(
      'from fastapi import HTTPException',
      'def get_current_user(token: str = ""):',
      '    try:',
      '        if token != "ok":',
      '            raise HTTPException(status_code=401)',
      '        return token',
      '    except Exception:',
      '        return "guest"',
    );
    const reraising = swallowing.replace('        return "guest"', '        raise');
    expect(guardAt([...fastapiRoute('item_id: int, user=Depends(get_current_user)'), ['app/auth.py', swallowing]], '/items/{item_id}')).toBeUndefined();
    expect(guardAt([...fastapiRoute('item_id: int, user=Depends(get_current_user)'), ['app/auth.py', reraising]], '/items/{item_id}')).toBe('auth');
  });

  it('raise NAME counts when NAME is bound to HTTPException(401)', () => {
    const bound = py(
      'from fastapi import HTTPException',
      'def get_current_user(token: str = ""):',
      '    credentials_exception = HTTPException(status_code=401, detail="no")',
      '    if not token:',
      '        raise credentials_exception',
      '    return token',
    );
    const notAuth = bound.replace('status_code=401', 'status_code=404');
    expect(guardAt([...fastapiRoute('item_id: int, user=Depends(get_current_user)'), ['app/auth.py', bound]], '/items/{item_id}')).toBe('auth');
    expect(guardAt([...fastapiRoute('item_id: int, user=Depends(get_current_user)'), ['app/auth.py', notAuth]], '/items/{item_id}')).toBeUndefined();
  });

  it('an Annotated alias imported from another module carries its Depends', () => {
    const deps = py(
      'from typing import Annotated',
      'from fastapi import Depends',
      'from .auth import get_current_user',
      'CurrentUser = Annotated[dict, Depends(get_current_user)]',
    );
    const files: Files = [
      ['app/db.py', DB],
      ['app/deps.py', deps],
      ['app/routes.py', py(
        'from fastapi import APIRouter',
        'from .deps import CurrentUser',
        'router = APIRouter()',
        '@router.delete("/x")',
        'def x(user: CurrentUser):',
        '    pass',
      )],
    ];
    expect(guardAt([...files, ['app/auth.py', REFUSING_USER]], '/x')).toBe('auth');
    expect(guardAt([...files, ['app/auth.py', PERMISSIVE_USER]], '/x')).toBeUndefined();
  });

  it('a require_*_role(...) factory is read through the def it returns, and its role test makes it admin', () => {
    const rbac = py(
      'from fastapi import Depends, HTTPException',
      'from .auth import get_current_user',
      'def require_role(minimum):',
      '    def _dep(user=Depends(get_current_user)):',
      '        if user.role != minimum:',
      '            raise HTTPException(403, "Forbidden")',
      '        return user',
      '    return _dep',
    );
    const files = (auth: string): Files => [
      ['app/db.py', DB],
      ['app/auth.py', auth],
      ['app/rbac.py', rbac],
      ['app/routes.py', py(
        'from fastapi import APIRouter, Depends',
        'from .rbac import require_role',
        'router = APIRouter()',
        '@router.delete("/admin/things")',
        'def drop(user=Depends(require_role("admin"))):',
        '    pass',
      )],
    ];
    expect(guardAt(files(REFUSING_USER), '/admin/things')).toBe('admin');
    expect(guardAt(files(PERMISSIVE_USER), '/admin/things')).toBe('admin');
    const noRefusal = rbac.replace('            raise HTTPException(403, "Forbidden")', '            pass');
    expect(guardAt([...files(PERMISSIVE_USER).filter(([p]) => p !== 'app/rbac.py'), ['app/rbac.py', noRefusal]], '/admin/things')).toBeUndefined();
  });

  it('a helper the dependency calls is read the same way', () => {
    const auth = py(
      'from fastapi import Depends, HTTPException',
      'def _check_membership(user, allowed):',
      '    if user.role not in allowed:',
      '        raise HTTPException(status_code=403)',
      'def require_member(user: str = ""):',
      '    _check_membership(user, ("member", "owner"))',
      '    return user',
    );
    const files: Files = [
      ['app/db.py', DB],
      ['app/auth.py', auth],
      ['app/routes.py', py(
        'from fastapi import APIRouter, Depends',
        'from .auth import require_member',
        'router = APIRouter()',
        '@router.post("/m")',
        'def m(user=Depends(require_member)):',
        '    pass',
      )],
    ];
    expect(guardAt(files, '/m')).toBe('admin');
    const ordering = auth.replace('if user.role not in allowed:', 'if user.role < allowed:');
    expect(guardAt([...files.filter(([p]) => p !== 'app/auth.py'), ['app/auth.py', ordering]], '/m')).toBeUndefined();
    const conditional = auth.replace('    _check_membership(user, ("member", "owner"))', '    if user.startswith("sk-"):\n        _check_membership(user, ("member", "owner"))\n    if not user:\n        raise HTTPException(status_code=401)');
    expect(guardAt([...files.filter(([p]) => p !== 'app/auth.py'), ['app/auth.py', conditional]], '/m')).toBe('auth');
    const nested = py(
      'from fastapi import HTTPException',
      'def require_member(user: str = ""):',
      '    if not user:',
      '        raise HTTPException(status_code=401)',
      '    if user.startswith("sk-"):',
      '        if not user.has_permission("keys"):',
      '            raise HTTPException(status_code=403)',
      '    return user',
    );
    expect(guardAt([...files.filter(([p]) => p !== 'app/auth.py'), ['app/auth.py', nested]], '/m')).toBe('auth');
    const harmless = auth.replace('        raise HTTPException(status_code=403)', '        return False');
    expect(guardAt([...files.filter(([p]) => p !== 'app/auth.py'), ['app/auth.py', harmless]], '/m')).toBeUndefined();
  });

  it('a FastAPI security scheme counts unless auto_error=False', () => {
    const scheme = (args: string): Files => [
      ['app/routes.py', py(
        'from fastapi import APIRouter, Depends',
        'from fastapi.security import HTTPBearer',
        `bearer = HTTPBearer(${args})`,
        'router = APIRouter()',
        '@router.post("/s")',
        'def s(creds=Depends(bearer)):',
        '    pass',
      )],
    ];
    expect(guardAt(scheme(''), '/s')).toBe('auth');
    expect(guardAt(scheme('auto_error=False'), '/s')).toBeUndefined();
  });

  it('a check on a header the caller sets is not a guard (client-controlled role)', () => {
    const files: Files = [
      ['app/routes.py', py(
        'from fastapi import APIRouter, Header, HTTPException',
        'router = APIRouter()',
        '@router.delete("/drivers/{driver_id}")',
        'def remove(driver_id: int, x_role: str = Header("driver")):',
        '    if x_role != "admin":',
        '        raise HTTPException(status_code=403)',
        '    pass',
      )],
    ];
    expect(guardAt(files, '/drivers/{driver_id}')).toBeUndefined();
    const query = files[0]![1].replace('x_role: str = Header("driver")', 'x_role: str = "driver"');
    expect(guardAt([['app/routes.py', query]], '/drivers/{driver_id}')).toBeUndefined();
    const stored = files[0]![1]
      .replace('x_role: str = Header("driver")', 'staff: dict = Depends(load_staff)')
      .replace('if x_role != "admin":', 'if staff["role"] != "admin":')
      .replace('from fastapi import APIRouter, Header, HTTPException', 'from fastapi import APIRouter, Depends, HTTPException\nfrom .staff import load_staff');
    expect(guardAt([['app/routes.py', stored], ['app/staff.py', py('def load_staff():', '    return {}')]], '/drivers/{driver_id}')).toBe('admin');
  });
});

describe('where the credential comes from decides presence, not its name (attempt 3)', () => {
  const route = (dependency: string): string | undefined =>
    guardAt([...fastapiRoute('item_id: int, user=Depends(get_current_user)'), ['app/auth.py', dependency]], '/items/{item_id}');
  const refuseBad = (name: string, indent: string): string[] => [
    `${indent}if not authenticate(${name}):`,
    `${indent}    raise HTTPException(status_code=401)`,
    `${indent}return {"id": 1}`,
  ];
  const AUTHENTICATE = ['def authenticate(value):', '    return value == "expected"'];

  it('an omittable parameter with a non-credential name (Header(None)) is a presence test; its strict twin is a guard', () => {
    const head = ['from fastapi import Header, HTTPException', ...AUTHENTICATE, 'def get_current_user(hdr_value: str = Header(None, alias="Authorization")):'];
    expect(route(py(...head, '    if hdr_value:', ...refuseBad('hdr_value', '        '), '    return None'))).toBeUndefined();
    expect(route(py(...head, '    if not hdr_value or not authenticate(hdr_value):', '        raise HTTPException(status_code=401)', '    return {"id": 1}'))).toBe('auth');
  });

  it('an Optional[str] = None parameter is a presence test; its strict twin is a guard', () => {
    const head = ['from typing import Optional', 'from fastapi import HTTPException', ...AUTHENTICATE, 'def get_current_user(passkey: Optional[str] = None):'];
    expect(route(py(...head, '    if passkey is not None:', ...refuseBad('passkey', '        '), '    return None'))).toBeUndefined();
    expect(route(py(...head, '    if passkey is None:', '        raise HTTPException(status_code=401)', ...refuseBad('passkey', '    ')))).toBe('auth');
  });

  it('a local read from request.headers.get(...) is a presence test; its strict twin is a guard', () => {
    const head = ['from fastapi import HTTPException, Request', ...AUTHENTICATE, 'def get_current_user(request: Request):', '    sent = request.headers.get("X-Access")'];
    expect(route(py(...head, '    if sent:', ...refuseBad('sent', '        '), '    return None'))).toBeUndefined();
    expect(route(py(...head, '    if not sent:', '        raise HTTPException(status_code=401)', ...refuseBad('sent', '    ')))).toBe('auth');
  });

  it('a local read from request.cookies.get(...) in a Flask decorator is a presence test; its strict twin is a guard', () => {
    const guards = (check: string[]): string => py(
      'from functools import wraps',
      'from flask import abort, request',
      ...AUTHENTICATE,
      'def member_required(f):',
      '    @wraps(f)',
      '    def wrapper(*args, **kwargs):',
      '        sid = request.cookies.get("sid")',
      ...check,
      '        return f(*args, **kwargs)',
      '    return wrapper',
    );
    const view = (check: string[]): Files => [
      ['web/guards.py', guards(check)],
      ['web/views.py', py(
        'from flask import Blueprint',
        'from .guards import member_required',
        'bp = Blueprint("posts", __name__)',
        '@bp.route("/<int:post_id>/publish", methods=["POST"])',
        '@member_required',
        'def publish(post_id):',
        '    db.session.commit()',
      )],
    ];
    expect(guardAt(view(['        if sid:', '            if not authenticate(sid):', '                abort(401)']), '/<int:post_id>/publish')).toBeUndefined();
    expect(guardAt(view(['        if not sid or not authenticate(sid):', '            abort(401)']), '/<int:post_id>/publish')).toBe('auth');
  });

  describe('in a handler body (no backstop there), the origin alone decides', () => {
    it('an omittable header parameter: a refusal under "if it was sent" meets no anonymous caller', () => {
      const handler = (body: string[]): Files => [['app/routes.py', py(
        'from fastapi import APIRouter, Header, HTTPException',
        'from .checks import authenticate',
        'router = APIRouter()',
        '@router.delete("/items/{item_id}")',
        'def delete_item(item_id: int, hdr_value: str = Header(None)):',
        ...body,
        '    db.delete(item_id)',
      )], ['app/checks.py', py(...AUTHENTICATE)]];
      expect(guardAt(handler(['    if hdr_value:', '        if not authenticate(hdr_value):', '            raise HTTPException(status_code=401)']), '/items/{item_id}')).toBeUndefined();
      expect(guardAt(handler(['    if not hdr_value or not authenticate(hdr_value):', '        raise HTTPException(status_code=401)']), '/items/{item_id}')).toBe('auth');
    });

    it('a scheme built with auto_error=False hands the handler None: the same', () => {
      const handler = (body: string[]): Files => [['app/routes.py', py(
        'from fastapi import APIRouter, Depends, HTTPException',
        'from fastapi.security import HTTPBearer',
        'from .checks import authenticate',
        'scheme = HTTPBearer(auto_error=False)',
        'router = APIRouter()',
        '@router.delete("/items/{item_id}")',
        'def delete_item(item_id: int, bearer_value=Depends(scheme)):',
        ...body,
        '    db.delete(item_id)',
      )], ['app/checks.py', py(...AUTHENTICATE)]];
      expect(guardAt(handler(['    if bearer_value:', '        if not authenticate(bearer_value):', '            raise HTTPException(status_code=401)']), '/items/{item_id}')).toBeUndefined();
      expect(guardAt(handler(['    if not authenticate(bearer_value):', '        raise HTTPException(status_code=401)']), '/items/{item_id}')).toBe('auth');
    });

    it('a Flask local read from request.cookies.get(...): the same', () => {
      const handler = (body: string[]): Files => [['web/views.py', py(
        'from flask import Blueprint, abort, request',
        'from .checks import authenticate',
        'bp = Blueprint("posts", __name__)',
        '@bp.route("/<int:post_id>/publish", methods=["POST"])',
        'def publish(post_id):',
        '    sid = request.cookies.get("sid")',
        ...body,
        '    db.session.commit()',
      )], ['web/checks.py', py(...AUTHENTICATE)]];
      expect(guardAt(handler(['    if sid:', '        if not authenticate(sid):', '            abort(401)']), '/<int:post_id>/publish')).toBeUndefined();
      expect(guardAt(handler(['    if not sid or not authenticate(sid):', '        abort(401)']), '/<int:post_id>/publish')).toBe('auth');
      expect(guardAt(handler(['    if sid is None:', '        print("guest")', '    else:', '        if not authenticate(sid):', '            abort(401)']), '/<int:post_id>/publish')).toBeUndefined();
    });
  });

  describe('the fail-closed backstop: a guard that can finish before any check has run is no guard', () => {
    it('a credential taken from a helper\'s return value, then if value: ... 401 ... return None', () => {
      const head = [
        'from fastapi import HTTPException, Request',
        ...AUTHENTICATE,
        'def fetch_credential(request):',
        '    return request.state.carried',
        'def get_current_user(request: Request):',
        '    value = fetch_credential(request)',
      ];
      expect(route(py(...head, '    if value:', ...refuseBad('value', '        '), '    return None'))).toBeUndefined();
      expect(route(py(...head, '    if not value:', '        raise HTTPException(status_code=401)', ...refuseBad('value', '    ')))).toBe('auth');
      expect(route(py(...head, '    if value:', ...refuseBad('value', '        ')))).toBeUndefined();
      expect(route(py(...head, '    if value:', '        return {"id": 1}', '    raise HTTPException(status_code=401)'))).toBeUndefined();
    });

    it('a check in every branch of a try/except, or in the return itself, still counts', () => {
      const head = ['from fastapi import HTTPException, Request', 'from .tokens import decode_or_refuse', 'def get_current_user(request: Request):'];
      const tokens: [string, string] = ['app/tokens.py', py(
        'from fastapi import HTTPException',
        'def decode_or_refuse(value):',
        '    if value != "expected":',
        '        raise HTTPException(status_code=401)',
        '    return {"id": 1}',
      )];
      const at = (body: string[]): string | undefined =>
        guardAt([...fastapiRoute('item_id: int, user=Depends(get_current_user)'), ['app/auth.py', py(...head, ...body)], tokens], '/items/{item_id}');
      expect(at(['    return decode_or_refuse(request.state.carried)'])).toBe('auth');
      expect(at(['    claims = decode_or_refuse(request.state.carried)', '    return claims'])).toBe('auth');
      expect(at(['    if request.state.carried:', '        return decode_or_refuse(request.state.carried)', '    return None'])).toBeUndefined();
    });

    it('a Flask gate whose early allow for some caller state comes before any check is not read', () => {
      const files: Files = [['srv/app.py', py(
        'from flask import Flask, jsonify, session',
        'app = Flask(__name__)',
        '@app.before_request',
        'def gate():',
        '    if session.get("seen"):',
        '        return None',
        '    if not session.get("member"):',
        '        return jsonify({"error": "sign in"}), 401',
        '@app.route("/api/notes", methods=["POST"])',
        'def notes_create():',
        '    pass',
      )]];
      expect(guardAt(files, '/api/notes')).toBeUndefined();
      const checkedFirst = files[0]![1].replace('    if session.get("seen"):\n        return None\n', '');
      expect(guardAt([['srv/app.py', checkedFirst]], '/api/notes')).toBe('auth');
    });

    it('a decorator that can hand back the undecorated function is no guard, whatever its wrapper does', () => {
      const guards = (extra: string[]): string => py(
        'from functools import wraps',
        'from flask import abort',
        'from flask_login import current_user',
        'def member_required(f):',
        '    @wraps(f)',
        '    def wrapper(*args, **kwargs):',
        '        if not current_user.is_authenticated:',
        '            abort(401)',
        '        return f(*args, **kwargs)',
        ...extra,
        '    return wrapper',
      );
      const view = (extra: string[]): Files => [
        ['web/guards.py', guards(extra)],
        ['web/views.py', py(
          'from flask import Blueprint',
          'from .guards import member_required',
          'bp = Blueprint("posts", __name__)',
          '@bp.route("/<int:post_id>/publish", methods=["POST"])',
          '@member_required',
          'def publish(post_id):',
          '    db.session.commit()',
        )],
      ];
      expect(guardAt(view([]), '/<int:post_id>/publish')).toBe('auth');
      expect(guardAt(view(['    if getattr(f, "open_to_all", False):', '        return f']), '/<int:post_id>/publish')).toBeUndefined();
    });

    it('a dependency that refuses a missing credential but returns None for an unknown one is still an optional user', () => {
      const lookupNone = py(
        'from fastapi import Header, HTTPException',
        'from .store import find_member',
        'def get_current_user(passkey: str = Header(None)):',
        '    if not passkey:',
        '        raise HTTPException(status_code=401)',
        '    user = find_member(passkey)',
        '    if user is None:',
        '        return None',
        '    return user',
      );
      const files = (auth: string): Files => [...fastapiRoute('item_id: int, user=Depends(get_current_user)'), ['app/auth.py', auth], ['app/store.py', py('def find_member(value):', '    return None')]];
      expect(guardAt(files(lookupNone), '/items/{item_id}')).toBeUndefined();
      expect(guardAt(files(lookupNone.replace('        return None', '        raise HTTPException(status_code=401)')), '/items/{item_id}')).toBe('auth');
    });

    it('in a handler body, a 401 swallowed by a broad except refuses nobody', () => {
      const handler = (handlerClause: string): Files => [['app/routes.py', py(
        'from fastapi import APIRouter, Header, HTTPException',
        'from .checks import authenticate',
        'router = APIRouter()',
        '@router.delete("/items/{item_id}")',
        'def delete_item(item_id: int, passkey: str = Header("")):',
        '    try:',
        '        if not authenticate(passkey):',
        '            raise HTTPException(status_code=401)',
        '    except Exception:',
        handlerClause,
        '    db.delete(item_id)',
      )], ['app/checks.py', py(...AUTHENTICATE)]];
      expect(guardAt(handler('        pass'), '/items/{item_id}')).toBeUndefined();
      expect(guardAt(handler('        raise'), '/items/{item_id}')).toBe('auth');
    });

    it('a Flask gate that falls off its end before any check on that path is not read', () => {
      const gate = (body: string[]): Files => [['srv/app.py', py(
        'from flask import Flask, abort, request, session',
        'from .checks import authenticate',
        'app = Flask(__name__)',
        '@app.before_request',
        'def gate():',
        '    sid = session.get("sid")',
        ...body,
        '@app.route("/api/notes", methods=["POST"])',
        'def notes_create():',
        '    pass',
      )], ['srv/checks.py', py(...AUTHENTICATE)]];
      expect(guardAt(gate([
        '    if sid:',
        '        if not authenticate(sid):',
        '            abort(401)',
        '    else:',
        '        if request.path.startswith("/admin"):',
        '            abort(401)',
      ]), '/api/notes')).toBeUndefined();
      expect(guardAt(gate(['    if not sid or not authenticate(sid):', '        abort(401)']), '/api/notes')).toBe('auth');
    });
  });

  describe('a refusal covers an exit only on its own path, and only when it can fire for a caller who sent nothing (the cut)', () => {
    const head = ['from fastapi import HTTPException, Request', ...AUTHENTICATE, 'def get_current_user(request: Request):'];

    it('a refusal in the if branch does not cover a return in a sibling elif', () => {
      const body = [
        '    kind, _, value = request.headers.get("X-Access", "").partition(" ")',
        '    if kind and kind != "v1":',
        '        raise HTTPException(status_code=401)',
        '    elif not value:',
        '        return None',
        ...refuseBad('value', '    '),
      ];
      expect(route(py(...head, ...body))).toBeUndefined();
      expect(route(py(...head, ...body.map((line) => line === '        return None' ? '        raise HTTPException(status_code=401)' : line)))).toBe('auth');
    });

    it('a refusal in one except clause does not cover a return in a sibling except', () => {
      const body = (second: string): string[] => [
        '    try:',
        '        claims = authenticate(request.state.carried)',
        '    except ValueError:',
        '        raise HTTPException(status_code=401)',
        '    except KeyError:',
        `        ${second}`,
        '    if not claims:',
        '        raise HTTPException(status_code=401)',
        '    return claims',
      ];
      expect(route(py(...head, ...body('return None')))).toBeUndefined();
      expect(route(py(...head, ...body('raise HTTPException(status_code=401)')))).toBe('auth');
    });

    it('a refusal under an unrelated positive condition does not cover a later return of a session read', () => {
      const body = (condition: string): string[] => [
        `    if ${condition}:`,
        '        raise HTTPException(status_code=403)',
        '    return request.session.get("member")',
      ];
      expect(route(py(...head, ...body('request.client.host in DENIED_HOSTS')))).toBeUndefined();
    });

    it('a positive test and-ed with a negative one can still let a caller who sent nothing through', () => {
      const mixed = [
        '    b = request.headers.get("X-Access")',
        '    if request.method == "POST" and not b:',
        '        raise HTTPException(status_code=401)',
        '    return b',
      ];
      expect(route(py(...head, ...mixed))).toBeUndefined();
    });

    it('strict twins: if not verify(x), and if x is None or x != secret, are checks', () => {
      const sent = '    x = request.headers.get("X-Access")';
      expect(route(py(...head, sent, '    if not authenticate(x):', '        raise HTTPException(status_code=401)', '    return {"id": 1}'))).toBe('auth');
      expect(route(py(...head, sent, '    if x is None or x != SECRET:', '        raise HTTPException(status_code=401)', '    return {"id": 1}'))).toBe('auth');
    });
  });
});

describe('FastAPI dependencies on the router, the mount and the app', () => {
  it('the route decorator\'s dependencies=[...] and APIRouter(dependencies=[...]) count', () => {
    const onRoute = fastapiRoute('item_id: int, db=Depends(get_db)')
      .map(([p, c]): [string, string] => [p, c.replace('@router.delete("/items/{item_id}")', '@router.delete("/items/{item_id}", dependencies=[Depends(get_current_user)])')]);
    expect(guardAt([...onRoute, ['app/auth.py', REFUSING_USER]], '/items/{item_id}')).toBe('auth');
    const onRouter = fastapiRoute('item_id: int, db=Depends(get_db)')
      .map(([p, c]): [string, string] => [p, c.replace('router = APIRouter()', 'router = APIRouter(prefix="/v1", dependencies=[Depends(get_current_user)])')]);
    expect(guardAt([...onRouter, ['app/auth.py', REFUSING_USER]], '/items/{item_id}')).toBe('auth');
    expect(guardAt([...onRouter, ['app/auth.py', PERMISSIVE_USER]], '/items/{item_id}')).toBeUndefined();
  });

  const mounted = (includes: string[]): Files => [
    ['svc/db.py', DB],
    ['svc/auth.py', REFUSING_USER],
    ['svc/routers/__init__.py', ''],
    ['svc/routers/notes.py', py(
      'from fastapi import APIRouter',
      'router = APIRouter()',
      '@router.delete("/notes/{note_id}")',
      'def drop(note_id: int):',
      '    pass',
    )],
    ['svc/main.py', py(
      'from fastapi import Depends, FastAPI',
      'from .auth import get_current_user',
      'from .routers import notes',
      'app = FastAPI()',
      '_guard = [Depends(get_current_user)]',
      ...includes,
    )],
  ];

  it('include_router(module.router, dependencies=NAME) protects the module\'s routes, through the import and the list name', () => {
    expect(guardAt(mounted(['app.include_router(notes.router, dependencies=_guard)']), '/notes/{note_id}')).toBe('auth');
    expect(guardAt(mounted(['app.include_router(notes.router, prefix="/api", dependencies=[Depends(get_current_user)])']), '/api/notes/{note_id}')).toBe('auth');
  });

  it('a router mounted without dependencies, or once with and once without, is not protected', () => {
    expect(guardAt(mounted(['app.include_router(notes.router)']), '/notes/{note_id}')).toBeUndefined();
    expect(guardAt(mounted([
      'app.include_router(notes.router, dependencies=_guard)',
      'app.include_router(notes.router, prefix="/open")',
    ]), '/notes/{note_id}')).toBeUndefined();
  });

  it('a router imported by name (from .routers.notes import router as notes_router) resolves too', () => {
    const files = mounted(['app.include_router(notes_router, dependencies=_guard)'])
      .map(([p, c]): [string, string] => [p, c.replace('from .routers import notes', 'from .routers.notes import router as notes_router')]);
    expect(guardAt(files, '/notes/{note_id}')).toBe('auth');
  });

  it('FastAPI(dependencies=[...]) protects the app\'s own routes and every router mounted on it', () => {
    const files = mounted(['app.include_router(notes.router)'])
      .map(([p, c]): [string, string] => [p, c.replace('app = FastAPI()', 'app = FastAPI(dependencies=[Depends(get_current_user)])')]);
    expect(guardAt(files, '/notes/{note_id}')).toBe('auth');
  });
});

const FLASK_MODELS = py('def save(x):', '    pass');

describe('Flask decorators and handler checks', () => {
  const flask = (decorators: string[], body: string[] = ['    db.session.commit()'], header = ''): Files => [
    ['web/views.py', py(
      'from flask import Blueprint, abort, redirect, url_for',
      'from flask_login import current_user, login_required',
      header,
      'bp = Blueprint("posts", __name__)',
      '',
      ...decorators,
      'def publish(post_id):',
      ...body,
    )],
  ];
  const ROUTE = '@bp.route("/<int:post_id>/publish", methods=["POST"])';

  it('flask_login\'s @login_required below the route decorator counts; above it, it protects nothing', () => {
    expect(guardAt(flask([ROUTE, '@login_required']), '/<int:post_id>/publish')).toBe('auth');
    expect(guardAt(flask(['@login_required', ROUTE]), '/<int:post_id>/publish')).toBeUndefined();
  });

  it('a project decorator named login_required that refuses nothing is not a guard', () => {
    const files: Files = [
      ['web/guards.py', py('def login_required(f):', '    return f')],
      ['web/views.py', flask([ROUTE, '@login_required'])[0]![1].replace('from flask_login import current_user, login_required', 'from .guards import login_required')],
    ];
    expect(guardAt(files, '/<int:post_id>/publish')).toBeUndefined();
  });

  it('a custom decorator whose wrapper redirects or aborts on the caller is read, and a role test makes it admin', () => {
    const guards = py(
      'from functools import wraps',
      'from flask import abort, redirect, url_for',
      'from flask_login import current_user',
      'def admin_required(f):',
      '    @wraps(f)',
      '    def wrapper(*args, **kwargs):',
      '        if not current_user.is_admin:',
      '            return redirect(url_for("main.home"))',
      '        return f(*args, **kwargs)',
      '    return wrapper',
      'def member_required(f):',
      '    @wraps(f)',
      '    def wrapper(*args, **kwargs):',
      '        if not current_user.is_authenticated:',
      '            abort(401)',
      '        return f(*args, **kwargs)',
      '    return wrapper',
      'def noisy(f):',
      '    @wraps(f)',
      '    def wrapper(*args, **kwargs):',
      '        if not current_user.is_authenticated:',
      '            print("anonymous")',
      '        return f(*args, **kwargs)',
      '    return wrapper',
      'def secure_only(f):',
      '    @wraps(f)',
      '    def wrapper(*args, **kwargs):',
      '        if not request.is_secure:',
      '            return redirect(request.url.replace("http://", "https://"))',
      '        return f(*args, **kwargs)',
      '    return wrapper',
    );
    const view = (decorator: string): Files => [
      ['web/guards.py', guards],
      ['web/views.py', flask([ROUTE, decorator], undefined, 'from .guards import admin_required, member_required, noisy, secure_only')[0]![1]],
    ];
    expect(guardAt(view('@admin_required'), '/<int:post_id>/publish')).toBe('admin');
    expect(guardAt(view('@member_required'), '/<int:post_id>/publish')).toBe('auth');
    expect(guardAt(view('@noisy'), '/<int:post_id>/publish')).toBeUndefined();
    expect(guardAt(view('@secure_only'), '/<int:post_id>/publish')).toBeUndefined();
  });

  it('a project decorator that refuses only a signed-in caller (if current_user.is_authenticated: abort) is not a guard', () => {
    const guards = (check: string[]): string => py(
      'from functools import wraps',
      'from flask import abort',
      'from flask_login import current_user',
      'def member_required(f):',
      '    @wraps(f)',
      '    def wrapper(*args, **kwargs):',
      ...check,
      '        return f(*args, **kwargs)',
      '    return wrapper',
    );
    const view = (check: string[]): Files => [
      ['web/guards.py', guards(check)],
      ['web/views.py', flask([ROUTE, '@member_required'], undefined, 'from .guards import member_required')[0]![1]],
    ];
    const positive = ['        if current_user.is_authenticated:', '            if current_user.banned:', '                abort(403)'];
    const strict = ['        if not current_user.is_authenticated:', '            abort(401)', '        if current_user.banned:', '            abort(403)'];
    expect(guardAt(view(positive), '/<int:post_id>/publish')).toBeUndefined();
    expect(guardAt(view(strict), '/<int:post_id>/publish')).toBe('auth');
    const inBody = flask([ROUTE], ['    if "user_id" in session:', '        if session["user_id"] != post_id:', '            abort(403)', '    db.session.commit()']);
    expect(guardAt(inBody, '/<int:post_id>/publish')).toBeUndefined();
    const strictBody = flask([ROUTE], ['    if "user_id" not in session:', '        abort(401)', '    db.session.commit()']);
    expect(guardAt(strictBody, '/<int:post_id>/publish')).toBe('auth');
  });

  it('a current_user check in the handler counts only before the write', () => {
    const files = flask([ROUTE], [
      '    if not current_user.is_authenticated:',
      '        abort(403)',
      '    db.session.commit()',
    ]);
    expect(guardAt(files, '/<int:post_id>/publish')).toBe('auth');
    const context = memoryContext(files);
    const route = context.projectMap.apiRoutes[0]!;
    expect(pythonRouteGuard(context, route, 9)).toBeUndefined();
    expect(pythonRouteGuard(context, route, 12)?.level).toBe('auth');
    const missingRow = flask([ROUTE], ['    if post is None:', '        abort(403)', '    db.session.commit()']);
    expect(guardAt(missingRow, '/<int:post_id>/publish')).toBeUndefined();
  });

  it('a helper the handler calls with the caller is read the same way; one called without the caller is not', () => {
    const helpers: [string, string] = ['web/checks.py', py(
      'from flask import abort',
      'def require_author(user, post_id):',
      '    if user.id != post_id:',
      '        abort(403)',
      'def audit(post_id):',
      '    if post_id < 0:',
      '        abort(403)',
    )];
    const header = 'from .checks import audit, require_author';
    expect(guardAt([helpers, ...flask([ROUTE], ['    require_author(current_user, post_id)', '    db.session.commit()'], header)], '/<int:post_id>/publish')).toBe('auth');
    expect(guardAt([helpers, ...flask([ROUTE], ['    audit(post_id)', '    db.session.commit()'], header)], '/<int:post_id>/publish')).toBeUndefined();
    const onlySignedIn = ['    if current_user.is_authenticated:', '        require_author(current_user, post_id)', '    db.session.commit()'];
    expect(guardAt([helpers, ...flask([ROUTE], onlySignedIn, header)], '/<int:post_id>/publish')).toBeUndefined();
  });

  it('a check on a request field the caller sends is not a guard', () => {
    const files = flask([ROUTE], [
      '    if request.headers.get("X-Role") != "admin":',
      '        abort(403)',
      '    db.session.commit()',
    ]);
    expect(guardAt(files, '/<int:post_id>/publish')).toBeUndefined();
  });

  it('flask-httpauth\'s @auth.login_required counts when auth is an HTTPBasicAuth()', () => {
    const files: Files = [['web/views.py', py(
      'from flask import Flask',
      'from flask_httpauth import HTTPBasicAuth',
      'app = Flask(__name__)',
      'auth = HTTPBasicAuth()',
      '@app.route("/p", methods=["POST"])',
      '@auth.login_required',
      'def p():',
      '    pass',
    )]];
    expect(guardAt(files, '/p')).toBe('auth');
    const notHttpAuth = files[0]![1].replace('auth = HTTPBasicAuth()', 'auth = object()');
    expect(guardAt([['web/views.py', notHttpAuth]], '/p')).toBeUndefined();
  });
});

describe('Flask before_request gates', () => {
  const app = (gate: string[]): Files => [['srv/app.py', py(
    'from flask import Flask, jsonify, redirect, request, session, url_for',
    'app = Flask(__name__)',
    '',
    '@app.before_request',
    'def gate():',
    ...gate,
    '',
    '@app.route("/login", methods=["POST"])',
    'def login():',
    '    pass',
    '',
    '@app.route("/api/notes", methods=["POST"])',
    'def notes_create():',
    '    pass',
    '',
    '@app.route("/api/users/<int:uid>", methods=["DELETE"])',
    'def users_delete(uid):',
    '    pass',
    '',
    '@app.route("/api/owner/reset", methods=["POST"])',
    'def owner():',
    '    pass',
  )]];
  const DENY_BY_DEFAULT = [
    "    _PUBLIC = {'login', 'static', None}",
    "    _SIGNED_IN = {'notes_create'}",
    '    endpoint = request.endpoint',
    '    is_public = endpoint in _PUBLIC',
    '    if is_public:',
    '        return None',
    '    logged_in = session.get("logged_in")',
    '    if endpoint in _SIGNED_IN:',
    '        if not logged_in:',
    '            return jsonify({"error": "sign in"}), 401',
    '        return None',
    '    if not logged_in:',
    '        return jsonify({"error": "sign in"}), 401',
    "    if session.get('role') not in ('admin', 'owner'):",
    '        return jsonify({"error": "admins only"}), 403',
    '    return None',
  ];

  it('a deny-by-default gate: the public list is open, the signed-in list is auth, everything else admin', () => {
    const files = app(DENY_BY_DEFAULT);
    expect(guardAt(files, '/login')).toBeUndefined();
    expect(guardAt(files, '/api/notes')).toBe('auth');
    expect(guardAt(files, '/api/users/<int:uid>')).toBe('admin');
    expect(guardAt(files, '/api/owner/reset')).toBe('admin');
  });

  it('a role refusal with a JSON form for /api/ and an abort for the rest is admin', () => {
    const files = app(DENY_BY_DEFAULT.map((text) => text === '        return jsonify({"error": "admins only"}), 403'
      ? '        if request.path.startswith("/api/"):\n            return jsonify({"error": "admins only"}), 403\n        abort(403)'
      : text));
    expect(guardAt(files, '/api/users/<int:uid>')).toBe('admin');
  });

  it('an early allow the reader cannot place makes the whole gate unread', () => {
    const files = app([
      '    if request.path.startswith("/api/"):',
      '        return None',
      ...DENY_BY_DEFAULT,
    ]);
    expect(guardAt(files, '/api/notes')).toBeUndefined();
    expect(guardAt(files, '/api/users/<int:uid>')).toBeUndefined();
  });

  it('a gate that refuses only signed-in callers (if session.get("user") and ...) leaves an anonymous caller through', () => {
    const positive = app([
      '    if session.get("user") and session.get("banned"):',
      '        return jsonify({"error": "banned"}), 403',
    ]);
    expect(guardAt(positive, '/api/notes')).toBeUndefined();
    const listed = app([
      '    if request.endpoint in ("login", "static"):',
      '        return None',
      '    if not session.get("user") or session.get("banned"):',
      '        return jsonify({"error": "sign in"}), 401',
    ]);
    expect(guardAt(listed, '/api/notes')).toBe('auth');
    const tiered = app([
      "    if request.endpoint in ('notes_create',):",
      '        if session.get("user") and session.get("banned"):',
      '            return jsonify({"error": "banned"}), 403',
      '        return None',
      '    if not session.get("user"):',
      '        return jsonify({"error": "sign in"}), 401',
    ]);
    expect(guardAt(tiered, '/api/notes')).toBeUndefined();
    expect(guardAt(tiered, '/api/users/<int:uid>')).toBe('auth');
  });

  it('a gate that never refuses is no gate', () => {
    const files = app(['    session.permanent = True', '    return None']);
    expect(guardAt(files, '/api/users/<int:uid>')).toBeUndefined();
  });

  it('"endpoint not in X" on the refusal exempts X', () => {
    const files = app([
      "    if not session.get('user') and request.endpoint not in ('login', 'static'):",
      "        return redirect(url_for('login'))",
    ]);
    expect(guardAt(files, '/login')).toBeUndefined();
    expect(guardAt(files, '/api/notes')).toBe('auth');
  });

  it('a blueprint gate covers only that blueprint\'s routes in its file', () => {
    const files: Files = [
      ['srv/admin.py', py(
        'from flask import Blueprint, abort',
        'from flask_login import current_user',
        'bp = Blueprint("admin", __name__)',
        '@bp.before_request',
        'def only_admins():',
        '    if not current_user.is_admin:',
        '        abort(403)',
        '@bp.route("/wipe", methods=["POST"])',
        'def wipe():',
        '    pass',
      )],
      ['srv/public.py', py(
        'from flask import Blueprint',
        'bp = Blueprint("pub", __name__)',
        '@bp.route("/hello", methods=["POST"])',
        'def hello():',
        '    pass',
      )],
    ];
    expect(guardAt(files, '/wipe')).toBe('admin');
    expect(guardAt(files, '/hello')).toBeUndefined();
  });
});

describe('Django and DRF (read now; Django routes are registered in job 3)', () => {
  const at = (files: Files, path: string, needle: string): string | undefined => {
    const context = memoryContext(files);
    const content = files.find(([p]) => p === path)![1];
    const line = content.split('\n').findIndex((text) => text.includes(needle)) + 1;
    return djangoViewGuard(context, path, line)?.level;
  };

  it('@login_required from django.contrib.auth.decorators counts; a local one that refuses nothing does not', () => {
    const view = (imp: string): Files => [['crm/views.py', py(imp, '@login_required', 'def rename(request, pk):', '    page.save()')]];
    expect(at(view('from django.contrib.auth.decorators import login_required'), 'crm/views.py', 'page.save')).toBe('auth');
    expect(at([...view('from .util import login_required'), ['crm/util.py', py('def login_required(f):', '    return f')]], 'crm/views.py', 'page.save')).toBeUndefined();
    expect(at(view('from django.contrib.auth.decorators import permission_required'), 'crm/views.py', 'page.save')).toBeUndefined();
    expect(at([['crm/views.py', py('from django.contrib.auth.decorators import permission_required', '@permission_required("crm.change")', 'def rename(request, pk):', '    page.save()')]], 'crm/views.py', 'page.save')).toBe('admin');
  });

  it('LoginRequiredMixin from django.contrib.auth.mixins counts', () => {
    const files: Files = [['crm/views.py', py(
      'from django.contrib.auth.mixins import LoginRequiredMixin',
      'from django.views import View',
      'class Edit(LoginRequiredMixin, View):',
      '    def post(self, request):',
      '        page.save()',
    )]];
    expect(at(files, 'crm/views.py', 'page.save')).toBe('auth');
    expect(at([['crm/views.py', files[0]![1].replace('LoginRequiredMixin, View', 'View')]], 'crm/views.py', 'page.save')).toBeUndefined();
    const local = files[0]![1].replace('from django.contrib.auth.mixins import LoginRequiredMixin', 'class LoginRequiredMixin:\n    pass');
    expect(at([['crm/views.py', local]], 'crm/views.py', 'page.save')).toBeUndefined();
  });

  const settings = (classes: string): [string, string] => ['proj/settings.py', py(
    'REST_FRAMEWORK = {',
    `    "DEFAULT_PERMISSION_CLASSES": [${classes}],`,
    '}',
  )];
  const viewset = (attribute: string): [string, string] => ['crm/api.py', py(
    'from rest_framework import permissions, viewsets',
    'class ContactViewSet(viewsets.ModelViewSet):',
    attribute,
    '    def perform_create(self, serializer):',
    '        serializer.save()',
  )];

  it('DRF permission_classes beat the default; AllowAny overrides an IsAuthenticated default', () => {
    expect(at([settings('"rest_framework.permissions.IsAuthenticated"'), viewset('    queryset = None')], 'crm/api.py', 'serializer.save')).toBe('auth');
    expect(at([settings('"rest_framework.permissions.IsAuthenticated"'), viewset('    permission_classes = [permissions.AllowAny]')], 'crm/api.py', 'serializer.save')).toBeUndefined();
    expect(at([viewset('    queryset = None')], 'crm/api.py', 'serializer.save')).toBeUndefined();
    expect(at([viewset('    permission_classes = [permissions.IsAdminUser]')], 'crm/api.py', 'serializer.save')).toBe('admin');
  });

  it('DRF requires every listed class: AllowAny beside IsAuthenticated still needs sign-in', () => {
    expect(at([viewset('    permission_classes = [permissions.AllowAny, permissions.IsAuthenticated]')], 'crm/api.py', 'serializer.save')).toBe('auth');
    expect(at([viewset('    permission_classes = [permissions.AllowAny]')], 'crm/api.py', 'serializer.save')).toBeUndefined();
  });

  it('a project permission class counts only when has_permission can say no about request.user', () => {
    const perms = (ret: string): [string, string] => ['crm/permissions.py', py(
      'from rest_framework.permissions import BasePermission',
      'class IsManager(BasePermission):',
      '    def has_permission(self, request, view):',
      `        return ${ret}`,
    )];
    const view: [string, string] = ['crm/api.py', py(
      'from rest_framework import viewsets',
      'from .permissions import IsManager',
      'class TeamViewSet(viewsets.ModelViewSet):',
      '    permission_classes = [IsManager]',
      '    def perform_create(self, serializer):',
      '        serializer.save()',
    )];
    expect(at([perms('request.user.role == "manager"'), view], 'crm/api.py', 'serializer.save')).toBe('admin');
    expect(at([perms('True'), view], 'crm/api.py', 'serializer.save')).toBeUndefined();
  });
});

describe('the rules', () => {
  const run = (context: RuleContext) => apiMutationWithoutAuth.run(context);
  const routes = (guardSecond: boolean): Files => [
    ['app/db.py', DB],
    ['app/auth.py', REFUSING_USER],
    ['app/routes.py', py(
      'from fastapi import APIRouter, Depends',
      'from .auth import get_current_user',
      'from .db import get_db',
      'router = APIRouter()',
      '',
      '@router.delete("/a/{x}")',
      'def drop_a(x: int, user=Depends(get_current_user), db=Depends(get_db)):',
      '    db.delete(x)',
      '',
      '@router.delete("/b/{x}")',
      `def drop_b(x: int, ${guardSecond ? 'user=Depends(get_current_user), ' : ''}db=Depends(get_db)):`,
      '    db.delete(x)',
      '',
      'def purge(db):',
      '    db.delete(0)',
    )],
  ];

  it('api_mutation_without_auth reports the unguarded handler\'s write, and a helper\'s while a route is open', () => {
    const findings = run(memoryContext(routes(false)));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain('line 12');
    expect(findings[0]?.evidence).toContain('line 15');
    expect(findings[0]?.evidence).not.toContain('line 8');
  });

  it('api_mutation_without_auth is silent when every handler is guarded, helpers included', () => {
    expect(run(memoryContext(routes(true)))).toEqual([]);
  });

  it('public_admin_route_hint: a refusing admin decorator clears the route; a sign-in decorator alone says so', () => {
    const view = (decorator: string): Files => [
      ['web/guards.py', py(
        'from functools import wraps',
        'from flask import abort',
        'from flask_login import current_user',
        'def admin_required(f):',
        '    @wraps(f)',
        '    def wrapper(*a, **k):',
        '        if not current_user.is_admin:',
        '            abort(403)',
        '        return f(*a, **k)',
        '    return wrapper',
      )],
      ['web/views.py', py(
        'from flask import Blueprint',
        'from flask_login import login_required',
        'from .guards import admin_required',
        'bp = Blueprint("admin", __name__)',
        '@bp.route("/admin/users/<int:uid>/ban", methods=["POST"])',
        decorator,
        'def ban(uid):',
        '    pass',
      )],
    ];
    expect(publicAdminRouteHint.run(memoryContext(view('@admin_required')))).toEqual([]);
    const signedIn = publicAdminRouteHint.run(memoryContext(view('@login_required')));
    expect(signedIn).toHaveLength(1);
    expect(signedIn[0]?.evidence).toContain('authenticates the caller but has no visible admin role check');
    const open = publicAdminRouteHint.run(memoryContext(view('@staticmethod')));
    expect(open[0]?.evidence).toContain('has no visible admin role guard');
  });
});

describe('the reader', () => {
  it('maskPython blanks comments and string interiors and keeps every offset', () => {
    const source = 'x = "a(b" # c)\ny = """\n)\n"""\n';
    const masked = maskPython(source);
    expect(masked).toHaveLength(source.length);
    expect(masked.split('\n')).toHaveLength(source.split('\n').length);
    expect(masked).not.toMatch(/[()]/);
  });
});

void FLASK_MODELS;
