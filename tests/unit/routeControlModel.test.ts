import { describe, expect, it } from 'vitest';
import { apiMutationWithoutAuth } from '../../src/rules/contextual/apiMutationWithoutAuth.js';
import { missingRequestBodyValidation } from '../../src/rules/contextual/missingRequestBodyValidation.js';
import { missingRateLimit } from '../../src/rules/contextual/missingRateLimit.js';
import { publicAdminRouteHint } from '../../src/rules/basic/publicAdminRouteHint.js';
import { classifyMiddlewareBody } from '../../src/shared/middlewareGuard.js';
import { routeControlsAt } from '../../src/shared/routeControlModel.js';
import { memoryContext } from './helpers.js';

const EXPRESS = ['package.json', '{"dependencies":{"express":"4.18.0"}}'] as [string, string];
const EXPRESS_VALIDATOR = [
  'package.json',
  '{"dependencies":{"express":"4.18.0","express-validator":"7.0.0"}}',
] as [string, string];

const AUTH_MIDDLEWARE =
  "import jwt from 'jsonwebtoken';\n" +
  'export const authenticateToken = async (req, res, next) => {\n' +
  "  const authHeader = req.headers['authorization'];\n" +
  "  const token = authHeader && authHeader.split(' ')[1];\n" +
  '  if (!token) {\n' +
  "    return res.status(401).json({ message: 'token required' });\n" +
  '  }\n' +
  '  req.user = jwt.verify(token, process.env.JWT_SECRET);\n' +
  '  next();\n' +
  '};\n';

const ITEM_ROUTES =
  "const express = require('express');\n" +
  'const router = express.Router();\n' +
  "router.post('/', async (req, res) => {\n" +
  '  await prisma.item.create({ data: { name: req.body.name } });\n' +
  '  res.json({ ok: true });\n' +
  '});\n' +
  'module.exports = router;\n';

describe('C2 routing tree: a guard applied at the mount is a guard on the route', () => {
  it('is SILENT on a mutation whose router is mounted with a rejecting auth middleware', () => {
    const context = memoryContext([
      EXPRESS,
      ['server/middleware/auth.js', AUTH_MIDDLEWARE],
      ['server/routes/items.js', ITEM_ROUTES],
      ['server/index.js',
        "const express = require('express');\n" +
        "const itemRoutes = require('./routes/items');\n" +
        "const { authenticateToken } = require('./middleware/auth');\n" +
        'const app = express();\n' +
        "app.use('/api/items', authenticateToken, itemRoutes);\n"],
    ]);
    expect(apiMutationWithoutAuth.run(context)).toHaveLength(0);
    expect(routeControlsAt(context, 'server/routes/items.js', 4)?.auth.state).toBe('proven');
  });

  it('STILL FIRES when the mounted middleware cannot be resolved at all', () => {
    const context = memoryContext([
      EXPRESS,
      ['server/routes/items.js', ITEM_ROUTES],
      ['server/index.js',
        "const express = require('express');\n" +
        "const itemRoutes = require('./routes/items');\n" +
        "const someGuard = require('a-package-not-in-this-project');\n" +
        'const app = express();\n' +
        "app.use('/api/items', someGuard, itemRoutes);\n"],
    ]);
    expect(apiMutationWithoutAuth.run(context).length).toBeGreaterThanOrEqual(1);
    expect(routeControlsAt(context, 'server/routes/items.js', 4)?.auth.state).toBe('unresolved');
  });

  it('STILL FIRES on an unguarded route whose SIBLING in the same file is guarded', () => {
    const context = memoryContext([
      EXPRESS,
      ['server/middleware/auth.js', AUTH_MIDDLEWARE],
      ['server/index.js',
        "const express = require('express');\n" +
        "const { authenticateToken } = require('./middleware/auth');\n" +
        'const app = express();\n' +
        "app.post('/api/save-token', authenticateToken, async (req, res) => {\n" +
        '  await prisma.token.create({ data: { value: req.body.value } });\n' +
        '  res.json({ ok: true });\n' +
        '});\n' +
        "app.post('/api/cookie-auth', async (req, res) => {\n" +
        '  await prisma.session.create({ data: { cookie: req.body.cookie } });\n' +
        '  res.json({ ok: true });\n' +
        '});\n'],
    ]);
    expect(routeControlsAt(context, 'server/index.js', 5)?.auth.state).toBe('proven');
    expect(routeControlsAt(context, 'server/index.js', 9)?.auth.state).toBe('absent');
    const findings = apiMutationWithoutAuth.run(context);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.every((finding) => finding.lineStart >= 8)).toBe(true);
  });
});

describe('C2 routing tree: a guard is what a middleware DOES', () => {
  it('credits a middleware that rejects on a missing session and resumes dispatch', () => {
    const effects = classifyMiddlewareBody(
      '  const session = await auth.api.getSession({ headers: req.headers });\n' +
      '  if (!session) {\n' +
      "    res.status(401).json({ error: 'Authentication required' });\n" +
      '    return;\n' +
      '  }\n' +
      '  req.user = session.user;\n' +
      '  next();\n',
    );
    expect(effects.auth).toBe(true);
  });

  it('refuses an optionalAuth that reads the same session and blocks nobody', () => {
    const effects = classifyMiddlewareBody(
      '  const session = await auth.api.getSession({ headers: req.headers });\n' +
      '  if (session) {\n' +
      '    req.user = session.user;\n' +
      '  }\n' +
      '  next();\n',
    );
    expect(effects.auth).toBe(false);
  });

  it('refuses a ban filter that rejects only when an identity IS present', () => {
    const effects = classifyMiddlewareBody(
      '  if (req.user && req.user.isBanned) {\n' +
      "    return res.status(403).json({ error: 'account suspended' });\n" +
      '  }\n' +
      '  next();\n',
    );
    expect(effects.auth).toBe(false);
  });

  it('refuses a middleware that reads an identity and only logs about it', () => {
    const effects = classifyMiddlewareBody(
      '  if (!req.user) {\n' +
      "    console.warn('[audit] anonymous request', req.path);\n" +
      '  }\n' +
      '  next();\n',
    );
    expect(effects.auth).toBe(false);
  });

  it('refuses a terminal handler that rejects but never calls next()', () => {
    const effects = classifyMiddlewareBody(
      '  if (!req.user) {\n' +
      "    return res.status(401).json({ error: 'no' });\n" +
      '  }\n' +
      '  return res.json({ me: req.user });\n',
    );
    expect(effects.auth).toBe(false);
  });

  it('credits a role guard built by a local factory and calls it admin, not auth-only', () => {
    const effects = classifyMiddlewareBody(
      '  return (req, res, next) => {\n' +
      "    if (!req.user) return res.status(401).json({ message: 'auth required' });\n" +
      "    if (!roles.includes(req.user.role)) return res.status(403).json({ message: 'forbidden' });\n" +
      '    next();\n' +
      '  };\n',
    );
    expect(effects.auth).toBe(true);
    expect(effects.admin).toBe(true);
  });
});

describe('C2 routing tree: the express-validator chain', () => {
  const CHAIN_ROUTES = (checksResult: boolean): string =>
    "const express = require('express');\n" +
    "const { body, validationResult } = require('express-validator');\n" +
    'const router = express.Router();\n' +
    "router.post('/', [body('email').isEmail(), body('password').isLength({ min: 8 })], async (req, res) => {\n" +
    (checksResult
      ? '  const errors = validationResult(req);\n' +
        '  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });\n'
      : '') +
    '  const { email, password } = req.body;\n' +
    '  await pool.execute("INSERT INTO users (email, password) VALUES (?, ?)", [email, password]);\n' +
    '  res.json({ ok: true });\n' +
    '});\n' +
    'module.exports = router;\n';

  it('is SILENT when the chain is route middleware and the handler rejects on validationResult', () => {
    const context = memoryContext([EXPRESS_VALIDATOR, ['server/routes/users.js', CHAIN_ROUTES(true)]]);
    expect(routeControlsAt(context, 'server/routes/users.js', 4)?.validation.state).toBe('proven');
    expect(missingRequestBodyValidation.run(context)).toHaveLength(0);
  });

  it('STILL FIRES when the chain is applied and the handler never reads validationResult', () => {
    const context = memoryContext([EXPRESS_VALIDATOR, ['server/routes/users.js', CHAIN_ROUTES(false)]]);
    expect(routeControlsAt(context, 'server/routes/users.js', 4)?.validation.state).not.toBe('proven');
    expect(missingRequestBodyValidation.run(context).length).toBeGreaterThanOrEqual(1);
  });
});

describe('C2 routing tree: the other three controls', () => {
  it('credits a rate limiter applied on the router that carries the route', () => {
    const context = memoryContext([
      ['package.json', '{"dependencies":{"express":"4.18.0","express-rate-limit":"7.0.0"}}'],
      ['server/middleware/limiter.js',
        "import rateLimit from 'express-rate-limit';\n" +
        'export const loginLimiter = (req, res, next) => {\n' +
        '  const hits = rateLimit({ windowMs: 900000, max: 5 });\n' +
        "  if (hits > 5) return res.status(429).json({ message: 'too many' });\n" +
        '  next();\n' +
        '};\n'],
      ['server/routes/auth.js',
        "const express = require('express');\n" +
        "const { loginLimiter } = require('../middleware/limiter');\n" +
        'const router = express.Router();\n' +
        'router.use(loginLimiter);\n' +
        "router.post('/login', async (req, res) => {\n" +
        '  res.json(await login(req.body));\n' +
        '});\n'],
    ]);
    expect(routeControlsAt(context, 'server/routes/auth.js', 5)?.rateLimit.state).toBe('proven');
    expect(missingRateLimit.run(context)).toHaveLength(0);
  });

  it('credits an admin role guard applied at the mount of an admin router', () => {
    const context = memoryContext([
      EXPRESS,
      ['server/middleware/roles.js',
        'export const requireAdmin = (req, res, next) => {\n' +
        "  if (!req.user) return res.status(401).json({ message: 'auth required' });\n" +
        "  if (req.user.role !== 'admin') return res.status(403).json({ message: 'forbidden' });\n" +
        '  next();\n' +
        '};\n'],
      ['server/routes/admin.js',
        "const express = require('express');\n" +
        'const router = express.Router();\n' +
        "router.get('/admin/users', async (req, res) => {\n" +
        '  res.json(await listUsers());\n' +
        '});\n' +
        'module.exports = router;\n'],
      ['server/index.js',
        "const express = require('express');\n" +
        "const adminRoutes = require('./routes/admin');\n" +
        "const { requireAdmin } = require('./middleware/roles');\n" +
        'const app = express();\n' +
        "app.use('/api', requireAdmin, adminRoutes);\n"],
    ]);
    expect(routeControlsAt(context, 'server/routes/admin.js', 3)?.admin.state).toBe('proven');
    expect(publicAdminRouteHint.run(context)).toHaveLength(0);
  });

  it('refuses an admin-named mount middleware whose body checks no role', () => {
    const context = memoryContext([
      EXPRESS,
      ['server/middleware/roles.js',
        'export const requireAdmin = (req, res, next) => {\n' +
        "  console.log('[admin] request', req.path);\n" +
        '  next();\n' +
        '};\n'],
      ['server/routes/admin.js',
        "const express = require('express');\n" +
        'const router = express.Router();\n' +
        "router.get('/admin/users', async (req, res) => {\n" +
        '  res.json(await listUsers());\n' +
        '});\n' +
        'module.exports = router;\n'],
      ['server/index.js',
        "const express = require('express');\n" +
        "const adminRoutes = require('./routes/admin');\n" +
        "const { requireAdmin } = require('./middleware/roles');\n" +
        'const app = express();\n' +
        "app.use('/api', requireAdmin, adminRoutes);\n"],
    ]);
    expect(routeControlsAt(context, 'server/routes/admin.js', 3)?.admin.state).not.toBe('proven');
    expect(publicAdminRouteHint.run(context).length).toBeGreaterThanOrEqual(1);
  });
});
