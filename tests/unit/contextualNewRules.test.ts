import { describe, expect, it } from 'vitest';
import { missingWebhookVerification } from '../../src/rules/contextual/missingWebhookVerification.js';
import { brokenAccessControl } from '../../src/rules/contextual/brokenAccessControl.js';
import { missingRateLimit } from '../../src/rules/contextual/missingRateLimit.js';
import { csrfProtection } from '../../src/rules/contextual/csrfProtection.js';
import { memoryContext } from './helpers.js';

const PKG_NEXT: [string, string] = ['package.json', '{"name":"x","dependencies":{"next":"14.0.0"}}'];
const PKG_EXPRESS: [string, string] = ['package.json', '{"name":"x","dependencies":{"express":"4.19.0"}}'];

describe('missing_webhook_verification', () => {
  it('flags a Stripe webhook route with no signature check (unsafe)', () => {
    const ctx = memoryContext([PKG_NEXT, ['app/api/webhook/stripe/route.ts',
      'export async function POST(req: Request){ const event = await req.json(); if(event.type==="checkout.session.completed"){} return Response.json({ received: true }); }\n']]);
    const f = missingWebhookVerification.run(ctx);
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe('high');
  });
  it('does not flag a verified webhook (safe)', () => {
    const ctx = memoryContext([PKG_NEXT, ['app/api/webhook/stripe/route.ts',
      'import Stripe from "stripe";\nconst stripe = new Stripe(process.env.SK);\n' +
      'export async function POST(req: Request){ const sig = req.headers.get("stripe-signature"); const event = stripe.webhooks.constructEvent(await req.text(), sig, process.env.WHSEC); return Response.json({ received: true }); }\n']]);
    expect(missingWebhookVerification.run(ctx)).toHaveLength(0);
  });
});

describe('broken_access_control', () => {
  it('flags record fetched by request id without ownership (unsafe)', () => {
    const ctx = memoryContext([PKG_NEXT, ['pages/api/orders.ts',
      'import { prisma } from "../../lib/db";\n' +
      'export default async function handler(req, res){ const order = await prisma.order.findUnique({ where: { id: req.query.id } }); res.json(order); }\n']]);
    const f = brokenAccessControl.run(ctx);
    expect(f).toHaveLength(1);
    expect(f[0]?.category).toBe('authorization');
  });
  it('does not flag when scoped to the user (safe)', () => {
    const ctx = memoryContext([PKG_NEXT, ['pages/api/orders.ts',
      'import { prisma } from "../../lib/db";\n' +
      'export default async function handler(req, res){ const order = await prisma.order.findFirst({ where: { id: req.query.id, userId: req.session.userId } }); res.json(order); }\n']]);
    expect(brokenAccessControl.run(ctx)).toHaveLength(0);
  });
});

describe('missing_rate_limit', () => {
  it('flags a login route when no rate limiting exists (unsafe)', () => {
    const ctx = memoryContext([PKG_EXPRESS, ['routes/auth.js',
      'export default function(app){ app.post("/api/login", (req,res)=>{ res.json({ ok: true }); }); }\n']]);
    const f = missingRateLimit.run(ctx);
    expect(f).toHaveLength(1);
    expect(f[0]?.category).toBe('rate_limiting');
  });
  it('does not flag when a rate limiter is present (safe)', () => {
    const ctx = memoryContext([PKG_EXPRESS, ['routes/auth.js',
      'import rateLimit from "express-rate-limit";\n' +
      'const limiter = rateLimit({ windowMs: 60000, max: 5 });\n' +
      'export default function(app){ app.post("/api/login", limiter, (req,res)=>{ res.json({ ok: true }); }); }\n']]);
    expect(missingRateLimit.run(ctx)).toHaveLength(0);
  });
});

describe('missing_csrf_protection', () => {
  it('flags a cookie-session app with state-changing routes and no CSRF (unsafe)', () => {
    const ctx = memoryContext([PKG_EXPRESS, ['server.js',
      'import session from "express-session";\n' +
      'export default function(app){ app.use(session({ secret: process.env.S })); app.post("/api/transfer", (req,res)=>{ res.json({ ok: true }); }); }\n']]);
    const f = csrfProtection.run(ctx);
    expect(f).toHaveLength(1);
    expect(f[0]?.category).toBe('csrf');
  });
  it('does not flag when CSRF protection exists (safe)', () => {
    const ctx = memoryContext([PKG_EXPRESS, ['server.js',
      'import session from "express-session";\nimport csrf from "csurf";\n' +
      'export default function(app){ app.use(session({ secret: process.env.S })); app.use(csrf()); app.post("/api/transfer", (req,res)=>{ res.json({ ok: true }); }); }\n']]);
    expect(csrfProtection.run(ctx)).toHaveLength(0);
  });
  it('does not flag a token-based API with no cookies (safe)', () => {
    const ctx = memoryContext([PKG_EXPRESS, ['server.js',
      'export default function(app){ app.post("/api/transfer", (req,res)=>{ res.json({ ok: true }); }); }\n']]);
    expect(csrfProtection.run(ctx)).toHaveLength(0);
  });

  describe('per-route CSRF on a cookie-session app', () => {
    const SESSION =
      'const express = require("express");\n' +
      'const session = require("express-session");\n' +
      'const csrfProtection = require("csurf")({ cookie: true });\n' +
      'const app = express();\n' +
      'app.use(session({ secret: process.env.S }));\n';

    it('MUST FIRE: csrf on one route, none on the sibling that changes data', () => {
      const ctx = memoryContext([
        PKG_EXPRESS,
        ['server.js', SESSION +
          'app.post("/admin/settings", csrfProtection, (req, res) => res.json({ ok: true }));\n' +
          'app.post("/api/transfer", (req, res) => res.json({ ok: true }));\n'],
      ]);
      const f = csrfProtection.run(ctx);
      expect(f).toHaveLength(1);
      expect(f[0]?.evidence).toContain('/api/transfer');
      expect(f[0]?.evidence).toContain('not here');
    });

    it('MUST FIRE: csrf on a mounted router, none on a route outside it', () => {
      const ctx = memoryContext([
        PKG_EXPRESS,
        ['server.js', SESSION +
          'const adminRoutes = require("./routes/admin");\n' +
          'app.use("/admin", csrfProtection, adminRoutes);\n' +
          'app.post("/api/transfer", (req, res) => res.json({ ok: true }));\n'],
        ['routes/admin.js',
          'const router = require("express").Router();\n' +
          'router.post("/settings", (req, res) => res.json({ ok: true }));\n' +
          'module.exports = router;\n'],
      ]);
      const f = csrfProtection.run(ctx);
      expect(f).toHaveLength(1);
      expect(f[0]?.evidence).toContain('/api/transfer');
    });

    it('MUST STAY SILENT: the csrf middleware is mounted UPSTREAM of the route (C1/C2 consistency)', () => {
      const ctx = memoryContext([
        PKG_EXPRESS,
        ['server.js', SESSION +
          'const adminRoutes = require("./routes/admin");\n' +
          'const apiRoutes = require("./routes/api");\n' +
          'app.use("/admin", csrfProtection, adminRoutes);\n' +
          'app.use("/api", csrfProtection, apiRoutes);\n'],
        ['routes/admin.js',
          'const router = require("express").Router();\n' +
          'router.post("/settings", (req, res) => res.json({ ok: true }));\n' +
          'module.exports = router;\n'],
        ['routes/api.js',
          'const router = require("express").Router();\n' +
          'router.post("/transfer", (req, res) => res.json({ ok: true }));\n' +
          'module.exports = router;\n'],
      ]);
      expect(csrfProtection.run(ctx)).toHaveLength(0);
    });

    it('MUST STAY SILENT: a pathless app.use(csurf()) covers every route', () => {
      const ctx = memoryContext([
        PKG_EXPRESS,
        ['server.js', SESSION +
          'app.use(csrfProtection);\n' +
          'app.post("/admin/settings", csrfProtection, (req, res) => res.json({ ok: true }));\n' +
          'app.post("/api/transfer", (req, res) => res.json({ ok: true }));\n'],
      ]);
      expect(csrfProtection.run(ctx)).toHaveLength(0);
    });

    it('MUST STAY SILENT: SameSite on the session cookie is a browser-enforced project-wide defence', () => {
      const ctx = memoryContext([
        PKG_EXPRESS,
        ['server.js',
          'const express = require("express");\n' +
          'const session = require("express-session");\n' +
          'const csrfProtection = require("csurf")();\n' +
          'const app = express();\n' +
          'app.use(session({ secret: process.env.S, cookie: { sameSite: "lax", secure: true } }));\n' +
          'app.post("/admin/settings", csrfProtection, (req, res) => res.json({ ok: true }));\n' +
          'app.post("/api/transfer", (req, res) => res.json({ ok: true }));\n'],
      ]);
      expect(csrfProtection.run(ctx)).toHaveLength(0);
    });

    it('MUST STAY SILENT: csrf evidence this scan cannot place on any route', () => {
      const ctx = memoryContext([
        PKG_EXPRESS,
        ['server.js',
          'const express = require("express");\n' +
          'const session = require("express-session");\n' +
          'const app = express();\n' +
          'app.use(session({ secret: process.env.S }));\n' +
          'app.post("/api/transfer", (req, res) => res.json({ ok: true }));\n'],
        ['views/form.html',
          '<form method="post" action="/api/transfer">\n' +
          '<input type="hidden" name="_csrf" value="{{csrfToken}}" />\n' +
          '</form>\n'],
      ]);
      expect(csrfProtection.run(ctx)).toHaveLength(0);
    });

    it('THE ORIGINAL PATH IS UNCHANGED: no csrf anywhere still reports the first route', () => {
      const ctx = memoryContext([
        PKG_EXPRESS,
        ['server.js',
          'const express = require("express");\n' +
          'const session = require("express-session");\n' +
          'const app = express();\n' +
          'app.use(session({ secret: process.env.S }));\n' +
          'app.post("/api/transfer", (req, res) => res.json({ ok: true }));\n'],
      ]);
      const f = csrfProtection.run(ctx);
      expect(f).toHaveLength(1);
      expect(f[0]?.evidence).toContain('no CSRF token or SameSite defence found');
    });
  });
});
