import { describe, expect, it } from 'vitest';
import { dangerousCorsWildcard } from '../../src/rules/basic/dangerousCorsWildcard.js';
import { envFileIncluded } from '../../src/rules/basic/envFileIncluded.js';
import { firebaseOpenRules } from '../../src/rules/basic/firebaseOpenRules.js';
import { hardcodedSecret } from '../../src/rules/basic/hardcodedSecret.js';
import { missingSecurityHeaders } from '../../src/rules/basic/missingSecurityHeaders.js';
import { publicAdminRouteHint } from '../../src/rules/basic/publicAdminRouteHint.js';
import { supabaseServiceRoleExposed } from '../../src/rules/basic/supabaseServiceRoleExposed.js';
import { loadFixtureContext, memoryContext } from './helpers.js';

describe('basic rules', () => {
  it('env_file_included flags committed .env but not .env.example', async () => {
    const insecure = await loadFixtureContext('next-supabase-insecure');
    const findings = envFileIncluded.run(insecure);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.filePath).toBe('.env');
    expect(findings[0]?.severity).toBe('high');

    const clean = await loadFixtureContext('clean-basic-project');
    expect(envFileIncluded.run(clean)).toHaveLength(0);
  });

  it('hardcoded_secret flags the fake Stripe key with redacted evidence', async () => {
    const context = await loadFixtureContext('express-cors-insecure');
    const findings = hardcodedSecret.run(context);
    const stripe = findings.find((finding) => finding.title.includes('Stripe'));
    expect(stripe).toBeDefined();
    expect(stripe?.severity).toBe('critical');
    expect(stripe?.filePath).toBe('server.js');
    expect(stripe?.evidence).toContain('[redacted]');
    expect(stripe?.evidence).not.toContain('FAKEFIXTUREKEY000000000000');
  });

  it('hardcoded_secret stays quiet on the clean project', async () => {
    const context = await loadFixtureContext('clean-basic-project');
    expect(hardcodedSecret.run(context)).toHaveLength(0);
  });

  it('supabase_service_role_exposed flags the client component', async () => {
    const context = await loadFixtureContext('next-supabase-insecure');
    const findings = supabaseServiceRoleExposed.run(context);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]?.filePath).toBe('components/ProfileCard.tsx');
    expect(findings[0]?.severity).toBe('critical');
  });

  it('firebase_open_rules flags allow-all rules', async () => {
    const context = await loadFixtureContext('firebase-open-rules');
    const findings = firebaseOpenRules.run(context);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.filePath).toBe('firestore.rules');
    expect(findings[0]?.severity).toBe('critical');
    expect(findings[0]?.lineStart).toBe(5);
  });

  it('dangerous_cors_wildcard reports a literal wildcard + credentials at low, and says why', async () => {
    const context = await loadFixtureContext('express-cors-insecure');
    const findings = dangerousCorsWildcard.run(context);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]?.severity).toBe('low');
    expect(findings[0]?.confidence).toBe('low');
    expect(findings[0]?.title).toBe('CORS allows all origins');
    expect(findings[0]?.userExplanation).toContain('Credentials are switched on, but browsers refuse');
  });

  it('dangerous_cors_wildcard still fires on a cookie-authenticated project, at low', () => {
    const context = memoryContext([
      ['package.json', '{"name":"app"}'],
      ['server/session.js', "app.use(session({ secret: process.env.S, name: 'connect.sid' }));\n"],
      ['server/api.js', "res.setHeader('Access-Control-Allow-Origin', '*');\n"],
    ]);
    const findings = dangerousCorsWildcard.run(context);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('low');
    expect(findings[0]?.userExplanation).toContain('Your project signs users in with cookies, but browsers refuse');
  });

  it('dangerous_cors_wildcard downgrades a wildcard with no credentials in play', () => {
    const context = memoryContext([
      ['package.json', '{"name":"app"}'],
      ['src/routes/api/public/waitlist.ts',
        "const CORS = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type' };\n" +
        'export const POST = async (request) => new Response("{}", { headers: CORS });\n'],
    ]);
    const findings = dangerousCorsWildcard.run(context);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('low');
    expect(findings[0]?.confidence).toBe('low');
  });

  it('dangerous_cors_wildcard keeps a reflected origin at low when no credentials are in play', () => {
    const context = memoryContext([
      ['package.json', '{"name":"app"}'],
      ['server/app.js', 'app.use(cors({ origin: true }));\n'],
    ]);
    const findings = dangerousCorsWildcard.run(context);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('low');
    expect(findings[0]?.confidence).toBe('low');
  });

  it('dangerous_cors_wildcard recognises Supabase edge-function corsHeaders', () => {
    const context = memoryContext([
      ['package.json', '{"name":"app"}'],
      ['supabase/config.toml', 'project_id = "abc"\n'],
      ['supabase/functions/geocode/index.ts',
        "const corsHeaders = {\n  'Access-Control-Allow-Origin': '*',\n" +
        "  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',\n};\n"],
    ]);
    const findings = dangerousCorsWildcard.run(context);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('low');
    expect(findings[0]?.technicalExplanation).toContain('Supabase edge-function');
    expect(findings[0]?.technicalExplanation).toContain('verify_jwt');
  });

  it('missing_security_headers fires on express fixture, not on clean project', async () => {
    const express = await loadFixtureContext('express-cors-insecure');
    expect(missingSecurityHeaders.run(express)).toHaveLength(1);

    const clean = await loadFixtureContext('clean-basic-project');
    expect(missingSecurityHeaders.run(clean)).toHaveLength(0);
  });

  describe('per-feature security headers and x-powered-by', () => {
    const EXPRESS_PKG: [string, string] = ['package.json', '{"dependencies":{"express":"^4.18.0","helmet":"^7.0.0"}}'];
    const app = (body: string): [string, string] => [
      'server.js',
      'const express = require("express");\nconst helmet = require("helmet");\nconst app = express();\n' + body,
    ];

    it('MUST FIRE: helmet with contentSecurityPolicy turned off and no CSP anywhere else', () => {
      const f = missingSecurityHeaders.run(
        memoryContext([EXPRESS_PKG, app('app.use(helmet({ contentSecurityPolicy: false }));\napp.disable("x-powered-by");\n')]),
      );
      expect(f).toHaveLength(1);
      expect(f[0]?.title).toContain('Content-Security-Policy');
      expect(f[0]?.userExplanation).not.toContain('does not appear to set security headers');
    });

    it('MUST FIRE: helmet with hsts turned off', () => {
      const f = missingSecurityHeaders.run(
        memoryContext([EXPRESS_PKG, app('app.use(helmet({ hsts: false }));\napp.disable("x-powered-by");\n')]),
      );
      expect(f).toHaveLength(1);
      expect(f[0]?.title).toContain('Strict-Transport-Security');
    });

    it('MUST FIRE: an Express app that never disables x-powered-by', () => {
      const f = missingSecurityHeaders.run(
        memoryContext([EXPRESS_PKG, app('app.use(function (req, res, next) { res.setHeader("X-Frame-Options", "DENY"); next(); });\n')]),
      );
      expect(f).toHaveLength(1);
      expect(f[0]?.title).toContain('X-Powered-By');
      expect(f[0]?.severity).toBe('low');
    });

    it('MUST STAY SILENT: CSP turned off in helmet because the app sets its own', () => {
      const f = missingSecurityHeaders.run(
        memoryContext([
          EXPRESS_PKG,
          app(
            'app.use(helmet({ contentSecurityPolicy: false }));\napp.disable("x-powered-by");\n' +
              'app.use((req, res, next) => { res.setHeader("Content-Security-Policy", "default-src \'self\'"); next(); });\n',
          ),
        ]),
      );
      expect(f).toHaveLength(0);
    });

    it('MUST STAY SILENT: helmet fully on, x-powered-by covered by helmet itself', () => {
      const f = missingSecurityHeaders.run(memoryContext([EXPRESS_PKG, app('app.use(helmet());\n')]));
      expect(f).toHaveLength(0);
    });

    it('MUST STAY SILENT: a helmet call written in a comment turns nothing off', () => {
      const f = missingSecurityHeaders.run(
        memoryContext([
          EXPRESS_PKG,
          app('app.use(helmet());\n// app.use(helmet({ contentSecurityPolicy: false }));\n'),
        ]),
      );
      expect(f).toHaveLength(0);
    });

    it('THE PROJECT-WIDE FINDING IS UNTOUCHED, AND NEVER DOUBLED UP', () => {
      const f = missingSecurityHeaders.run(
        memoryContext([
          ['package.json', '{"dependencies":{"express":"^4.18.0"}}'],
          ['server.js', 'const express = require("express");\nconst app = express();\napp.get("/", (req, res) => res.send("hi"));\n'],
        ]),
      );
      expect(f).toHaveLength(1);
      expect(f[0]?.title).toBe('No security headers configured');
    });
  });

  it('public_admin_route_hint flags the unauthenticated admin route', async () => {
    const context = await loadFixtureContext('next-supabase-insecure');
    const findings = publicAdminRouteHint.run(context);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.filePath).toContain('app/api/admin');
    expect(findings[0]?.severity).toBe('high');
  });
});

describe('public_admin_route_hint route precision', () => {
  it('does not flag an admin route protected by direct admin middleware', () => {
    const context = memoryContext([['package.json', '{"dependencies":{"express":"^4.0.0"}}'], ['server.js',
      'function require_admin(req,res,next){ if(req.user.role !== \"admin\") return res.status(403).end(); next(); }\n' +
      'router.post("/search-users", get_current_user, require_admin, async (req, res) => { res.json([]); });\n']]);
    expect(publicAdminRouteHint.run(context)).toHaveLength(0);
  });

  it('evaluates admin routes individually instead of suppressing the whole file', () => {
    const context = memoryContext([['package.json', '{"dependencies":{"express":"^4.0.0"}}'], ['server.js',
      'function require_admin(req,res,next){ if(req.user.role !== \"admin\") return res.status(403).end(); next(); }\n' +
      'router.post("/admin/search-users", get_current_user, require_admin, async (req, res) => { res.json([]); });\n' +
      'router.post("/admin/delete-user", async (req, res) => { res.json({ ok: true }); });\n']]);
    const findings = publicAdminRouteHint.run(context);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain('/admin/delete-user');
  });
});