import { describe, expect, it } from 'vitest';
import { weakJwtHandling } from '../../src/rules/basic/weakJwtHandling.js';
import { insecureCookies } from '../../src/rules/basic/insecureCookies.js';
import { unsafeFileUpload } from '../../src/rules/basic/unsafeFileUpload.js';
import { sensitiveDataInLogs } from '../../src/rules/basic/sensitiveDataInLogs.js';
import { debugModeEnabled } from '../../src/rules/basic/debugModeEnabled.js';
import { memoryContext } from './helpers.js';

const PKG: [string, string] = ['package.json', '{"name":"x"}'];

describe('weak_jwt_handling', () => {
  it('flags jwt.decode without verify, none-alg, and ignoreExpiration (unsafe)', () => {
    const ctx = memoryContext([PKG, ['server/auth.js',
      'import jwt from "jsonwebtoken";\n' +
      'export function a(t){ const u = jwt.decode(t); return u; }\n' +
      'export function b(t){ return jwt.verify(t, k, { algorithms: ["none"] }); }\n' +
      'export function c(t){ return jwt.verify(t, k, { ignoreExpiration: true }); }\n']]);
    const ids = weakJwtHandling.run(ctx).map((f) => f.title);
    expect(ids.some((t) => /without verifying/.test(t))).toBe(true);
    expect(ids.some((t) => /none/.test(t))).toBe(true);
    expect(ids.some((t) => /expiration/.test(t))).toBe(true);
  });
  it('does not flag a jwt library exercising its own API in its own test suite', () => {
    const ctx = memoryContext([
      ['package.json', '{"name":"jsonwebtoken","main":"index.js"}'],
      ['index.js', "module.exports = { decode: require('./decode'), verify: require('./verify'), sign: require('./sign') };\n"],
      ['test/decoding.tests.js',
        'const jwt = require("../index");\n' +
        'it("decodes without verifying", function(){ jwt.decode(token); });\n' +
        'it("rejects none", function(){ jwt.verify(t, "secret", { algorithms: ["none"] }); });\n' +
        'it("honours ignoreExpiration", function(){ jwt.verify(t, "secret", { ignoreExpiration: true }); });\n'],
    ]);
    expect(weakJwtHandling.run(ctx)).toHaveLength(0);
  });

  it('still flags the same constructs in an application that merely uses jwt', () => {
    const ctx = memoryContext([
      ['package.json', '{"name":"jwt-dashboard","main":"index.js","dependencies":{"jsonwebtoken":"^9"}}'],
      ['index.js', "const express = require('express'); module.exports = express();\n"],
      ['test/decoding.tests.js',
        'const jwt = require("jsonwebtoken");\n' +
        'it("decodes without verifying", function(){ jwt.decode(token); });\n'],
    ]);
    expect(weakJwtHandling.run(ctx).length).toBeGreaterThan(0);
  });

  it('does not flag a decode that the same function has already verified', () => {
    const ctx = memoryContext([PKG, ['server/auth.js',
      'import jwt from "jsonwebtoken";\n' +
      'export function readClaims(t){\n' +
      '  jwt.verify(t, process.env.SECRET, { algorithms: ["HS256"] });\n' +
      '  const claims = jwt.decode(t);\n' +
      '  return claims;\n' +
      '}\n']]);
    expect(weakJwtHandling.run(ctx).filter((f) => /without verifying/.test(f.title))).toHaveLength(0);
  });

  it('still flags a decode-only helper in a file that verifies elsewhere', () => {
    const ctx = memoryContext([PKG, ['server/auth.js',
      'import jwt from "jsonwebtoken";\n' +
      'export function checked(t){ return jwt.verify(t, process.env.SECRET); }\n' +
      'export function claimsOf(t){\n' +
      '  const claims = jwt.decode(t);\n' +
      '  return claims.sub;\n' +
      '}\n']]);
    expect(weakJwtHandling.run(ctx).filter((f) => /without verifying/.test(f.title))).toHaveLength(1);
  });

  it('does not flag a proper verify (safe)', () => {
    const ctx = memoryContext([PKG, ['server/auth.js',
      'import jwt from "jsonwebtoken";\n' +
      'export function v(t){ return jwt.verify(t, process.env.SECRET, { algorithms: ["HS256"] }); }\n']]);
    expect(weakJwtHandling.run(ctx)).toHaveLength(0);
  });
});

describe('insecure_cookies', () => {
  it('flags a session cookie missing flags (unsafe)', () => {
    const ctx = memoryContext([PKG, ['server/session.js',
      'export function h(res, token){ res.cookie("session", token, { path: "/" }); }\n']]);
    const f = insecureCookies.run(ctx);
    expect(f).toHaveLength(1);
    expect(f[0]?.evidence).toContain('HttpOnly');
  });
  it('does not flag a fully protected cookie (safe)', () => {
    const ctx = memoryContext([PKG, ['server/session.js',
      'export function h(res, token){ res.cookie("session", token, { httpOnly: true, secure: true, sameSite: "lax" }); }\n']]);
    expect(insecureCookies.run(ctx)).toHaveLength(0);
  });

  describe('session middleware cookie configuration', () => {
    const session = (body: string): [string, string] => [
      'server/app.js',
      'import session from "express-session";\n' +
        'import express from "express";\n' +
        'const app = express();\n' +
        `app.use(session(${body}));\n`,
    ];

    it('MUST FIRE: secure: false on the session cookie', () => {
      const f = insecureCookies.run(memoryContext([PKG, session('{ secret: "s", cookie: { secure: false } }')]));
      expect(f).toHaveLength(1);
      expect(f[0]?.evidence).toContain('Secure');
      expect(f[0]?.severity).toBe('medium');
    });

    it('MUST FIRE: httpOnly turned OFF is a defect even though absence is not', () => {
      const f = insecureCookies.run(
        memoryContext([PKG, session('{ secret: "s", cookie: { secure: true, httpOnly: false } }')]),
      );
      expect(f).toHaveLength(1);
      expect(f[0]?.evidence).toContain('HttpOnly');
      expect(f[0]?.severity).toBe('high');
    });

    it("MUST FIRE: sameSite: 'none' without Secure, and the evidence says which", () => {
      const f = insecureCookies.run(
        memoryContext([PKG, session('{ secret: "s", cookie: { sameSite: "none" } }')]),
      );
      expect(f).toHaveLength(1);
      expect(f[0]?.evidence).toContain('SameSite=None');
    });

    it('MUST FIRE: a cookie-session app with no cookie options at all', () => {
      const ctx = memoryContext([
        PKG,
        [
          'server/app.js',
          'import cookieSession from "cookie-session";\n' +
            'const app = require("express")();\n' +
            'app.use(cookieSession({ name: "session", keys: ["k1", "k2"], maxAge: 86400000 }));\n',
        ],
      ]);
      const f = insecureCookies.run(ctx);
      expect(f).toHaveLength(1);
      expect(f[0]?.evidence).toContain('Secure');
    });

    it('MUST STAY SILENT: a correctly configured session cookie', () => {
      const f = insecureCookies.run(
        memoryContext([PKG, session("{ secret: 's', cookie: { httpOnly: true, secure: true, sameSite: 'lax' } }")]),
      );
      expect(f).toHaveLength(0);
    });

    it('MUST STAY SILENT: secure gated on NODE_ENV, which is the correct idiom', () => {
      const f = insecureCookies.run(
        memoryContext([
          PKG,
          session('{ secret: "s", cookie: { secure: process.env.NODE_ENV === "production", sameSite: "lax" } }'),
        ]),
      );
      expect(f).toHaveLength(0);
    });

    it("MUST STAY SILENT: the deferred `sess.cookie.secure = true` the Express docs recommend", () => {
      const ctx = memoryContext([
        PKG,
        [
          'server/app.js',
          'import session from "express-session";\n' +
            'const app = require("express")();\n' +
            'const sess = { secret: "s", resave: false, cookie: { httpOnly: true } };\n' +
            'if (app.get("env") === "production") { sess.cookie.secure = true; }\n' +
            'app.use(session(sess));\n' +
            'app.use(session({ secret: "s2", resave: false, cookie: { httpOnly: true } }));\n',
        ],
      ]);
      expect(insecureCookies.run(ctx)).toHaveLength(0);
    });

    it('MUST STAY SILENT: options built elsewhere - nothing here can settle the question', () => {
      const ctx = memoryContext([
        PKG,
        [
          'server/app.js',
          'import session from "express-session";\n' +
            'const app = require("express")();\n' +
            'app.use(session(sessionOptions));\n',
        ],
      ]);
      expect(insecureCookies.run(ctx)).toHaveLength(0);
    });

    it('MUST STAY SILENT: a project function that merely happens to be called session()', () => {
      const ctx = memoryContext([
        PKG,
        [
          'server/app.js',
          'import { session } from "./db.js";\n' +
            'export const load = () => session({ include: { user: true }, orderBy: { createdAt: "desc" } });\n',
        ],
      ]);
      expect(insecureCookies.run(ctx)).toHaveLength(0);
    });

    it('MUST STAY SILENT: a session config written in a comment', () => {
      const ctx = memoryContext([
        PKG,
        [
          'server/app.js',
          'import session from "express-session";\n' +
            '// app.use(session({ secret: "s", cookie: { secure: false } }));\n',
        ],
      ]);
      expect(insecureCookies.run(ctx)).toHaveLength(0);
    });
  });
});

describe('unsafe_file_upload', () => {
  it('flags multer with no filter or limits (unsafe)', () => {
    const ctx = memoryContext([PKG, ['server/upload.js',
      'import multer from "multer";\nconst upload = multer({ dest: "uploads/" });\nexport default upload;\n']]);
    const f = unsafeFileUpload.run(ctx);
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe('high');
  });
  it('does not flag multer with fileFilter and limits (safe)', () => {
    const ctx = memoryContext([PKG, ['server/upload.js',
      'import multer from "multer";\n' +
      'const upload = multer({ dest: "uploads/", limits: { fileSize: 1000000 }, fileFilter: (req,file,cb)=>cb(null, file.mimetype==="image/png") });\n' +
      'export default upload;\n']]);
    expect(unsafeFileUpload.run(ctx)).toHaveLength(0);
  });
});

describe('sensitive_data_in_logs', () => {
  it('flags logging a password (unsafe)', () => {
    const ctx = memoryContext([PKG, ['server/login.js',
      'export function h(req){ console.log("login", req.body.password); }\n']]);
    expect(sensitiveDataInLogs.run(ctx)).toHaveLength(1);
  });
  it('does not flag benign logging (safe)', () => {
    const ctx = memoryContext([PKG, ['server/login.js',
      'export function h(userId){ console.log("login for", userId); }\n']]);
    expect(sensitiveDataInLogs.run(ctx)).toHaveLength(0);
  });
});

describe('debug_mode_enabled', () => {
  it('flags Flask debug=True (unsafe)', () => {
    const ctx = memoryContext([PKG, ['app/main.py',
      'from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)\n']]);
    const f = debugModeEnabled.run(ctx);
    expect(f.length).toBeGreaterThan(0);
    expect(f[0]?.severity).toBe('high');
  });
  it('does not flag production config (safe)', () => {
    const ctx = memoryContext([PKG, ['app/main.py',
      'import os\nfrom flask import Flask\napp = Flask(__name__)\napp.run(debug=os.environ.get("DEBUG")=="1")\n']]);
    expect(debugModeEnabled.run(ctx)).toHaveLength(0);
  });
});

describe('sensitive_data_in_logs precision regressions', () => {
  it('does not flag static security wording or boolean presence checks', () => {
    const ctx = memoryContext([PKG, ['server/logs.js',
      'console.log("Webhook secret not configured");\n' +
      'console.log("No authentication token available");\n' +
      'console.log("Has webhook secret:", !!secret);\n' +
      'console.error("Password reset error:", err.message);\n']]);
    expect(sensitiveDataInLogs.run(ctx)).toHaveLength(0);
  });

  it('grades actual sensitive values and whole request objects', () => {
    const ctx = memoryContext([PKG, ['server/logs.js',
      'console.log(accessToken);\n' +
      'logger.info({ password });\n' +
      'console.log(req.headers.authorization);\n' +
      'console.log(req.body);\n']]);
    const findings = sensitiveDataInLogs.run(ctx);
    expect(findings.length).toBeGreaterThanOrEqual(4);
    expect(findings.some((finding) => finding.severity === 'high')).toBe(true);
    expect(findings.some((finding) => finding.severity === 'medium')).toBe(true);
  });
});
describe('sensitive_data_in_logs AST-like argument precision', () => {
  it('flags template strings that interpolate sensitive values', () => {
    const ctx = memoryContext([PKG, ['server/logs.js',
      'console.log(`token=${accessToken}`);\n' +
      'console.log(`auth=${req.headers.authorization}`);\n']]);
    expect(sensitiveDataInLogs.run(ctx)).toHaveLength(2);
  });

  it('does not flag logger setup, static names, or null checks', () => {
    const ctx = memoryContext([PKG, ['app/logs.py',
      'import logging\n' +
      'logger = logging.getLogger(__name__)\n' +
      'print("token variable not available")\n' +
      'console.log("has token", token != null)\n']]);
    expect(sensitiveDataInLogs.run(ctx)).toHaveLength(0);
  });
});
