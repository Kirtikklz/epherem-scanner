import { describe, expect, it } from 'vitest';
import { missingRateLimit } from '../../src/rules/contextual/missingRateLimit.js';
import { memoryContext } from './helpers.js';

const PKG: [string, string] = ['package.json', '{"name":"x","dependencies":{"express":"4.19.0"}}'];
const run = (files: [string, string][]) => missingRateLimit.run(memoryContext([PKG, ...files]));

describe('missing_rate_limit (per-route attachment)', () => {
  it('CONFIRMED BYPASS: a limiter on /health does NOT protect /login (same file)', () => {
    const findings = run([
      ['routes/auth.js',
        'import rateLimit from "express-rate-limit";\n' +
          'const healthLimiter = rateLimit({ max: 100 });\n' +
          'export default function(app){\n' +
          '  app.get("/health", healthLimiter, (req,res)=>res.json({ok:true}));\n' +
          '  app.post("/login", (req,res)=>res.json({ok:true}));\n' +
          '}\n'],
    ]);
    expect(findings.map((f) => f.evidence.includes('/login'))).toContain(true);
  });
  it('a limiter in a DIFFERENT router/file does not protect /login', () => {
    const findings = run([
      ['routes/public.js', 'import rateLimit from "express-rate-limit";\nconst l = rateLimit({max:100});\nexport default function(app){ app.get("/public", l, (req,res)=>res.json({ok:true})); }\n'],
      ['routes/auth.js', 'export default function(app){ app.post("/login",(req,res)=>res.json({ok:true})); }\n'],
    ]);
    expect(findings.some((f) => f.filePath === 'routes/auth.js')).toBe(true);
  });
  it('a limiter attached directly to the login route is safe', () => {
    expect(
      run([['routes/auth.js', 'import rateLimit from "express-rate-limit";\nconst loginLimiter = rateLimit({max:5});\nexport default function(app){ app.post("/login", loginLimiter, (req,res)=>res.json({ok:true})); }\n']]),
    ).toHaveLength(0);
  });
  it('a router-level limiter (router.use) protects routes in that router', () => {
    expect(
      run([['routes/auth.js', 'import rateLimit from "express-rate-limit";\nconst limiter = rateLimit({max:5});\nexport default function(router){ router.use(limiter); router.post("/login",(req,res)=>res.json({ok:true})); }\n']]),
    ).toHaveLength(0);
  });
  it('no limiter anywhere flags the sensitive route', () => {
    expect(run([['routes/auth.js', 'export default function(app){ app.post("/login",(req,res)=>res.json({ok:true})); }\n']])).toHaveLength(1);
  });
});
