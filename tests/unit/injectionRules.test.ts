import { describe, expect, it } from 'vitest';
import { commandInjection } from '../../src/rules/basic/commandInjection.js';
import { pathTraversal } from '../../src/rules/basic/pathTraversal.js';
import { sqlInjection } from '../../src/rules/basic/sqlInjection.js';
import { serverSideRequestForgery } from '../../src/rules/basic/ssrf.js';
import { openRedirect } from '../../src/rules/basic/openRedirect.js';
import { crossSiteScripting } from '../../src/rules/basic/xss.js';
import { unsafeDynamicCode } from '../../src/rules/basic/unsafeDynamicCode.js';
import { memoryContext } from './helpers.js';

const PKG: [string, string] = ['package.json', '{"name":"x"}'];

describe('sql_injection', () => {
  it('flags interpolated SQL built from user input (unsafe)', () => {
    const ctx = memoryContext([PKG, ['server/db.js',
      'export function find(req, db) {\n' +
      '  return db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);\n}\n']]);
    const f = sqlInjection.run(ctx);
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe('critical');
  });
  it('does not flag parameterised queries (safe)', () => {
    const ctx = memoryContext([PKG, ['server/db.js',
      'export function find(req, db) {\n' +
      '  return db.query("SELECT * FROM users WHERE id = $1", [req.query.id]);\n}\n']]);
    expect(sqlInjection.run(ctx)).toHaveLength(0);
  });
  it('does not flag static SQL without user input (safe)', () => {
    const ctx = memoryContext([PKG, ['server/db.js',
      'export function all(db) { return db.query(`SELECT * FROM users`); }\n']]);
    expect(sqlInjection.run(ctx)).toHaveLength(0);
  });
});

describe('AST sanitizer trust', () => {
  it('does not trust a helper merely because its name contains validate', () => {
    const ctx = memoryContext([PKG, ['server/db.js',
      'function validateButReturnRaw(value){ return value; }\n' +
      'export function h(req){ return db.query(`SELECT * FROM users WHERE id=${validateButReturnRaw(req.query.id)}`); }\n',
    ]]);
    expect(sqlInjection.run(ctx)).toHaveLength(1);
  });

  it('does not treat schema parsing as SQL escaping', () => {
    const ctx = memoryContext([PKG, ['server/db.js',
      'export function h(req){ return db.query(`SELECT * FROM users WHERE id=${idSchema.parse(req.query.id)}`); }\n',
    ]]);
    expect(sqlInjection.run(ctx)).toHaveLength(1);
  });
});

describe('command_injection', () => {
  it('flags exec built from request input (unsafe)', () => {
    const ctx = memoryContext([PKG, ['server/run.js',
      'import { exec } from "child_process";\n' +
      'export function h(req){ exec("convert " + req.body.name); }\n']]);
    const f = commandInjection.run(ctx);
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe('critical');
  });
  it('flags python subprocess with shell=True (unsafe)', () => {
    const ctx = memoryContext([PKG, ['app/run.py',
      'import subprocess\n' +
      'def h(name):\n    subprocess.run("ls " + name, shell=True)\n']]);
    expect(commandInjection.run(ctx).length).toBeGreaterThan(0);
  });
  it('does not flag a static command (safe)', () => {
    const ctx = memoryContext([PKG, ['server/run.js',
      'import { execFile } from "child_process";\n' +
      'export function h(){ execFile("ls", ["-la"]); }\n']]);
    expect(commandInjection.run(ctx)).toHaveLength(0);
  });
});

describe('path_traversal', () => {
  it('flags fs read from user input without confinement (unsafe)', () => {
    const ctx = memoryContext([PKG, ['server/files.js',
      'import fs from "fs";\n' +
      'export function h(req,res){ const data = fs.readFileSync("./uploads/" + req.query.name); res.end(data); }\n']]);
    const f = pathTraversal.run(ctx);
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe('high');
  });
  it('does not flag when basename confines the path (safe)', () => {
    const ctx = memoryContext([PKG, ['server/files.js',
      'import fs from "fs";\nimport path from "path";\n' +
      'export function h(req,res){ const name = path.basename(req.query.name); res.end(fs.readFileSync("./uploads/" + name)); }\n']]);
    expect(pathTraversal.run(ctx)).toHaveLength(0);
  });
});

describe('ssrf', () => {
  it('flags server fetch of a user URL without allowlist (unsafe)', () => {
    const ctx = memoryContext([PKG, ['app/api/proxy/route.ts',
      'export async function POST(req: Request){ const { url } = await req.json(); return fetch(url); }\n']]);
    const f = serverSideRequestForgery.run(ctx);
    expect(f).toHaveLength(1);
    expect(f[0]?.category).toBe('ssrf');
  });
  it('does not flag when an allowlist is used (safe)', () => {
    const ctx = memoryContext([PKG, ['app/api/proxy/route.ts',
      'const allowedHosts = ["api.example.com"];\n' +
      'export async function POST(req: Request){ const { url } = await req.json(); const u = new URL(url); if(!allowedHosts.includes(u.hostname)) throw new Error("no"); return fetch(url); }\n']]);
    expect(serverSideRequestForgery.run(ctx)).toHaveLength(0);
  });

  describe('HTTP client vocabulary', () => {
    const proxy = (call: string): [string, string] => [
      'app/api/proxy/route.ts',
      `export async function POST(req: Request){ const { url } = await req.json(); return ${call}; }\n`,
    ];

    for (const [client, call] of [
      ['needle', 'needle("get", url)'],
      ['node-fetch under an alias', 'nodeFetch(url)'],
      ['undici', 'undici.request(url)'],
      ['got, method-qualified', 'got.get(url)'],
      ['superagent', 'superagent.get(url)'],
      ['ky', 'ky(url)'],
    ] as const) {
      it(`MUST FIRE: a user-controlled URL passed to ${client}`, () => {
        const f = serverSideRequestForgery.run(memoryContext([PKG, proxy(call)]));
        expect(f.length).toBeGreaterThan(0);
        expect(f[0]?.category).toBe('ssrf');
      });
    }

    it('MUST STAY SILENT: a fixed host literal, on a new client', () => {
      const ctx = memoryContext([PKG, ['app/api/sync/route.ts',
        'export async function POST(req: Request){ const { id } = await req.json(); return needle("get", `https://api.stripe.com/v1/charges/${id}`); }\n']]);
      expect(serverSideRequestForgery.run(ctx)).toHaveLength(0);
    });

    it('MUST STAY SILENT: a deploy-time config head, on a new client', () => {
      const ctx = memoryContext([PKG, ['app/api/sync/route.ts',
        'export async function POST(req: Request){ return undici.request(`${process.env.NEXT_PUBLIC_APP_URL}/api/inner`); }\n']]);
      expect(serverSideRequestForgery.run(ctx)).toHaveLength(0);
    });

    it('MUST STAY SILENT: a pagination cursor from an upstream response, on a new client', () => {
      const ctx = memoryContext([PKG, ['lib/pager.ts',
        'export async function pageAll(token: string){\n' +
        '  let url = "https://graph.microsoft.com/v1.0/users";\n' +
        '  while (url) {\n' +
        '    const res = await got.get(url);\n' +
        '    const json = await res.json();\n' +
        '    url = json["@odata.nextLink"];\n' +
        '  }\n' +
        '}\n']]);
      expect(serverSideRequestForgery.run(ctx)).toHaveLength(0);
    });

    it('MUST STAY SILENT: a data-layer loader that merely has a client’s name', () => {
      const ctx = memoryContext([PKG, ['app/api/docs/route.ts',
        'export async function POST(req: Request){ const { slug } = await req.json(); return documents.fetch(slug); }\n']]);
      expect(serverSideRequestForgery.run(ctx)).toHaveLength(0);
    });
  });
});

describe('open_redirect', () => {
  it('flags redirect to a user-controlled destination (unsafe)', () => {
    const ctx = memoryContext([PKG, ['server/auth.js',
      'export function h(req,res){ res.redirect(req.query.next); }\n']]);
    expect(openRedirect.run(ctx)).toHaveLength(1);
  });
  it('does not flag a robustly validated relative redirect (safe)', () => {
    const ctx = memoryContext([PKG, ['server/auth.js',
      'export function h(req,res){ const next = req.query.next; if(!next.startsWith("/") || next.startsWith("//")) return res.redirect("/"); res.redirect(next); }\n']]);
    expect(openRedirect.run(ctx)).toHaveLength(0);
  });
});

describe('xss', () => {
  it('flags dangerouslySetInnerHTML with user data (unsafe)', () => {
    const ctx = memoryContext([PKG, ['components/Comment.tsx',
      "'use client';\nexport default function C(props){ return <div dangerouslySetInnerHTML={{ __html: props.comment }} />; }\n"]]);
    const f = crossSiteScripting.run(ctx);
    expect(f.length).toBeGreaterThan(0);
    expect(f[0]?.category).toBe('xss');
  });
  it('does not flag sanitised HTML (safe)', () => {
    const ctx = memoryContext([PKG, ['components/Comment.tsx',
      "'use client';\nimport DOMPurify from 'dompurify';\nexport default function C(props){ return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(props.comment) }} />; }\n"]]);
    expect(crossSiteScripting.run(ctx)).toHaveLength(0);
  });
  it('does not flag a constant string (safe)', () => {
    const ctx = memoryContext([PKG, ['components/Static.tsx',
      "export default function S(){ return <div dangerouslySetInnerHTML={{ __html: '<b>hi</b>' }} />; }\n"]]);
    expect(crossSiteScripting.run(ctx)).toHaveLength(0);
  });
});

describe('xss: the layout slot is not a value', () => {
  const SHELL = (slot: string): string =>
    `<!DOCTYPE html>\n<html>\n<head><title>t</title></head>\n<body>\n  <div id="layout">\n    ${slot}\n  </div>\n</body>\n</html>\n`;

  it('suppresses the EJS layout slot', () => {
    const ctx = memoryContext([PKG, ['views/layout.ejs', SHELL('<%- body %>')]]);
    expect(crossSiteScripting.run(ctx)).toHaveLength(0);
  });

  it('suppresses the Handlebars spelling of the same mechanism', () => {
    const ctx = memoryContext([PKG, ['views/layout.hbs', SHELL('{{{body}}}')]]);
    expect(crossSiteScripting.run(ctx)).toHaveLength(0);
  });

  it('a partial is not a layout: bare body without <html> still fires', () => {
    const ctx = memoryContext([PKG, ['views/post.ejs',
      '<article>\n  <h1><%= post.title %></h1>\n  <%- body %>\n</article>\n']]);
    expect(crossSiteScripting.run(ctx).length).toBeGreaterThan(0);
  });

  it('post.body is an ordinary value, even inside a full page', () => {
    const ctx = memoryContext([PKG, ['views/show.ejs', SHELL('<%- post.body %>')]]);
    expect(crossSiteScripting.run(ctx).length).toBeGreaterThan(0);
  });

  it('other raw output in the SAME layout still fires', () => {
    const ctx = memoryContext([PKG, ['views/layout.ejs',
      SHELL('<%- body %>\n    <%- userHtml %>')]]);
    const findings = crossSiteScripting.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain('userHtml');
  });
});

describe('priority precision regressions', () => {
  it('does not flag real timer function callbacks as dynamic code', () => {
    const ctx = memoryContext([PKG, ['server/timer.js',
      'export function wait(ms){ return new Promise((resolve) => setTimeout(resolve, ms)); }\n' +
      'setInterval(refresh, 5000);\nfunction refresh(){}\n']]);
    expect(unsafeDynamicCode.run(ctx)).toHaveLength(0);
  });

  it('flags string timers and tainted eval with different severity', () => {
    const timer = memoryContext([PKG, ['server/timer.js',
      'setTimeout("runUserCode()", 100);\n']]);
    expect(unsafeDynamicCode.run(timer)).toHaveLength(1);

    const taintedEval = memoryContext([PKG, ['server/eval.js',
      'export function h(req){ eval(req.query.code); }\n']]);
    const findings = unsafeDynamicCode.run(taintedEval);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('critical');
  });

  it('does not classify template logging as SQL injection', () => {
    const ctx = memoryContext([PKG, ['server/mail.js',
      'const RESEND_FROM_EMAIL = process.env.RESEND_FROM_EMAIL;\nconsole.log(`From: ${RESEND_FROM_EMAIL}`);\n']]);
    expect(sqlInjection.run(ctx)).toHaveLength(0);
  });

  it('does not treat generic cloud object download as OS path traversal', () => {
    const ctx = memoryContext([PKG, ['server/storage.js',
      'export async function h(req, supabase){ const filename = req.query.name; return supabase.storage.from("clips").download(filename); }\n']]);
    expect(pathTraversal.run(ctx)).toHaveLength(0);
  });
});
describe('deep precision regressions', () => {
  it('flags SQL constructed on an earlier line and passed by identifier', () => {
    const ctx = memoryContext([PKG, ['server/db.js',
      'export function h(req, db){\n' +
      '  const sql = `SELECT * FROM users WHERE id = ${req.query.id}`;\n' +
      '  return db.query(sql);\n}\n']]);
    const findings = sqlInjection.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.lineStart).toBe(2);
  });

  it('keeps GraphQL and search query calls out of SQL injection', () => {
    const ctx = memoryContext([PKG, ['server/search.js',
      'export function h(req, client){\n' +
      '  console.log(`From: ${req.query.email}`);\n' +
      '  gql.query(`query User { user(id: ${req.query.id}) { id } }`);\n' +
      '  search.query(req.query.q);\n' +
      '}\n']]);
    expect(sqlInjection.run(ctx)).toHaveLength(0);
  });

  it('flags Prisma unsafe raw SQL but not tagged parameterized raw SQL', () => {
    const unsafe = memoryContext([PKG, ['server/prisma.js',
      'export function h(req, prisma){ return prisma.$queryRawUnsafe(`SELECT * FROM User WHERE id = ${req.query.id}`); }\n']]);
    expect(sqlInjection.run(unsafe)).toHaveLength(1);

    const safe = memoryContext([PKG, ['server/prisma.js',
      'export function h(req, prisma){ return prisma.$queryRaw`SELECT * FROM User WHERE id = ${req.query.id}`; }\n']]);
    expect(sqlInjection.run(safe)).toHaveLength(0);
  });

  it('requires strong SSRF controls, not just new URL()', () => {
    const ctx = memoryContext([PKG, ['app/api/proxy/route.ts',
      'export async function POST(req){ const { url } = await req.json(); const u = new URL(url); return fetch(u); }\n']]);
    expect(serverSideRequestForgery.run(ctx)).toHaveLength(1);
  });

  it('suppresses fixed trusted SSRF destinations with user path only', () => {
    const ctx = memoryContext([PKG, ['app/api/proxy/route.ts',
      'const API_BASE = "https://api.example.com";\n' +
      'export async function POST(req){ const { id } = await req.json(); return fetch(`${API_BASE}/users/${encodeURIComponent(id)}`); }\n']]);
    expect(serverSideRequestForgery.run(ctx)).toHaveLength(0);
  });

  it('treats JSON-LD serialization as safe but configurable HTML as unsafe', () => {
    const jsonLd = memoryContext([PKG, ['components/Seo.tsx',
      'export default function S(){ const schema = { name: "Acme" }; return <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(schema) }} />; }\n']]);
    expect(crossSiteScripting.run(jsonLd)).toHaveLength(0);

    const configurable = memoryContext([PKG, ['components/Banner.tsx',
      'export default function B({ settings }){ return <div dangerouslySetInnerHTML={{ __html: settings.banner_text }} />; }\n']]);
    expect(crossSiteScripting.run(configurable).length).toBeGreaterThan(0);
  });

  it('does not trust fake sanitize helpers for XSS', () => {
    const ctx = memoryContext([PKG, ['components/Comment.tsx',
      'function sanitizeHtml(x){ return x; }\n' +
      'export default function C(props){ return <div dangerouslySetInnerHTML={{ __html: sanitizeHtml(props.comment) }} />; }\n']]);
    expect(crossSiteScripting.run(ctx).length).toBeGreaterThan(0);
  });
});
