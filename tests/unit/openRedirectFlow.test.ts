import { describe, expect, it } from 'vitest';
import { openRedirect } from '../../src/rules/basic/openRedirect.js';
import { memoryContext } from './helpers.js';

const P: [string, string] = ['package.json', '{"name":"x"}'];
const run = (file: string, code: string) => openRedirect.run(memoryContext([P, [file, code]]));

describe('open_redirect (data-flow)', () => {
  it('CONFIRMED BYPASS: variable from request into redirect is flagged', () => {
    expect(run('server/a.js', 'const next = req.query.next;\nres.redirect(next);\n')).toHaveLength(1);
  });
  it('direct request redirect is flagged', () => {
    expect(run('server/b.js', 'res.redirect(req.query.url);\n')).toHaveLength(1);
  });
  it('startsWith("/") ALONE is not safe (//evil.com passes it)', () => {
    expect(
      run('server/c.js', 'const n = req.query.next;\nif (!n.startsWith("/")) return res.redirect("/");\nres.redirect(n);\n'),
    ).toHaveLength(1);
  });
  it('a guard that also rejects "//" is safe', () => {
    expect(
      run('server/d.js', 'const n = req.query.next;\nif (!n.startsWith("/") || n.startsWith("//")) return res.redirect("/");\nres.redirect(n);\n'),
    ).toHaveLength(0);
  });
  it('a fixed literal path is safe', () => {
    expect(run('server/e.js', 'res.redirect("/dashboard");\n')).toHaveLength(0);
  });
  it('new URL("/literal", base) is safe', () => {
    expect(
      run('m.ts', "import { NextResponse } from 'next/server';\nexport function middleware(r){ return NextResponse.redirect(new URL('/login', r.url)); }\n"),
    ).toHaveLength(0);
  });

  it('a template with a fixed single-slash head is safe', () => {
    expect(run('server/f.js', 'res.redirect(`/t/${req.params.teamUrl}/documents`);\n')).toHaveLength(0);
  });

  it('a URL built on a process.env base is safe', () => {
    expect(
      run('app/api/x/route.ts',
        'const baseUrl = process.env.BASE_URL;\n' +
        'const target = req.query.courseId ? `${baseUrl}/cursos/${req.query.courseId}` : `${baseUrl}/`;\n' +
        'return NextResponse.redirect(target);\n'),
    ).toHaveLength(0);
  });

  it('a helper whose every return has a fixed prefix is safe', () => {
    expect(
      run('server/g.js',
        'function loginRedirect(client){ return `/?method=passkey&client=${client}`; }\n' +
        'router.get("/x", (ctx) => { ctx.redirect(loginRedirect(ctx.query.client)); });\n'),
    ).toHaveLength(0);
  });

  it('a protocol-relative head is NOT a fixed prefix', () => {
    expect(run('server/h.js', 'res.redirect(`//${req.query.host}/login`);\n')).toHaveLength(1);
  });

  it('a ternary with one unfixed arm is NOT a fixed prefix', () => {
    expect(
      run('server/i.js', 'const target = req.query.safe ? `/home/${req.query.id}` : req.query.next;\nres.redirect(target);\n'),
    ).toHaveLength(1);
  });

  it('a helper that returns its own argument is NOT a fixed prefix', () => {
    expect(
      run('server/j.js',
        'function passthrough(dest){ return dest; }\n' +
        'app.get("/go", (req, res) => { res.redirect(passthrough(req.query.next)); });\n'),
    ).toHaveLength(1);
  });

  it('a config base the request can extend is NOT a fixed prefix', () => {
    expect(
      run('server/k.js',
        'const base = process.env.BASE_URL;\n' +
        'app.get("/go", (req, res) => { res.redirect(`${base}${req.query.host}`); });\n'),
    ).toHaveLength(1);
  });
});
