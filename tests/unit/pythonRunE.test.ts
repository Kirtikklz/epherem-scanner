import { describe, expect, it } from 'vitest';
import { openRedirect } from '../../src/rules/basic/openRedirect.js';
import { memoryContext } from './helpers.js';

const FILE = 'server.js';

function lines(...body: string[]): number[] {
  const content = [
    "const express = require('express');",
    'const app = express();',
    ...body,
    '',
  ].join('\n');
  return openRedirect.run(memoryContext([[FILE, content]])).filter((f) => f.filePath === FILE).map((f) => f.lineStart).sort((a, b) => a - b);
}

const route = (...body: string[]): number[] => lines("app.get('/go', (req, res) => {", ...body.map((l) => `  ${l}`), '});');

describe('job E: a bare "/" head reports', () => {
  it('"/" + a request value and its template twin', () => {
    expect(route('res.redirect("/" + req.query.next);')).toEqual([4]);
    expect(route('res.redirect(`/${req.query.next}`);')).toEqual([4]);
  });
  it('with a 3xx status as the first argument', () => {
    expect(route('res.redirect(302, "/" + req.query.next);')).toEqual([4]);
  });
  it('through a local bound to the concatenation or the template', () => {
    expect(route('const target = "/" + req.query.next;', 'res.redirect(target);')).toEqual([5]);
    expect(route('const target = `/${req.body.path}`;', 'res.redirect(target);')).toEqual([5]);
  });
  it('when one arm of a ternary is "/" plus the request value', () => {
    expect(route('res.redirect(req.query.ok ? "/" : "/" + req.query.next);')).toEqual([4]);
  });
  it('through a helper that returns "/" plus its argument', () => {
    expect(lines('function toPath(p) { return "/" + p; }', "app.get('/go', (req, res) => {", '  res.redirect(toPath(req.query.next));', '});')).toEqual([5]);
  });
  it('a newline after the slash is stripped by the browser, so it fixes nothing', () => {
    expect(route('res.redirect(`/\n${req.query.next}`);')).toEqual([4]);
  });
  it('encodeURI leaves "/" and "\\" alone, so it is not a sanitiser for a redirect', () => {
    expect(route('res.redirect("/" + encodeURI(req.query.next));')).toEqual([4]);
    expect(route('res.redirect(encodeURI(req.query.next));')).toEqual([4]);
  });
});

describe('job E: a local that can be the root "/" is not a prefix', () => {
  it('home + a request value reports', () => {
    expect(route('const home = "/";', 'res.redirect(home + req.query.next);')).toEqual([5]);
  });
  it('${root}/${host} reports: the program wrote the second slash, the request the host', () => {
    expect(route('const root = "/";', 'res.redirect(`${root}/${req.query.host}`);')).toEqual([5]);
  });
});

describe('job E: strict twins stay silent', () => {
  it('a fixed first segment: "/items/" + id and `/items/${id}`', () => {
    expect(route('res.redirect("/items/" + req.query.id);')).toEqual([]);
    expect(route('res.redirect(`/items/${req.query.id}`);')).toEqual([]);
  });
  it('a fixed query mark: "/?q=" + q', () => {
    expect(route('res.redirect("/?q=" + req.query.q);')).toEqual([]);
  });
  it('the root itself, whole: "/", `/`, a ternary of literals, a local, a helper', () => {
    expect(route('res.redirect("/");')).toEqual([]);
    expect(route('res.redirect(`/`);')).toEqual([]);
    expect(route('res.redirect(req.query.ok ? "/" : "/login");')).toEqual([]);
    expect(route('const home = "/";', 'res.redirect(home);')).toEqual([]);
    expect(lines('function home() { return "/"; }', "app.get('/go', (req, res) => {", '  res.redirect(home());', '});')).toEqual([]);
  });
  it('a helper in another module that returns the whole root on one path: the root is the site, not a prefix', () => {
    const files: [string, string][] = [
      ['paths.js', ['export function landing(tab) {', "  if (tab === 'team') return '/team';", "  return '/';", '}', ''].join('\n')],
      ['server.js', ["import express from 'express';", "import { landing } from './paths.js';", 'const app = express();', "app.get('/go', (req, res) => {", '  res.redirect(landing(req.query.tab));', '});', ''].join('\n')],
    ];
    expect(openRedirect.run(memoryContext(files))).toEqual([]);
  });
  it('a local path with a fixed first segment, and fixed origins', () => {
    expect(route('const base = "/app";', 'res.redirect(base + "/" + req.query.id);')).toEqual([]);
    expect(route('res.redirect(`${process.env.APP_URL}/${req.query.next}`);')).toEqual([]);
    expect(route('res.redirect("https://app.example.com/" + req.query.next);')).toEqual([]);
  });
  it('a program constant after the slash', () => {
    expect(route('const page = "dashboard";', 'res.redirect("/" + page);')).toEqual([]);
  });
  it('an encoded value after the slash: encodeURIComponent writes "/" and "\\" as %2F and %5C', () => {
    expect(route('res.redirect("/" + encodeURIComponent(req.query.next));')).toEqual([]);
  });
  it('encodeURI after a fixed first segment: "/items/" + encodeURI(id)', () => {
    expect(route('res.redirect("/items/" + encodeURI(req.query.id));')).toEqual([]);
  });
});
