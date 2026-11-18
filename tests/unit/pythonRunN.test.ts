import { describe, expect, it } from 'vitest';
import { openRedirect } from '../../src/rules/basic/openRedirect.js';
import { ANALYSIS_METHOD_BY_LANGUAGE } from '../../src/shared/languages.js';
import { pythonRedirectStraightFromQuery } from '../../src/shared/pythonFlow.js';
import type { Finding, RuleContext } from '../../src/shared/types.js';
import { memoryContext } from './helpers.js';

type Files = [string, string][];
const py = (...lines: string[]): string => `${lines.join('\n')}\n`;
const redirects = (files: Files): string[] =>
  openRedirect.run(memoryContext(files) as RuleContext).map((f: Finding) => `${f.filePath}:${f.lineStart} ${f.confidence}`);

const FLASK_HEAD = ['from flask import Flask, redirect, request, url_for', 'app = Flask(__name__)', ''];
const flask = (...body: string[]): Files => [['web/app.py', py(...FLASK_HEAD, '@app.route("/go")', 'def go():', ...body)]];
const DJANGO_HEAD = ['from django.shortcuts import redirect', ''];
const django = (...body: string[]): Files => [['shop/views.py', py(...DJANGO_HEAD, 'def go(request):', ...body)]];
const fastapi = (decorator: string, signature: string, ...body: string[]): Files => [[
  'api/main.py',
  py('from typing import Optional', 'from fastapi import FastAPI, Depends, Query', 'from fastapi.responses import RedirectResponse', 'app = FastAPI()', '', decorator, signature, ...body),
]];

describe('job N, 2: a Python redirect to the query string\'s own value is high confidence', () => {
  it('CRUCIAL: Flask, the value read inline', () => {
    expect(redirects(flask('    return redirect(request.args.get("next"))'))).toEqual(['web/app.py:6 high']);
  });

  it('CRUCIAL: Django, request.GET by item and by get, with a fixed fallback', () => {
    expect(redirects(django('    return redirect(request.GET["next"])'))).toEqual(['shop/views.py:4 high']);
    expect(redirects(django('    return redirect(request.GET.get("next") or "/home/")'))).toEqual(['shop/views.py:4 high']);
  });

  it('CRUCIAL: a name bound once to the read, in the same block as the redirect (the sign-in shape)', () => {
    expect(redirects(flask(
      '    if request.method == "POST":',
      '        account = find(request.form.get("email"))',
      '        if account and account.ok(request.form.get("password")):',
      '            target = request.args.get("next")',
      '            sign_in(account)',
      '            return redirect(target or url_for("home"))',
      '    return "form"',
    ))).toEqual(['web/app.py:11 high']);
  });

  it('CRUCIAL: a FastAPI query parameter, plain or Optional, passed to RedirectResponse', () => {
    expect(redirects(fastapi('@app.get("/go")', 'async def go(target: str):', '    return RedirectResponse(url=target)'))).toEqual(['api/main.py:8 high']);
    expect(redirects(fastapi('@app.get("/go")', 'async def go(target: Optional[str] = None):', '    return RedirectResponse(target)'))).toEqual(['api/main.py:8 high']);
    expect(redirects(fastapi('@app.get("/go")', 'async def go(target: str = Query(...)):', '    return RedirectResponse(url=target)'))).toEqual(['api/main.py:8 high']);
  });

  it('a form or POST value keeps medium', () => {
    expect(redirects(flask('    return redirect(request.form.get("next"))'))).toEqual(['web/app.py:6 medium']);
    expect(redirects(django('    return redirect(request.POST.get("next") or "/")'))).toEqual(['shop/views.py:4 medium']);
  });

  it('a value something was done to keeps medium: a check, a second binding, a branch, a wrapper', () => {
    expect(redirects(flask(
      '    target = request.args.get("next")',
      '    if not target.startswith("/"):',
      '        target = "/home"',
      '    return redirect(target)',
    ))).toEqual(['web/app.py:9 medium']);
    expect(redirects(flask(
      '    target = request.args.get("next")',
      '    target = request.args.get("then")',
      '    return redirect(target)',
    ))).toEqual(['web/app.py:8 medium']);
    expect(redirects(flask(
      '    if request.args:',
      '        target = request.args.get("next")',
      '    return redirect(target)',
    ))).toEqual(['web/app.py:8 medium']);
    expect(redirects(flask('    return redirect(request.args.get("next") if request.args else "/")'))).toEqual(['web/app.py:6 medium']);
    expect(redirects(flask('    return redirect(tidy(request.args.get("next")))'))).toEqual(['web/app.py:6 medium']);
  });

  it('an inline read the function tests first keeps medium', () => {
    expect(redirects(flask(
      '    if request.args.get("next", "").startswith("/"):',
      '        return redirect(request.args.get("next"))',
      '    return "no"',
    ))).toEqual(['web/app.py:7 medium']);
  });

  it('a fallback that reads the request keeps medium', () => {
    expect(redirects(flask('    return redirect(request.args.get("next") or request.form["then"])'))).toEqual(['web/app.py:6 medium']);
  });

  it('FastAPI: a path parameter, a parameter used again, a dependency, a non-string type: none is high', () => {
    const conf = (files: Files) => redirects(files).map((r) => r.split(' ')[1]);
    expect(conf(fastapi('@app.get("/go/{target}")', 'async def go(target: str):', '    return RedirectResponse(url=target)'))).not.toContain('high');
    expect(conf(fastapi('@app.get("/go")', 'async def go(target: str):', '    log(target)', '    return RedirectResponse(url=target)'))).not.toContain('high');
    expect(conf(fastapi('@app.get("/go")', 'async def go(target: str = Depends(pick)):', '    return RedirectResponse(url=target)'))).not.toContain('high');
    expect(conf(fastapi('@app.get("/go")', 'async def go(target: Destination):', '    return RedirectResponse(url=target)'))).not.toContain('high');
  });

  it('a name bound to a form value, a name bound in an earlier sibling block, and an `and` keep medium', () => {
    expect(redirects(flask(
      '    target = request.form.get("next")',
      '    return redirect(target)',
    ))).toEqual(['web/app.py:7 medium']);
    expect(redirects(flask(
      '    if request.args:',
      '        target = request.args.get("next")',
      '    if request.method == "GET":',
      '        return redirect(target)',
      '    return "no"',
    ))).toEqual(['web/app.py:9 medium']);
    expect(redirects(flask('    return redirect(request.args.get("next") and "/home")'))).toEqual(['web/app.py:6 medium']);
  });

  it('a validated redirect stays silent, as before', () => {
    expect(redirects(django(
      '    target = request.GET.get("next")',
      '    if not url_has_allowed_host_and_scheme(target, allowed_hosts={request.get_host()}):',
      '        target = "/"',
      '    return redirect(target)',
    ))).toEqual([]);
  });

  it('JavaScript is untouched: a tainted Express redirect keeps the confidence it had', () => {
    const js = redirects([['srv/app.js', 'const express = require("express");\nconst app = express();\napp.get("/go", (req, res) => {\n  res.redirect(req.query.next);\n});\n']]);
    expect(js).toHaveLength(1);
    expect(js[0]).toMatch(/^srv\/app\.js:4 /);
  });
});

describe('job N, 2: the proof itself, asked directly', () => {
  const straight = (src: string): boolean => {
    const call = src.search(/(?:redirect|RedirectResponse)\(/);
    const open = src.indexOf('(', call);
    let depth = 0;
    let close = -1;
    for (let i = open; i < src.length; i += 1) {
      if ('([{'.includes(src[i]!)) depth += 1;
      if (')]}'.includes(src[i]!)) { depth -= 1; if (depth === 0) { close = i; break; } }
    }
    let start = open + 1;
    const kw = /^\s*url\s*=\s*/.exec(src.slice(start));
    if (kw !== null) start += kw[0].length;
    return pythonRedirectStraightFromQuery(src, start, close);
  };

  it('the binding must come before the redirect', () => {
    expect(straight(py('def go():', '    target = request.args.get("next")', '    return redirect(target)'))).toBe(true);
    expect(straight(py('def go():', '    return redirect(target)', '    target = request.args.get("next")'))).toBe(false);
  });

  it('the binding must be the name\'s own, single assignment', () => {
    expect(straight(py('def go():', '    cache[target] = request.args.get("next")', '    return redirect(target)'))).toBe(false);
    expect(straight(py('def go():', '    target = other = request.args.get("next")', '    return redirect(target)'))).toBe(false);
  });

  it('a bound read whose fallback reads the request is not straight', () => {
    expect(straight(py('def go():', '    target = request.args.get("next") or "/"', '    return redirect(target)'))).toBe(true);
    expect(straight(py('def go():', '    target = request.args.get("next") or request.form["then"]', '    return redirect(target)'))).toBe(false);
  });

  it('a parameter is a source only on a FastAPI route', () => {
    expect(straight(py('def go(target: str):', '    return redirect(target)'))).toBe(false);
    expect(straight(py('from fastapi import FastAPI', '@app.get("/go")', 'def go(target: str):', '    return RedirectResponse(target)'))).toBe(true);
  });

  it('a FastAPI default must be absent, None, a literal or Query(...)', () => {
    const route = (param: string) => py('from fastapi import FastAPI', '@app.get("/go")', `def go(${param}):`, '    return RedirectResponse(target)');
    expect(straight(route('target: str = "/home"'))).toBe(true);
    expect(straight(route('target: str = pick_default()'))).toBe(false);
  });

  it('the destination outside a function is not proved', () => {
    expect(straight(py('target = redirect(request.args.get("next"))'))).toBe(false);
  });
});

describe('job N, 3: Django in the stack', () => {
  const stacks = (files: Files): string[] => memoryContext(files).stack.stacks.map((s) => s.name);

  it('CRUCIAL: a module importing django, or a manage.py naming a settings module, reports django', () => {
    expect(stacks([['notes/views.py', py('from django.http import HttpResponse', 'def show(request):', '    return HttpResponse("ok")')]])).toContain('django');
    expect(stacks([['notes/apps.py', py('import django', 'print(django.VERSION)')]])).toContain('django');
    expect(stacks([['manage.py', py('import os', 'os.environ.setdefault("DJANGO_SETTINGS_MODULE", "site_cfg.settings")')]])).toContain('django');
  });

  it('a requirements line, a README, a comment or a string does not', () => {
    expect(stacks([['requirements.txt', 'django==5.0.0\n'], ['README.md', 'from django.http import HttpResponse\n']])).not.toContain('django');
    expect(stacks([['web/app.py', py('# from django.http import HttpResponse', 'from flask import Flask', 'NOTE = "import django"')]])).not.toContain('django');
    expect(stacks([['tools/manage.py', py('print("hello")')]])).not.toContain('django');
    expect(stacks([['Dockerfile', 'FROM python:3.12\nENV DJANGO_SETTINGS_MODULE=site_cfg.settings\n']])).not.toContain('django');
  });

  it('Flask, FastAPI and the JavaScript stacks are detected as before', () => {
    expect(stacks([['web/app.py', py('from flask import Flask', 'app = Flask(__name__)')]])).toEqual(['flask', 'python']);
    expect(stacks([['package.json', '{"dependencies":{"next":"14.0.0","react":"18.0.0"}}'], ['app/page.tsx', 'import React from "react";\n']])).toEqual(['nextjs', 'nodejs', 'react']);
  });
});

describe('job N, 4: Python\'s analysis method', () => {
  it('CRUCIAL: Python is parsed where the parser can read it, with patterns otherwise; SQL is still patterns only', () => {
    expect(ANALYSIS_METHOD_BY_LANGUAGE.python).toBe('parsed_with_pattern_fallback');
    expect(ANALYSIS_METHOD_BY_LANGUAGE.sql).toBe('regex_only');
    expect(ANALYSIS_METHOD_BY_LANGUAGE.javascript).toBe('ast+regex');
    expect(ANALYSIS_METHOD_BY_LANGUAGE.typescript).toBe('ast+regex');
  });
});
