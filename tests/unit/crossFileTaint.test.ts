import { describe, expect, it } from 'vitest';
import { sqlInjection } from '../../src/rules/basic/sqlInjection.js';
import { crossFileAstHits } from '../../src/ast/crossFileTaint.js';
import { serverSideRequestForgery } from '../../src/rules/basic/ssrf.js';
import { memoryContext } from './helpers.js';

const pkg: [string, string] = ['package.json', '{"dependencies":{"next":"14.0.0"}}'];

describe('bounded cross-file data flow', () => {
  it('traces route input into an imported SQL helper', () => {
    const context = memoryContext([
      pkg,
      ['app/api/users/route.ts',
        'import { lookup } from "../../../lib/db";\nexport function GET(req){ return lookup(req.query.id); }'],
      ['lib/db.ts', 'export function lookup(id){ return db.query(`SELECT * FROM users WHERE id=${id}`); }'],
    ]);
    const findings = sqlInjection.run(context);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ filePath: 'lib/db.ts', lineStart: 1, confidence: 'high' });
    expect(context.projectMap.crossFileTaint?.status).toBe('complete');
  });

  it('propagates a tainted return value from an imported helper into a local sink', () => {
    const context = memoryContext([
      pkg,
      ['app/api/users/route.ts',
        'import { identity } from "../../../lib/value";\nexport function GET(req){ const id = identity(req.query.id); return db.query(`SELECT ${id}`); }'],
      ['lib/value.ts', 'export function identity(value){ return value; }'],
    ]);
    expect(sqlInjection.run(context)).toHaveLength(1);
  });

  it('handles named aliases and tsconfig path aliases', () => {
    const context = memoryContext([
      pkg,
      ['tsconfig.json', '{"compilerOptions":{"baseUrl":".","paths":{"@svc/*":["src/services/*"]}}}'],
      ['app/api/proxy/route.ts',
        'import { fetchRemote as go } from "@svc/net";\nexport function GET(req){ return go(req.query.url); }'],
      ['src/services/net.ts', 'export function fetchRemote(url){ return fetch(url); }'],
    ]);
    expect(serverSideRequestForgery.run(context)).toHaveLength(1);
  });

  it('handles default, namespace, and destructured-parameter calls', () => {
    const context = memoryContext([
      pkg,
      ['app/api/proxy/route.ts', [
        'import proxy from "../../../lib/defaultProxy";',
        'import * as service from "../../../lib/service";',
        'export function GET(req){ proxy({ url: req.query.first }); return service.load(req.query.second); }',
      ].join('\n')],
      ['lib/defaultProxy.ts', 'export default function ({ url }){ return fetch(url); }'],
      ['lib/service.ts', 'export function load(url){ return fetch(url); }'],
    ]);
    expect(serverSideRequestForgery.run(context)).toHaveLength(2);
  });

  it('summarizes every injection-family sink kind', () => {
    const context = memoryContext([
      pkg,
      ['app/api/run/route.ts', [
        'import * as sinks from "../../../lib/sinks";',
        'export function POST(req){',
        '  sinks.sql(req.body.a); sinks.command(req.body.b); sinks.path(req.body.c);',
        '  sinks.request(req.body.d); sinks.redirect(req.body.e); sinks.html(req.body.f); sinks.dynamic(req.body.g);',
        '}',
      ].join('\n')],
      ['lib/sinks.ts', [
        'export function sql(v){ return db.query(`SELECT ${v}`); }',
        'export function command(v){ return exec(v); }',
        'export function path(v){ return fs.readFile(v); }',
        'export function request(v){ return fetch(v); }',
        'export function redirect(v){ return res.redirect(v); }',
        'export function html(v){ return document.write(v); }',
        'export function dynamic(v){ return eval(v); }',
      ].join('\n')],
    ]);
    expect(context.projectMap.crossFileTaint?.hits.map((hit) => hit.kind).sort()).toEqual(
      ['command', 'dynamic_code', 'html', 'path', 'redirect', 'request', 'sql'],
    );
  });

  it('follows a multi-hop cyclic graph without looping forever', () => {
    const context = memoryContext([
      pkg,
      ['app/api/users/route.ts',
        'import { run } from "../../../lib/a";\nexport function GET(req){ return run(req.query.id); }'],
      ['lib/a.ts', 'import { next } from "./b";\nexport function run(value){ return next(value); }'],
      ['lib/b.ts', 'import { run } from "./a";\nexport function next(value){ if(false) run(value); return db.query(`SELECT ${value}`); }'],
    ]);
    expect(sqlInjection.run(context)).toHaveLength(1);
  });

  it('does not taint a helper called with a constant or a transformed value', () => {
    const constant = memoryContext([
      pkg,
      ['app/api/users/route.ts', 'import { lookup } from "../../../lib/db";\nexport function GET(){ return lookup("fixed"); }'],
      ['lib/db.ts', 'export function lookup(id){ return db.query(`SELECT ${id}`); }'],
    ]);
    const transformed = memoryContext([
      pkg,
      ['app/api/users/route.ts', 'import { lookup } from "../../../lib/db";\nexport function GET(req){ return lookup(parseInt(req.query.id)); }'],
      ['lib/db.ts', 'export function lookup(id){ return db.query(`SELECT ${id}`); }'],
    ]);
    expect(sqlInjection.run(constant)).toHaveLength(0);
    expect(sqlInjection.run(transformed)).toHaveLength(0);
  });

  it('reports a helper whose own parameter reaches a sink, with the caller in the same file', () => {
    const context = memoryContext([
      pkg,
      ['app/api/proxy/route.ts', [
        'async function callUpstream(url){ return fetch(url); }',
        'export async function GET(req){ return callUpstream(req.query.target); }',
      ].join('\n')],
    ]);
    const hits = context.projectMap.crossFileTaint?.hits ?? [];
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ kind: 'request', filePath: 'app/api/proxy/route.ts', line: 1 });
    expect(serverSideRequestForgery.run(context)).toHaveLength(1);
  });

  it('stays silent on a sink written at the sink, however tainted, when no call carried it', () => {
    const context = memoryContext([
      pkg,
      ['app/api/auth/logout/route.ts', [
        'import { NextResponse } from "next/server";',
        'export async function POST(request){ return NextResponse.redirect(new URL("/", request.url)); }',
      ].join('\n')],
    ]);
    expect(context.projectMap.crossFileTaint?.hits ?? []).toHaveLength(0);
  });

  it('stays silent when every call site of the helper passes a fixed destination', () => {
    const context = memoryContext([
      pkg,
      ['app/api/prices/route.ts', [
        'async function callUpstream(url){ return fetch(url); }',
        'export async function GET(req){',
        '  const code = String(req.query.code || "");',
        '  await callUpstream(`https://api.example.com/v1/prices?code=${encodeURIComponent(code)}`);',
        '  return callUpstream("https://api.example.com/v1/meta");',
        '}',
      ].join('\n')],
    ]);
    expect(context.projectMap.crossFileTaint?.hits ?? []).toHaveLength(0);
  });

  it('still reports the helper when one call site is safe and another passes request input', () => {
    const context = memoryContext([
      pkg,
      ['app/api/mixed/route.ts', [
        'async function callUpstream(url){ return fetch(url); }',
        'export async function meta(){ return callUpstream("https://api.example.com/v1/meta"); }',
        'export async function GET(req){ return callUpstream(req.query.target); }',
      ].join('\n')],
    ]);
    expect(context.projectMap.crossFileTaint?.hits ?? []).toHaveLength(1);
  });

  it('keeps a call-carried flow and a directly-written sink apart on the same line', () => {
    const context = memoryContext([
      pkg,
      ['app/api/both/route.js',
        'async function helper(u){ return fetch(u); } export async function GET(req){ await helper(req.query.b); return fetch(req.query.a); }'],
    ]);
    const hits = context.projectMap.crossFileTaint?.hits ?? [];
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ kind: 'request', filePath: 'app/api/both/route.js', line: 1 });
  });

  it('names a flow that never left the file as a call, not as a cross-file flow', () => {
    const context = memoryContext([
      pkg,
      ['app/api/proxy/route.ts', [
        'async function callUpstream(url){ return fetch(url); }',
        'export async function GET(req){ return callUpstream(req.query.target); }',
      ].join('\n')],
    ]);
    const hits = crossFileAstHits(context.projectMap.crossFileTaint, 'app/api/proxy/route.ts');
    expect(hits).toHaveLength(1);
    expect(hits[0]?.callee).toBe('flow through a call in this file');
    expect(hits[0]?.callee).not.toMatch(/cross-file/);
  });

  it('fails closed when the cross-file file budget is exceeded', () => {
    const files: [string, string][] = [pkg];
    for (let index = 0; index < 2_001; index += 1) files.push([`src/f${index}.ts`, 'export const x = 1;']);
    const context = memoryContext(files);
    expect(context.projectMap.crossFileTaint?.status).toBe('truncated');
    expect(context.fileMap.warnings.join(' ')).toMatch(/JavaScript\/TypeScript files, against a limit of 2,000/);
  });
});
