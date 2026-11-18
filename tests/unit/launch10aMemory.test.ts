import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { analyzeCrossFileTaint, crossFileTruncationWarning } from '../../src/ast/crossFileTaint.js';
import { commentSyntaxFor, stripComments, stripCommentsOnly } from '../../src/shared/source.js';
import { memoryContext } from './helpers.js';

const SRC = path.resolve(__dirname, '../../src');
const read = (file: string) => readFileSync(path.join(SRC, file), 'utf8').replace(/\r\n/g, '\n');

const bigFile = (name: string, chars: number) =>
  `export function ${name}(input: string) { return input.trim(); }\nexport const ${name.toUpperCase()}_TEXT = "${'a'.repeat(chars)}";\n`;

describe('§2 cross-file data flow stops at the code it can hold parsed', () => {
  it('CRUCIAL: past 6,000,000 characters in files with functions: truncated, kind source, no hits', () => {
    const context = memoryContext([['src/a.ts', bigFile('alpha', 3_100_000)], ['src/b.ts', bigFile('beta', 3_100_000)]]);
    expect(context.projectMap.crossFileTaint).toEqual({
      hits: [],
      status: 'truncated',
      reason: 'Cross-file source limit (6000000 characters) exceeded.',
      limit: { kind: 'source', limit: 6_000_000 },
    });
  });

  it('under it, the same files are analysed as before', () => {
    const context = memoryContext([['src/a.ts', bigFile('alpha', 2_900_000)], ['src/b.ts', bigFile('beta', 2_900_000)]]);
    expect(context.projectMap.crossFileTaint?.status).toBe('complete');
  });

  it('a file with no function is parsed and let go: it does not count', () => {
    const noFunction = `export const BIG = "${'a'.repeat(3_100_000)}";\n`;
    const context = memoryContext([['src/a.ts', noFunction], ['src/b.ts', noFunction], ['src/c.ts', bigFile('gamma', 10)]]);
    expect(context.projectMap.crossFileTaint?.status).toBe('complete');
  });

  it('CRUCIAL: the report says it in words, with what was not followed', () => {
    expect(crossFileTruncationWarning({ hits: [], status: 'truncated', limit: { kind: 'source', limit: 6_000_000 } })).toMatch(
      /^This project is larger than cross-file analysis supports \(more than 6,000,000 characters of JavaScript\/TypeScript in files with functions\), so data passing from one function into another was not followed anywhere in the project/,
    );
    const context = memoryContext([['src/a.ts', bigFile('alpha', 3_100_000)], ['src/b.ts', bigFile('beta', 3_100_000)]]);
    expect(context.fileMap.warnings.some((w) => w.startsWith('This project is larger than cross-file analysis supports (more than 6,000,000 characters'))).toBe(true);
  });

  it('the direct call is the one the stage runs', () => {
    expect(analyzeCrossFileTaint(memoryContext([['src/a.ts', bigFile('alpha', 10)]]).fileMap, []).status).toBe('complete');
  });
});

describe('§2 the route call graph keeps no syntax tree', () => {
  const file = read('project-map/buildRouteSecurity.ts');
  const model = file.slice(file.indexOf('interface FunctionModel {'), file.indexOf('}', file.indexOf('interface FunctionModel {')));

  it('CRUCIAL: a function model holds its span and its calls, not its node or its file\'s tree', () => {
    expect(model).not.toMatch(/\bnode:|\bsf:/);
    expect(model).toMatch(/start: number;\n {2}end: number;/);
    expect(model).toMatch(/calls: string\[\];/);
    expect(file).not.toMatch(/scope\.node|model\.node|\.getStart\(scope\.sf\)/);
  });

  it('CRUCIAL: the calls are read on both ways out of a file, so a file that stopped part-way keeps its functions\' calls as before', () => {
    expect(file).toMatch(/readCalls\(pending\);\n {6}continue;\n {4}\}\n {4}readCalls\(pending\);\n {4}localKeys\.set\(entry\.path, locals\);/);
  });

  it('routes are still followed into the helpers they call, in another file', () => {
    const context = memoryContext([
      ['src/guard.ts', 'import { getAuth } from "firebase-admin/auth";\nexport async function requireUser(req: any) { const token = req.headers.authorization; if (!token) throw new Error("unauthorized"); return getAuth().verifyIdToken(token); }\n'],
      ['src/server.ts', 'import express from "express";\nimport { requireUser } from "./guard";\nconst app = express();\napp.post("/api/items", async (req, res) => { await requireUser(req); res.json({ ok: true }); });\n'],
    ]);
    const profile = (context.projectMap.routeSecurityProfiles ?? []).find((p) => p.routePath === '/api/items');
    expect(profile?.analysisStatus).toBe('complete');
    expect(profile?.reachableFiles).toEqual(['src/guard.ts', 'src/server.ts']);
  });
});

describe('§2 stripComments keeps its last answer, and only for the same question', () => {
  it('CRUCIAL: the same source and syntax: the same text', () => {
    const source = 'const a = 1; // note\n/* block */ const b = "// not a comment";\n';
    const first = stripComments(source, commentSyntaxFor('.ts'));
    expect(stripComments(source, commentSyntaxFor('.ts'))).toBe(first);
    expect(first).toBe('const a = 1;        \n            const b = "// not a comment";\n');
  });

  it('CRUCIAL: another syntax, or another source, is stripped afresh', () => {
    const source = '# hash\n// slash\n';
    const cStyle = stripCommentsOnly(source);
    const hash = stripCommentsOnly(source, true);
    expect(cStyle).toBe('# hash\n        \n');
    expect(hash).toBe('      \n// slash\n');
    expect(stripCommentsOnly(source)).toBe(cStyle);
    expect(stripCommentsOnly('x // y\n')).toBe('x     \n');
    expect(stripCommentsOnly(source)).toBe(cStyle);
  });
});

describe('§2 the two lookups that grew with file size', () => {
  it('open redirect: the whole-file question once per name, and only after the right-hand side could be credited', () => {
    const rule = read('rules/basic/openRedirect.ts');
    const body = rule.slice(rule.indexOf('function fixedPrefixLocals('), rule.indexOf('/** Any single-expression binding'));
    expect(body).toMatch(/const unreadable = new Map<string, boolean>\(\);/);
    const cheap = body.indexOf('if (!hasFixedPrefix(rhs, fixed)) continue;');
    expect(cheap).toBeGreaterThan(0);
    expect(cheap).toBeLessThan(body.indexOf('hasUnreadableAssignment(content, name)'));
  });

  it('a helper\'s body: once per file and name, weakly keyed by the entry, so nothing outlives the scan', () => {
    const guard = read('shared/handlerGuardCall.ts');
    expect(guard).toMatch(/const bodiesByEntry = new WeakMap<object, Map<string, string \| undefined>>\(\);/);
    expect(guard).toMatch(/const body = helperBodyOf\(entry, name\);/);
    expect(guard.split('middlewareBodyOf(entry.content, name)').length - 1).toBe(1);
  });
});
