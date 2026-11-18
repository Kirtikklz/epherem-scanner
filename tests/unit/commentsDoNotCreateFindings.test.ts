import { describe, expect, it } from 'vitest';

import { insecureCookies } from '../../src/rules/basic/insecureCookies.js';
import { sensitiveDataInLogs } from '../../src/rules/basic/sensitiveDataInLogs.js';
import { weakSessionHandling } from '../../src/rules/basic/weakSessionHandling.js';
import { memoryContext } from './helpers.js';

describe('a comment cannot create a finding', () => {
  it('block comment, cookie: a commented-out res.cookie sets no cookie', () => {
    const commented = memoryContext([['app.js', [
      'function login(req, res) {',
      '  /*',
      '  res.cookie("session", sessionId);',
      '  */',
      '}',
    ].join('\n')]]);
    expect(insecureCookies.run(commented)).toHaveLength(0);
  });

  it('block comment, cookie: the SAME line uncommented still fires', () => {
    const live = memoryContext([['app.js', [
      'function login(req, res) {',
      '  res.cookie("session", sessionId, { path: "/" });',
      '}',
    ].join('\n')]]);
    expect(insecureCookies.run(live).length).toBeGreaterThan(0);
  });

  it('line comment, log: a commented-out console.log logs nothing', () => {
    const commented = memoryContext([['routes.js', [
      'function handler(req, res) {',
      "  // console.log('req.body: ' + JSON.stringify(req.body));",
      '}',
    ].join('\n')]]);
    expect(sensitiveDataInLogs.run(commented)).toHaveLength(0);
  });

  it('line comment, log: the SAME line uncommented still fires', () => {
    const live = memoryContext([['routes.js', [
      'function handler(req, res) {',
      "  console.log('req.body: ' + JSON.stringify(req.body));",
      '}',
    ].join('\n')]]);
    expect(sensitiveDataInLogs.run(live).length).toBeGreaterThan(0);
  });

  it('block comment, factory: a patternRule probe inside a comment is silent', () => {
    const commented = memoryContext([['session.js', [
      'app.use(session({',
      '  /*',
      "  secret: 'keyboard cat',",
      '  cookie: { secure: false },',
      '  */',
      '}));',
    ].join('\n')]]);
    const live = memoryContext([['session.js', [
      'app.use(session({',
      "  secret: 'keyboard cat',",
      '  cookie: { secure: false },',
      '}));',
    ].join('\n')]]);
    expect(weakSessionHandling.run(commented)).toHaveLength(0);
    expect(weakSessionHandling.run(live).length).toBeGreaterThan(0);
  });
});

describe('the fix cannot move a surviving finding', () => {
  it('evidence is the ORIGINAL line, not the stripped one', () => {
    const context = memoryContext([
      ['session.js', "app.use(session({ secret: 'keyboard cat' })); // TODO rotate this"],
    ]);
    const findings = weakSessionHandling.run(context);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toBe(
      "app.use(session({ secret: 'keyboard cat' })); // TODO rotate this",
    );
  });

  it('the same single line, fully commented out, is silent', () => {
    const context = memoryContext([
      ['session.js', "// app.use(session({ secret: 'keyboard cat' }));"],
    ]);
    expect(weakSessionHandling.run(context)).toHaveLength(0);
  });

  it('line numbers are unchanged, because the stripper preserves newlines', () => {
    const context = memoryContext([['routes.js', [
      '/* a',
      '   multi-line',
      '   banner */',
      'function handler(req, res) {',
      "  console.log('req.body: ' + JSON.stringify(req.body));",
      '}',
    ].join('\n')]]);
    const findings = sensitiveDataInLogs.run(context);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.lineStart).toBe(5);
  });
});

describe('a string is not a comment', () => {
  it('a probe matching inside a string literal still fires', () => {
    const context = memoryContext([['session.js', "app.use(session({ secret: 'a//b//c' }));"]]);
    const findings = weakSessionHandling.run(context);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain('a//b//c');
  });
});
