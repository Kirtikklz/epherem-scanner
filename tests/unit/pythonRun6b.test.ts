import { describe, expect, it } from 'vitest';
import { buildRuleResults } from '../../src/report/buildRuleResults.js';
import { detectLanguages } from '../../src/shared/languages.js';
import type { DependencyAuditSummary, Finding, RuleContext } from '../../src/shared/types.js';
import { memoryContext } from './helpers.js';

const audit: DependencyAuditSummary = {
  performed: false,
  incomplete: false,
  source: 'none',
  dependenciesCollected: 0,
  checked: 0,
  notChecked: [],
  vulnerabilities: [],
  diagnostics: [],
  note: 'not run',
};
const finding = (ruleId: string): Finding => ({ ruleId }) as Finding;

function rows(context: RuleContext, findings: Finding[]) {
  return new Map(
    buildRuleResults({
      findings,
      context,
      codeScanComplete: true,
      dependencyAudit: audit,
      dependencyAuditStatus: 'complete',
      archiveObserved: false,
      languages: detectLanguages(context.fileMap),
    }).map((row) => [row.ruleId, row]),
  );
}

const PARTLY = 'Python CSRF protection was only partly checked';

const flaskConfig: [string, string] = ['shop/config.py', 'class BaseConfig:\n    WTF_CSRF_ENABLED = False\n'];
const expressApp: [string, string] = [
  'server/app.js',
  [
    "const session = require('express-session');",
    "app.use(session({ secret: process.env.S }));",
    "app.post('/api/notes', (req, res) => { req.session.n = req.body; res.json({}); });",
    '',
  ].join('\n'),
];

describe('missing_csrf_protection coverage on Python', () => {
  it('a Python project with a CSRF finding is failed with coverage partial, and says why', () => {
    const row = rows(memoryContext([flaskConfig]), [finding('missing_csrf_protection')]).get('missing_csrf_protection');
    expect(row).toMatchObject({ status: 'failed', coverage: 'partial' });
    expect(row?.coverageReason).toContain(PARTLY);
  });

  it('a JavaScript-only project keeps exactly what it had: failed full, or passed full', () => {
    const failed = rows(memoryContext([expressApp]), [finding('missing_csrf_protection')]).get('missing_csrf_protection');
    expect(failed).toEqual({ ruleId: 'missing_csrf_protection', label: failed?.label, status: 'failed', coverage: 'full' });
    const passed = rows(memoryContext([expressApp]), []).get('missing_csrf_protection');
    expect(passed).toEqual({ ruleId: 'missing_csrf_protection', label: passed?.label, status: 'passed', coverage: 'full' });
  });

  it('JavaScript routes beside any Python file: partial, so a clean result is not a pass', () => {
    const mixed = memoryContext([expressApp, ['tools/report.py', 'print("hi")\n']]);
    const clean = rows(mixed, []).get('missing_csrf_protection');
    expect(clean).toMatchObject({ status: 'not_completed', coverage: 'partial' });
    expect(clean?.coverageReason).toContain(PARTLY);
    const failed = rows(mixed, [finding('missing_csrf_protection')]).get('missing_csrf_protection');
    expect(failed).toMatchObject({ status: 'failed', coverage: 'partial' });
  });

  it('other rules on a Python project are not touched', () => {
    const result = rows(memoryContext([flaskConfig]), [finding('xss'), finding('missing_csrf_protection')]);
    expect(result.get('xss')).toMatchObject({ status: 'failed', coverage: 'full' });
    expect(result.get('xss')?.coverageReason).toBeUndefined();
  });

  it('a row already partial for another reason keeps both sentences', () => {
    const goToo = memoryContext([flaskConfig, ['cmd/main.go', 'package main\nfunc main() {}\n']]);
    const row = rows(goToo, [finding('missing_csrf_protection')]).get('missing_csrf_protection');
    expect(row?.coverage).toBe('partial');
    expect(row?.coverageReason).toContain('go is detected');
    expect(row?.coverageReason).toContain(PARTLY);
  });
});
