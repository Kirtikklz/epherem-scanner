import { describe, expect, it } from 'vitest';
import { reportModel, startHere } from '../../src/report/reportModel.js';

type Raw = Record<string, unknown>;
const finding = (ruleId: string, severity: string, group: 'likely' | 'check' | 'known', file = `src/${ruleId}.py`): Raw => ({
  ruleId,
  title: `${ruleId} title`,
  severity,
  confidence: group === 'check' ? 'medium' : 'high',
  detectionKind: group === 'check' && ruleId.startsWith('missing') ? 'absence' : 'pattern',
  category: group === 'known' ? 'dependencies' : 'injection',
  filePath: file,
  lineStart: 3,
});
const started = (findings: Raw[]): string[] => startHere(reportModel({ findings })).map((e) => `${e.group}:${e.ruleId}`);

describe('Start here', () => {
  it('ranks a Likely medium finding before Needs checking high ones', () => {
    expect(started([
      finding('missing_webhook_verification', 'high', 'check'),
      finding('open_redirect', 'high', 'check'),
      finding('xss', 'medium', 'likely'),
    ])).toEqual(['likely:xss', 'check:missing_webhook_verification', 'check:open_redirect']);
  });

  it('ranks Likely and Known findings of any severity before Needs checking, most serious first', () => {
    expect(started([
      finding('open_redirect', 'critical', 'check'),
      finding('insecure_cookies', 'low', 'likely'),
      finding('dependency_vulnerability', 'medium', 'known', 'requirements.txt'),
    ])).toEqual(['known:dependency_vulnerability', 'likely:insecure_cookies', 'check:open_redirect']);
  });

  it('keeps the serious-first order among Likely and Known findings', () => {
    expect(started([
      finding('xss', 'medium', 'likely'),
      finding('dependency_vulnerability', 'high', 'known', 'package-lock.json'),
      finding('sql_injection', 'critical', 'likely'),
      finding('missing_webhook_verification', 'high', 'check'),
    ])).toEqual(['likely:sql_injection', 'known:dependency_vulnerability', 'likely:xss']);
  });

  it('is empty when every finding needs checking', () => {
    expect(started([
      finding('missing_webhook_verification', 'high', 'check'),
      finding('open_redirect', 'critical', 'check'),
    ])).toEqual([]);
  });
});
