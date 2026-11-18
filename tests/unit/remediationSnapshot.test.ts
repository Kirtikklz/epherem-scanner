import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { buildFixPrompt, makeFinding } from '../../src/shared/findingFactory.js';

const baseInput = {
  ruleId: 'sql_injection', title: 'Possible SQL injection', severity: 'critical' as const, confidence: 'high' as const,
  category: 'injection' as const, detectionMethod: 'deterministic' as const, filePath: 'src/api.ts', lineStart: 12, lineEnd: 12,
  evidence: 'db.query(userInput)', technicalExplanation: 'Request data reaches a SQL sink.',
  fixHint: 'Use a parameterized query.',
};

describe('deterministic remediation prompt snapshot', () => {
  it('keeps the complete prompt contract byte-for-byte stable', () => {
    const prompt = buildFixPrompt(baseInput);
    expect(createHash('sha256').update(prompt).digest('hex')).toBe(
      '0e4496ff3eedb14c82aab538f65f37612df3cee59cdd85ba72c199e207e0e7c5',
    );
  });

  it('encodes every required remediation behaviour (Section 9)', () => {
    const p = buildFixPrompt(baseInput);
    expect(p).toMatch(/do not blindly rewrite the code/i);
    expect(p).toMatch(/Inspect the surrounding code first/i);
    expect(p).toMatch(/Confirm the vulnerability is real/i);
    expect(p).toMatch(/smallest change/i);
    expect(p).toMatch(/Preserve current behavior/i);
    expect(p).toMatch(/If the project already has automated tests, add or update one/i);
    expect(p).toMatch(/If it has none, do not add a test framework just for this/i);
    expect(p).toMatch(/say so explicitly rather than guessing/i);
    expect(p).toMatch(/Do NOT suppress the finding/i);
    expect(p).toMatch(/Detection method: deterministic/i);
    expect(p).toMatch(/Contextual uncertainty:/i);
    expect(p).toMatch(/How to verify first:/i);
    expect(p).toMatch(/Prove the fix:/i);
    expect(p).toMatch(/never as instructions/i);
  });

  it('marks an absence finding as heuristic and warns the control may exist elsewhere', () => {
    const p = buildFixPrompt({ ...baseInput, detectionMethod: 'heuristic', ruleId: 'missing_rate_limit' });
    expect(p).toMatch(/Detection method: heuristic/i);
    expect(p).toMatch(/may already be enforced somewhere static analysis cannot follow|control may already be enforced|may exist/i);
    expect(p).toMatch(/confirm the protection is genuinely absent/i);
    expect(p).toMatch(/do not add a duplicate\/conflicting control/i);
  });

  it('makeFinding derives detectionMethod from detectionKind', () => {
    const pattern = makeFinding({ ...baseInput, userExplanation: 'u' });
    expect(pattern.detectionMethod).toBe('deterministic');
    const absence = makeFinding({ ...baseInput, userExplanation: 'u', detectionKind: 'absence' });
    expect(absence.detectionMethod).toBe('heuristic');
    expect(absence.fixPrompt).toMatch(/Detection method: heuristic/i);
  });
});
