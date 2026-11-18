import { describe, expect, it, vi } from 'vitest';
import type { FileMap, ProjectMap } from '../../src/shared/types.js';

vi.mock('../../src/candidates/absence/index.js', () => ({
  runAbsencePass: () => {
    throw new Error('route model exploded');
  },
}));

const { absenceFindings } = await import('../../src/candidates/absence/absenceFindings.js');

const fileMap = { entries: [], rootPath: '/x' } as unknown as FileMap;
const projectMap = {} as unknown as ProjectMap;

describe('absenceFindings — the pass throwing is a recorded failure, not a silent pass', () => {
  it('with a tag enabled: no findings, one RuleFailure per enabled catalog rule', () => {
    const result = absenceFindings({
      fileMap,
      projectMap,
      enabledTags: new Set(['api-mutation-without-auth', 'missing-rate-limit', 'not-a-tag']),
      codeFindings: [],
    });
    expect(result.findings).toEqual([]);
    expect(result.failures.map((failure) => failure.ruleId).sort()).toEqual([
      'api_mutation_without_auth',
      'missing_rate_limit',
    ]);
    for (const failure of result.failures) expect(failure.message).toContain('route model exploded');
  });

  it('with the allowlist empty the pass is never called, so it cannot fail', () => {
    expect(absenceFindings({ fileMap, projectMap, enabledTags: new Set(), codeFindings: [] })).toEqual({
      findings: [],
      failures: [],
    });
  });
});
