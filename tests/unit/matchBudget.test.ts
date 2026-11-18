import { describe, expect, it } from 'vitest';
import { findMatches, runWithMatchBudget, type MatchBudget } from '../../src/shared/utils.js';
import { FindingBudget, runRules } from '../../src/rules/index.js';
import { makeFinding } from '../../src/shared/findingFactory.js';
import type { Finding, RuleContext, ScanRule } from '../../src/shared/types.js';
import { memoryContext } from './helpers.js';

const repeat = (token: string, n: number): string => Array.from({ length: n }, () => token).join('\n');

describe('findMatches truncation is proven, not assumed', () => {
  it('EXACTLY N matches with a cap of N is NOT marked truncated', () => {
    const budget: MatchBudget = { remaining: 5, truncated: false };
    const matches = runWithMatchBudget(budget, () => findMatches(repeat('HIT', 5), /HIT/g));
    expect(matches).toHaveLength(5);
    expect(budget.truncated).toBe(false);
    expect(budget.remaining).toBe(0);
  });

  it('N+1 matches with a cap of N IS marked truncated', () => {
    const budget: MatchBudget = { remaining: 5, truncated: false };
    const matches = runWithMatchBudget(budget, () => findMatches(repeat('HIT', 6), /HIT/g));
    expect(matches).toHaveLength(5);
    expect(budget.truncated).toBe(true);
  });

  it('2001 matches against the 2000 per-find cap marks truncated (incomplete)', () => {
    const budget: MatchBudget = { remaining: 100_000, truncated: false };
    const matches = runWithMatchBudget(budget, () => findMatches(repeat('HIT', 2001), /HIT/g));
    expect(matches).toHaveLength(2000);
    expect(budget.truncated).toBe(true);
  });

  it('EXACTLY 2000 matches against the 2000 per-find cap is NOT truncated', () => {
    const budget: MatchBudget = { remaining: 100_000, truncated: false };
    const matches = runWithMatchBudget(budget, () => findMatches(repeat('HIT', 2000), /HIT/g));
    expect(matches).toHaveLength(2000);
    expect(budget.truncated).toBe(false);
  });

  it('an already-exhausted work budget emits nothing and flags truncation', () => {
    const budget: MatchBudget = { remaining: 0, truncated: false };
    const matches = runWithMatchBudget(budget, () => findMatches(repeat('HIT', 3), /HIT/g));
    expect(matches).toHaveLength(0);
    expect(budget.truncated).toBe(true);
  });
});

function ruleThatMatches(id: string, pattern: RegExp, keep: (m: { snippet: string }) => boolean): ScanRule {
  return {
    id,
    title: id,
    category: 'secrets',
    kind: 'basic',
    run(ctx: RuleContext): Finding[] {
      const out: Finding[] = [];
      for (const entry of ctx.fileMap.entries) {
        for (const match of findMatches(entry.content, pattern)) {
          if (!keep(match)) continue;
          out.push(
            makeFinding({
              ruleId: id,
              title: id,
              severity: 'low',
              confidence: 'low',
              filePath: entry.path,
              lineStart: match.line,
              evidence: match.snippet,
              userExplanation: 'x',
              technicalExplanation: 'x',
              fixHint: 'x',
              category: 'secrets',
            }),
          );
        }
      }
      return out;
    },
  };
}

describe('candidate matches do not consume the finding budget or hide later findings', () => {
  it('many rejected candidates in one rule do not starve a later rule sharing the budget', () => {
    const content = `${repeat('CANDIDATE', 3000)}\nREAL_SECRET_TOKEN`;
    const context = memoryContext([['package.json', '{"name":"x"}'], ['dense.ts', content]]);
    const rejectAll = ruleThatMatches('reject_all', /CANDIDATE/g, () => false);
    const findReal = ruleThatMatches('find_real', /REAL_SECRET_TOKEN/g, () => true);

    const budget = new FindingBudget(5);
    const result = runRules([rejectAll, findReal], context, { budget });
    expect(result.findings.map((f) => f.ruleId)).toContain('find_real');
  });

  it('multiple rules share ONE finding budget; retained findings are capped + truncated flagged', () => {
    const content = repeat('SECRET', 40);
    const context = memoryContext([['package.json', '{"name":"x"}'], ['a.ts', content]]);
    const r1 = ruleThatMatches('r1', /SECRET/g, () => true);
    const r2 = ruleThatMatches('r2', /SECRET/g, () => true);
    const budget = new FindingBudget(10);
    const result = runRules([r1, r2], context, { budget });
    expect(result.findings.length).toBeLessThanOrEqual(10);
    expect(result.truncated).toBe(true);
  });
});
