import { describe, expect, it } from 'vitest';
import {
  MAX_AST_FILE_BYTES,
  analyzeFileAst,
  astVerdict,
  runWithAstCache,
} from '../../src/ast/astAnalysis.js';

describe('bounded AST safety and adversarial inputs', () => {
  it('fails safely to regex analysis for oversized input', () => {
    const result = runWithAstCache(() => analyzeFileAst('huge.ts', 'x'.repeat(MAX_AST_FILE_BYTES + 1), '.ts'));
    expect(result).toBeUndefined();
    expect(astVerdict(result, 'sql', 1)).toBe('none');
  });

  it('never throws on malformed syntax and remains deterministic', () => {
    const malformed = 'function x( { const q = req.body.id; db.query(`SELECT ${q}`';
    const first = runWithAstCache(() => analyzeFileAst('broken.ts', malformed, '.ts'));
    const second = runWithAstCache(() => analyzeFileAst('broken.ts', malformed, '.ts'));
    expect(second).toEqual(first);
  });

  it('survives deterministic fuzz inputs without executing submitted text', () => {
    let seed = 0x5eed1234;
    const next = (): number => (seed = (seed * 1664525 + 1013904223) >>> 0);
    const alphabet = '{}[]()`${};,.?/\\\"\'abcdefghijklmnopqrstuvwxyz0123456789\0\n';
    for (let caseIndex = 0; caseIndex < 250; caseIndex += 1) {
      let source = '';
      const length = next() % 2048;
      for (let index = 0; index < length; index += 1) source += alphabet[next() % alphabet.length];
      expect(() => runWithAstCache(() => analyzeFileAst(`fuzz-${caseIndex}.tsx`, source, '.tsx'))).not.toThrow();
    }
  });
});
