import { describe, expect, it } from 'vitest';
import { exceedsNestingDepth, measureNestingDepth } from '../../src/input/nestingDepth.js';

describe('nesting depth measurement', () => {
  it('counts every bracket family', () => {
    expect(measureNestingDepth('const a = { b: [1, (2)] };')).toBe(3);
    expect(measureNestingDepth('f(g(h(1)))')).toBe(3);
    expect(measureNestingDepth('')).toBe(0);
    expect(measureNestingDepth('const a = 1;')).toBe(0);
  });

  it('does not count brackets inside string literals', () => {
    expect(measureNestingDepth('const a = "((((((((((";')).toBe(0);
    expect(measureNestingDepth("const a = '{{{{{{{{{{';")).toBe(0);
    expect(measureNestingDepth('const a = "\\"((((";')).toBe(0);
  });

  it('does not count brackets inside comments', () => {
    expect(measureNestingDepth('// ((((((((\nconst a = 1;')).toBe(0);
    expect(measureNestingDepth('/* {{{{{{{{ */ const a = 1;')).toBe(0);
    expect(measureNestingDepth('/* unterminated ((((')).toBe(0);
  });

  it('does not count template TEXT but does count its substitutions', () => {
    expect(measureNestingDepth('const a = `((((((`;')).toBe(0);
    expect(measureNestingDepth('const a = `x${1}y`;')).toBe(1);
    expect(measureNestingDepth('const a = `${`${`${1}`}`}`;')).toBe(3);
    expect(measureNestingDepth('const a = `${ f({ b: 1 }) }`;')).toBe(3);
  });

  it('is not confused by unbalanced closers', () => {
    expect(measureNestingDepth(')))))))')).toBe(0);
    expect(measureNestingDepth('}}}}}}}')).toBe(0);
    expect(measureNestingDepth('(((')).toBe(3);
  });

  it('reports the deepest point, not the last one', () => {
    expect(measureNestingDepth('f(g(h(1))); a(1);')).toBe(3);
  });

  it('stops at the limit rather than measuring a pathological file in full', () => {
    const deep = '('.repeat(2_000_000);
    expect(exceedsNestingDepth(deep, 200)).toBe(true);
    expect(exceedsNestingDepth('f(1)', 200)).toBe(false);
  });

  it('flags exactly the shapes that make the TypeScript parser overflow', () => {
    const shapes = [
      `const x = ${'{ a: '.repeat(1000)}1${' }'.repeat(1000)};`,
      `const y = ${'f('.repeat(1000)}1${')'.repeat(1000)};`,
      `const z = ${'['.repeat(1000)}1${']'.repeat(1000)};`,
      `const t = ${'`${'.repeat(1000)}1${'}`'.repeat(1000)};`,
      `function q() { ${'if (a) {'.repeat(1000)}b();${'}'.repeat(1000)} }`,
    ];
    for (const shape of shapes) expect(exceedsNestingDepth(shape, 200)).toBe(true);
  });

  it('leaves real code alone: the deepest file in this repository is far below the bound', () => {
    const realistic = `export function C({ items }) {
  return (
    <ul>
      {items.map((item) => (
        <li key={item.id}>{format({ value: item.value, opts: { pad: [1, 2, 3] } })}</li>
      ))}
    </ul>
  );
}`;
    expect(exceedsNestingDepth(realistic, 200)).toBe(false);
    expect(measureNestingDepth(realistic)).toBeLessThan(20);
  });
});
