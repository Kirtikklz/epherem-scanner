import { describe, expect, it } from 'vitest';

import {
  HASH_COMMENT_EXTENSIONS,
  stripCommentsOnly,
  usesHashComments,
} from '../../src/shared/source.js';

describe('stripCommentsOnly: hash-comment languages have no C-style comments', () => {
  it('keeps python floor division intact', () => {
    const out = stripCommentsOnly('chunk = total // parts\n', true);
    expect(out).toBe('chunk = total // parts\n');
  });

  it('keeps a python block-comment-shaped expression intact', () => {
    const source = 'a = x /* y\nSECRET = "hunter2"\n';
    expect(stripCommentsOnly(source, true)).toBe(source);
  });

  it('keeps an unquoted .env URL whole, host and path included', () => {
    const source = 'API_URL=https://internal.example.com/admin\n';
    const out = stripCommentsOnly(source, true);
    expect(out).toBe(source);
    expect(out).toContain('internal.example.com');
    expect(out).toContain('/admin');
  });

  it('keeps an unquoted YAML URL whole', () => {
    const source = 'callback: https://example.com//oauth\n';
    expect(stripCommentsOnly(source, true)).toBe(source);
  });

  it('still strips `#` line comments in a hash-comment language', () => {
    const out = stripCommentsOnly('DEBUG = True  # SECRET_KEY = "hunter2"\n', true);
    expect(out).toContain('DEBUG = True');
    expect(out).not.toContain('hunter2');
  });

  it('preserves every newline and the exact length', () => {
    const source = 'a = 1 // 2\n# gone\nb = "keep"\n';
    const out = stripCommentsOnly(source, true);
    expect(out).toHaveLength(source.length);
    expect(out.split('\n')).toHaveLength(source.split('\n').length);
  });
});

describe('stripCommentsOnly: C-style languages are unchanged by the fix', () => {
  it('still strips a `//` line comment', () => {
    const out = stripCommentsOnly('const a = 1; // secret = "x"\n', false);
    expect(out).toContain('const a = 1;');
    expect(out).not.toContain('secret');
  });

  it('still strips a block comment', () => {
    const out = stripCommentsOnly('/* res.cookie("session", id); */\nconst b = 2;\n', false);
    expect(out).not.toContain('res.cookie');
    expect(out).toContain('const b = 2;');
  });

  it('never treats `#` as a comment, so a private class field survives', () => {
    const source = 'class A { #secret = 1; get x() { return this.#secret; } }\n';
    expect(stripCommentsOnly(source, false)).toBe(source);
  });

  it('does not mistake a `//` inside a string literal for a comment', () => {
    const source = 'const u = "https://example.com/x"; const b = 2;\n';
    expect(stripCommentsOnly(source, false)).toBe(source);
  });
});

describe('usesHashComments: one definition, and the label is part of it', () => {
  it('covers every extension the four former private copies disagreed about', () => {
    for (const extension of ['.py', '.rb', '.yaml', '.yml', '.toml', '.env']) {
      expect(usesHashComments(extension)).toBe(true);
    }
  });

  it('is false for the C-style extensions', () => {
    for (const extension of ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.json']) {
      expect(usesHashComments(extension)).toBe(false);
    }
  });

  it('recognises a dotted env file by LABEL, which its extension cannot say', () => {
    expect(usesHashComments('.development')).toBe(false);
    expect(usesHashComments('.development', 'env')).toBe(true);
  });

  it('is exactly HASH_COMMENT_EXTENSIONS, so the set cannot drift from the check', () => {
    for (const extension of HASH_COMMENT_EXTENSIONS) {
      expect(usesHashComments(extension)).toBe(true);
    }
    expect([...HASH_COMMENT_EXTENSIONS].sort()).toEqual(
      ['.env', '.py', '.rb', '.toml', '.yaml', '.yml'],
    );
  });

  it('does NOT claim PHP, which uses both `#` and `//`', () => {
    expect(usesHashComments('.php')).toBe(false);
  });
});
