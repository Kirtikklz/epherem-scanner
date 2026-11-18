import { describe, expect, it } from 'vitest';

import { clientSideAiSecret } from '../../src/rules/basic/clientSideAiSecret.js';
import { hardcodedSecret } from '../../src/rules/basic/hardcodedSecret.js';
import { memoryContext } from './helpers.js';

const run = (files: [string, string][]): string[] =>
  clientSideAiSecret.run(memoryContext(files)).map((f) => `${f.filePath}:${f.lineStart}`);

const titles = (files: [string, string][]): string[] =>
  clientSideAiSecret.run(memoryContext(files)).map((f) => f.title);

const hardcoded = (files: [string, string][]): string[] =>
  hardcodedSecret.run(memoryContext(files)).map((f) => f.title);

const OPENAI_KEY = ('sk' + '-proj-Zx91QpLm4Tv7Nb2Rd8Ke6Hs3Wq5Yc0Uj');
const ANTHROPIC_KEY = ('sk' + '-ant-api03-Zx91QpLm4Tv7Nb2Rd8Ke6Hs3Wq5Yc0Uj');
const GROQ_KEY = ('gs' + 'k_Zx91QpLm4Tv7Nb2Rd8Ke6Hs3Wq5Yc0Uj');

const clientComponent = (body: string): string => `'use client';\n${body}\n`;

describe('condition 1 — dangerouslyAllowBrowser', () => {
  it('MUST FIRE: the flag handed to an AI SDK client', () => {
    expect(
      run([
        [
          'src/components/Chat.tsx',
          clientComponent(
            "import OpenAI from 'openai';\nconst client = new OpenAI({ apiKey: key, dangerouslyAllowBrowser: true });",
          ),
        ],
      ]),
    ).toEqual(['src/components/Chat.tsx:3']);
  });

  it('MUST FIRE: in a module the client-bundle closure never reached', () => {
    expect(
      run([['lib/ai.ts', 'export const client = new OpenAI({ dangerouslyAllowBrowser: true });']]),
    ).toEqual(['lib/ai.ts:1']);
  });

  it('MUST FIRE: inside a script block in a plain HTML page', () => {
    expect(
      run([
        [
          'public/widget.html',
          '<script type="module">\n  const c = new OpenAI({ dangerouslyAllowBrowser: true });\n</script>',
        ],
      ]),
    ).toEqual(['public/widget.html:2']);
  });

  it('accepts the quoted-key and assignment spellings', () => {
    expect(
      run([
        ['src/a.tsx', clientComponent('const o = { "dangerouslyAllowBrowser": true };')],
        ['src/b.tsx', clientComponent('options.dangerouslyAllowBrowser = true;')],
      ]),
    ).toEqual(['src/a.tsx:2', 'src/b.tsx:2']);
  });

  it('names itself, so a reader can tell which condition fired', () => {
    expect(
      titles([['src/a.tsx', clientComponent('new OpenAI({ dangerouslyAllowBrowser: true })')]]),
    ).toEqual(['AI provider client enabled in the browser: dangerouslyAllowBrowser']);
  });

  it('MUST STAY QUIET: the flag set to false', () => {
    expect(
      run([['src/a.tsx', clientComponent('new OpenAI({ dangerouslyAllowBrowser: false })')]]),
    ).toEqual([]);
  });

  it('MUST STAY QUIET: the flag set to a variable', () => {
    expect(
      run([['src/a.tsx', clientComponent('new OpenAI({ dangerouslyAllowBrowser: isPreview })')]]),
    ).toEqual([]);
  });

  it('MUST STAY QUIET: the flag inside a comment', () => {
    expect(
      run([
        ['src/a.tsx', clientComponent('// new OpenAI({ dangerouslyAllowBrowser: true })')],
        ['src/b.tsx', clientComponent('/* dangerouslyAllowBrowser: true */')],
      ]),
    ).toEqual([]);
  });

  it('MUST STAY QUIET: the flag inside an HTML comment', () => {
    expect(
      run([
        [
          'public/widget.html',
          '<!--\n  new OpenAI({ dangerouslyAllowBrowser: true });\n-->',
        ],
      ]),
    ).toEqual([]);
  });

  it('MUST STAY QUIET: the flag quoted inside a string literal', () => {
    expect(
      run([
        [
          'src/Docs.tsx',
          clientComponent('const sample = "new OpenAI({ dangerouslyAllowBrowser: true })";'),
        ],
      ]),
    ).toEqual([]);
  });

  it('MUST STAY QUIET: the flag in a JSON or Markdown file', () => {
    expect(
      run([
        ['config/ai.json', '{ "dangerouslyAllowBrowser": true }'],
        ['README.md', 'Pass `dangerouslyAllowBrowser: true` to run in the browser.'],
      ]),
    ).toEqual([]);
  });
});

describe('condition 2 — the key itself, in the bundle', () => {
  it('MUST FIRE: an OpenAI key in a client component', () => {
    expect(
      run([['src/components/Chat.tsx', clientComponent(`const key = '${OPENAI_KEY}';`)]]),
    ).toEqual(['src/components/Chat.tsx:2']);
  });

  it('MUST FIRE: an Anthropic key in a client component', () => {
    expect(
      run([['src/components/Chat.tsx', clientComponent(`const key = '${ANTHROPIC_KEY}';`)]]),
    ).toEqual(['src/components/Chat.tsx:2']);
  });

  it('MUST FIRE: a Groq key, one of the later signatures', () => {
    expect(run([['src/components/Chat.tsx', clientComponent(`const key = '${GROQ_KEY}';`)]])).toEqual(
      ['src/components/Chat.tsx:2'],
    );
  });

  it('reports an sk-ant- key exactly once, named Anthropic', () => {
    expect(
      titles([['src/components/Chat.tsx', clientComponent(`const key = '${ANTHROPIC_KEY}';`)]]),
    ).toEqual(['AI provider secret is exposed to the browser: Anthropic API key']);
  });

  it('MUST FIRE: a key in a module a client component imports', () => {
    expect(
      run([
        [
          'src/components/Chat.tsx',
          clientComponent("import { key } from '../lib/keys';\nconsole.log(key);"),
        ],
        ['src/lib/keys.ts', `export const key = '${OPENAI_KEY}';`],
      ]),
    ).toEqual(['src/lib/keys.ts:1']);
  });
});

describe('condition 2 — the guards, and who reports instead', () => {
  it('MUST STAY QUIET: the same key read server-side — and hardcoded_secret reports it', () => {
    const files: [string, string][] = [
      ['app/api/chat/route.ts', `const key = process.env.OPENAI_API_KEY ?? '${OPENAI_KEY}';`],
    ];
    expect(run(files)).toEqual([]);
    expect(hardcoded(files)).toEqual(['Hardcoded secret in source code: OpenAI API key']);
  });

  it('MUST STAY QUIET: a server route reading the key from process.env', () => {
    const files: [string, string][] = [
      [
        'app/api/chat/route.ts',
        "import OpenAI from 'openai';\nconst client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });",
      ],
    ];
    expect(run(files)).toEqual([]);
    expect(hardcoded(files)).toEqual([]);
  });

  it('MUST STAY QUIET: a NEXT_PUBLIC_ publishable value in the same client file', () => {
    const files: [string, string][] = [
      [
        'src/components/Chat.tsx',
        clientComponent(
          "const url = process.env.NEXT_PUBLIC_SUPABASE_URL;\nconst anon = 'sb_publishable_Zx91QpLm4Tv7Nb2Rd8Ke6Hs3';",
        ),
      ],
    ];
    expect(run(files)).toEqual([]);
    expect(hardcoded(files)).toEqual([]);
  });

  it('MUST FIRE: an AI key under a NEXT_PUBLIC_ name — the prefix does not pardon it', () => {
    expect(
      run([
        [
          'src/components/Chat.tsx',
          clientComponent(`const NEXT_PUBLIC_GROQ_KEY = '${GROQ_KEY}';`),
        ],
      ]),
    ).toEqual(['src/components/Chat.tsx:2']);
  });

  it('MUST STAY QUIET: a placeholder key — and hardcoded_secret still has it', () => {
    const files: [string, string][] = [
      ['src/a.tsx', clientComponent(("const key = 'sk" + "-your-openai-api-key-goes-here';"))],
      ['src/b.tsx', clientComponent(("const key = 'sk" + "-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';"))],
    ];
    expect(run(files)).toEqual([]);
    expect(hardcoded(files)).toHaveLength(2);
  });

  it('MUST STAY QUIET: a masked key', () => {
    expect(
      run([
        ['src/a.tsx', clientComponent(("const key = 'sk" + "-ant-api03-REDACTED-Zx91QpLm4Tv7Nb2Rd8';"))],
        ['src/b.tsx', clientComponent("const key = 'sk-proj-Zx91QpLm4T****************';")],
      ]),
    ).toEqual([]);
  });

  it('MUST STAY QUIET: a server-only new OpenAI() with no browser flag', () => {
    const files: [string, string][] = [
      [
        'server/ai.ts',
        "import OpenAI from 'openai';\nexport const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });",
      ],
    ];
    expect(run(files)).toEqual([]);
    expect(hardcoded(files)).toEqual([]);
  });
});

describe('the hand-off between the two rules', () => {
  const cases: [string, [string, string][]][] = [
    ['client component, real key', [['src/a.tsx', clientComponent(`const k = '${OPENAI_KEY}';`)]]],
    ['server route, real key', [['app/api/r/route.ts', `const k = '${OPENAI_KEY}';`]]],
    ['client component, placeholder', [['src/a.tsx', clientComponent(("const k = 'sk" + "-your-key-here-aaaaaaaa';"))]]],
    ['client component, masked', [['src/a.tsx', clientComponent(("const k = 'sk" + "-proj-REDACTED-aaaaaaaaaaaaaaaa';"))]]],
    ['client component, Groq key', [['src/a.tsx', clientComponent(`const k = '${GROQ_KEY}';`)]]],
  ];

  for (const [label, files] of cases) {
    it(`exactly one rule reports the literal: ${label}`, () => {
      const context = memoryContext(files);
      const mine = clientSideAiSecret.run(context).filter((f) => f.title.includes('key') || f.title.includes('token'));
      const theirs = hardcodedSecret.run(context);
      expect(mine.length + theirs.length, `${label}: ${mine.length} + ${theirs.length}`).toBeGreaterThan(0);
      expect(mine.length === 0 || theirs.length === 0, `${label}: both rules reported`).toBe(true);
    });
  }

  it('a non-AI provider key in a client component is unaffected', () => {
    const files: [string, string][] = [
      ['src/a.tsx', clientComponent(("const k = 'sk" + "_live_Zx91QpLm4Tv7Nb2Rd8Ke';"))],
    ];
    expect(run(files)).toEqual([]);
    expect(hardcoded(files)).toEqual(['Hardcoded secret in source code: Stripe live secret key']);
  });
});
