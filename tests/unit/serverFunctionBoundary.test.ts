import { describe, expect, it } from 'vitest';
import {
  isInsideServerFunctionHandler,
  serverFunctionHandlerLineRanges,
} from '../../src/shared/serverFunctionBoundary.js';
import { envUsageWithoutServerBoundary } from '../../src/rules/contextual/envUsageWithoutServerBoundary.js';
import { memoryContext } from './helpers.js';

const PKG = '{"name":"x","dependencies":{"@tanstack/react-start":"1.0.0","react":"18.0.0"}}';

describe('server-function handler boundaries', () => {
  it('finds the handler body of a fluent createServerFn chain', () => {
    const source = [
      'import { createServerFn } from "@tanstack/react-start";',
      'export const synth = createServerFn({ method: "POST" })',
      '  .middleware([requireAuth])',
      '  .inputValidator((input: unknown) => Schema.parse(input))',
      '  .handler(async ({ data, context }) => {',
      '    const key = process.env.OPENAI_API_KEY;',
      '    return call(key, data);',
      '  });',
    ].join('\n');
    expect(serverFunctionHandlerLineRanges(source)).toEqual([{ startLine: 5, endLine: 8 }]);
    expect(isInsideServerFunctionHandler(source, 6)).toBe(true);
    expect(isInsideServerFunctionHandler(source, 2)).toBe(false);
  });

  it('the destructuring pattern in the parameter list is not mistaken for the body', () => {
    const source = [
      'export const fn = createServerFn().handler(async ({ data }) => {',
      '  const key = process.env.STRIPE_SECRET_KEY;',
      '  return key;',
      '});',
    ].join('\n');
    expect(serverFunctionHandlerLineRanges(source)).toEqual([{ startLine: 1, endLine: 4 }]);
    expect(isInsideServerFunctionHandler(source, 2)).toBe(true);
  });

  it('two declarations in one file get two separate boundaries', () => {
    const source = [
      'export const a = createServerFn().handler(async () => {',
      '  return 1;',
      '});',
      'const leaked = process.env.API_SECRET;',
      'export const b = createServerFn().handler(async () => {',
      '  return 2;',
      '});',
    ].join('\n');
    expect(serverFunctionHandlerLineRanges(source)).toEqual([
      { startLine: 1, endLine: 3 },
      { startLine: 5, endLine: 7 },
    ]);
    expect(isInsideServerFunctionHandler(source, 4)).toBe(false);
  });

  it('a createServerFn quoted inside a string creates no boundary', () => {
    const source = [
      'const sample = "createServerFn().handler(async () => { x })";',
      'const key = process.env.API_SECRET;',
    ].join('\n');
    expect(serverFunctionHandlerLineRanges(source)).toEqual([]);
  });

  it('a handler passed as a bare reference yields no boundary (reports, never guesses)', () => {
    const source = 'export const a = createServerFn().handler(namedHandler);\n';
    expect(serverFunctionHandlerLineRanges(source)).toEqual([]);
  });
});

describe('env_usage_without_server_boundary: real boundaries only', () => {
  it('suppresses a secret read inside a createServerFn handler body', () => {
    const context = memoryContext([
      ['package.json', PKG],
      [
        'src/components/Chat.tsx',
        'import { stylistChat } from "@/lib/chat.functions";\n' +
          'export default function Chat() { return <button onClick={() => stylistChat()}>go</button>; }\n',
      ],
      [
        'src/lib/chat.functions.ts',
        'import { createServerFn } from "@tanstack/react-start";\n' +
          'export const stylistChat = createServerFn({ method: "POST" })\n' +
          '  .handler(async ({ data }) => {\n' +
          '    const key = process.env.LOVABLE_API_KEY;\n' +
          '    return fetch("https://ai.example", { headers: { authorization: key } });\n' +
          '  });\n',
      ],
    ]);
    expect(envUsageWithoutServerBoundary.run(context)).toHaveLength(0);
  });

  it('still fires for a module-scope secret read in a file that ALSO has a server function', () => {
    const context = memoryContext([
      ['package.json', PKG],
      [
        'src/components/Chat.tsx',
        'import { stylistChat } from "@/lib/chat.functions";\n' +
          'export default function Chat() { return <button onClick={() => stylistChat()}>go</button>; }\n',
      ],
      [
        'src/lib/chat.functions.ts',
        'import { createServerFn } from "@tanstack/react-start";\n' +
          'const key = process.env.LOVABLE_API_KEY;\n' +
          'export const stylistChat = createServerFn({ method: "POST" })\n' +
          '  .handler(async ({ data }) => {\n' +
          '    return fetch("https://ai.example", { headers: { authorization: key } });\n' +
          '  });\n',
      ],
    ]);
    const findings = envUsageWithoutServerBoundary.run(context);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.filePath).toBe('src/lib/chat.functions.ts');
    expect(findings[0]?.lineStart).toBe(2);
  });

  it('still fires for a secret read in ordinary browser code', () => {
    const context = memoryContext([
      ['package.json', PKG],
      [
        'src/components/Widget.tsx',
        'export default function Widget() {\n' +
          '  const key = process.env.STRIPE_SECRET_KEY;\n' +
          '  return <span>{key}</span>;\n' +
          '}\n',
      ],
    ]);
    const findings = envUsageWithoutServerBoundary.run(context);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.filePath).toBe('src/components/Widget.tsx');
  });

  it('does not exempt a client component merely named like a server module', () => {
    const context = memoryContext([
      ['package.json', PKG],
      [
        'src/components/Dashboard.server.helper.tsx',
        'export default function D() {\n' +
          '  const key = process.env.STRIPE_SECRET_KEY;\n' +
          '  return <span>{key}</span>;\n' +
          '}\n',
      ],
    ]);
    expect(envUsageWithoutServerBoundary.run(context)).toHaveLength(1);
  });
});

describe('*.server.<ext> is a server boundary', () => {
  const files: [string, string][] = [
    ['package.json', PKG],
    [
      'src/components/Calendar.tsx',
      'import { connect } from "@/lib/calendar.functions";\n' +
        'export default function Cal() { return <button onClick={connect}>go</button>; }\n',
    ],
    [
      'src/lib/calendar.functions.ts',
      'export async function connect() {\n' +
        '  const { buildAuthUrl } = await import("./google-calendar.server");\n' +
        '  return buildAuthUrl();\n' +
        '}\n',
    ],
    [
      'src/lib/google-calendar.server.ts',
      'import { sign } from "./token-mint.server";\n' +
        'export function buildAuthUrl() {\n' +
        '  const secret = process.env.GOOGLE_CALENDAR_CLIENT_SECRET;\n' +
        '  return sign(secret);\n' +
        '}\n',
    ],
    [
      'src/lib/token-mint.server.ts',
      'export function sign(s: string) { return process.env.JWT_SECRET + s; }\n',
    ],
  ];

  it('a .server module is server-side and outside the client bundle', () => {
    const { projectMap } = memoryContext(files);
    expect(projectMap.publicClientUsage).not.toContain('src/lib/google-calendar.server.ts');
    expect(projectMap.serverSideUsage).toContain('src/lib/google-calendar.server.ts');
  });

  it('cuts the import closure — what only a .server module imports is server-side too', () => {
    const { projectMap } = memoryContext(files);
    expect(projectMap.publicClientUsage).not.toContain('src/lib/token-mint.server.ts');
  });

  it('no env_usage findings for secrets read inside .server modules', () => {
    const context = memoryContext(files);
    expect(envUsageWithoutServerBoundary.run(context)).toHaveLength(0);
  });

  it('every .server extension the frameworks accept is recognised', () => {
    for (const ext of ['ts', 'tsx', 'js', 'jsx', 'mjs', 'cjs']) {
      const { projectMap } = memoryContext([
        ['package.json', PKG],
        [
          'src/App.tsx',
          `import { go } from "./secrets.server";\nexport default function A() { return <b>{go()}</b>; }\n`,
        ],
        [`src/secrets.server.${ext}`, 'export function go() { return process.env.API_SECRET; }\n'],
      ]);
      expect(projectMap.publicClientUsage, ext).not.toContain(`src/secrets.server.${ext}`);
    }
  });
});
