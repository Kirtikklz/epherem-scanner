import { describe, expect, it } from 'vitest';
import { dangerousCorsWildcard } from '../../src/rules/basic/dangerousCorsWildcard.js';
import { unsafeFileUpload } from '../../src/rules/basic/unsafeFileUpload.js';
import { commandInjection } from '../../src/rules/basic/commandInjection.js';
import { openRedirect } from '../../src/rules/basic/openRedirect.js';
import { memoryContext } from './helpers.js';

const NEXT = ['package.json', '{"dependencies":{"next":"14.0.0"}}'] as [string, string];
const rulesFor = (files: [string, string][], rule: { run: (c: never) => unknown }) =>
  rule.run(memoryContext(files) as never) as { filePath: string; lineStart: number; severity: string }[];

describe('unsafe_file_upload: the Web-standard upload shape', () => {
  const UPLOAD = (body: string) => `import { writeFile } from 'node:fs/promises';\nimport path from 'node:path';\nexport async function POST(request: Request) {\n${body}\n}\n`;

  it('fires when a client-supplied filename is concatenated into a server path', () => {
    const findings = rulesFor(
      [
        NEXT,
        [
          'app/api/upload/route.ts',
          UPLOAD(
            '  const form = await request.formData();\n' +
              "  const file = form.get('file') as File;\n" +
              '  const target = path.join(UPLOAD_DIR, `${id}-${file.name}`);\n' +
              '  await writeFile(target, Buffer.from(await file.arrayBuffer()));\n' +
              '  return Response.json({ ok: true });',
          ),
        ],
      ],
      unsafeFileUpload,
    );
    expect(findings.map((finding) => finding.filePath)).toContain('app/api/upload/route.ts');
  });

  it('stays quiet when the filename is sanitised before being joined', () => {
    const findings = rulesFor(
      [
        NEXT,
        [
          'app/api/upload/route.ts',
          UPLOAD(
            '  const form = await request.formData();\n' +
              "  const file = form.get('file') as File;\n" +
              '  const target = path.join(UPLOAD_DIR, path.basename(file.name));\n' +
              '  await writeFile(target, Buffer.from(await file.arrayBuffer()));\n' +
              '  return Response.json({ ok: true });',
          ),
        ],
      ],
      unsafeFileUpload,
    );
    expect(findings).toHaveLength(0);
  });

  it('stays quiet when the stored name is server-generated', () => {
    const findings = rulesFor(
      [
        NEXT,
        [
          'app/api/upload/route.ts',
          UPLOAD(
            '  const form = await request.formData();\n' +
              "  const file = form.get('file') as File;\n" +
              '  await writeFile(path.join(UPLOAD_DIR, `${randomUUID()}.png`), Buffer.from(await file.arrayBuffer()));\n' +
              '  return Response.json({ ok: true });',
          ),
        ],
      ],
      unsafeFileUpload,
    );
    expect(findings).toHaveLength(0);
  });
});

describe('dangerous_cors_wildcard: origin reflection', () => {
  const reflect = (guard: string) =>
    'export async function GET(request: Request) {\n' +
    "  const origin = request.headers.get('origin') ?? '';\n" +
    `${guard}` +
    '  const response = Response.json({});\n' +
    "  response.headers.set('access-control-allow-origin', origin);\n" +
    "  response.headers.set('access-control-allow-credentials', 'true');\n" +
    '  return response;\n' +
    '}\n';

  it('fires on a reflected origin with credentials and no allowlist', () => {
    const findings = rulesFor([NEXT, ['app/api/x/route.ts', reflect('')]], dangerousCorsWildcard);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('high');
  });

  it('stays quiet when the origin is tested for EXACT membership of an allowlist', () => {
    const findings = rulesFor(
      [NEXT, ['app/api/x/route.ts', reflect('  if (!ALLOWED_ORIGINS.includes(origin)) return new Response(null, { status: 403 });\n')]],
      dangerousCorsWildcard,
    );
    expect(findings).toHaveLength(0);
  });

  it('STILL FIRES when the "allowlist" is a prefix test — that is the bug, not the control', () => {
    const findings = rulesFor(
      [NEXT, ['app/api/x/route.ts', reflect("  if (!origin.startsWith('https://app.example.com')) return new Response(null, { status: 403 });\n")]],
      dangerousCorsWildcard,
    );
    expect(findings).toHaveLength(1);
  });

  it('sees a hardcoded wildcard written in lowercase', () => {
    const findings = rulesFor(
      [
        NEXT,
        [
          'app/api/x/route.ts',
          'export async function GET() {\n' +
            '  const response = Response.json({});\n' +
            "  response.headers.set('access-control-allow-origin', '*');\n" +
            '  return response;\n' +
            '}\n',
        ],
      ],
      dangerousCorsWildcard,
    );
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });
});

describe('command_injection: promisify(exec)', () => {
  it('fires on a promisified exec called through a local alias', () => {
    const findings = rulesFor(
      [
        NEXT,
        [
          'app/api/export/route.ts',
          "import { exec } from 'node:child_process';\n" +
            "import { promisify } from 'node:util';\n" +
            'const run = promisify(exec);\n' +
            'export async function POST(request: Request) {\n' +
            '  const { name } = await request.json();\n' +
            '  await run(`zip -r out.zip ${name}`);\n' +
            '  return Response.json({ ok: true });\n' +
            '}\n',
        ],
      ],
      commandInjection,
    );
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('stays quiet when the promisified alias is given a fixed command', () => {
    const findings = rulesFor(
      [
        NEXT,
        [
          'app/api/export/route.ts',
          "import { execFile } from 'node:child_process';\n" +
            "import { promisify } from 'node:util';\n" +
            'const run = promisify(execFile);\n' +
            'export async function POST(request: Request) {\n' +
            '  const { name } = await request.json();\n' +
            "  await run('/usr/local/bin/render', [name]);\n" +
            '  return Response.json({ ok: true });\n' +
            '}\n',
        ],
      ],
      commandInjection,
    );
    expect(findings).toHaveLength(0);
  });

  it('does not treat promisify of a BARE non-shell function as a command sink', () => {
    const findings = rulesFor(
      [
        NEXT,
        [
          'app/api/wait/route.ts',
          "import { setTimeout } from 'node:timers';\n" +
            "import { promisify } from 'node:util';\n" +
            'const delay = promisify(setTimeout);\n' +
            'export async function POST(request: Request) {\n' +
            '  const { ms } = await request.json();\n' +
            '  await delay(`${ms}`);\n' +
            '  return Response.json({ ok: true });\n' +
            '}\n',
        ],
      ],
      commandInjection,
    );
    expect(findings).toHaveLength(0);
  });

  it('does not treat promisify of a non-shell MEMBER function as a command sink', () => {
    const findings = rulesFor(
      [
        NEXT,
        [
          'app/api/read/route.ts',
          "import fs from 'node:fs';\n" +
            "import { promisify } from 'node:util';\n" +
            'const read = promisify(fs.readFile);\n' +
            'export async function POST(request: Request) {\n' +
            '  const { name } = await request.json();\n' +
            '  await read(`/data/${name}`);\n' +
            '  return Response.json({ ok: true });\n' +
            '}\n',
        ],
      ],
      commandInjection,
    );
    expect(findings).toHaveLength(0);
  });
});

describe('open_redirect: redirect(status, url)', () => {
  it('fires when the DESTINATION is user-controlled and a status is passed first', () => {
    const findings = rulesFor(
      [
        NEXT,
        [
          'app/api/go/route.ts',
          "import { redirect } from '@sveltejs/kit';\n" +
            'export async function GET({ url }) {\n' +
            "  const destination = url.searchParams.get('u') ?? '/';\n" +
            '  throw redirect(302, destination);\n' +
            '}\n',
        ],
      ],
      openRedirect,
    );
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('stays quiet when the destination beside a status is a same-origin literal', () => {
    const findings = rulesFor(
      [
        NEXT,
        [
          'app/api/go/route.ts',
          "import { redirect } from '@sveltejs/kit';\n" +
            'export async function GET() {\n' +
            "  throw redirect(303, '/dashboard');\n" +
            '}\n',
        ],
      ],
      openRedirect,
    );
    expect(findings).toHaveLength(0);
  });
});
