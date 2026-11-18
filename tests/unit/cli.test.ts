import { createHash } from 'node:crypto';
import { cp, mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, afterEach, beforeEach, describe, expect, it } from 'vitest';
import { parseArgs, runCli, VERSION, type CliIo } from '../../src/cli.js';
import { HTML_REPORT_MARKER } from '../../src/report/htmlReport.js';
import { NOT_EVERYTHING } from '../../src/report/reportModel.js';
import { PROMPTS_ELSEWHERE } from '../../src/report/textReport.js';
import type { ScanReport } from '../../src/shared/types.js';
import { fixturePath } from './helpers.js';

const CANARY = 'epherem-canary-3f7a91c2';

interface Sent {
  url: string;
  method: string;
  body: string;
}
let sent: Sent[] = [];
const realFetch = globalThis.fetch;
beforeEach(() => {
  sent = [];
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = input instanceof Request ? input.url : String(input);
    const body = init?.body === undefined || init.body === null ? '' : typeof init.body === 'string' ? init.body : '<not a string>';
    sent.push({ url, method: init?.method ?? 'GET', body });
    if (url === 'https://api.osv.dev/v1/querybatch') {
      const queries = (JSON.parse(body) as { queries: unknown[] }).queries;
      return new Response(JSON.stringify({ results: queries.map(() => ({})) }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return new Response('{}', { status: 404, headers: { 'content-type': 'application/json' } });
  }) as typeof fetch;
});
afterEach(() => {
  globalThis.fetch = realFetch;
});

const temps: string[] = [];
afterAll(async () => {
  for (const dir of temps) await rm(dir, { recursive: true, force: true });
});
async function tempDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), prefix));
  temps.push(dir);
  return dir;
}

async function makeProject(): Promise<string> {
  const project = path.join(await tempDir('epherem-cli-project-'), 'shop-app');
  await cp(fixturePath('next-supabase-insecure'), project, { recursive: true });
  const mark = (name: string): string => `require('fs').writeFileSync(require('path').join(__dirname, 'RAN-${name}'), 'ran');`;
  await writeFile(path.join(project, 'next.config.js'), `${mark('next-config')}\nmodule.exports = {};\n`);
  await writeFile(path.join(project, 'run_me.py'), "open('RAN-python', 'w').write('ran')\n");
  const pkg = JSON.parse(await readFile(path.join(project, 'package.json'), 'utf8')) as Record<string, unknown>;
  const script = (name: string): string => `node -e "require('fs').writeFileSync('RAN-${name}', 'ran')"`;
  pkg.scripts = { preinstall: script('preinstall'), postinstall: script('postinstall'), prepare: script('prepare'), build: script('build'), test: script('test') };
  pkg.main = 'next.config.js';
  await writeFile(path.join(project, 'package.json'), `${JSON.stringify(pkg, null, 2)}\n`);
  await writeFile(path.join(project, 'lib', 'canary.ts'), `export const CANARY = '${CANARY}';\n`);
  return project;
}

async function snapshot(dir: string): Promise<string[]> {
  const out: string[] = [];
  const walk = async (rel: string): Promise<void> => {
    for (const entry of await readdir(path.join(dir, rel), { withFileTypes: true })) {
      const r = rel === '' ? entry.name : `${rel}/${entry.name}`;
      const full = path.join(dir, r);
      const info = await stat(full);
      if (entry.isDirectory()) {
        out.push(`${r}/ ${info.mtimeMs}`);
        await walk(r);
      } else {
        out.push(`${r} ${info.size} ${info.mtimeMs} ${createHash('sha256').update(await readFile(full)).digest('hex')}`);
      }
    }
  };
  await walk('');
  return out.sort();
}

function capture(cwd: string): CliIo & { stdout: () => string; stderr: () => string } {
  const out: string[] = [];
  const err: string[] = [];
  return {
    out: (text) => out.push(text),
    err: (text) => err.push(text),
    cwd,
    color: false,
    stdout: () => out.join(''),
    stderr: () => err.join(''),
  };
}

describe('epherem-scanner on a project', () => {
  it('prints the report, says the mode first, runs nothing and writes nothing', async () => {
    const project = await makeProject();
    const cwd = await tempDir('epherem-cli-cwd-');
    const beforeProject = await snapshot(project);
    const beforeCwd = await snapshot(cwd);
    const io = capture(cwd);

    const code = await runCli([project, '--offline'], io);

    expect(io.stderr()).toBe('');
    expect(code).toBe(0);
    const text = io.stdout();
    expect(text.split('\n')[0]).toMatch(/^Package check: offline/);
    expect(text).toContain('Epherem security report: shop-app');
    expect(text).toContain('Findings, most serious first');
    expect(text).toContain('supabase_service_role_exposed');
    expect(text).toContain(PROMPTS_ELSEWHERE);
    expect(text).not.toContain('You are triaging');
    expect(text).toContain("What this scan couldn't check");
    expect(text.trimEnd().endsWith(NOT_EVERYTHING)).toBe(true);
    expect(text).not.toContain('\u001b');
    expect(await snapshot(project)).toEqual(beforeProject);
    expect(await snapshot(cwd)).toEqual(beforeCwd);
    expect(beforeProject.some((line) => line.startsWith('RAN-'))).toBe(false);
    expect(sent).toEqual([]);
  });

  it('online, sends only package names, versions and ecosystems to api.osv.dev', async () => {
    const project = await makeProject();
    const io = capture(await tempDir('epherem-cli-cwd-'));
    const code = await runCli([project], io);
    expect(code).toBe(0);
    expect(io.stdout().split('\n')[0]).toMatch(/^Package check: online/);
    expect(sent.length).toBeGreaterThan(0);
    for (const request of sent) {
      expect(request.url.startsWith('https://api.osv.dev/')).toBe(true);
      expect(request.body).not.toContain(CANARY);
      expect(request.body).not.toContain('shop-app');
      if (request.url.endsWith('/v1/querybatch')) {
        const { queries } = JSON.parse(request.body) as { queries: Record<string, unknown>[] };
        for (const query of queries) {
          expect(Object.keys(query).sort()).toEqual(['package', 'version']);
          expect(Object.keys(query.package as object).sort()).toEqual(['ecosystem', 'name']);
        }
      }
    }
  });

  it('--json prints the whole report as JSON and nothing else on standard output', async () => {
    const project = await makeProject();
    const io = capture(await tempDir('epherem-cli-cwd-'));
    const code = await runCli([project, '--offline', '--json', '--severity', 'high'], io);
    expect(code).toBe(0);
    const report = JSON.parse(io.stdout()) as ScanReport;
    expect(report.findings.length).toBeGreaterThan(0);
    expect(report.findings.some((f) => f.severity === 'medium' || f.severity === 'low')).toBe(true);
    expect(report.findings.every((f) => typeof f.fixPrompt === 'string' && f.fixPrompt.startsWith('You are triaging'))).toBe(true);
    expect(io.stderr()).toMatch(/^Package check: offline/);
    expect(io.stderr()).toContain('--json prints every finding');
  });

  it('--severity hides lower findings but still counts them, and says how many it hid', async () => {
    const project = await makeProject();
    const all = capture(await tempDir('epherem-cli-cwd-'));
    await runCli([project, '--offline'], all);
    const high = capture(await tempDir('epherem-cli-cwd-'));
    expect(await runCli([project, '--offline', '--severity', 'high'], high)).toBe(0);
    const counts = (text: string): string => text.split('\n').filter((l) => l.startsWith('Findings: ') || l.startsWith('By severity: ')).join('\n');
    expect(counts(high.stdout())).toBe(counts(all.stdout()));
    expect(high.stdout()).toMatch(/Showing findings at High or above: \d+ findings? below High (?:is|are) hidden/);
    expect(high.stdout()).not.toMatch(/Severity: (?:Medium|Low)/);
    expect(all.stdout()).toMatch(/Severity: (?:Medium|Low)/);
  });
});

describe('--html', () => {
  it('writes exactly one self-contained file outside the project', async () => {
    const project = await makeProject();
    const out = await tempDir('epherem-cli-out-');
    const beforeProject = await snapshot(project);
    const io = capture(out);
    const code = await runCli([project, '--offline', '--html', 'report.html'], io);
    expect(code).toBe(0);
    expect(await readdir(out)).toEqual(['report.html']);
    expect(await snapshot(project)).toEqual(beforeProject);
    const html = await readFile(path.join(out, 'report.html'), 'utf8');
    expect(html).toContain(HTML_REPORT_MARKER);
    expect(html).toContain("default-src 'none'");
    expect(html).not.toMatch(/<script|<link|<img|<iframe|src=|https?:\/\//i);
    expect(io.stdout()).toContain(`Saved the report as a web page: ${path.join(out, 'report.html')}`);
  });

  it('refuses a file inside the scanned folder, before scanning, and writes nothing', async () => {
    const project = await makeProject();
    const before = await snapshot(project);
    for (const target of [path.join(project, 'report.html'), path.join(project, 'lib', 'new', 'report.html')]) {
      const io = capture(project);
      expect(await runCli(['.', '--offline', '--html', target], io)).toBe(1);
      expect(io.stderr()).toContain('Epherem never saves anything inside the project it scans');
      expect(io.stdout()).toBe('');
    }
    expect(await snapshot(project)).toEqual(before);
  });

  it('never replaces a file that is not an earlier Epherem report', async () => {
    const project = await makeProject();
    const out = await tempDir('epherem-cli-out-');
    await writeFile(path.join(out, 'notes.html'), '<p>my notes</p>');
    const io = capture(out);
    expect(await runCli([project, '--offline', '--html', 'notes.html'], io)).toBe(1);
    expect(io.stderr()).toContain("isn't an Epherem report");
    expect(await readFile(path.join(out, 'notes.html'), 'utf8')).toBe('<p>my notes</p>');
    expect(await runCli([project, '--offline', '--html', 'report.html'], capture(out))).toBe(0);
    expect(await runCli([project, '--offline', '--html', 'report.html'], capture(out))).toBe(0);
  });

  it('needs a file name ending in .html, in a folder that exists', async () => {
    const project = await makeProject();
    const out = await tempDir('epherem-cli-out-');
    const io = capture(out);
    expect(await runCli([project, '--offline', '--html', 'report.txt'], io)).toBe(2);
    expect(io.stderr()).toContain('ending in .html');
    const io2 = capture(out);
    expect(await runCli([project, '--offline', '--html', path.join('missing', 'report.html')], io2)).toBe(1);
    expect(io2.stderr()).toContain("doesn't exist");
    expect(await readdir(out)).toEqual([]);
  });
});

describe('errors are said plainly, with a non-zero exit', () => {
  it('a folder that does not exist', async () => {
    const io = capture(await tempDir('epherem-cli-cwd-'));
    expect(await runCli(['no-such-folder'], io)).toBe(1);
    expect(io.stderr()).toMatch(/^Can't find the folder .*no-such-folder\.\n$/);
  });

  it('a ZIP file, and any other file', async () => {
    const dir = await tempDir('epherem-cli-cwd-');
    await writeFile(path.join(dir, 'app.zip'), 'PK');
    await writeFile(path.join(dir, 'app.js'), '');
    const zip = capture(dir);
    expect(await runCli(['app.zip'], zip)).toBe(1);
    expect(zip.stderr()).toContain('unzip it first');
    const file = capture(dir);
    expect(await runCli(['app.js'], file)).toBe(1);
    expect(file.stderr()).toContain('is a file, not a folder');
  });

  it('a command it does not understand exits 2 with the usage line', async () => {
    for (const argv of [['--nope'], ['a', 'b'], ['--severity', 'urgent'], ['--severity'], ['--html']]) {
      const io = capture(await tempDir('epherem-cli-cwd-'));
      expect(await runCli(argv, io)).toBe(2);
      expect(io.stderr()).toContain('Usage: epherem-scanner');
      expect(io.stdout()).toBe('');
    }
  });

  it('--help and --version print and exit 0', async () => {
    const help = capture(await tempDir('epherem-cli-cwd-'));
    expect(await runCli(['--help'], help)).toBe(0);
    expect(help.stdout()).toContain('Usage: epherem-scanner');
    const version = capture(await tempDir('epherem-cli-cwd-'));
    expect(await runCli(['--version'], version)).toBe(0);
    expect(version.stdout()).toBe(`${VERSION}\n`);
  });

  it('parses each option in both spellings', () => {
    expect(parseArgs(['app', '--severity=medium', '--html=r.html', '--json', '--offline'])).toEqual({
      folder: 'app', json: true, severity: 'medium', offline: true, html: 'r.html', help: false, version: false,
    });
    expect(parseArgs([]).folder).toBeUndefined();
  });
});

describe('text from the scanned project cannot drive the terminal', () => {
  it('control characters in a file name and in code are replaced in the report', async () => {
    const project = path.join(await tempDir('epherem-cli-project-'), 'esc-app');
    await mkdir(path.join(project, 'src'), { recursive: true });
    await writeFile(path.join(project, 'package.json'), '{"name":"esc-app","dependencies":{"express":"4.18.2"}}\n');
    const evil = 'x\u001b[2J\u001b]0;owned\u0007\u202e';
    const rlo = String.fromCharCode(0x202e);
    const esc = String.fromCharCode(27);
    const name = process.platform === 'win32' ? `app${rlo}sj.js` : `app${esc}[31m${rlo}sj.js`;
    await writeFile(path.join(project, 'src', name), [
      "const express = require('express');",
      'const app = express();',
      `app.get('/run', (req, res) => { require('child_process').exec(req.query.cmd + '${evil}'); res.send('ok'); });`,
      "app.get('/hi', (req, res) => { res.send('<script>alert(1)</script><b>' + req.query.name + '</b>'); });",
      'app.listen(3000);',
      '',
    ].join('\n'));
    const out = await tempDir('epherem-cli-out-');
    const io = capture(out);
    expect(await runCli([project, '--offline', '--html', 'r.html'], io)).toBe(0);
    const html = await readFile(path.join(out, 'r.html'), 'utf8');
    expect(html).not.toMatch(/<script|<b>/i);
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(io.stdout()).not.toMatch(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/);
    expect(io.stdout()).toContain('Findings, most serious first');
    expect(io.stdout()).toMatch(/Where: src\/app\?(?:\[31m\?)?sj\.js:\d+/);
  });
});
