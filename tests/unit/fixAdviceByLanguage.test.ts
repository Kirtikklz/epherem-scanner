import { readdirSync, readFileSync } from 'node:fs';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import { afterAll, describe, expect, it } from 'vitest';
import { adviceFor, isOtherLanguageSource, NEUTRAL_FIX_PHRASES } from '../../src/rules/fixAdviceByLanguage.js';
import { MockDependencyVulnerabilityScanner } from '../../src/dependency-audit/dependencyAudit.js';
import { scanProject } from '../../src/scanProject.js';
import { makeFinding, type FindingInput } from '../../src/shared/findingFactory.js';
import type { Finding } from '../../src/shared/types.js';

const SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'src');
const JS_MARKERS = /fileFilter|fileSize|new URL\(|path\.resolve|path\.basename|process\.env|req\.body|res\.\w|fs\.\*|getServerSession|supabase\.auth|jwt\.verify|DOMPurify|escape-html|escapeHtml|\bzod\b|express|Next\.js|crypto\.random|Math\.random|NODE_ENV|httpOnly:|sameSite:|where: \{|\.eq\(|app\.post|execFile|spawn|getRandomValues|ALLOWED_ORIGINS/;

function sourceStrings(): string[] {
  const out: string[] = [];
  const fold = (n: ts.Node): string | undefined => {
    if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) return n.text;
    if (ts.isParenthesizedExpression(n)) return fold(n.expression);
    if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      const left = fold(n.left);
      const right = fold(n.right);
      return left === undefined || right === undefined ? undefined : left + right;
    }
    return undefined;
  };
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith('.ts') && entry.name !== 'fixAdviceByLanguage.ts') {
        const file = ts.createSourceFile(full, readFileSync(full, 'utf8'), ts.ScriptTarget.Latest, true);
        const visit = (node: ts.Node): void => {
          if (ts.isTemplateHead(node) || ts.isTemplateMiddle(node) || ts.isTemplateTail(node)) out.push(node.text);
          const folded = fold(node);
          if (folded !== undefined) out.push(folded);
          ts.forEachChild(node, visit);
        };
        visit(file);
      }
    }
  };
  walk(SRC);
  return out;
}

describe('the phrase table', () => {
  it('every JavaScript phrase still occurs in a rule text, so a reworded rule cannot slip past it', () => {
    const strings = sourceStrings();
    const missing = NEUTRAL_FIX_PHRASES.map(([javascript]) => javascript).filter((javascript) => !strings.some((s) => s.includes(javascript)));
    expect(missing).toEqual([]);
  });

  it('every replacement is free of JavaScript APIs, and every phrase it replaces names one', () => {
    for (const [javascript, neutral] of NEUTRAL_FIX_PHRASES) {
      expect(neutral, neutral).not.toMatch(JS_MARKERS);
      expect(javascript, javascript).toMatch(JS_MARKERS);
    }
  });

  it('applies to Python files only', () => {
    const text = 'Add a fileFilter that allowlists expected MIME types/extensions, set limits: { fileSize }, generate random stored filenames, and store uploads outside the web/served directory (or in object storage).';
    expect(adviceFor('app/uploads.py', text)).toBe('Allowlist the file types you expect (check both the extension and the content type), cap the upload size, generate random stored filenames, and store uploads outside the web/served directory (or in object storage).');
    for (const file of ['server.js', 'app/api/upload/route.ts', 'package.json', 'templates/index.html', 'py/README']) {
      expect(adviceFor(file, text), file).toBe(text);
    }
    expect(isOtherLanguageSource('src/App.PY')).toBe(true);
    expect(isOtherLanguageSource('python.d/app.ts')).toBe(false);
  });

  it('a finding rewrites its hint, its extra requirements and its plain explanation, never its technical one', () => {
    const input: FindingInput = {
      ruleId: 'path_traversal',
      title: 'Path traversal',
      severity: 'high',
      confidence: 'medium',
      filePath: 'app/files.py',
      lineStart: 4,
      evidence: 'open(name)',
      userExplanation: 'Note that path.resolve() alone does not help.',
      technicalExplanation: 'path.resolve() normalises but does not confine.',
      fixHint: 'Never log req.body, headers, cookies, or process.env wholesale.',
      category: 'configuration',
      extraFixRequirements: ['Pass the secret from process.env (never a literal).'],
    };
    const python = makeFinding(input);
    expect(python.userExplanation).toBe('Note that resolving the path alone does not help.');
    expect(python.fixHint).toBe('Never log the request body, headers, cookies, or the whole environment.');
    expect(python.fixPrompt).toContain('Read the secret from an environment variable (never a literal).');
    expect(python.fixPrompt).not.toContain('process.env');
    expect(python.technicalExplanation).toBe(input.technicalExplanation);
    const javascript = makeFinding({ ...input, filePath: 'app/files.js' });
    expect([javascript.userExplanation, javascript.fixHint]).toEqual([input.userExplanation, input.fixHint]);
    expect(javascript.fixPrompt).toContain('Pass the secret from process.env (never a literal).');
    expect(javascript.id).not.toBe(python.id);
    expect(makeFinding({ ...input, fixHint: 'x', userExplanation: 'y' }).id).toBe(python.id);
  });
});

const temps: string[] = [];
afterAll(async () => {
  for (const dir of temps) await rm(dir, { recursive: true, force: true });
});

const lines = (...text: string[]): string => `${text.join('\n')}\n`;
const FILES: Record<string, string> = {
  'web/views.py': lines(
    'import os',
    'from flask import Flask, redirect, request, send_file',
    '',
    'app = Flask(__name__)',
    '',
    '@app.route("/go")',
    'def go():',
    '    return redirect(request.args.get("next"))',
    '',
    '@app.route("/file")',
    'def read_file():',
    '    return send_file(request.args.get("name"))',
    '',
    '@app.route("/hello")',
    'def hello():',
    '    resp = app.make_response("hi")',
    '    resp.set_cookie("session", request.args.get("token"))',
    '    return resp',
  ),
  'api/blobs.py': lines(
    'import os',
    'import shutil',
    'from fastapi import APIRouter, File, UploadFile',
    '',
    'router = APIRouter()',
    'FOLDER = "/srv/blobs"',
    '',
    '@router.post("/blobs")',
    'async def put_blob(incoming: UploadFile = File(...)):',
    '    with open(os.path.join(FOLDER, "x.bin"), "wb") as out:',
    '        shutil.copyfileobj(incoming.file, out)',
    '    return {"ok": True}',
  ),
  'server.js': lines(
    "const express = require('express');",
    "const multer = require('multer');",
    '',
    'const app = express();',
    "const upload = multer({ dest: 'uploads/' });",
    "app.post('/upload', upload.single('file'), (req, res) => res.send('ok'));",
    "app.get('/go', (req, res) => res.redirect(req.query.next));",
    'app.listen(3000);',
  ),
  'requirements.txt': lines('flask==3.0.0', 'fastapi==0.110.0'),
  'package.json': lines('{ "name": "mixed", "dependencies": { "express": "4.19.2", "multer": "1.4.5-lts.1" } }'),
};

describe('a scan with Python and JavaScript side by side', () => {
  it('Python findings carry no JavaScript fix phrase, in the hint, the explanation or the prompt; JavaScript ones keep theirs', async () => {
    const project = await mkdtemp(path.join(tmpdir(), 'epherem-fix-advice-'));
    temps.push(project);
    for (const [file, text] of Object.entries(FILES)) {
      await mkdir(path.dirname(path.join(project, file)), { recursive: true });
      await writeFile(path.join(project, file), text);
    }
    const report = await scanProject(project, { dependencyScanner: new MockDependencyVulnerabilityScanner() });
    const python = report.findings.filter((f) => f.filePath?.endsWith('.py'));
    const fired = (findings: Finding[]): string[] => [...new Set(findings.map((f) => f.ruleId))].sort();
    expect(fired(python)).toEqual(expect.arrayContaining(['open_redirect', 'unsafe_file_upload']));
    for (const finding of python) {
      for (const [javascript] of NEUTRAL_FIX_PHRASES) {
        for (const text of [finding.fixHint, finding.userExplanation, finding.fixPrompt]) {
          expect(text, `${finding.ruleId} ${finding.filePath}`).not.toContain(javascript);
        }
      }
    }
    const upload = python.find((f) => f.ruleId === 'unsafe_file_upload');
    expect(upload?.fixHint).toContain('Allowlist the file types you expect');
    expect(upload?.fixPrompt).toContain('cap the upload size');
    const redirect = python.find((f) => f.ruleId === 'open_redirect');
    expect(redirect?.fixHint).toContain('parse the URL and confirm its scheme and host are your own');

    const javascriptUpload = report.findings.find((f) => f.ruleId === 'unsafe_file_upload' && f.filePath === 'server.js');
    expect(javascriptUpload?.fixHint).toContain('fileFilter');
  });
});
