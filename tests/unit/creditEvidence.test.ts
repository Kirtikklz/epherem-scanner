import { describe, expect, it } from 'vitest';
import { creditEvidence, creditScopedEntries, isScanReport } from '../../src/shared/creditScope.js';
import { missingSecurityHeaders } from '../../src/rules/basic/missingSecurityHeaders.js';
import { csrfProtection } from '../../src/rules/contextual/csrfProtection.js';
import { loadFixtureContext, memoryContext, memoryFile } from './helpers.js';
import { classifyFile } from '../../src/file-map/classifyFile.js';

const EXPRESS_MANIFEST = '{"name":"app","dependencies":{"express":"^4.18.0"}}';

function projectWith(serverSource: string, extra: [string, string][] = []) {
  return memoryContext([
    ['package.json', EXPRESS_MANIFEST],
    ['server.js', serverSource],
    ...extra,
  ]);
}


function projectWideHeaderFindings(context: Parameters<typeof missingSecurityHeaders.run>[0]) {
  return missingSecurityHeaders.run(context).filter((f) => f.title === 'No security headers configured');
}

const PLAIN_SERVER =
  "const express = require('express');\n" +
  'const app = express();\n' +
  "app.get('/', (req, res) => res.send('hi'));\n" +
  'app.listen(3000);\n';

describe('missing_security_headers: a comment is not a control', () => {
  it('BASELINE — a project with no header configuration fires', () => {
    expect(projectWideHeaderFindings(projectWith(PLAIN_SERVER))).toHaveLength(1);
  });

  it('THE DEFECT: a commented-out helmet block no longer suppresses the project', () => {
    const commentedOut =
      "const express = require('express');\n" +
      "// const helmet = require('helmet');\n" +
      'const app = express();\n' +
      '/*\n' +
      ' * Fix for security misconfiguration\n' +
      ' * app.use(helmet.frameguard());\n' +
      ' * app.use(helmet.hsts());\n' +
      ' */\n' +
      'app.listen(3000);\n';
    expect(projectWideHeaderFindings(projectWith(commentedOut))).toHaveLength(1);
  });

  it('a line comment naming Content-Security-Policy no longer suppresses the project', () => {
    const source = `${PLAIN_SERVER}// TODO: add a Content-Security-Policy header here\n`;
    expect(projectWideHeaderFindings(projectWith(source))).toHaveLength(1);
  });

  it('GUARD: a real helmet call still suppresses the project', () => {
    const realUse =
      "const express = require('express');\n" +
      "const helmet = require('helmet');\n" +
      'const app = express();\n' +
      'app.use(helmet());\n' +
      'app.listen(3000);\n';
    expect(projectWideHeaderFindings(projectWith(realUse))).toHaveLength(0);
  });

  it('GUARD: real code still suppresses even when a comment sits on the same line', () => {
    const realUse =
      "const helmet = require('helmet');\n" +
      'app.use(helmet()); // baseline security headers\n';
    expect(projectWideHeaderFindings(projectWith(realUse))).toHaveLength(0);
  });

  it('GUARD: a header name inside a string literal still suppresses', () => {
    const realUse = `${PLAIN_SERVER}app.use((req, res, next) => { res.setHeader('X-Frame-Options', 'DENY'); next(); });\n`;
    expect(projectWideHeaderFindings(projectWith(realUse))).toHaveLength(0);
  });
});

describe("missing_security_headers: another scanner's report is not this project's configuration", () => {
  const SARIF_REPORT = JSON.stringify(
    {
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: { driver: { name: 'SomeOtherScanner' } },
          results: [
            {
              message: { text: 'Secure the app with helmet' },
              fixes: [{ description: { text: 'app.use(helmet());' } }],
            },
          ],
        },
      ],
    },
    null,
    2,
  );

  it('THE DEFECT: a committed SARIF report no longer suppresses the project', () => {
    const context = projectWith(PLAIN_SERVER, [['sarif.json', SARIF_REPORT]]);
    expect(projectWideHeaderFindings(context)).toHaveLength(1);
  });

  it('a *.sarif file no longer suppresses the project', () => {
    const context = projectWith(PLAIN_SERVER, [
      ['reports/scan.sarif', '{"runs":[{"results":[{"message":{"text":"use helmet"}}]}]}'],
    ]);
    expect(projectWideHeaderFindings(context)).toHaveLength(1);
  });

  it('GUARD: a real config file that happens to be JSON still suppresses', () => {
    const vercelConfig =
      '{"headers":[{"source":"/(.*)","headers":[{"key":"X-Frame-Options","value":"DENY"}]}]}';
    const context = projectWith(PLAIN_SERVER, [['vercel.json', vercelConfig]]);
    expect(projectWideHeaderFindings(context)).toHaveLength(0);
  });

  it('isScanReport recognises the standard and refuses to guess beyond it', () => {
    const entry = (filePath: string, content: string) =>
      classifyFile(memoryFile(filePath, content));

    expect(isScanReport(entry('out/scan.sarif', '{}'))).toBe(true);
    expect(isScanReport(entry('OUT/SCAN.SARIF', '{}'))).toBe(true);
    expect(isScanReport(entry('report.json', SARIF_REPORT))).toBe(true);
    expect(isScanReport(entry('audit/2026-08-15.json', SARIF_REPORT))).toBe(true);

    expect(isScanReport(entry('tsconfig.json', '{"$schema":"https://json.schemastore.org/tsconfig"}'))).toBe(false);
    expect(isScanReport(entry('data.json', '{"runs":[{"distance":5}]}'))).toBe(false);
    expect(isScanReport(entry('server.js', "app.use(helmet());\n"))).toBe(false);

    expect(isScanReport(entry('snyk-report.json', '{"vulnerabilities":[{"title":"helmet missing"}]}'))).toBe(false);
  });
});

const CSRF_MANIFEST = '{"name":"app","dependencies":{"express":"^4.18.0","csurf":"^1.11.0"}}';

function csrfProject(extra: [string, string][] = [], manifest = EXPRESS_MANIFEST) {
  return memoryContext([
    ['package.json', manifest],
    ['server.js',
      "const express = require('express');\n" +
      "const session = require('express-session');\n" +
      'const app = express();\n' +
      "app.use(session({ secret: 's' }));\n" +
      "app.post('/transfer', (req, res) => res.json({ ok: true }));\n"],
    ...extra,
  ]);
}

describe('a declaration is not a control', () => {
  it('THE DEFECT: a helmet dependency entry no longer suppresses the headers rule', () => {
    const manifest = '{"name":"app","dependencies":{"express":"^4.18.0","helmet":"^7.0.0"}}';
    const context = memoryContext([['package.json', manifest], ['server.js', PLAIN_SERVER]]);
    expect(projectWideHeaderFindings(context)).toHaveLength(1);
  });

  it('a lockfile naming helmet no longer suppresses the headers rule', () => {
    const lock = '{"lockfileVersion":3,"packages":{"node_modules/helmet":{"version":"7.0.0"}}}';
    const context = projectWith(PLAIN_SERVER, [['package-lock.json', lock]]);
    expect(projectWideHeaderFindings(context)).toHaveLength(1);
  });

  it('THE DEFECT: a csurf dependency entry no longer suppresses the CSRF rule', () => {
    expect(csrfProtection.run(csrfProject([], CSRF_MANIFEST))).toHaveLength(1);
  });

  it('GUARD: a project that actually installs AND uses helmet still suppresses', () => {
    const manifest = '{"name":"app","dependencies":{"express":"^4.18.0","helmet":"^7.0.0"}}';
    const context = memoryContext([
      ['package.json', manifest],
      ['src/app.js', "const helmet = require('helmet');\napp.use(helmet());\n"],
    ]);
    expect(projectWideHeaderFindings(context)).toHaveLength(0);
  });

  it('GUARD: a project that actually uses csurf still suppresses the CSRF rule', () => {
    const context = csrfProject(
      [['src/security.js', "const csurf = require('csurf');\napp.use(csurf());\n"]],
      CSRF_MANIFEST,
    );
    expect(csrfProtection.run(context)).toHaveLength(0);
  });
});

describe('prose is not a control', () => {
  it('a README describing security headers no longer suppresses the rule', () => {
    const readme =
      '# Security\n\nWe intend to add helmet and a Content-Security-Policy header.\n' +
      'See https://helmetjs.github.io for X-Frame-Options and X-Content-Type-Options.\n';
    expect(projectWideHeaderFindings(projectWith(PLAIN_SERVER, [['README.md', readme]]))).toHaveLength(1);
  });

  it('an HTML tutorial page teaching about headers no longer suppresses the rule', () => {
    const tutorial =
      '<html><body>\n' +
      '<li><a href="https://www.npmjs.com/package/helmet">Helmet</a> adds security headers</li>\n' +
      '<p>The header below allows content from your own domain:</p>\n' +
      "<pre>Content-Security-Policy: default-src 'self'</pre>\n" +
      '<p>Headers can be added with helmet middleware as shown above.</p>\n' +
      '</body></html>\n';
    expect(projectWideHeaderFindings(projectWith(PLAIN_SERVER, [['views/tutorial.html', tutorial]]))).toHaveLength(1);
  });

  it('GUARD: a real <meta http-equiv> CSP tag STILL suppresses the rule', () => {
    const page =
      '<html><head>\n' +
      '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'">\n' +
      '</head><body>Hello</body></html>\n';
    expect(projectWideHeaderFindings(projectWith(PLAIN_SERVER, [['views/index.html', page]]))).toHaveLength(0);
  });

  it('GUARD: a real hidden _csrf token field STILL suppresses the CSRF rule', () => {
    const loginPage =
      '<html><body><form method="post" action="/login">\n' +
      '<input type="hidden" name="_csrf" value="{{csrftoken}}" />\n' +
      '<input type="submit" value="Log in" />\n' +
      '</form></body></html>\n';
    expect(csrfProtection.run(csrfProject([['views/login.html', loginPage]]))).toHaveLength(0);
  });

  it('GUARD: a <meta name="csrf-token"> tag STILL suppresses the CSRF rule', () => {
    const page = '<html><head><meta name="csrf-token" content="abc123"></head><body></body></html>\n';
    expect(csrfProtection.run(csrfProject([['views/layout.html', page]]))).toHaveLength(0);
  });

  it('an HTML page that only TALKS about CSRF no longer suppresses the CSRF rule', () => {
    const page = '<html><body><h1>A8 Cross-Site Request Forgery (CSRF)</h1><p>What CSRF is.</p></body></html>\n';
    expect(csrfProtection.run(csrfProject([['views/tutorial/a8.html', page]]))).toHaveLength(1);
  });
});

describe('creditEvidence: what each kind of file may speak with', () => {
  const entry = (filePath: string, content: string) => classifyFile(memoryFile(filePath, content));

  it('a manifest and a lockfile speak with nothing', () => {
    expect(creditEvidence(entry('package.json', '{"dependencies":{"helmet":"^7.0.0"}}'))).toBe('');
    expect(creditEvidence(entry('package-lock.json', '{"packages":{}}'))).toBe('');
    expect(creditEvidence(entry('yarn.lock', 'helmet@^7.0.0:\n  version "7.0.0"\n'))).toBe('');
  });

  it('prose formats speak with nothing', () => {
    for (const name of ['README.md', 'notes.mdx', 'guide.markdown', 'doc.rst', 'book.adoc']) {
      expect(creditEvidence(entry(name, '# helmet\n')), name).toBe('');
    }
  });

  it('markup speaks with its meta and input tags, and with nothing else', () => {
    const html =
      '<p>helmet is nice</p>\n' +
      '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'">\n' +
      '<a href="https://npmjs.com/package/helmet">link</a>\n' +
      '<input type="hidden" name="_csrf" value="x">\n';
    const out = creditEvidence(entry('page.html', html));
    expect(out).toContain('Content-Security-Policy');
    expect(out).toContain('_csrf');
    expect(out).not.toContain('helmet is nice');
    expect(out).not.toContain('npmjs.com');
  });

  it('an HTML file with no meta or input tag speaks with nothing at all', () => {
    expect(creditEvidence(entry('t.html', '<p>Content-Security-Policy explained</p>'))).toBe('');
  });

  it('ordinary source speaks with all of itself', () => {
    const source = "const helmet = require('helmet');\napp.use(helmet());\n";
    expect(creditEvidence(entry('server.js', source))).toBe(source);
  });

  it('THE DELIBERATE GAP: a .txt is NOT prose, because requirements.txt is a manifest', () => {
    expect(creditEvidence(entry('README.txt', 'helmet'))).toBe('helmet');
  });

  it('THE DELIBERATE GAP: a template language is NOT markup, because nothing exercises it here', () => {
    expect(creditEvidence(entry('view.ejs', '<p>csrf</p>'))).toBe('<p>csrf</p>');
  });
});


describe('a bun.lock speaks with nothing', () => {
  const bunEntry = (filePath: string, content: string) => classifyFile(memoryFile(filePath, content));

  it('is labelled a lockfile, like the other three', () => {
    expect(bunEntry('bun.lock', '{"lockfileVersion":1}').label).toBe('lockfile');
  });

  it('contributes no credit evidence at all', () => {
    const lock = '{"packages":{"react-helmet-async":["react-helmet-async@2.0.5","",{},"sha512-x"]}}';
    expect(bunEntry('bun.lock', lock).content).toContain('helmet');
    expect(creditEvidence(bunEntry('bun.lock', lock))).toBe('');
  });

  it('GUARD (green on both sides): the project-wide credit is refused twice over', () => {
    const bunLock = JSON.stringify({
      lockfileVersion: 1,
      workspaces: { '': { name: 'app', dependencies: { 'react-helmet-async': '^2.0.5' } } },
      packages: { 'react-helmet-async': ['react-helmet-async@2.0.5', '', {}, 'sha512-x'] },
    });
    const context = projectWith(PLAIN_SERVER, [['bun.lock', bunLock]]);
    expect(creditScopedEntries(context).map((entry) => entry.path)).not.toContain('bun.lock');
    expect(projectWideHeaderFindings(context)).toHaveLength(1);
  });

  it('a real helmet call in the project\'s own source still suppresses it', () => {
    const served =
      "const express = require('express');\n" +
      "const helmet = require('helmet');\n" +
      'const app = express();\n' +
      'app.use(helmet());\n' +
      'app.listen(3000);\n';
    expect(projectWideHeaderFindings(projectWith(served))).toHaveLength(0);
  });

  it('bun.lockb is NOT swept in with it: it is binary and nothing reads it', () => {
    expect(bunEntry('bun.lockb', 'binary-ish').label).not.toBe('lockfile');
  });
});

describe('missing_security_headers: an SEO library is not a security control', () => {
  it('THE TRAP: a word boundary matches inside react-helmet-async, so \\b cannot be the fix', () => {
    const seoImport = 'import { Helmet } from "react-helmet-async";';
    expect(/helmet/.test(seoImport)).toBe(true);
    expect(/\bhelmet\b/.test(seoImport)).toBe(true);
    expect(/\bhelmet\s*\(/.test(seoImport)).toBe(false);
    expect(/\bhelmet\s*[.(]/.test(seoImport)).toBe(false);
  });

  it('DEMONSTRATION (fails on the unfixed tree): an Express app whose only helmet is react-helmet-async reports', async () => {
    const context = await loadFixtureContext('express-react-helmet-seo');
    expect(projectWideHeaderFindings(context)).toHaveLength(1);
  });

  it('DEMONSTRATION: each of the three real credit shapes fails to vouch on its own', () => {
    const shapes: [string, string][] = [
      ['src/components/SEO.jsx', "import { Helmet } from 'react-helmet-async';\n"],
      ['src/App.jsx', 'import { HelmetProvider } from "react-helmet-async";\n'],
      ['src/pages/Index.jsx', 'export const copy = "Helmet and safety gear required";\n'],
      ['src/lib/seo.js', "const pkg = 'react-helmet-async';\n"],
    ];
    for (const shape of shapes) {
      expect(projectWideHeaderFindings(projectWith(PLAIN_SERVER, [shape]))).toHaveLength(1);
    }
  });

  it('GUARD: app.use(helmet()) still suppresses', () => {
    const served = `${PLAIN_SERVER}const helmet = require('helmet');\napp.use(helmet());\n`;
    expect(projectWideHeaderFindings(projectWith(served))).toHaveLength(0);
  });

  it('GUARD: a member-style helmet call still suppresses the project-wide finding', () => {
    for (const call of [
      'app.use(helmet.contentSecurityPolicy({ directives: {} }));',
      'app.use(helmet.hsts({ maxAge: 31536000 }));',
      'app.use(helmet.frameguard({ action: "deny" }));',
    ]) {
      const served = `${PLAIN_SERVER}const helmet = require('helmet');\n${call}\n`;
      expect(projectWideHeaderFindings(projectWith(served))).toHaveLength(0);
    }
  });

  it('DECLARED LOSS: an import with no call is a record of what was installed, and now reports', () => {
    for (const served of [
      `${PLAIN_SERVER}const helmet = require('helmet');\n`,
      `${PLAIN_SERVER}import helmet from 'helmet';\n`,
    ]) {
      expect(projectWideHeaderFindings(projectWith(served))).toHaveLength(1);
    }
  });

  it('DECLARED LOSS: app.use(helmet) hands Express the factory, not the middleware, and now reports', () => {
    const served = `${PLAIN_SERVER}const helmet = require('helmet');\napp.use(helmet);\n`;
    expect(projectWideHeaderFindings(projectWith(served))).toHaveLength(1);
  });

  it('INVARIANT: the credit stays case-sensitive, so <Helmet> is not a control', () => {
    const served = `${PLAIN_SERVER}// rendered by <Helmet> in the client\nconst x = 'Helmet.rewind()';\n`;
    expect(projectWideHeaderFindings(projectWith(served))).toHaveLength(1);
  });

  it('INVARIANT: the other header alternatives still vouch exactly as before', () => {
    for (const served of [
      `${PLAIN_SERVER}app.use((req, res, next) => { res.setHeader('Strict-Transport-Security', 'max-age=31536000'); next(); });\n`,
      `${PLAIN_SERVER}res.setHeader('Content-Security-Policy', "default-src 'self'");\n`,
      `${PLAIN_SERVER}res.setHeader('X-Frame-Options', 'DENY');\n`,
      `${PLAIN_SERVER}res.setHeader('X-Content-Type-Options', 'nosniff');\n`,
    ]) {
      expect(projectWideHeaderFindings(projectWith(served))).toHaveLength(0);
    }
  });
});
