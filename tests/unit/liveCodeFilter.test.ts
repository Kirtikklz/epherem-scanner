import { describe, expect, it } from 'vitest';

import {
  isGeneratedOrVendorPath,
  isInsideComment,
  isInsideDevelopmentOnlyBlock,
  isNonProductionCodePath,
  isVendoredBundleContent,
  mayVouchForProject,
} from '../../src/shared/liveCode.js';
import { crossSiteScripting } from '../../src/rules/basic/xss.js';
import { memoryContext } from './helpers.js';

describe('A36 (1) matches inside comments are not live code', () => {
  const at = (content: string, needle: string): number => content.indexOf(needle);

  it('MUST GO QUIET: a line commented out with //', () => {
    const src = 'connect();\n// this.element.innerHTML = data.churp.view_count\n';
    expect(isInsideComment(src, at(src, 'innerHTML'), '.js')).toBe(true);
  });

  it('MUST GO QUIET: a route inside a /* */ block', () => {
    const src = "start();\n/*\napp.post('/api/auth/register', register);\n*/\n";
    expect(isInsideComment(src, at(src, 'app.post'), '.ts')).toBe(true);
  });

  it('MUST GO QUIET: a hash comment in Python', () => {
    const src = 'run()\n# os.system(user_input)\n';
    expect(isInsideComment(src, at(src, 'os.system'), '.py')).toBe(true);
  });

  it('MUST GO QUIET: an HTML comment', () => {
    const src = '<div></div>\n<!-- <script>alert(1)</script> -->\n';
    expect(isInsideComment(src, at(src, 'alert'), '.html')).toBe(true);
  });

  it('MUST STILL FIRE: the same statement one line lower, as live code', () => {
    const src = '// this.element.innerHTML = old\nthis.element.innerHTML = data.value;\n';
    expect(isInsideComment(src, src.lastIndexOf('innerHTML'), '.js')).toBe(false);
  });

  it('MUST STILL FIRE: a match inside a string literal that merely contains //', () => {
    const src = 'const url = "https://internal.example.com/admin";\n';
    expect(isInsideComment(src, at(src, 'admin'), '.ts')).toBe(false);
  });

  it('MUST STILL FIRE: an absolute URL in HTML is not a // comment', () => {
    const src = '<a href="https://example.com/admin">go</a>\n';
    expect(isInsideComment(src, at(src, 'admin'), '.html')).toBe(false);
  });

  it('MUST STILL FIRE: an unterminated <!-- does not swallow the rest of the file', () => {
    const src = '<script>var s = "<!--";</script>\n<div onclick="steal()"></div>\n';
    expect(isInsideComment(src, at(src, 'steal'), '.html')).toBe(false);
  });
});

describe('A36 (1) vendored library bundles are not the application', () => {
  const FA_BANNER = [
    '/*!',
    ' * Font Awesome Pro 5.13.0 by @fontawesome - https://fontawesome.com',
    ' * License - https://fontawesome.com/license (Commercial License)',
    ' */',
    "(function () { 'use strict';",
    '  node.outerHTML = toHtml(abstract);',
    '})();',
  ].join('\n');

  it('MUST GO QUIET: a preserved bundler banner naming a version and a licence', () => {
    expect(isVendoredBundleContent(FA_BANNER)).toBe(true);
  });

  it('MUST GO QUIET: end to end — no rule reads a vendored bundle in an assets folder', () => {
    expect(crossSiteScripting.run(memoryContext([['assets/fa/js/fontawesome.js', FA_BANNER]]))).toEqual([]);
  });

  it('MUST GO QUIET: a bundle of an unknown library with the same banner shape', () => {
    const src = ['/*! quixotl 2.4.1 | (c) 2026 Someone | MIT */', 'el.innerHTML = render(x);'].join('\n');
    expect(isVendoredBundleContent(src)).toBe(true);
  });

  it('MUST STILL FIRE: an ordinary file whose comment happens to start with /*', () => {
    const src = ['/* helpers for the profile page */', 'el.innerHTML = props.bio;'].join('\n');
    expect(isVendoredBundleContent(src)).toBe(false);
  });

  it('MUST STILL FIRE: a banner-shaped comment that is not at the top of the file', () => {
    const src = ['import x from "y";', '/*! vendored 1.0.0 https://x.example */', 'el.innerHTML = props.bio;'].join('\n');
    expect(isVendoredBundleContent(src)).toBe(false);
  });

  it('MUST STILL FIRE: a /*! banner with no version and no provenance proves nothing', () => {
    expect(isVendoredBundleContent('/*! keep this comment */\nel.innerHTML = props.bio;')).toBe(false);
  });
});

describe('A36 (1) code behind an in-file NODE_ENV development guard', () => {
  it('MUST GO QUIET: a sink inside if (process.env.NODE_ENV !== "production")', () => {
    const src = "if (process.env.NODE_ENV !== 'production') {\n  el.innerHTML = debugPayload;\n}\n";
    expect(isInsideDevelopmentOnlyBlock(src, src.indexOf('innerHTML'))).toBe(true);
  });

  it('MUST GO QUIET: the === development spelling of the same guard', () => {
    const src = "if (process.env.NODE_ENV === 'development') {\n  el.innerHTML = debugPayload;\n}\n";
    expect(isInsideDevelopmentOnlyBlock(src, src.indexOf('innerHTML'))).toBe(true);
  });

  it('MUST STILL FIRE: if (NODE_ENV === "production") is not a development guard', () => {
    const src = "if (process.env.NODE_ENV === 'production') {\n  el.innerHTML = payload;\n}\n";
    expect(isInsideDevelopmentOnlyBlock(src, src.indexOf('innerHTML'))).toBe(false);
  });

  it('MUST STILL FIRE: code after the guard block has closed', () => {
    const src = "if (process.env.NODE_ENV !== 'production') {\n  log();\n}\nel.innerHTML = payload;\n";
    expect(isInsideDevelopmentOnlyBlock(src, src.indexOf('innerHTML'))).toBe(false);
  });
});

describe('A36 (2) non-production and generated paths', () => {
  it.each([
    'src/test/mockServer/MockServer.ts',
    'src/test/mock-server/start.ts',
    'server/mock_server/routes.js',
  ])('MUST GO QUIET: %s is a program written to impersonate a real service', (path) => {
    expect(isNonProductionCodePath(path)).toBe(true);
  });

  it.each([
    'test-results/playwright-report/index.html',
    'playwright-report/index.html',
    'allure-report/index.html',
  ])('MUST GO QUIET: %s is a test runner writing its own output', (path) => {
    expect(isGeneratedOrVendorPath(path)).toBe(true);
  });

  it('a mock server may not vouch for the project either', () => {
    expect(mayVouchForProject('server/mockServer/MockServer.ts')).toBe(false);
    expect(mayVouchForProject('src/test/mockServer/MockServer.ts')).toBe(false);
  });
});

describe('A36 the standing guard: real source directories are still scanned', () => {
  it.each([
    'src/app/api/users/route.ts',
    'app/api/backups/route.ts',
    'examples/d1/app/api/notes/route.ts',
    'samples/checkout/server.js',
    'tests/setup.ts',
    'src/fixtures/dataLoader.ts',
    'scripts/seed-database.ts',
    'prisma/seed.ts',
    'lib/mocks.ts',
    'src/services/mockData.ts',
  ])('%s is still scanned', (path) => {
    expect(isNonProductionCodePath(path)).toBe(false);
    expect(isGeneratedOrVendorPath(path)).toBe(false);
  });

  it('end to end: real vulnerable code in a normally-named source dir still fires', () => {
    const findings = crossSiteScripting.run(
      memoryContext([[
        'src/components/Profile.jsx',
        'export function render(req) {\n  element.innerHTML = req.query.bio;\n}\n',
      ]]),
    );
    expect(findings.map((f) => `${f.filePath}:${f.lineStart}`)).toEqual(['src/components/Profile.jsx:2']);
  });
});
