import { describe, expect, it } from 'vitest';
import { extractFileImports, parseImportBindings } from '../../src/project-map/extractImports.js';
import type { FileMapEntry } from '../../src/shared/types.js';

function entry(path: string, content: string): FileMapEntry {
  return {
    path,
    extension: path.slice(path.lastIndexOf('.')),
    label: 'unknown_useful',
    size: content.length,
    isLikelyConfig: false,
    isLikelyApiRoute: false,
    isLikelyAuthRelated: false,
    isLikelyDatabaseRelated: false,
    isLikelyMiddleware: false,
    usesEnvVariables: false,
    technologyHints: [],
    content,
  };
}

describe('parseImportBindings', () => {
  it('parses ESM named, aliased, default and namespace forms', () => {
    expect(parseImportBindings('{ runJob, foo as bar }')).toEqual(['runJob', 'bar']);
    expect(parseImportBindings('* as runner')).toEqual(['runner']);
    expect(parseImportBindings('runJob, { helper }')).toEqual(['runJob', 'helper']);
    expect(parseImportBindings('runner')).toEqual(['runner']);
    expect(parseImportBindings('Default')).toEqual(['Default']);
  });

  it('parses CommonJS destructure with renames and plain assignment', () => {
    expect(parseImportBindings('{ a, b: c }')).toEqual(['a', 'c']);
    expect(parseImportBindings('runner')).toEqual(['runner']);
  });
});

describe('extractFileImports bindings (additive)', () => {
  it('attaches ESM bindings without disturbing source/order', () => {
    const fi = extractFileImports(
      entry('a.ts', `import { runJob } from './runner';\nimport * as ns from './lib';\n`),
    );
    const runner = fi.imports.find((i) => i.source === './runner');
    const lib = fi.imports.find((i) => i.source === './lib');
    expect(runner?.bindings).toEqual(['runJob']);
    expect(lib?.bindings).toEqual(['ns']);
  });

  it('attaches CommonJS require bindings (destructured and namespace)', () => {
    const fi = extractFileImports(
      entry('a.js', `const { runJob } = require('./runner');\nconst runner = require('./other');\n`),
    );
    const runner = fi.imports.find((i) => i.source === './runner');
    const other = fi.imports.find((i) => i.source === './other');
    expect(runner?.bindings).toEqual(['runJob']);
    expect(other?.bindings).toEqual(['runner']);
  });

  it('leaves bindings undefined for side-effect imports and re-exports', () => {
    const fi = extractFileImports(entry('a.ts', `import './styles.css';\nexport { x } from './x';\n`));
    const css = fi.imports.find((i) => i.source === './styles.css');
    expect(css?.bindings).toBeUndefined();
  });
});
