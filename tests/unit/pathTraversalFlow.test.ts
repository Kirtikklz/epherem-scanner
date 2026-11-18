import { describe, expect, it } from 'vitest';
import { pathTraversal } from '../../src/rules/basic/pathTraversal.js';
import { memoryContext } from './helpers.js';

const P: [string, string] = ['package.json', '{"name":"x"}'];
const run = (file: string, code: string) => pathTraversal.run(memoryContext([P, [file, code]]));

describe('path_traversal (confinement)', () => {
  it('CONFIRMED BYPASS: path.resolve() alone does not confine', () => {
    expect(
      run('server/a.js', 'import fs from "fs";\nimport path from "path";\nconst p = path.resolve("/safe", req.query.name);\nreturn fs.readFileSync(p);\n'),
    ).toHaveLength(1);
  });
  it('../ style direct concatenation is flagged', () => {
    expect(run('server/b.js', 'import fs from "fs";\nexport function h(req){ return fs.readFileSync("./up/" + req.query.name); }\n')).toHaveLength(1);
  });
  it('absolute-path input is flagged', () => {
    expect(run('server/c.js', 'import fs from "fs";\nexport function h(req){ const f = req.body.file;\nreturn fs.readFileSync(f); }\n')).toHaveLength(1);
  });
  it('path.basename() (filename only) is safe', () => {
    expect(
      run('server/d.js', 'import fs from "fs";\nimport path from "path";\nexport function h(req){ const n = path.basename(req.query.name); return fs.readFileSync("./up/" + n); }\n'),
    ).toHaveLength(0);
  });
  it('resolve + prefix check including the separator is safe', () => {
    expect(
      run('server/e.js', 'import fs from "fs";\nimport path from "path";\nconst base = "/safe";\nconst full = path.resolve(base, req.query.name);\nif (!full.startsWith(base + path.sep)) throw new Error("no");\nreturn fs.readFileSync(full);\n'),
    ).toHaveLength(0);
  });
});
