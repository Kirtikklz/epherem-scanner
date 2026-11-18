export type DbOpKind = 'read' | 'mutation';

export interface DbOp {
  filePath: string;
  line: number;
  kind: DbOpKind;
  store: string;
  evidence: string;
}

const MODEL_MUTATION =
  /\b([A-Z][A-Za-z0-9_]*)\s*\.\s*(create|insertMany|bulkCreate|updateOne|updateMany|update|replaceOne|findByIdAndUpdate|findOneAndUpdate|findByIdAndDelete|findOneAndDelete|deleteOne|deleteMany|destroy|remove|save|upsert|increment|decrement)\s*\(/g;
const MODEL_READ =
  /\b([A-Z][A-Za-z0-9_]*)\s*\.\s*(find|findOne|findById|findByPk|findAll|countDocuments|count|aggregate|exists|distinct)\s*\(/g;
const INSTANCE_MUTATION = /\b([a-z][A-Za-z0-9_]*)\s*\.\s*(save|remove|deleteOne|updateOne)\s*\(/g;
const KNEX_MUTATION = /\bknex\s*\([^)]*\)\s*\.\s*(insert|update|del|delete)\s*\(/g;
const TYPEORM_MUTATION = /\b(?:repo|repository|manager|getRepository\([^)]*\))\s*\.\s*(save|insert|update|delete|remove|softDelete)\s*\(/g;
const FS_MUTATION = /\bfs(?:\.promises)?\s*\.\s*(writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|rm|rmSync)\s*\(/g;
const FS_READ = /\bfs(?:\.promises)?\s*\.\s*(readFile|readFileSync|createReadStream)\s*\(/g;

function lineOf(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i += 1) if (content[i] === '\n') line += 1;
  return line;
}

function scan(
  content: string,
  filePath: string,
  re: RegExp,
  kind: DbOpKind,
  store: string,
  ops: DbOp[],
): void {
  const r = new RegExp(re.source, 'g');
  for (let m = r.exec(content); m !== null; m = r.exec(content)) {
    ops.push({
      filePath,
      line: lineOf(content, m.index),
      kind,
      store,
      evidence: m[0].replace(/\s+/g, ' ').trim(),
    });
  }
}

export function detectBroadenedDbOps(filePath: string, content: string): DbOp[] {
  const ops: DbOp[] = [];
  scan(content, filePath, MODEL_MUTATION, 'mutation', 'model', ops);
  scan(content, filePath, MODEL_READ, 'read', 'model', ops);
  scan(content, filePath, INSTANCE_MUTATION, 'mutation', 'model-instance', ops);
  scan(content, filePath, KNEX_MUTATION, 'mutation', 'knex', ops);
  scan(content, filePath, TYPEORM_MUTATION, 'mutation', 'typeorm', ops);
  scan(content, filePath, FS_MUTATION, 'mutation', 'fs-store', ops);
  scan(content, filePath, FS_READ, 'read', 'fs-store', ops);
  return ops;
}
