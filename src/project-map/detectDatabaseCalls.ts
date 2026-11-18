import type { DatabaseCall, DatabaseCallKind, FileMapEntry } from '../shared/types.js';
import { findMatches } from '../shared/utils.js';

const SUPABASE_CALL =
  /\bsupabase\w*\s*\.\s*from\s*\(\s*['"`]([\w.-]+)['"`]\s*\)[\s\S]{0,200}?\.\s*(select|insert|update|delete|upsert)\s*\(/g;
const PRISMA_CALL =
  /\bprisma\.(\w+)\.(create|createMany|update|updateMany|delete|deleteMany|findMany|findUnique|findFirst|upsert)\s*\(/g;
const DRIZZLE_CALL = /\bdb\.(select|insert|update|delete)\s*\(/g;
const FIREBASE_READ = /\b(getDoc|getDocs|onSnapshot)\s*\(|\.collection\([^)]*\)[\s\S]{0,80}?\.(get|onSnapshot)\s*\(/g;
const FIREBASE_WRITE =
  /\b(setDoc|addDoc|updateDoc|deleteDoc)\s*\(|\.collection\([^)]*\)[\s\S]{0,80}?\.(add|set|update|delete)\s*\(/g;
const RAW_SQL_CALL = /\.\s*(?:query|execute|exec)\s*\(\s*[`'"]\s*(SELECT|INSERT|UPDATE|DELETE)\b/gi;
const SQL_FILE_STATEMENT = /^\s*(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP)\b/im;

const PRISMA_KIND_MAP: Record<string, DatabaseCallKind> = {
  create: 'insert', createMany: 'insert',
  update: 'update', updateMany: 'update', upsert: 'upsert',
  delete: 'delete', deleteMany: 'delete',
  findMany: 'select', findUnique: 'select', findFirst: 'select',
};

export function detectDatabaseCalls(entry: FileMapEntry): DatabaseCall[] {
  const calls: DatabaseCall[] = [];
  const { path: filePath, content } = entry;

  if (entry.extension === '.sql') {
    if (SQL_FILE_STATEMENT.test(content)) {
      calls.push({ filePath, line: 1, client: 'sql', kind: 'raw_sql', snippet: 'SQL statements in schema/migration file' });
    }
    return calls;
  }

  for (const match of findMatches(content, SUPABASE_CALL)) {
    const table = match.groups[0];
    const kind = (match.groups[1] ?? 'select') as DatabaseCallKind;
    calls.push({
      filePath, line: match.line, index: match.index, client: 'supabase', kind,
      ...(table !== undefined ? { table: table.toLowerCase() } : {}),
      snippet: compact(match.matchText),
    });
  }
  for (const match of findMatches(content, PRISMA_CALL)) {
    const model = match.groups[0];
    const operation = match.groups[1] ?? '';
    calls.push({
      filePath, line: match.line, index: match.index, client: 'prisma',
      kind: PRISMA_KIND_MAP[operation] ?? 'select',
      ...(model !== undefined ? { table: model.toLowerCase() } : {}),
      snippet: compact(match.matchText),
    });
  }
  for (const match of findMatches(content, DRIZZLE_CALL)) {
    const kind = (match.groups[0] ?? 'select') as DatabaseCallKind;
    calls.push({ filePath, line: match.line, index: match.index, client: 'drizzle', kind, snippet: compact(match.matchText) });
  }
  for (const match of findMatches(content, FIREBASE_READ)) {
    calls.push({ filePath, line: match.line, index: match.index, client: 'firebase', kind: 'read', snippet: compact(match.matchText) });
  }
  for (const match of findMatches(content, FIREBASE_WRITE)) {
    calls.push({ filePath, line: match.line, index: match.index, client: 'firebase', kind: 'write', snippet: compact(match.matchText) });
  }
  for (const match of findMatches(content, RAW_SQL_CALL)) {
    calls.push({ filePath, line: match.line, index: match.index, client: 'sql', kind: 'raw_sql', snippet: match.snippet });
  }

  calls.sort((a, b) => a.line - b.line || a.snippet.localeCompare(b.snippet));
  return calls;
}

function compact(text: string): string {
  const singleLine = text.replace(/\s+/g, ' ').trim();
  return singleLine.length > 160 ? `${singleLine.slice(0, 160)}…` : singleLine;
}
