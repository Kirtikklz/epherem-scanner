import path from 'node:path';
import type { ArchiveWatchListCarry } from '../shared/archiveObservations.js';
import type { FileMap } from '../shared/types.js';

export type SqlDumpContent = 'holds_data' | 'no_data';

export const MIN_INSERTED_ROWS = 20;

const DUMP_HEADER =
  /(?:^|\n)[ \t]*--[ \t]*(?:PostgreSQL database (?:cluster )?dump\b|Dumped (?:from database version|by pg_dump version)\b|MySQL dump\b|MariaDB dump\b|phpMyAdmin SQL Dump\b)/i;

const COPY_FROM_STDIN = /(?:^|\n)[ \t]*COPY[ \t]+[^\n;]+?[ \t]+FROM[ \t]+stdin[ \t]*;/i;

function skipSpace(content: string, i: number): number {
  let at = i;
  for (;;) {
    while (at < content.length && /\s/.test(content[at] as string)) at += 1;
    if (content.startsWith('--', at)) {
      const end = content.indexOf('\n', at);
      at = end === -1 ? content.length : end + 1;
    } else if (content.startsWith('/*', at)) {
      const end = content.indexOf('*/', at + 2);
      at = end === -1 ? content.length : end + 2;
    } else return at;
  }
}

function skipQuoted(content: string, i: number): number {
  const quote = content[i];
  let at = i + 1;
  while (at < content.length) {
    if (content[at] === quote) {
      if (content[at + 1] !== quote) return at + 1;
      at += 2;
      continue;
    }
    at += 1;
  }
  return -1;
}

function skipGroup(content: string, i: number): number {
  let depth = 0;
  let at = i;
  while (at < content.length) {
    const c = content[at];
    if (c === "'" || c === '"' || c === '`') {
      at = skipQuoted(content, at);
      if (at < 0) return -1;
      continue;
    }
    if (c === '(') depth += 1;
    if (c === ')') {
      depth -= 1;
      if (depth === 0) return at + 1;
    }
    at += 1;
  }
  return -1;
}

function insertedRows(content: string, atLeast: number): number | 'unsure' {
  const insertInto = /\bINSERT\s+INTO\b/gi;
  let rows = 0;
  let match: RegExpExecArray | null;
  while ((match = insertInto.exec(content)) !== null) {
    let i = match.index + match[0].length;
    let values = false;
    for (;;) {
      i = skipSpace(content, i);
      const c = content[i];
      if (c === undefined || c === ';') break;
      if (c === "'" || c === '"' || c === '`' || c === '(') {
        i = c === '(' ? skipGroup(content, i) : skipQuoted(content, i);
        if (i < 0) return 'unsure';
        continue;
      }
      if (/[A-Za-z_]/.test(c)) {
        let end = i + 1;
        while (end < content.length && /[\w$]/.test(content[end] as string)) end += 1;
        const word = content.slice(i, end).toLowerCase();
        i = end;
        if (word === 'values') values = true;
        if (word === 'values' || word === 'select' || word === 'default') break;
        continue;
      }
      i += 1;
    }
    if (values) {
      for (;;) {
        i = skipSpace(content, i);
        if (content[i] !== '(') break;
        const after = skipGroup(content, i);
        if (after < 0) return 'unsure';
        rows += 1;
        if (rows >= atLeast) return rows;
        i = skipSpace(content, after);
        if (content[i] !== ',') break;
        i += 1;
      }
    }
    insertInto.lastIndex = Math.max(insertInto.lastIndex, i);
  }
  return rows;
}

export function sqlHoldsData(content: string): boolean {
  if (DUMP_HEADER.test(content) || COPY_FROM_STDIN.test(content)) return true;
  const rows = insertedRows(content, MIN_INSERTED_ROWS);
  return rows === 'unsure' || rows >= MIN_INSERTED_ROWS;
}

export function sqlDumpContentLookup(
  fileMap: FileMap,
  carry: ArchiveWatchListCarry | undefined,
): (archivePath: string) => SqlDumpContent | undefined {
  const rootPrefix = carry?.rootPrefix;
  const insideRoot = rootPrefix !== undefined && rootPrefix !== '' && path.basename(fileMap.rootPath) === rootPrefix;
  const byArchivePath = new Map(
    fileMap.entries
      .filter((entry) => entry.extension === '.sql')
      .map((entry) => [insideRoot ? `${rootPrefix}/${entry.path}` : entry.path, entry]),
  );
  return (archivePath) => {
    const entry = byArchivePath.get(archivePath);
    if (entry === undefined) return undefined;
    return sqlHoldsData(entry.content) ? 'holds_data' : 'no_data';
  };
}
