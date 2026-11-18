import { compareRunOrder, migrationPositions, type SqlPosition } from '../../project-map/detectRls.js';
import type { FileMapEntry } from '../../shared/types.js';

type Token =
  | { kind: 'word'; text: string; lower: string; at: number }
  | { kind: 'quoted'; text: string; at: number }
  | { kind: 'string'; text: string; at: number }
  | { kind: 'number'; text: string; at: number }
  | { kind: 'punct'; text: string; at: number };

const WORD_START = /[A-Za-z_\u0080-\uffff]/;
const WORD_PART = /[\w$\u0080-\uffff]/;
const SPACE = /\s/;

function lex(content: string): Token[] {
  const tokens: Token[] = [];
  const n = content.length;
  let i = 0;
  while (i < n) {
    const c = content[i] as string;
    if (SPACE.test(c)) {
      i += 1;
      continue;
    }
    if (c === '-' && content[i + 1] === '-') {
      const end = content.indexOf('\n', i);
      i = end === -1 ? n : end + 1;
      continue;
    }
    if (c === '/' && content[i + 1] === '*') {
      let depth = 1;
      i += 2;
      while (i < n && depth > 0) {
        if (content[i] === '/' && content[i + 1] === '*') {
          depth += 1;
          i += 2;
        } else if (content[i] === '*' && content[i + 1] === '/') {
          depth -= 1;
          i += 2;
        } else i += 1;
      }
      continue;
    }
    if (c === "'" || c === '"') {
      const read = readQuoted(content, i, c, false);
      tokens.push(c === "'" ? { kind: 'string', text: read.text, at: i } : { kind: 'quoted', text: read.text, at: i });
      i = read.end;
      continue;
    }
    if (c === '$') {
      const tag = /^\$(?:[A-Za-z_]\w*)?\$/.exec(content.slice(i, i + 64));
      if (tag !== null) {
        const close = content.indexOf(tag[0], i + tag[0].length);
        tokens.push({ kind: 'string', text: content.slice(i + tag[0].length, close === -1 ? n : close), at: i });
        i = close === -1 ? n : close + tag[0].length;
        continue;
      }
    }
    if (WORD_START.test(c)) {
      let j = i + 1;
      while (j < n && WORD_PART.test(content[j] as string)) j += 1;
      const text = content.slice(i, j);
      if ((text === 'E' || text === 'e') && content[j] === "'") {
        const read = readQuoted(content, j, "'", true);
        tokens.push({ kind: 'string', text: read.text, at: i });
        i = read.end;
        continue;
      }
      tokens.push({ kind: 'word', text, lower: text.toLowerCase(), at: i });
      i = j;
      continue;
    }
    if (c >= '0' && c <= '9') {
      let j = i + 1;
      while (j < n && /[\d.]/.test(content[j] as string)) j += 1;
      tokens.push({ kind: 'number', text: content.slice(i, j), at: i });
      i = j;
      continue;
    }
    if (c === ':' && content[i + 1] === ':') {
      tokens.push({ kind: 'punct', text: '::', at: i });
      i += 2;
      continue;
    }
    tokens.push({ kind: 'punct', text: c, at: i });
    i += 1;
  }
  return tokens;
}

function readQuoted(content: string, start: number, quote: string, backslashes: boolean): { text: string; end: number } {
  let text = '';
  let i = start + 1;
  while (i < content.length) {
    const c = content[i] as string;
    if (backslashes && c === '\\' && i + 1 < content.length) {
      text += content[i + 1];
      i += 2;
      continue;
    }
    if (c === quote) {
      if (content[i + 1] === quote) {
        text += quote;
        i += 2;
        continue;
      }
      return { text, end: i + 1 };
    }
    text += c;
    i += 1;
  }
  return { text, end: content.length };
}

const isWord = (token: Token | undefined, ...words: string[]): boolean =>
  token?.kind === 'word' && words.includes(token.lower);
const isPunct = (token: Token | undefined, text: string): boolean => token?.kind === 'punct' && token.text === text;

function nameOf(token: Token | undefined): string | undefined {
  if (token?.kind === 'word') return token.lower;
  if (token?.kind === 'quoted') return token.text;
  return undefined;
}

type BucketKey = string;
const valueOf = (key: BucketKey): string => key.slice(key.indexOf(':') + 1);
type Bucket = readonly BucketKey[];

type Literal = { kind: 'string'; value: string } | { kind: 'bool'; value: boolean } | { kind: 'other' };

interface Effect {
  madePublic: Bucket[] | 'any';
  publicIfNew: Bucket[];
  madePrivate: Bucket[];
  deleted: Bucket[];
  onlyMakesPrivate: boolean;
  created: Bucket[];
  unapplied: { reaches: Bucket[] | undefined; deletes: boolean } | undefined;
}

const NO_PUBLIC_CHANGE: Effect = {
  madePublic: [],
  publicIfNew: [],
  madePrivate: [],
  deleted: [],
  onlyMakesPrivate: false,
  created: [],
  unapplied: undefined,
};
const UNREADABLE: Effect = { ...NO_PUBLIC_CHANGE, madePublic: 'any' };

function bucketsTableEnd(tokens: readonly Token[], i: number): number {
  if (nameOf(tokens[i]) !== 'storage' || !isPunct(tokens[i + 1], '.') || nameOf(tokens[i + 2]) !== 'buckets') return -1;
  return i + 3;
}

function skipAlias(tokens: readonly Token[], i: number, stops: readonly string[]): number {
  if (isWord(tokens[i], 'as')) return i + 2;
  const token = tokens[i];
  if ((token?.kind === 'word' && !stops.includes(token.lower)) || token?.kind === 'quoted') return i + 1;
  return i;
}

function splitTopLevel(tokens: readonly Token[], from: number, to: number): Token[][] {
  const parts: Token[][] = [];
  let depth = 0;
  let current: Token[] = [];
  for (let i = from; i < to; i += 1) {
    const token = tokens[i] as Token;
    if (isPunct(token, '(') || isPunct(token, '[')) depth += 1;
    if (isPunct(token, ')') || isPunct(token, ']')) depth -= 1;
    if (depth === 0 && isPunct(token, ',')) {
      parts.push(current);
      current = [];
      continue;
    }
    current.push(token);
  }
  parts.push(current);
  return parts;
}

function closeOf(tokens: readonly Token[], open: number, end: number): number {
  let depth = 0;
  for (let i = open; i < end; i += 1) {
    if (isPunct(tokens[i], '(')) depth += 1;
    if (isPunct(tokens[i], ')')) {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function firstWord(tokens: readonly Token[], from: number, to: number, words: readonly string[]): number {
  let depth = 0;
  for (let i = from; i < to; i += 1) {
    const token = tokens[i];
    if (isPunct(token, '(')) depth += 1;
    if (isPunct(token, ')')) depth -= 1;
    if (depth === 0 && token?.kind === 'word' && words.includes(token.lower)) return i;
  }
  return to;
}

function literalOf(expression: readonly Token[]): Literal {
  let tokens = [...expression];
  const cast = tokens.findIndex((token) => isPunct(token, '::'));
  if (cast > 0) tokens = tokens.slice(0, cast);
  while (tokens.length >= 3 && isPunct(tokens[0], '(') && isPunct(tokens[tokens.length - 1], ')')) {
    tokens = tokens.slice(1, -1);
  }
  if (tokens.length !== 1) return { kind: 'other' };
  const only = tokens[0] as Token;
  if (only.kind === 'string') return { kind: 'string', value: only.text };
  if (isWord(only, 'true')) return { kind: 'bool', value: true };
  if (isWord(only, 'false')) return { kind: 'bool', value: false };
  return { kind: 'other' };
}

type PublicAssignment = 'absent' | boolean | 'excluded' | 'other';

function publicAssigned(tokens: readonly Token[], from: number, to: number): PublicAssignment {
  let found: PublicAssignment = 'absent';
  for (const part of splitTopLevel(tokens, from, to)) {
    if (isPunct(part[0], '(')) {
      if (part.some((token) => nameOf(token) === 'public')) found = 'other';
      continue;
    }
    if (nameOf(part[0]) !== 'public' || !isPunct(part[1], '=')) continue;
    const value = part.slice(2);
    const literal = literalOf(value);
    if (literal.kind === 'bool') found = literal.value;
    else if (value.length === 3 && nameOf(value[0]) === 'excluded' && isPunct(value[1], '.') && nameOf(value[2]) === 'public') {
      found = 'excluded';
    } else found = 'other';
  }
  return found;
}

function bucketsNamedBy(tokens: readonly Token[], from: number, to: number): Bucket[] | undefined {
  let i = from;
  const column = (): 'id' | 'name' | undefined => {
    let last: string | undefined;
    for (;;) {
      last = nameOf(tokens[i]);
      if (last === undefined) return undefined;
      i += 1;
      if (!isPunct(tokens[i], '.')) break;
      i += 1;
    }
    return last === 'id' || last === 'name' ? last : undefined;
  };
  const literal = (): string | undefined => {
    const token = tokens[i];
    if (token?.kind !== 'string') return undefined;
    i += 1;
    if (isPunct(tokens[i], '::')) {
      i += 1;
      while (i < to && tokens[i]?.kind === 'word') i += 1;
    }
    return token.text;
  };
  const term = (): Bucket[] | undefined => {
    if (isPunct(tokens[i], '(')) {
      i += 1;
      const inner = disjunction();
      if (inner === undefined || !isPunct(tokens[i], ')')) return undefined;
      i += 1;
      return inner;
    }
    if (tokens[i]?.kind === 'string') {
      const value = literal();
      if (value === undefined || !isPunct(tokens[i], '=')) return undefined;
      i += 1;
      const col = column();
      return col === undefined ? undefined : [[`${col}:${value}`]];
    }
    const col = column();
    if (col === undefined) return undefined;
    if (isPunct(tokens[i], '=')) {
      i += 1;
      const value = literal();
      return value === undefined ? undefined : [[`${col}:${value}`]];
    }
    if (!isWord(tokens[i], 'in') || !isPunct(tokens[i + 1], '(')) return undefined;
    i += 2;
    const named: Bucket[] = [];
    for (;;) {
      const value = literal();
      if (value === undefined) return undefined;
      named.push([`${col}:${value}`]);
      if (isPunct(tokens[i], ')')) {
        i += 1;
        return named;
      }
      if (!isPunct(tokens[i], ',')) return undefined;
      i += 1;
    }
  };
  const disjunction = (): Bucket[] | undefined => {
    const all = term();
    while (all !== undefined && isWord(tokens[i], 'or')) {
      i += 1;
      const next = term();
      if (next === undefined) return undefined;
      all.push(...next);
    }
    return all;
  };
  const named = disjunction();
  return named !== undefined && named.length > 0 && i === to ? named : undefined;
}

function readInsert(tokens: readonly Token[], start: number, end: number): Effect {
  let i = bucketsTableEnd(tokens, start + 2);
  if (i < 0) return UNREADABLE;
  i = skipAlias(tokens, i, ['values', 'select', 'default', 'overriding']);
  if (!isPunct(tokens[i], '(')) return UNREADABLE;
  const columnsClose = closeOf(tokens, i, end);
  if (columnsClose < 0) return UNREADABLE;
  const columns = splitTopLevel(tokens, i + 1, columnsClose).map((part) => (part.length === 1 ? nameOf(part[0]) : undefined));
  i = columnsClose + 1;
  if (!isWord(tokens[i], 'values')) return UNREADABLE;
  i += 1;

  const rows: { bucket: BucketKey[]; isPublic: boolean | undefined }[] = [];
  for (;;) {
    if (!isPunct(tokens[i], '(')) return UNREADABLE;
    const close = closeOf(tokens, i, end);
    if (close < 0) return UNREADABLE;
    const values = splitTopLevel(tokens, i + 1, close).map(literalOf);
    if (values.length !== columns.length) return UNREADABLE;
    const bucket: BucketKey[] = [];
    let isPublic: boolean | undefined = false;
    for (let column = 0; column < columns.length; column += 1) {
      const name = columns[column];
      const value = values[column] as Literal;
      if ((name === 'id' || name === 'name') && value.kind === 'string') bucket.push(`${name}:${value.value}`);
      if (name === 'public') isPublic = value.kind === 'bool' ? value.value : undefined;
    }
    rows.push({ bucket, isPublic });
    i = close + 1;
    if (!isPunct(tokens[i], ',')) break;
    i += 1;
  }

  let conflict: 'none' | 'nothing' | PublicAssignment = 'none';
  if (isWord(tokens[i], 'on') && isWord(tokens[i + 1], 'conflict')) {
    const doAt = firstWord(tokens, i + 2, end, ['do']);
    if (isWord(tokens[doAt + 1], 'nothing')) conflict = 'nothing';
    else if (isWord(tokens[doAt + 1], 'update') && isWord(tokens[doAt + 2], 'set')) {
      const setEnd = firstWord(tokens, doAt + 3, end, ['where', 'returning']);
      conflict = publicAssigned(tokens, doAt + 3, setEnd);
      if (isWord(tokens[setEnd], 'where') && conflict !== 'absent') conflict = 'other';
    } else return UNREADABLE;
  } else if (i < end && !isWord(tokens[i], 'returning')) return UNREADABLE;

  const mayBePublic = rows.filter((row) => conflict === true || conflict === 'other' || row.isPublic !== false);
  const always = conflict === false ? [] : mayBePublic;
  const ifNew = conflict === false ? mayBePublic : [];
  const named = rows.filter((row) => row.bucket.length > 0);
  return {
    ...NO_PUBLIC_CHANGE,
    madePublic: mayBePublic.some((row) => row.bucket.length === 0) ? 'any' : always.map((row) => row.bucket),
    publicIfNew: ifNew.map((row) => row.bucket),
    madePrivate: named
      .filter((row) => conflict === false || (conflict === 'excluded' && row.isPublic === false))
      .map((row) => row.bucket),
    created: named.map((row) => row.bucket),
  };
}

function readUpdate(tokens: readonly Token[], start: number, end: number): Effect {
  let i = start + 1;
  if (isWord(tokens[i], 'only')) i += 1;
  i = bucketsTableEnd(tokens, i);
  if (i < 0) return UNREADABLE;
  i = skipAlias(tokens, i, ['set']);
  if (!isWord(tokens[i], 'set')) return UNREADABLE;
  const setEnd = firstWord(tokens, i + 1, end, ['from', 'where', 'returning']);
  const value = publicAssigned(tokens, i + 1, setEnd);
  if (value === 'absent') return NO_PUBLIC_CHANGE;
  const whereEnd = firstWord(tokens, setEnd, end, ['returning']);
  const buckets = isWord(tokens[setEnd], 'where') ? bucketsNamedBy(tokens, setEnd + 1, whereEnd) : undefined;
  if (value === true) return { ...NO_PUBLIC_CHANGE, madePublic: buckets ?? 'any' };
  if (value === false && buckets !== undefined) {
    return { ...NO_PUBLIC_CHANGE, madePrivate: buckets, onlyMakesPrivate: true };
  }
  return {
    ...NO_PUBLIC_CHANGE,
    madePublic: value === false ? [] : 'any',
    onlyMakesPrivate: value === false,
    unapplied: { reaches: buckets, deletes: false },
  };
}

function readDelete(tokens: readonly Token[], start: number, end: number): Effect {
  let i = start + 2;
  if (isWord(tokens[i], 'only')) i += 1;
  i = bucketsTableEnd(tokens, i);
  if (i < 0) return NO_PUBLIC_CHANGE;
  i = skipAlias(tokens, i, ['using', 'where', 'returning']);
  const whereEnd = firstWord(tokens, i, end, ['returning']);
  const buckets = isWord(tokens[i], 'where') ? bucketsNamedBy(tokens, i + 1, whereEnd) : undefined;
  if (buckets !== undefined) return { ...NO_PUBLIC_CHANGE, madePrivate: buckets, deleted: buckets };
  return { ...NO_PUBLIC_CHANGE, unapplied: { reaches: undefined, deletes: true } };
}

interface BucketStatement extends Effect {
  file: string;
  line: number;
  position: SqlPosition;
  end: number;
}

function lineAt(content: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < content.length; i += 1) if (content[i] === '\n') line += 1;
  return line;
}

function statementsIn(entry: FileMapEntry, place: Omit<SqlPosition, 'offset'>): BucketStatement[] {
  const tokens = lex(entry.content);
  const out: BucketStatement[] = [];
  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i] as Token;
    let table: number;
    let read: (tokens: readonly Token[], start: number, end: number) => Effect;
    if (isWord(token, 'insert') && isWord(tokens[i + 1], 'into')) {
      table = i + 2;
      read = readInsert;
    } else if (isWord(token, 'update')) {
      table = isWord(tokens[i + 1], 'only') ? i + 2 : i + 1;
      read = readUpdate;
    } else if (isWord(token, 'delete') && isWord(tokens[i + 1], 'from')) {
      table = isWord(tokens[i + 2], 'only') ? i + 3 : i + 2;
      read = readDelete;
    } else continue;
    if (bucketsTableEnd(tokens, table) < 0) continue;
    let end = i;
    while (end < tokens.length && !isPunct(tokens[end], ';')) end += 1;
    out.push({
      file: entry.path,
      line: lineAt(entry.content, token.at),
      position: { ...place, offset: token.at },
      end: end < tokens.length ? (tokens[end] as Token).at + 1 : entry.content.length,
      ...read(tokens, i, end),
    });
    i = end;
  }
  return out;
}

export const MAX_REPLAYED_BUCKET_STATEMENTS = 2_000;

export interface BucketVerdict {
  keep: boolean;
  notes: string[];
}

const AS_BEFORE: BucketVerdict = { keep: true, notes: [] };

export interface BucketReplay {
  judge(filePath: string, offset: number): BucketVerdict;
}

export function reportedStatementKey(filePath: string, offset: number): string {
  return `${filePath}\u0000${offset}`;
}

const BUCKET_TEXT = /storage"?\s*\.\s*"?buckets/i;

export interface ReportedStatement {
  name: string | undefined;
  end: number;
}

export function replayBucketStatements(
  entries: readonly FileMapEntry[],
  reported: ReadonlyMap<string, ReportedStatement>,
): BucketReplay {
  const sqlEntries = entries.filter((entry) => entry.extension === '.sql');
  const positionOf = migrationPositions(sqlEntries.map((entry) => entry.path));
  const statements: BucketStatement[] = [];
  for (const entry of sqlEntries) {
    if (!BUCKET_TEXT.test(entry.content)) continue;
    const place = positionOf(entry.path);
    if (!place.applied) continue;
    statements.push(...statementsIn(entry, { file: place.file, version: place.version }));
    if (statements.length > MAX_REPLAYED_BUCKET_STATEMENTS) return { judge: () => AS_BEFORE };
  }
  if (statements.length === 0) return { judge: () => AS_BEFORE };
  const byPlace = new Map(statements.map((statement) => [reportedStatementKey(statement.file, statement.position.offset), statement]));

  const before = (a: BucketStatement, b: BucketStatement): boolean => compareRunOrder(a.position, b.position) === 'before';
  const meets = (a: Bucket, b: Bucket): boolean => a.some((key) => b.includes(key));
  const existsBefore = (statement: BucketStatement, bucket: Bucket): boolean => {
    const deletes = statements.filter(
      (other) => other.deleted.some((named) => meets(named, bucket)) || other.unapplied?.deletes === true,
    );
    return statements.some(
      (earlier) =>
        before(earlier, statement) &&
        earlier.created.some((named) => meets(named, bucket)) &&
        !deletes.some((gone) => !before(gone, earlier) && !before(statement, gone)),
    );
  };
  const setsPublic = (statement: BucketStatement, bucket: Bucket): boolean =>
    statement.madePublic === 'any' ||
    statement.madePublic.some((named) => meets(named, bucket)) ||
    (statement.publicIfNew.some((named) => meets(named, bucket)) && !existsBefore(statement, bucket));
  const setsPrivate = (statement: BucketStatement, bucket: Bucket): boolean =>
    statement.madePrivate.some((named) => meets(named, bucket));
  const privateAtEnd = (live: readonly BucketStatement[], bucket: Bucket): boolean =>
    live.length > 0 && live.every((other) => setsPrivate(other, bucket) && !setsPublic(other, bucket));
  const liveFor = (bucket: Bucket): BucketStatement[] => {
    const touching = statements.filter((statement) => setsPublic(statement, bucket) || setsPrivate(statement, bucket));
    return touching.filter((statement) => !touching.some((other) => other !== statement && before(statement, other)));
  };
  const reportedFor = (statement: BucketStatement, bucket: Bucket): boolean => {
    const label = reported.get(reportedStatementKey(statement.file, statement.position.offset))?.name;
    if (label === undefined || statement.madePublic === 'any' || statement.madePublic.length !== 1) return false;
    return (
      meets(statement.madePublic[0] as Bucket, bucket) &&
      bucket.some((named) => valueOf(named).split('/').pop() === label)
    );
  };
  const earliest = (list: readonly BucketStatement[]): BucketStatement | undefined =>
    [...list].sort(
      (a, b) =>
        (before(a, b) ? -1 : before(b, a) ? 1 : 0) ||
        (a.position.version ?? '\uffff').localeCompare(b.position.version ?? '\uffff') ||
        a.file.localeCompare(b.file) ||
        a.position.offset - b.position.offset,
    )[0];

  function judge(filePath: string, offset: number): BucketVerdict {
    const key = reportedStatementKey(filePath, offset);
    const statement = byPlace.get(key);
    if (statement === undefined || (reported.get(key)?.end ?? Infinity) > statement.end) return AS_BEFORE;
    if (statement.onlyMakesPrivate) return { keep: false, notes: [] };
    const buckets = statement.madePublic;
    const notes: string[] = [];

    if (buckets !== 'any' && buckets.length > 0) {
      let needed = false;
      const madePrivateLater: { bucket: Bucket; where: BucketStatement }[] = [];
      for (const bucket of buckets) {
        const live = liveFor(bucket);
        if (privateAtEnd(live, bucket)) {
          madePrivateLater.push({ bucket, where: earliest(live) as BucketStatement });
          continue;
        }
        if (live.includes(statement) || !live.some((other) => reportedFor(other, bucket))) needed = true;
      }
      if (!needed) return { keep: false, notes: [] };
      for (const { bucket, where } of madePrivateLater) {
        notes.push(`"${valueOf(bucket[0] as BucketKey)}" was made private later, in ${where.file}:${where.line}`);
      }

      if (buckets.length === 1) {
        const bucket = buckets[0] as Bucket;
        if (liveFor(bucket).includes(statement)) {
          const cancellers = statements.filter((other) => setsPrivate(other, bucket));
          const origin = earliest(
            statements.filter(
              (other) =>
                other !== statement &&
                before(other, statement) &&
                setsPublic(other, bucket) &&
                other.madePublic !== 'any' &&
                !cancellers.some((canceller) => before(other, canceller)),
            ),
          );
          const creation = earliest(
            statements.filter(
              (other) =>
                other !== statement && before(other, statement) && other.created.some((named) => meets(named, bucket)),
            ),
          );
          if (origin !== undefined) notes.push(`originally made public in ${origin.file}:${origin.line}`);
          else if (creation !== undefined) notes.push(`the bucket was created in ${creation.file}:${creation.line}`);
        }
      }
    }

    const unapplied = earliest(
      statements.filter(
        (other) =>
          other !== statement &&
          other.unapplied !== undefined &&
          !before(other, statement) &&
          (other.unapplied.reaches === undefined ||
            buckets === 'any' ||
            other.unapplied.reaches.some((reached) => buckets.some((bucket) => meets(reached, bucket)))),
      ),
    );
    if (unapplied?.unapplied !== undefined) {
      const what = unapplied.unapplied.deletes
        ? 'deletes buckets without naming them literally'
        : unapplied.unapplied.reaches === undefined
          ? 'changes public access without naming the bucket literally'
          : 'sets public access to a value that is not a literal';
      notes.push(`not applied: ${unapplied.file}:${unapplied.line} ${what}`);
    }
    return { keep: true, notes };
  }

  return { judge };
}
