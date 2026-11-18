import type { FileMap, FileMapEntry, SchemaModel, SchemaModelMap } from '../shared/types.js';

const IDENTITY_WORDS = new Set([
  'user', 'users', 'account', 'accounts', 'member', 'members', 'membership', 'memberships',
  'team', 'teams', 'org', 'orgs', 'organisation', 'organisations', 'organization', 'organizations',
  'workspace', 'workspaces', 'tenant', 'tenants', 'owner', 'owners', 'profile', 'profiles',
  'author', 'authors', 'host', 'hosts',
]);

const OWNER_COLUMN =
  /^(?:user|owner|account|tenant|team|author|host|member|profile|org|organisation|organization|group|workspace|created_by|updated_by|belongs_to|assignee|assigned_to)(?:_id)?$/;
const BARE_IDENTITY_COLUMN = /^(?:uid|sub|clerk_id|auth_id|auth_user_id)$/;
const SELF_KEY = /^_?(?:id|uuid|pk|rowid)$/;
const FOREIGN_KEY_SHAPE = /^(.+)_id$/;

const MAX_MODELS = 2_000;
const MAX_SCHEMA_BYTES = 400_000;

function normaliseFieldName(raw: string): string {
  return raw
    .replace(/^["'`\[]+|["'`\]]+$/g, '')
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .toLowerCase();
}

export function normaliseModelKey(raw: string): string {
  const bare = raw.replace(/^["'`]+|["'`]+$/g, '').split('.').pop() ?? raw;
  const flat = bare.replace(/[^A-Za-z0-9]/g, '').toLowerCase();
  if (flat === '') return '';
  if (flat.length > 4 && flat.endsWith('ies')) return `${flat.slice(0, -3)}y`;
  if (flat.length > 4 && (flat.endsWith('ses') || flat.endsWith('xes') || flat.endsWith('ches') || flat.endsWith('shes'))) {
    return flat.slice(0, -2);
  }
  if (flat.length > 3 && flat.endsWith('s') && !flat.endsWith('ss') && !flat.endsWith('us') && !flat.endsWith('is')) {
    return flat.slice(0, -1);
  }
  return flat;
}

function nameWords(raw: string): string[] {
  return raw
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .filter((word) => word !== '')
    .map((word) => word.toLowerCase());
}

function isIdentityName(raw: string): boolean {
  return nameWords(raw).some((word) => IDENTITY_WORDS.has(word));
}

interface Draft {
  key: string;
  name: string;
  source: SchemaModel['source'];
  directOwner: boolean;
  references: Set<string>;
  unresolvedForeignKey: boolean;
}

function newDraft(name: string, source: SchemaModel['source']): Draft {
  return {
    key: normaliseModelKey(name),
    name,
    source,
    directOwner: isIdentityName(name),
    references: new Set<string>(),
    unresolvedForeignKey: false,
  };
}

function addField(draft: Draft, rawName: string, typeName: string | undefined, isList: boolean): void {
  const field = normaliseFieldName(rawName);
  if (field === '') return;
  if (OWNER_COLUMN.test(field) || BARE_IDENTITY_COLUMN.test(field)) {
    draft.directOwner = true;
    return;
  }
  if (typeName !== undefined && typeName !== '') {
    if (isList) return;
    if (isIdentityName(typeName)) { draft.directOwner = true; return; }
    draft.references.add(normaliseModelKey(typeName));
    return;
  }
  if (SELF_KEY.test(field)) return;
  const foreignKey = FOREIGN_KEY_SHAPE.exec(field);
  if (foreignKey === null) return;
  const target = foreignKey[1] ?? '';
  if (isIdentityName(target)) { draft.directOwner = true; return; }
  draft.references.add(normaliseModelKey(target));
}

const PRISMA_MODEL = /^\s*model\s+([A-Za-z_]\w*)\s*\{/;
const PRISMA_MAP = /^\s*@@map\s*\(\s*["']([^"']+)["']\s*\)/;
const PRISMA_FIELD = /^\s*([A-Za-z_]\w*)\s+([A-Za-z_]\w*)(\[\])?(\?)?\s*(.*)$/;
const PRISMA_RELATION_FIELDS = /@relation\s*\([^)]*fields\s*:\s*\[([^\]]*)\]/;

const PRISMA_ENUM = /^\s*enum\s+([A-Za-z_]\w*)\s*\{/;

interface PrismaBlock { name: string; body: string[]; mapped?: string }

function parsePrismaFile(content: string): { blocks: PrismaBlock[]; enums: Set<string> } {
  const lines = content.split('\n');
  const blocks: PrismaBlock[] = [];
  const enums = new Set<string>();
  let current: PrismaBlock | undefined;
  let depth = 0;
  for (const line of lines) {
    if (current === undefined) {
      const enumMatch = PRISMA_ENUM.exec(line);
      if (enumMatch?.[1] !== undefined) { enums.add(enumMatch[1]); continue; }
      const modelMatch = PRISMA_MODEL.exec(line);
      if (modelMatch?.[1] === undefined) continue;
      current = { name: modelMatch[1], body: [] };
      depth = 1;
      continue;
    }
    for (const ch of line) {
      if (ch === '{') depth += 1;
      else if (ch === '}') depth -= 1;
    }
    if (depth <= 0) { blocks.push(current); current = undefined; continue; }
    const mapMatch = PRISMA_MAP.exec(line);
    if (mapMatch?.[1] !== undefined) { current.mapped = mapMatch[1]; continue; }
    current.body.push(line);
  }
  return { blocks, enums };
}

const SQL_CREATE_TABLE =
  /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([\w."`]+)\s*\(/gi;
const SQL_ALTER_ADD_COLUMN =
  /ALTER\s+TABLE\s+(?:ONLY\s+)?(?:IF\s+EXISTS\s+)?([\w."`]+)\s+ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?["`]?(\w+)["`]?/gi;
const SQL_REFERENCES = /\bREFERENCES\s+([\w."`]+)/i;
const SQL_CONSTRAINT_LINE =
  /^\s*(?:PRIMARY|FOREIGN|UNIQUE|CHECK|CONSTRAINT|KEY|INDEX|EXCLUDE|LIKE)\b/i;

function parenSlice(content: string, open: number, limit = 20_000): string | undefined {
  let depth = 0;
  for (let i = open; i < content.length && i - open < limit; i += 1) {
    const ch = content[i];
    if (ch === '(') depth += 1;
    else if (ch === ')') {
      depth -= 1;
      if (depth === 0) return content.slice(open + 1, i);
    }
  }
  return undefined;
}

function splitTopLevel(body: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < body.length; i += 1) {
    const ch = body[i];
    if (ch === '(') depth += 1;
    else if (ch === ')') depth -= 1;
    else if (ch === ',' && depth === 0) { parts.push(body.slice(start, i)); start = i + 1; }
  }
  parts.push(body.slice(start));
  return parts.map((part) => part.trim()).filter((part) => part !== '');
}

const SCHEMA_EXTENSIONS = new Set(['.prisma', '.sql']);

function isCandidate(entry: FileMapEntry): boolean {
  if (!SCHEMA_EXTENSIONS.has(entry.extension)) return false;
  return entry.content.length <= MAX_SCHEMA_BYTES;
}

export function detectSchemaModels(fileMap: FileMap): SchemaModelMap {
  const drafts = new Map<string, Draft>();
  const aliases = new Map<string, string>();
  let sourcesParsed = 0;

  const put = (draft: Draft): Draft => {
    const existing = drafts.get(draft.key);
    if (existing === undefined) { drafts.set(draft.key, draft); return draft; }
    existing.directOwner ||= draft.directOwner;
    existing.unresolvedForeignKey ||= draft.unresolvedForeignKey;
    for (const reference of draft.references) existing.references.add(reference);
    return existing;
  };

  for (const entry of fileMap.entries) {
    if (drafts.size > MAX_MODELS) break;
    if (!isCandidate(entry)) continue;

    if (entry.extension === '.prisma') {
      const { blocks, enums } = parsePrismaFile(entry.content);
      if (blocks.length === 0) continue;
      sourcesParsed += 1;
      const declared = new Set(blocks.map((block) => block.name));
      for (const block of blocks) {
        const draft = newDraft(block.name, 'prisma');
        const relationScalars = new Map<string, string>();
        for (const line of block.body) {
          const field = PRISMA_FIELD.exec(line);
          if (field === null) continue;
          const [, , typeName, list, , rest = ''] = field;
          if (typeName === undefined || !declared.has(typeName)) continue;
          const fields = PRISMA_RELATION_FIELDS.exec(rest)?.[1];
          if (fields === undefined) continue;
          for (const scalar of fields.split(',')) {
            const name = scalar.trim();
            if (name !== '' && list === undefined) relationScalars.set(normaliseFieldName(name), typeName);
          }
        }
        for (const line of block.body) {
          if (/^\s*(?:\/\/|@@|$)/.test(line)) continue;
          const field = PRISMA_FIELD.exec(line);
          if (field === null) continue;
          const name = field[1];
          const typeName = field[2];
          const isList = field[3] !== undefined;
          if (name === undefined || typeName === undefined) continue;
          const viaRelation = relationScalars.get(normaliseFieldName(name));
          if (viaRelation !== undefined) { addField(draft, name, viaRelation, false); continue; }
          if (declared.has(typeName)) { addField(draft, name, typeName, isList); continue; }
          if (enums.has(typeName)) continue;
          addField(draft, name, undefined, isList);
        }
        const stored = put(draft);
        if (block.mapped !== undefined) {
          const mappedKey = normaliseModelKey(block.mapped);
          if (mappedKey !== '' && mappedKey !== stored.key) aliases.set(mappedKey, stored.key);
        }
      }
      continue;
    }

    if (entry.extension === '.sql') {
      let parsedAnyTable = false;
      SQL_CREATE_TABLE.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = SQL_CREATE_TABLE.exec(entry.content)) !== null) {
        const tableName = match[1];
        if (tableName === undefined) continue;
        const open = entry.content.indexOf('(', match.index + match[0].length - 1);
        if (open === -1) continue;
        const body = parenSlice(entry.content, open);
        if (body === undefined) continue;
        parsedAnyTable = true;
        const draft = newDraft(tableName, 'sql');
        for (const part of splitTopLevel(body)) {
          if (SQL_CONSTRAINT_LINE.test(part)) {
            const referenced = SQL_REFERENCES.exec(part)?.[1];
            if (referenced !== undefined) {
              if (isIdentityName(referenced)) draft.directOwner = true;
              else draft.references.add(normaliseModelKey(referenced));
            }
            continue;
          }
          const columnName = /^["`]?(\w+)["`]?/.exec(part)?.[1];
          if (columnName === undefined) continue;
          const referenced = SQL_REFERENCES.exec(part)?.[1];
          addField(draft, columnName, referenced, false);
        }
        put(draft);
      }
      SQL_ALTER_ADD_COLUMN.lastIndex = 0;
      while ((match = SQL_ALTER_ADD_COLUMN.exec(entry.content)) !== null) {
        const tableName = match[1];
        const columnName = match[2];
        if (tableName === undefined || columnName === undefined) continue;
        const existing = drafts.get(normaliseModelKey(tableName));
        if (existing === undefined) continue;
        addField(existing, columnName, undefined, false);
      }
      if (parsedAnyTable) sourcesParsed += 1;
    }
  }

  for (const draft of drafts.values()) {
    const resolved = new Set<string>();
    for (const reference of draft.references) {
      const canonical = aliases.get(reference) ?? reference;
      if (drafts.has(canonical)) resolved.add(canonical);
      else draft.unresolvedForeignKey = true;
    }
    draft.references = resolved;
  }

  const blocked = new Set<string>();
  const incoming = new Map<string, string[]>();
  for (const draft of drafts.values()) {
    for (const reference of draft.references) {
      const list = incoming.get(reference) ?? [];
      list.push(draft.key);
      incoming.set(reference, list);
    }
    if (draft.directOwner || draft.unresolvedForeignKey) blocked.add(draft.key);
  }
  const queue = [...blocked];
  while (queue.length > 0) {
    const key = queue.pop();
    if (key === undefined) continue;
    for (const parent of incoming.get(key) ?? []) {
      if (blocked.has(parent)) continue;
      blocked.add(parent);
      queue.push(parent);
    }
  }

  const models: SchemaModel[] = [...drafts.values()]
    .map((draft) => ({
      key: draft.key,
      name: draft.name,
      source: draft.source,
      hasOwnerLink: blocked.has(draft.key),
    }))
    .sort((a, b) => a.key.localeCompare(b.key));
  const aliasEntries = [...aliases.entries()]
    .filter(([alias, canonical]) => drafts.has(canonical) && !drafts.has(alias))
    .sort((a, b) => a[0].localeCompare(b[0]));

  return { models, aliases: Object.fromEntries(aliasEntries), sourcesParsed };
}

export function emptySchemaModelMap(): SchemaModelMap {
  return { models: [], aliases: {}, sourcesParsed: 0 };
}
