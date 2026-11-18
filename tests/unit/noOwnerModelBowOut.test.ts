import { describe, expect, it } from 'vitest';
import { brokenAccessControl } from '../../src/rules/contextual/brokenAccessControl.js';
import { databaseDeleteWithoutOwnershipCheck } from '../../src/rules/contextual/databaseDeleteWithoutOwnershipCheck.js';
import { detectSchemaModels } from '../../src/project-map/detectSchemaModels.js';
import { modelHasNoOwner } from '../../src/shared/modelOwnership.js';
import { memoryContext } from './helpers.js';

const PKG: [string, string] = [
  'package.json',
  '{"name":"x","dependencies":{"next":"14.0.0","@prisma/client":"5.0.0"}}',
];

const SCHEMA = `
model User {
  id    String @id
  email String @unique
  name  String
  @@map("users")
}

model Category {
  id        String   @id
  name      String
  createdAt DateTime
  @@map("categories")
}

model Project {
  id     String @id
  name   String
  userId String
  owner  User   @relation(fields: [userId], references: [id])
  @@map("projects")
}

model Report {
  id       String @id
  title    String
  tenantId String
  @@map("reports")
}

model Course {
  id      String @id
  ownerId String
  name    String
  @@map("courses")
}

model Card {
  id       String @id
  courseId String
  course   Course @relation(fields: [courseId], references: [id])
  front    String
  @@map("cards")
}

model Ledger {
  id      String @id
  orderId String
  amount  Int
  @@map("ledgers")
}
`;

const SCHEMA_FILE: [string, string] = ['prisma/schema.prisma', SCHEMA];

const authed = (body: string): string =>
  "import { auth } from '@/auth';\n" +
  'export async function POST(req){\n' +
  '  const session = await auth();\n' +
  "  if (!session) return new Response('no', { status: 401 });\n" +
  `${body}\n}\n`;

const ROUTE = 'app/api/x/route.ts';
const withSchema = (code: string): [string, string][] => [PKG, SCHEMA_FILE, [ROUTE, code]];

const bac = (code: string, files = withSchema(code)): number =>
  brokenAccessControl.run(memoryContext(files)).length;
const del = (code: string, files = withSchema(code)): number =>
  databaseDeleteWithoutOwnershipCheck.run(memoryContext(files)).length;

const readById = (model: string): string =>
  authed(`  const { id } = await req.json();\n  await prisma.${model}.findUnique({ where: { id } });`);
const deleteById = (model: string): string =>
  authed(`  const { id } = await req.json();\n  await prisma.${model}.delete({ where: { id } });`);

describe('no-owner model — the bow-out fires, and only here', () => {
  it('a model whose columns are all scalar business data does not fire either rule', () => {
    expect(bac(readById('category'))).toBe(0);
    expect(del(deleteById('category'))).toBe(0);
  });

  it('the same two calls DO fire when the schema is not there to prove it', () => {
    expect(bac(readById('category'), [PKG, [ROUTE, readById('category')]])).toBe(1);
    expect(del(deleteById('category'), [PKG, [ROUTE, deleteById('category')]])).toBe(1);
  });

  it('the Supabase table form bows out on the same evidence', () => {
    const code = authed(
      "  const { id } = await req.json();\n  await supabase.from('categories').delete().eq('id', id);",
    );
    expect(del(code)).toBe(0);
    const owned = authed(
      "  const { id } = await req.json();\n  await supabase.from('projects').delete().eq('id', id);",
    );
    expect(del(owned)).toBe(1);
  });
});

describe('the hard line — these must never be suppressed', () => {
  it('the user model fires, even though it has no owner column of its own', () => {
    expect(bac(readById('user'))).toBe(1);
    expect(del(deleteById('user'))).toBe(1);
  });

  it('a model with an owner column fires', () => {
    expect(bac(readById('project'))).toBe(1);
    expect(del(deleteById('project'))).toBe(1);
  });

  it('a model with a TENANT column fires — cross-tenant IDOR is still IDOR', () => {
    expect(bac(readById('report'))).toBe(1);
    expect(del(deleteById('report'))).toBe(1);
  });

  it('a model that inherits its owner through a foreign key fires (a course card shape)', () => {
    expect(bac(readById('card'))).toBe(1);
    expect(del(deleteById('card'))).toBe(1);
  });

  it('a model with a foreign key pointing at nothing the schema declares fires', () => {
    expect(bac(readById('ledger'))).toBe(1);
    expect(del(deleteById('ledger'))).toBe(1);
  });

  it('a model absent from the schema fires', () => {
    expect(bac(readById('invoice'))).toBe(1);
    expect(del(deleteById('invoice'))).toBe(1);
  });

  it('an unparseable schema suppresses nothing', () => {
    const broken: [string, string][] = [
      PKG,
      ['prisma/schema.prisma', 'model Category { id String @id\n// never closed\n'],
      [ROUTE, deleteById('category')],
    ];
    expect(del(deleteById('category'), broken)).toBe(1);
  });
});

describe('modelHasNoOwner — the predicate itself', () => {
  const map = (files: [string, string][]) =>
    memoryContext(files).projectMap;

  it('answers by table name as well as by model name', () => {
    const projectMap = map([PKG, SCHEMA_FILE]);
    expect(modelHasNoOwner(projectMap, 'Category')).toBe(true);
    expect(modelHasNoOwner(projectMap, 'category')).toBe(true);
    expect(modelHasNoOwner(projectMap, 'categories')).toBe(true);
    expect(modelHasNoOwner(projectMap, 'User')).toBe(false);
    expect(modelHasNoOwner(projectMap, 'users')).toBe(false);
  });

  it('is false for undefined, for an empty name and for a project with no schema', () => {
    const projectMap = map([PKG, SCHEMA_FILE]);
    expect(modelHasNoOwner(projectMap, undefined)).toBe(false);
    expect(modelHasNoOwner(projectMap, '')).toBe(false);
    expect(modelHasNoOwner(map([PKG]), 'Category')).toBe(false);
  });

  it('does not read a Mongoose model file at all — a Mongoose model never suppresses', () => {
    const models = detectSchemaModels(
      memoryContext([
        PKG,
        ['models/Tag.js', "import mongoose from 'mongoose';\nconst TagSchema = new mongoose.Schema({ label: { type: String }, colour: { type: String } });\nexport default mongoose.model('Tag', TagSchema);"],
      ]).fileMap,
    );
    expect(models.models).toHaveLength(0);
    expect(models.sourcesParsed).toBe(0);
  });

  it('reads SQL CREATE TABLE, including a REFERENCES clause', () => {
    const models = detectSchemaModels(
      memoryContext([
        PKG,
        [
          'migrations/0001.sql',
          'CREATE TABLE users (id uuid PRIMARY KEY, email text);\n' +
            'CREATE TABLE categories (id uuid PRIMARY KEY, name text NOT NULL);\n' +
            'CREATE TABLE notes (id uuid PRIMARY KEY, body text, owner_id uuid REFERENCES users(id));\n',
        ],
      ]).fileMap,
    );
    const verdict = (name: string) => models.models.find((m) => m.key === name)?.hasOwnerLink;
    expect(verdict('categorie' ) ?? verdict('category')).toBe(false);
    expect(verdict('note')).toBe(true);
    expect(verdict('user')).toBe(true);
  });

  it('does not read a bare client receiver as a model name', () => {
    const projectMap = map([PKG, SCHEMA_FILE]);
    expect(modelHasNoOwner(projectMap, 'db')).toBe(false);
    expect(modelHasNoOwner(projectMap, 'prisma')).toBe(false);
  });
});
