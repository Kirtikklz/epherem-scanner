import { describe, expect, it } from 'vitest';
import { nosqlInjection } from '../../src/rules/basic/nosqlInjection.js';
import { ldapInjection } from '../../src/rules/basic/ldapInjection.js';
import { xmlExternalEntity } from '../../src/rules/basic/xxe.js';
import { oauthMisconfiguration } from '../../src/rules/basic/oauthMisconfiguration.js';
import { weakSessionHandling } from '../../src/rules/basic/weakSessionHandling.js';
import { memoryContext } from './helpers.js';

const PKG: [string, string] = ['package.json', '{"name":"x"}'];

describe('nosql_injection', () => {
  const MONGO_PKG: [string, string] = [
    'package.json',
    '{"name":"x","dependencies":{"express":"^4.18.0","mongoose":"^8.0.0"}}',
  ];
  const nosql = (path: string, code: string) => nosqlInjection.run(memoryContext([MONGO_PKG, [path, code]]));

  it('flags a whole request object passed as a Mongo filter', () => {
    expect(nosql('server/users.js', 'export async function h(req){ return User.findOne(req.body); }\n')).toHaveLength(1);
  });

  it('flags a raw request value used as an object-property filter', () => {
    expect(
      nosql('server/users.js', 'export async function h(req){ return User.findOne({ email: req.body.email }); }\n'),
    ).toHaveLength(1);
  });

  it('flags $where fed request input at critical severity', () => {
    const findings = nosql('server/q.js', 'export async function h(req){ return Account.find({ $where: req.body.filter }); }\n');
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('critical');
  });

  it('flags when the driver is only imported, with no manifest entry', () => {
    const ctx = memoryContext([
      ['package.json', '{"name":"x","dependencies":{"next":"14.0.0"}}'],
      ['server/db.js', "import { MongoClient } from 'mongodb';\nexport const client = new MongoClient(process.env.URL);\n"],
      ['server/users.js', 'export async function h(req){ return User.findOne(req.body); }\n'],
    ]);
    expect(nosqlInjection.run(ctx)).toHaveLength(1);
  });

  it('pymongo projects are still covered', () => {
    const ctx = memoryContext([
      ['requirements.txt', 'flask==3.0.0\npymongo==4.6.0\n'],
      ['app/users.js', 'export async function h(req){ return User.findOne(req.body); }\n'],
    ]);
    expect(nosqlInjection.run(ctx)).toHaveLength(1);
  });

  it('FP regression: { $eq: req.x } scalar-forces the value (the canonical fix)', () => {
    expect(
      nosql('server/users.js', 'export async function h(req){ return User.findOne({ email: { $eq: req.body.email } }); }\n'),
    ).toHaveLength(0);
  });

  it('FP regression: a primitive cast around the request value is safe', () => {
    expect(
      nosql('server/users.js', 'export async function h(req){ return User.findOne({ id: ObjectId(req.params.id) }); }\n'),
    ).toHaveLength(0);
  });

  it('FP regression: a string-coercing method is safe', () => {
    expect(
      nosql('server/users.js', 'export async function h(req){ return User.findOne({ email: req.body.email.toLowerCase() }); }\n'),
    ).toHaveLength(0);
  });

  it('FP regression: Array.prototype.find with a callback is not a query', () => {
    expect(
      nosql('server/ai.js', 'async function f(collection){ const rows = await collection.listSearchIndexes().toArray();\n  return rows.find((index) => index.name === "x"); }\n'),
    ).toHaveLength(0);
  });

  it('FP regression: a literal-only filter with no request input is safe', () => {
    expect(
      nosql('server/ai.js', 'async function f(db){ const c = db.collection("x"); return c.findOne({ embedding: { $exists: true } }); }\n'),
    ).toHaveLength(0);
  });

  it('FP regression: findById on a scalar id is not object-injectable', () => {
    expect(
      nosql('server/users.js', 'export async function h(req){ return User.findById(req.user.id); }\n'),
    ).toHaveLength(0);
  });

  it('FP regression: silent in a project with no Mongo driver at all', () => {
    const sql: [string, string] = [
      'package.json',
      '{"name":"x","dependencies":{"express":"^4.18.0","sequelize":"^4.44.0","mysql2":"^1.5.0"}}',
    ];
    const ctx = memoryContext([sql, ['server/users.js', 'export async function h(req){ return db.User.find({ where: req.body }); }\n']]);
    expect(nosqlInjection.run(ctx)).toHaveLength(0);
  });

  it('a type-forcing schema (z.string) IS safe — the value can no longer be an object', () => {
    expect(
      nosql('server/users.js', "import { z } from 'zod';\nexport async function h(req){ const email = z.string().parse(req.body.email); return User.findOne({ email }); }\n"),
    ).toHaveLength(0);
  });

  it('a bare field allowlist (pick) is NOT safe — its values are still raw objects', () => {
    expect(
      nosql('server/users.js', 'export async function h(req){ const filter = pick(req.body, ["email"]); return User.findOne(filter); }\n'),
    ).toHaveLength(1);
  });
});

describe('ldap_injection', () => {
  it('flags LDAP filters built by interpolation', () => {
    const ctx = memoryContext([PKG, ['server/ldap.js', 'export function h(req, client){ client.search("ou=users", { filter: `(uid=${req.query.uid})` }); }\n']]);
    expect(ldapInjection.run(ctx)).toHaveLength(1);
  });

  it('does not flag escaped LDAP filter values', () => {
    const ctx = memoryContext([PKG, ['server/ldap.js', 'export function h(req, client){ client.search("ou=users", { filter: `(uid=${escapeFilter(req.query.uid)})` }); }\n']]);
    expect(ldapInjection.run(ctx)).toHaveLength(0);
  });
});

describe('xxe', () => {
  it('flags XML parsers configured to resolve entities', () => {
    const ctx = memoryContext([PKG, ['app/xml.py', 'from lxml import etree\nparser = etree.XMLParser(resolve_entities=True)\n']]);
    expect(xmlExternalEntity.run(ctx)).toHaveLength(1);
  });

  it('does not flag safe XML parser settings', () => {
    const ctx = memoryContext([PKG, ['app/xml.py', 'from lxml import etree\nparser = etree.XMLParser(resolve_entities=False, no_network=True)\n']]);
    expect(xmlExternalEntity.run(ctx)).toHaveLength(0);
  });
});

describe('oauth_misconfiguration', () => {
  it('flags missing state and request-controlled redirect URI', () => {
    const ctx = memoryContext([PKG, ['server/oauth.js', 'provider.authorizationUrl({ state: "", redirect_uri: req.query.redirect_uri });\n']]);
    expect(oauthMisconfiguration.run(ctx).length).toBeGreaterThan(0);
  });

  it('does not flag fixed callback and state', () => {
    const ctx = memoryContext([PKG, ['server/oauth.js', 'provider.authorizationUrl({ state: req.session.oauthState, redirect_uri: process.env.OAUTH_CALLBACK_URL });\n']]);
    expect(oauthMisconfiguration.run(ctx)).toHaveLength(0);
  });
});

describe('weak_session_handling', () => {
  it('flags short hardcoded session secrets', () => {
    const ctx = memoryContext([PKG, ['server/session.js', 'app.use(session({ secret: "keyboardcat", resave: false, saveUninitialized: false }));\n']]);
    expect(weakSessionHandling.run(ctx)).toHaveLength(1);
  });

  it('does not flag environment-backed strong session secrets', () => {
    const ctx = memoryContext([PKG, ['server/session.js', 'app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }));\n']]);
    expect(weakSessionHandling.run(ctx)).toHaveLength(0);
  });
});
