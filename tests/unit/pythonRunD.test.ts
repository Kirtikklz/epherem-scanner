import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildRuleResults } from '../../src/report/buildRuleResults.js';
import { RULE_REGISTRY } from '../../src/rules/ruleRegistry.js';
import { scanProject } from '../../src/scanProject.js';
import { detectLanguages } from '../../src/shared/languages.js';
import type { DependencyAuditSummary, Finding, RuleContext, RuleResult, ScanReport } from '../../src/shared/types.js';
import { memoryContext } from './helpers.js';

const audit: DependencyAuditSummary = {
  performed: false,
  incomplete: false,
  source: 'none',
  dependenciesCollected: 0,
  checked: 0,
  notChecked: [],
  vulnerabilities: [],
  diagnostics: [],
  note: 'not run',
};
const finding = (ruleId: string): Finding => ({ ruleId }) as Finding;

function rows(context: RuleContext, findings: Finding[]): Map<string, RuleResult> {
  return new Map(
    buildRuleResults({
      findings,
      context,
      codeScanComplete: true,
      dependencyAudit: audit,
      dependencyAuditStatus: 'complete',
      archiveObserved: false,
      languages: detectLanguages(context.fileMap),
    }).map((row) => [row.ruleId, row]),
  );
}

const PYTHON_SHAPE_READERS: Readonly<Record<string, string>> = {
  api_mutation_without_auth: 'so Python routes that write data were only partly checked for a sign-in check.',
  broken_access_control: 'so Python record access was only partly checked for an ownership check.',
  database_delete_without_ownership_check: 'so Python deletes were only partly checked for an ownership check.',
  mass_assignment: 'so Python mass assignment was only partly checked.',
  missing_rate_limit: 'so Python rate limiting was only partly checked.',
  missing_request_body_validation: 'so Python request validation was only partly checked.',
  missing_webhook_verification: 'so Python webhook verification was only partly checked.',
};
const SHAPE_READERS = Object.keys(PYTHON_SHAPE_READERS);

const NO_PYTHON = [
  'client_controlled_authorization',
  'client_side_ai_secret',
  'client_side_only_authorization',
  'env_usage_without_server_boundary',
  'exposed_source_maps',
  'fail_open_authentication',
  'missing_security_headers',
  'nosql_injection',
  'oauth_misconfiguration',
  'placeholder_authentication',
  'prototype_pollution',
  'public_cloud_storage',
  'server_action_without_authorization',
  'supabase_client_used_for_privileged_operation',
  'supabase_rls_not_detected',
  'supabase_service_role_exposed',
  'unrestricted_graphql',
  'weak_session_handling',
];

const OLD_JS_ONLY_SENTENCE = 'python is detected but this rule currently supports javascript, typescript only.';
const flaskApp: [string, string] = ['app.py', 'from flask import Flask\napp = Flask(__name__)\n'];
const expressApp: [string, string] = [
  'server/app.js',
  "const app = require('express')();\napp.post('/api/notes', (req, res) => res.json({}));\n",
];

describe('the registry: which rules declare Python', () => {
  it('the seven shape readers declare python', () => {
    for (const ruleId of SHAPE_READERS) {
      expect(RULE_REGISTRY.find((rule) => rule.ruleId === ruleId)?.languages, ruleId).toContain('python');
    }
  });

  it('rules that read no Python shape still do not declare it', () => {
    for (const ruleId of NO_PYTHON) {
      const meta = RULE_REGISTRY.find((rule) => rule.ruleId === ruleId);
      expect(meta, ruleId).toBeDefined();
      expect(meta?.languages, ruleId).not.toContain('python');
    }
  });
});

describe('coverage values on a Python project', () => {
  it('a finding on Python: failed, coverage partial, with the sentence naming its shapes', () => {
    for (const ruleId of SHAPE_READERS) {
      const row = rows(memoryContext([flaskApp]), [finding(ruleId)]).get(ruleId);
      expect(row, ruleId).toEqual({
        ruleId,
        label: row?.label,
        status: 'failed',
        coverage: 'partial',
        coverageReason: expect.stringMatching(/^python is detected but this rule reads only /),
      });
      expect(row?.coverageReason?.endsWith(PYTHON_SHAPE_READERS[ruleId]!), ruleId).toBe(true);
      expect(row?.coverageReason, ruleId).not.toContain('currently supports');
    }
  });

  it('no finding on Python: never full and never passed', () => {
    const result = rows(memoryContext([flaskApp]), []);
    for (const ruleId of SHAPE_READERS) {
      const row = result.get(ruleId);
      expect(row?.coverage, ruleId).not.toBe('full');
      expect(row?.status, ruleId).not.toBe('passed');
      if (row?.status === 'not_completed') expect(row.coverage, ruleId).toBe('partial');
    }
  });

  it('a rule that reads no Python keeps none and the old sentence, word for word', () => {
    const row = rows(memoryContext([flaskApp]), [finding('prototype_pollution')]).get('prototype_pollution');
    expect(row).toEqual({
      ruleId: 'prototype_pollution',
      label: row?.label,
      status: 'failed',
      coverage: 'none',
      coverageReason: OLD_JS_ONLY_SENTENCE,
    });
  });

  it('JavaScript beside Python: partial with the shape sentence, not the old "supports javascript, typescript only"', () => {
    const mixed = memoryContext([expressApp, ['tools/report.py', 'print("hi")\n']]);
    for (const ruleId of SHAPE_READERS) {
      const row = rows(mixed, [finding(ruleId)]).get(ruleId);
      expect(row, ruleId).toMatchObject({ status: 'failed', coverage: 'partial' });
      expect(row?.coverageReason, ruleId).toContain(PYTHON_SHAPE_READERS[ruleId]);
      expect(row?.coverageReason, ruleId).not.toContain(OLD_JS_ONLY_SENTENCE);
    }
  });

  it('Go beside Python: partial, keeping the Go sentence and adding the shape sentence', () => {
    const goToo = memoryContext([flaskApp, ['cmd/main.go', 'package main\nfunc main() {}\n']]);
    for (const ruleId of SHAPE_READERS) {
      const row = rows(goToo, [finding(ruleId)]).get(ruleId);
      expect(row?.coverage, ruleId).toBe('partial');
      expect(row?.coverageReason, ruleId).toContain(
        'go is detected but this rule currently supports javascript, typescript, python only.',
      );
      expect(row?.coverageReason, ruleId).toContain(PYTHON_SHAPE_READERS[ruleId]);
    }
  });

  it('a JavaScript-only project keeps exactly what it had: full, no sentence', () => {
    for (const ruleId of SHAPE_READERS) {
      const failed = rows(memoryContext([expressApp]), [finding(ruleId)]).get(ruleId);
      expect(failed, ruleId).toEqual({ ruleId, label: failed?.label, status: 'failed', coverage: 'full' });
    }
  });
});

const PY_APP: Record<string, string> = {
  'requirements.txt': 'flask\nsupabase\n',
  'app.py': [
    'from flask import Flask, request, jsonify',
    'from supabase import create_client',
    'from models import db, User',
    'app = Flask(__name__)',
    'supabase = create_client("https://x.supabase.co", "anon")',
    '',
    '@app.route("/api/login", methods=["POST"])',
    'def login():',
    '    name = request.form.get("name")',
    '    return jsonify({"name": name})',
    '',
    '@app.route("/api/notes", methods=["POST"])',
    'def update_note():',
    '    supabase.table("notes").update({"title": request.json["title"]}).eq("id", request.json["id"]).execute()',
    '    return jsonify({"ok": True})',
    '',
    '@app.route("/api/profile", methods=["POST"])',
    'def save_profile():',
    '    user = User.query.get(1)',
    '    user.update(request.json)',
    '    return jsonify({"ok": True})',
    '',
    '@app.route("/api/notes/remove", methods=["POST"])',
    'def remove_note():',
    '    db.execute("DELETE FROM notes WHERE id = ?", (request.json["id"],))',
    '    return jsonify({"ok": True})',
    '',
    '@app.route("/api/webhooks/stripe", methods=["POST"])',
    'def stripe_webhook():',
    '    payload = request.json',
    '    create_order(payload)',
    '    return jsonify({"ok": True})',
    '',
  ].join('\n'),
};

describe('end to end on a Python-only project', () => {
  let root: string;
  let report: ScanReport;
  beforeAll(async () => {
    root = await mkdtemp(path.join(tmpdir(), 'pyrunD-scan-'));
    for (const [relative, content] of Object.entries(PY_APP)) {
      await mkdir(path.dirname(path.join(root, relative)), { recursive: true });
      await writeFile(path.join(root, relative), content);
    }
    report = await scanProject(root);
  }, 120_000);
  afterAll(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it('each of the seven fires on a Python line, and its row is failed with coverage partial', () => {
    const fired = new Set(report.findings.filter((f) => f.filePath.endsWith('.py')).map((f) => f.ruleId));
    for (const ruleId of SHAPE_READERS) {
      expect(fired.has(ruleId), `${ruleId} fires on app.py`).toBe(true);
      const row = report.ruleResults.find((r) => r.ruleId === ruleId);
      expect(row, ruleId).toMatchObject({ status: 'failed', coverage: 'partial' });
      expect(row?.coverageReason, ruleId).toContain(PYTHON_SHAPE_READERS[ruleId]);
    }
  });

  it('the coverage block lists them as partial, and no rule reads python as full there', () => {
    const partial = new Map(report.coverage.partiallyCoveredRules.map((r) => [r.ruleId, r.coverage]));
    for (const ruleId of SHAPE_READERS) expect(partial.get(ruleId), ruleId).toBe('partial');
    for (const ruleId of NO_PYTHON) {
      const row = report.ruleResults.find((r) => r.ruleId === ruleId);
      if (row?.coverage !== undefined) expect(row.coverage, ruleId).toBe('none');
    }
  });
});
