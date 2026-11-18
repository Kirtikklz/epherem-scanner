import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { ABSENCE_RULES, ENABLED_ABSENCE_TAGS, type AbsenceRuleTag } from '../../src/candidates/absence/absenceFindings.js';
import type { AbsenceHit } from '../../src/candidates/absence/rules.js';
import { MockDependencyVulnerabilityScanner } from '../../src/dependency-audit/dependencyAudit.js';
import { scanProject } from '../../src/scanProject.js';

const hit = (spanResolved: boolean): AbsenceHit => ({
  filePath: 'server.js',
  line: 4,
  ruleTag: 'x',
  sinkKind: 'x',
  observation: 'POST /thing',
  evidence: 'POST /thing',
  route: { method: 'POST', relPath: '/thing', line: 4, endLine: 4, spanResolved },
});

const READABLE: Record<string, string> = {
  'missing-request-body-validation': 'POST /thing. No middleware applied to the route matched a validator, schema or sanitiser name.',
  'missing-rate-limit': 'POST /thing. No middleware applied to the route matched a rate-limiter or throttle name.',
  'public-admin-route-hint':
    'POST /thing. The path matched an admin naming convention and no applied middleware resolved to a recognised auth guard.',
};

const NOT_ABSENCE_OF: Record<string, string> = {
  'missing-request-body-validation': 'not on the absence of a validator',
  'missing-rate-limit': 'not on the absence of a rate limiter',
  'public-admin-route-hint': 'not on the absence of an auth guard',
};

describe('each of the three specs: the unread sentence, and the readable one unchanged', () => {
  for (const tag of Object.keys(READABLE) as AbsenceRuleTag[]) {
    it(`${tag}: an unread route says it was not read`, () => {
      const text = ABSENCE_RULES[tag].technicalExplanation(hit(false));
      expect(text.startsWith('POST /thing. ')).toBe(true);
      expect(text).toContain("could not read this route's registration call");
      expect(text).toMatch(/middleware applied at the route, router or mount level/);
      expect(text).toContain('nothing was searched and nothing was ruled out');
      expect(text).toContain(`This finding rests on the absence of a reading, ${NOT_ABSENCE_OF[tag]}`);
      expect(text).toContain('Read the registration yourself before changing anything.');
      expect(text).not.toContain(READABLE[tag]?.slice('POST /thing. '.length));
    });

    it(`${tag}: a readable route keeps its sentence byte for byte`, () => {
      expect(ABSENCE_RULES[tag].technicalExplanation(hit(true))).toBe(READABLE[tag]);
    });

    it(`${tag}: a hit with no route (project-level) keeps the readable sentence`, () => {
      const { route: _route, ...projectLevel } = hit(true);
      expect(ABSENCE_RULES[tag].technicalExplanation(projectLevel)).toBe(READABLE[tag]);
    });
  }

  it('the admin sentence keeps the one fact that WAS read: the path', () => {
    expect(ABSENCE_RULES['public-admin-route-hint'].technicalExplanation(hit(false))).toContain(
      'The path matched an admin naming convention, but the route model could not read',
    );
  });

  it('only body validation of the three is enabled — the only one a user reads today', () => {
    expect(ENABLED_ABSENCE_TAGS.has('missing-request-body-validation')).toBe(true);
    expect(ENABLED_ABSENCE_TAGS.has('missing-rate-limit')).toBe(false);
    expect(ENABLED_ABSENCE_TAGS.has('public-admin-route-hint')).toBe(false);
  });
});

describe('end to end, the enabled tag: the bridge writes the unread sentence on an unread route', () => {
  it('body validation on an unreadable POST route', async () => {
    const root = await mkdtemp(path.join(tmpdir(), 'epherem-g5-'));
    try {
      await mkdir(root, { recursive: true });
      await writeFile(path.join(root, 'package.json'), '{"name":"fixture","dependencies":{"express":"^4.18.0"}}');
      await writeFile(
        path.join(root, 'server.js'),
        "const express = require('express');\nconst app = express();\n\napp.post('/orders', (req, res) => { res.status(201).json({ ok: 1 }); }\n",
      );
      const report = await scanProject(root, {
        dependencyScanner: new MockDependencyVulnerabilityScanner(),
        absenceTags: new Set(['missing-request-body-validation']),
      });
      const bridged = report.findings.filter(
        (f) => f.ruleId === 'missing_request_body_validation' && f.detectionKind === 'absence',
      );
      expect(bridged).toHaveLength(1);
      expect(bridged[0]?.technicalExplanation).toContain('not on the absence of a validator');
      expect(bridged[0]?.technicalExplanation).not.toContain('No middleware applied to the route matched a validator');
      expect(bridged[0]?.confidence).toBe('low');
      expect(bridged[0]?.evidence).toBe('POST /orders');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 120_000);
});
