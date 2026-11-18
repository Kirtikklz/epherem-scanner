import type { ScanRule } from '../../shared/types.js';
import { patternRule } from './patternRule.js';

const JS_TS_EXTENSIONS: ReadonlySet<string> = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);

export const prototypePollution: ScanRule = patternRule({
  id: 'prototype_pollution',
  title: 'Untrusted keys may modify objects or their prototypes',
  category: 'injection',
  extensions: JS_TS_EXTENSIONS,
  probes: [
    {
      pattern: /[a-z_$][\w$]*\s*\[\s*(?:req\.(?:body|query|params)|request\.(?:args|form))[^\]]*\]\s*=/gi,
      title: 'dynamic property assignment', severity: 'high', confidence: 'medium',
      explanation: 'An untrusted property name is assigned into an object, so a caller can set fields the code never meant to accept. In JavaScript, special keys such as __proto__ or constructor can go further and alter behavior across the application.',
      technical: 'A computed property write uses a request-derived or key-like value without an allowlist.',
      fix: 'Allowlist permitted property names, reject __proto__/prototype/constructor, and use null-prototype objects for untrusted dictionaries.',
    },
    {
      pattern: /\b(?:merge|mergeWith|defaultsDeep|deepmerge)\s*\([^\n]{0,160}(?:req\.(?:body|query)|request\.(?:json|form))/gi,
      title: 'recursive merge of request data', severity: 'high', confidence: 'medium',
      explanation: 'Request data is recursively merged into another object, so a caller can set fields the code never meant to accept; in JavaScript this is a common route to prototype pollution.',
      technical: 'A deep merge consumes attacker-controlled object keys.',
      fix: 'Validate to an explicit schema, copy only allowlisted own properties, reject prototype keys, and use a dependency version with prototype-pollution fixes.',
    },
  ],
});
