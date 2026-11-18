import type { ScanRule } from '../../shared/types.js';
import { patternRule } from './patternRule.js';

export const xmlExternalEntity: ScanRule = patternRule({
  id: 'xxe',
  title: 'XML parser may allow external entities',
  category: 'injection',
  probes: [
    {
      pattern: /libxmljs\.(?:parseXml|parseXmlString)\s*\([\s\S]{0,200}(?:noent\s*:\s*true|dtdload\s*:\s*true)|etree\.XMLParser\s*\([\s\S]{0,160}resolve_entities\s*=\s*True|DocumentBuilderFactory[\s\S]{0,240}setFeature\s*\([^)]*disallow-doctype-decl[^)]*false/gi,
      title: 'external entity capable XML parser', severity: 'high', confidence: 'medium',
      explanation: 'This XML parser configuration may allow external entities or DTD processing. Malicious XML can read local files or trigger server-side requests.',
      technical: 'XML parsing is configured or instantiated without visible XXE-safe parser features.',
      fix: 'Disable DTDs and external entities, use a hardened XML parser, and reject XML when JSON or another data-only format will work.',
    },
  ],
});
