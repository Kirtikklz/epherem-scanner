import type { ScanRule } from '../../shared/types.js';
import { patternRule } from './patternRule.js';

export const unsafeDeserialization: ScanRule = patternRule({
  id: 'unsafe_deserialization',
  title: 'Unsafe deserialization may process untrusted data',
  category: 'injection',
  probes: [
    {
      pattern: /\b(?:pickle|cPickle|dill|shelve)\.(?:loads?|load)\s*\(/g,
      title: 'Python object deserialization', severity: 'critical', confidence: 'medium',
      explanation: 'Python object deserialization can execute attacker-controlled code while loading data.',
      technical: 'pickle-compatible formats are code execution formats, not safe data formats.',
      fix: 'Do not deserialize untrusted pickle/dill data. Use JSON with strict schema validation, or cryptographically authenticate a trusted internal payload before loading.',
    },
    {
      pattern: /\byaml\.load\s*\((?![^\n)]*SafeLoader)/g,
      title: 'unsafe YAML loader', severity: 'high', confidence: 'medium',
      explanation: 'A general YAML loader may instantiate unsafe object types from submitted YAML.',
      technical: 'yaml.load is used without a visibly safe loader.',
      fix: 'Use yaml.safe_load/SafeLoader and validate the resulting plain data against a strict schema.',
    },
    {
      pattern: /(?:node-serialize|serialize-javascript)[\s\S]{0,200}\b(?:unserialize|deserialize)\s*\(|\b(?:unserialize|deserialize)\s*\(\s*req\./gi,
      title: 'JavaScript object deserialization', severity: 'critical', confidence: 'medium',
      explanation: 'A JavaScript object deserializer appears to consume request data and may revive executable behavior.',
      technical: 'A non-data-only deserializer is used on potentially untrusted input.',
      fix: 'Use JSON.parse followed by strict schema validation; never revive functions, classes, or prototypes from request data.',
    },
  ],
});
