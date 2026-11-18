import type { ScanRule } from '../../shared/types.js';
import { patternRule } from './patternRule.js';
import { MASS_ASSIGNMENT_TARGET_OBJECTS } from '../../shared/sensitiveData.js';

const TARGET_OBJECT = MASS_ASSIGNMENT_TARGET_OBJECTS.join('|');

export const massAssignment: ScanRule = patternRule({
  id: 'mass_assignment',
  title: 'Request data is mass-assigned to a model',
  category: 'authorization',
  probes: [
    {
      pattern: /\b(?:create|update|upsert|set)\s*\(\s*(?:req\.body|request\.(?:json|data))\s*\)/gi,
      title: 'unfiltered persistence input', severity: 'high', confidence: 'medium',
      explanation: 'The complete request body is sent to a model or database update. Attackers may set protected fields such as role, ownerId, price, or approval status.',
      technical: 'A persistence-like operation receives an unfiltered request object.',
      fix: 'Validate the body against an explicit schema and construct the persistence object from an allowlist of writable fields.',
    },
    {
      pattern: new RegExp(`\\bObject\\.assign\\s*\\(\\s*(?:${TARGET_OBJECT})\\s*,\\s*req\\.body`, 'gi'),
      title: 'request merged into domain object', severity: 'high', confidence: 'high',
      explanation: 'Every submitted field is copied onto a sensitive object, allowing protected properties to be overwritten.',
      technical: 'Object.assign mass-assigns req.body into a domain object.',
      fix: 'Copy only explicitly writable fields after schema validation; set ownership and privilege fields exclusively from trusted server state.',
    },
    {
      pattern: /\bdata\s*:\s*(?:req\.body|request\.(?:json|data))\b/gi,
      title: 'ORM data from full request', severity: 'high', confidence: 'medium',
      explanation: 'An ORM data object is populated from the complete request body.',
      technical: 'The data property directly references unfiltered request data.',
      fix: 'Parse the body with a strict schema and build data from an allowlist; reject unknown fields.',
    },
  ],
});
