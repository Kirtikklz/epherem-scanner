import type { ScanRule } from '../../shared/types.js';
import { patternRule } from './patternRule.js';

export const weakPasswordStorage: ScanRule = patternRule({
  id: 'weak_password_storage',
  title: 'Password storage appears weak or plaintext',
  category: 'authentication',
  probes: [
    {
      pattern: /\bpassword\s*:\s*(?:req\.body(?:\.password|\[['"]password['"]\])|request\.(?:form|json)(?:\[['"]password['"]\]|\.get\(['"]password['"]\)))/gi,
      title: 'plaintext password persisted', severity: 'critical', confidence: 'medium',
      explanation: 'A submitted password appears to be placed directly into a database object without password hashing.',
      technical: 'The password field is populated directly from request input with no password KDF visible at the assignment.',
      fix: 'Hash the password with Argon2id (preferred), scrypt, bcrypt, or PBKDF2 using a unique salt before storage; never store or log plaintext passwords.',
    },
    {
      pattern: /(?:md5|sha1)\s*\([^\n]{0,120}password|password[^\n]{0,120}(?:createHash\s*\(\s*['"](?:md5|sha1)|hashlib\.(?:md5|sha1))/gi,
      title: 'password uses fast hash', severity: 'critical', confidence: 'high',
      explanation: 'A password is hashed with MD5 or SHA-1. These fast hashes can be brute-forced very cheaply.',
      technical: 'A general-purpose fast digest is used as a password hash.',
      fix: 'Replace it with Argon2id, scrypt, bcrypt, or PBKDF2 using calibrated work factors and unique salts, and migrate existing hashes on login.',
    },
  ],
});
