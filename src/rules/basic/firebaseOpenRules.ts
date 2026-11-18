import { makeFinding } from '../../shared/findingFactory.js';
import type { Finding, RuleContext, ScanRule } from '../../shared/types.js';
import { basename, findMatches } from '../../shared/utils.js';

const RULE_VERB = 'read|write|create|update|delete|get|list';
const VERB_LIST = `(?:${RULE_VERB})(?:\\s*,\\s*(?:${RULE_VERB}))*`;
const OPEN_FIRESTORE_RULE = new RegExp(
  `allow\\s+${VERB_LIST}[^;{]*:\\s*if\\s+true\\b` + `|allow\\s+${VERB_LIST}\\s*;`,
  'g',
);

const STORAGE_FIX_HINT =
  'Require sign-in and scope files to their owner, e.g. "match /users/{userId}/{allPaths=**} { allow read, write: if request.auth != null && request.auth.uid == userId; }", adapted to your folder layout, then redeploy the Storage rules with "firebase deploy --only storage".';

export const firebaseOpenRules: ScanRule = {
  id: 'firebase_open_rules',
  title: 'Firebase rules allow public access',
  category: 'authorization',
  kind: 'basic',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const entry of context.fileMap.entries) {
      if (entry.label !== 'firebase_rules') continue;
      const name = basename(entry.path).toLowerCase();

      if (name === 'database.rules.json') {
        findings.push(...checkRealtimeDatabaseRules(this, entry.path, entry.content));
        continue;
      }
      const storage = name === 'storage.rules' || /\bservice\s+firebase\.storage\b/.test(entry.content);
      for (const match of findMatches(entry.content, OPEN_FIRESTORE_RULE)) {
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: this.title,
            severity: 'critical',
            confidence: 'high',
            filePath: entry.path,
            lineStart: match.line,
            evidence: match.snippet,
            userExplanation:
              'Your Firebase rules allow anyone on the internet to read or write this data without signing in. Attackers routinely scan for open Firebase projects. Change the rule so it requires an authenticated user.',
            technicalExplanation: /:\s*if\b/.test(match.matchText)
              ? `Rule "${match.matchText.trim()}" grants unconditional access. Replace "if true" with an auth condition such as "if request.auth != null" plus per-document ownership checks.`
              : `Rule "${match.matchText.trim()}" has NO condition at all, which in Firestore rules syntax grants unconditional access exactly as "if true" does. Add a condition: "${match.matchText.trim().replace(/;$/, '')}: if request.auth != null;" plus per-document ownership checks.`,
            fixHint: storage
              ? STORAGE_FIX_HINT + (/:\s*if\b/.test(match.matchText) ? '' : ' A rule written without a condition is not a default-deny.')
              : /:\s*if\b/.test(match.matchText)
              ? 'Split the rule so each operation checks the right document: "allow read, update, delete: if request.auth != null && request.auth.uid == resource.data.ownerId; allow create: if request.auth != null && request.auth.uid == request.resource.data.ownerId;" (use the field your documents actually store the owner in), then redeploy the rules with "firebase deploy --only firestore:rules".'
              : 'Split the rule so each operation checks the right document: "allow read, update, delete: if request.auth != null && request.auth.uid == resource.data.ownerId; allow create: if request.auth != null && request.auth.uid == request.resource.data.ownerId;" (use the field your documents actually store the owner in), then redeploy the rules with "firebase deploy --only firestore:rules". A rule written without a condition is not a default-deny.',
            category: this.category,
          }),
        );
      }
    }
    return findings;
  },
};

function checkRealtimeDatabaseRules(rule: ScanRule, filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  for (const match of findMatches(content, /"\.(read|write)"\s*:\s*(?:true|"true")/g)) {
    findings.push(
      makeFinding({
        ruleId: rule.id,
        title: rule.title,
        severity: 'critical',
        confidence: 'high',
        filePath,
        lineStart: match.line,
        evidence: match.snippet,
        userExplanation:
          'Your Firebase Realtime Database rules allow public access. Anyone can read or modify your data without logging in. Require authentication in these rules.',
        technicalExplanation:
          `database.rules.json sets ".${match.groups[0] ?? 'read'}" to true, granting unauthenticated access to the whole subtree. Gate access on "auth != null" and per-path ownership.`,
        fixHint:
          'Require sign-in and scope data to its owner under a per-user path, e.g. { "rules": { "users": { "$uid": { ".read": "auth != null && auth.uid == $uid", ".write": "auth != null && auth.uid == $uid" } } } }, adapted to where your data lives, then redeploy with "firebase deploy --only database".',
        category: rule.category,
      }),
    );
  }
  return findings;
}
