import { makeFinding } from '../../shared/findingFactory.js';
import { classifySensitiveColumns, sensitiveCategories } from '../../shared/sensitiveData.js';
import type { Finding, RuleContext, ScanRule } from '../../shared/types.js';

const MATCH_BLOCK = /match\s+\/([A-Za-z_][\w-]*)\s*\/\s*\{[^{}]*?\}\s*\{|match\s+\/([A-Za-z_][\w-]*)\s*\/\{[^}]*?\}\s*\{/g;

const UNCONDITIONAL_READ =
  /allow\s+(?:read|get|list)(?:\s*,\s*(?:read|get|list|write|create|update|delete))*\s*(?:;|:\s*if\s+true\b)/i;

const COLLECTION_WRITE =
  /(?:collection\s*\(\s*[^,]+,\s*['"]([\w-]+)['"]\s*\)|collection\s*\(\s*['"]([\w-]+)['"]\s*\)|\.collection\s*\(\s*['"]([\w-]+)['"]\s*\)|doc\s*\(\s*[^,]+,\s*['"]([\w-]+)['"])/g;

export const firebaseReadableSensitiveData: ScanRule = {
  id: 'firebase_readable_sensitive_data',
  title: 'Firestore collection with sensitive fields is readable without sign-in',
  category: 'authorization',
  kind: 'contextual',
  run(context: RuleContext): Finding[] {
    const rulesFiles = context.fileMap.entries.filter((e) => e.label === 'firebase_rules');
    if (rulesFiles.length === 0) return [];

    const fieldsByCollection = inferCollectionFields(context);
    const findings: Finding[] = [];

    for (const entry of rulesFiles) {
      for (const open of openReadCollections(entry.content)) {
        const fields = fieldsByCollection.get(open.collection);
        if (fields === undefined || fields.length === 0) continue;
        const sensitive = classifySensitiveColumns(fields);
        if (sensitive.critical.length === 0 && sensitive.high.length === 0) continue;
        const named = [...sensitive.critical, ...sensitive.high];
        const critical = sensitive.critical.length > 0;
        const categories = sensitiveCategories(named);
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: this.title,
            severity: critical ? 'critical' : 'high',
            confidence: 'high',
            filePath: entry.path,
            lineStart: open.line,
            evidence: `allow read on "${open.collection}" is unconditional; documents contain ${named.join(', ')}`,
            userExplanation:
              `People who are not signed in can read documents in your "${open.collection}" collection, because its Firestore rule allows reads with no condition. Depending on the rule, that means every document, or any single document whose ID they know. Fields that look like ${categories.join(', ')} (${named.join(', ')}) appear in code that uses this collection, so those details may be exposed. Require an authenticated, owner-scoped condition on the read rule.`,
            technicalExplanation:
              `firestore.rules grants an unconditional read on /${open.collection} (${entry.path}:${open.line}). Firestore has no schema, but code that uses this collection references the field(s) ${named.join(', ')}. With the public web config, any client can read its documents (the whole collection when list is allowed; single documents by ID when only get is). Replace the open read with e.g. "allow read: if request.auth != null && request.auth.uid == resource.data.userId".`,
            fixHint:
              `Change the rule to "allow read: if request.auth != null && request.auth.uid == resource.data.ownerId" (or your owner field). If some documents are genuinely public, split the public fields into a separate collection and keep ${named.join(', ')} in an owner-scoped one.`,
            category: this.category,
          }),
        );
      }
    }
    return findings;
  },
};

interface OpenRead {
  collection: string;
  line: number;
}

export function openReadCollections(content: string): OpenRead[] {
  const out: OpenRead[] = [];
  const matchRe = /match\s+\/([A-Za-z_][\w-]*)\s*\/\s*\{[^}]*\}/g;
  let m: RegExpExecArray | null;
  let guard = 0;
  while ((m = matchRe.exec(content)) !== null) {
    if (guard++ > 500) break;
    const name = m[1];
    if (name === undefined) continue;
    const bodyStart = m.index + m[0].length;
    const nextMatch = content.indexOf('match /', bodyStart);
    const bodyEnd = nextMatch === -1 ? Math.min(content.length, bodyStart + 400) : nextMatch;
    const body = content.slice(bodyStart, bodyEnd);
    if (UNCONDITIONAL_READ.test(body)) {
      out.push({ collection: name, line: lineAt(content, m.index) });
    }
  }
  return out;
}

function inferCollectionFields(context: RuleContext): Map<string, string[]> {
  const byCollection = new Map<string, Set<string>>();
  const jsTs = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);
  for (const entry of context.fileMap.entries) {
    if (!jsTs.has(entry.extension)) continue;
    const content = entry.content;
    const re = new RegExp(COLLECTION_WRITE.source, 'g');
    let m: RegExpExecArray | null;
    let guard = 0;
    while ((m = re.exec(content)) !== null) {
      if (guard++ > 2000) break;
      const name = m[1] ?? m[2] ?? m[3] ?? m[4];
      if (name === undefined) continue;
      const window = content.slice(m.index, m.index + 600);
      for (const keys of objectLiteralKeys(window)) {
        const set = byCollection.get(name) ?? new Set<string>();
        for (const k of keys) set.add(k.toLowerCase());
        byCollection.set(name, set);
      }
    }
  }
  const out = new Map<string, string[]>();
  for (const [k, v] of byCollection) out.set(k, [...v]);
  return out;
}

function objectLiteralKeys(text: string): string[][] {
  const results: string[][] = [];
  const braceStart = text.indexOf('{');
  if (braceStart === -1) return results;
  let depth = 0;
  let end = braceStart;
  for (let i = braceStart; i < text.length && i < braceStart + 500; i += 1) {
    if (text[i] === '{') depth += 1;
    else if (text[i] === '}') {
      depth -= 1;
      if (depth === 0) {
        end = i;
        break;
      }
    }
  }
  const inner = text.slice(braceStart + 1, end);
  const keys: string[] = [];
  for (const km of inner.matchAll(/(?:^|[,{])\s*['"]?([A-Za-z_][\w]*)['"]?\s*:/g)) {
    if (km[1] !== undefined) keys.push(km[1]);
  }
  if (keys.length > 0) results.push(keys);
  return results;
}

function lineAt(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i += 1) if (content[i] === '\n') line += 1;
  return line;
}
