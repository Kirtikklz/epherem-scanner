import { makeFinding } from '../../shared/findingFactory.js';
import type { Finding, RuleContext, ScanRule } from '../../shared/types.js';
import { basename } from '../../shared/utils.js';
import { PUBLIC_NAME, PUBLIC_PREFIX, SECRET_NAME, SECRET_VALUE } from '../../shared/publicIdentifier.js';
import { isPlaceholderEnvValue } from '../../shared/sensitiveData.js';

const TEMPLATE_ENV_PATTERN = /\.(example|sample|template|dist)$/i;
const ASSIGNMENT_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*\s*=\s*.+/m;
const ASSIGNMENT_LINE = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/;

interface EnvClassification {
  hasRealSecret: boolean;
  secretKeys: string[];
}

function classifyEnv(content: string): EnvClassification {
  const secretKeys: string[] = [];
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line === '' || line.startsWith('#')) continue;
    const m = ASSIGNMENT_LINE.exec(line);
    if (m === null) continue;
    const key = m[1] ?? '';
    const value = (m[2] ?? '').replace(/^['"]|['"]$/g, '').trim();
    if (isPlaceholderEnvValue(key, value)) continue;
    const isPublic = PUBLIC_PREFIX.test(key) || PUBLIC_NAME.test(key);
    const looksSecret = SECRET_VALUE.test(value) || (SECRET_NAME.test(key) && !isPublic);
    if (looksSecret) secretKeys.push(key);
  }
  return { hasRealSecret: secretKeys.length > 0, secretKeys };
}

export const envFileIncluded: ScanRule = {
  id: 'env_file_included',
  title: 'Environment file committed with the project',
  category: 'secrets',
  kind: 'basic',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    for (const entry of context.fileMap.entries) {
      if (entry.label !== 'env') continue;
      const name = basename(entry.path);
      if (TEMPLATE_ENV_PATTERN.test(name)) continue;
      if (!ASSIGNMENT_PATTERN.test(entry.content)) continue;

      const { hasRealSecret, secretKeys } = classifyEnv(entry.content);

      findings.push(
        hasRealSecret
          ? makeFinding({
              ruleId: this.id,
              title: this.title,
              severity: 'high',
              confidence: 'high',
              filePath: entry.path,
              lineStart: 1,
              evidence: `${name} contains real credential(s): ${secretKeys.join(', ')}`,
              userExplanation:
                'A .env file with real values is part of your project. Anyone who gets a copy of the code also gets these secrets. Keep .env files out of the project and share only a .env.example with placeholder values.',
              technicalExplanation:
                `A non-template dotenv file was found containing what appear to be real credentials (${secretKeys.join(', ')}). Environment files with secrets must be excluded from version control and uploads via .gitignore, and any committed credential must be rotated.`,
              fixHint:
                'Add the file to .gitignore (e.g. ".env*" with "!.env.example"), remove it from the repository history if it was committed, rotate every credential it contains, and keep a placeholder-only .env.example for collaborators.',
              category: this.category,
            })
          : makeFinding({
              ruleId: this.id,
              title: this.title,
              severity: 'low',
              confidence: 'high',
              filePath: entry.path,
              lineStart: 1,
              evidence: `${name} contains only public-by-design values (no real secret detected)`,
              userExplanation:
                'A .env file is committed, but it appears to hold only values that are meant to be public — a Supabase publishable/anon key, your project URL, or "public" front-end variables. Those are safe to expose (your Row Level Security policies are what actually protect your data), so this is informational, not a leak. Still, keep .env out of version control as a habit, and if you ever add a real secret it will be exposed.',
              technicalExplanation:
                'A non-template dotenv file was found, but every assignment is a public-by-design value (publishable/anon key, URL/project id, or a framework public-prefixed variable). No service_role key, API secret, private key, password, or credentialed URL was detected. Flagged low/informational; re-check if real secrets are added later.',
              fixHint:
                'This is fine to leave as-is for public keys, but as good practice add .env to .gitignore and keep a placeholder-only .env.example. Never put a service_role key, API secret, or database password in a client-loaded .env.',
              category: this.category,
            }),
      );
    }
    return findings;
  },
};
