import { makeFinding } from '../../shared/findingFactory.js';
import type { Confidence, Finding, RuleContext, ScanRule, Severity } from '../../shared/types.js';
import { decodeJwtPayload, findMatches, isPlaceholderValue, lineNumberAt, redactSecret } from '../../shared/utils.js';
import { isPublicByDesignSecret, isSupabaseLocalDemoKey } from '../../shared/publicIdentifier.js';
import { isInsideComment } from '../../shared/liveCode.js';
import { isClientExposedAiSecret } from '../../shared/clientAiSecret.js';
import { mayVouchForProject } from '../../input/fileFilters.js';
import { pythonMasked } from '../../shared/pythonFlow.js';

export interface SecretPattern {
  name: string;
  pattern: RegExp;
  severity: Severity;
  confidence: Confidence;
  // The pattern alone proves a real key shape: prefix, length and charset.
  formatValidated?: true;
  rejectValue?: RegExp;
  rejectMatch?: RegExp;
  // Generic arm with no provider prefix: low-entropy values are not reported.
  entropyGated?: true;
  // A PEM header alone is not a key: key material must follow it.
  demandsKeyMaterial?: true;
  aiProvider?: true;
  plainWord?: true;
  explanation?: string;
  fix?: string;
}

const PLAIN_VALUE = String.raw`['"](?!<REDACTED:)([^'"\\\r\n]{3,200})['"]`;
const PLAIN_ANNOTATION = String.raw`(?::\s*[A-Za-z_][A-Za-z0-9_.[\]|]*)?`;
const SIGNING_SECRET_NAME =
  String.raw`(?:jwt[_-]?(?:secret|signing[_-]?key|token[_-]?secret)|(?:access|refresh|auth|id)[_-]?token[_-]?secret|token[_-]?secret|secret[_-]?key|session[_-]?secret|cookie[_-]?secret|app[_-]?secret|signing[_-]?(?:secret|key)|hmac[_-]?(?:secret|key)|(?:encryption|encrypt|cipher|crypto|aes)[_-]?(?:secret|key))`;
const SECRET_SETTING_NAME = String.raw`[A-Z0-9_]*(?:SECRET(?:_KEY)?|PASSWORD|PASSWD|SIGNING_KEY|ENCRYPTION_KEY)`;

const PLAIN_WORD_NOT_A_SECRET = /^[$%]|\$\(|\$\{\{|^(?:true|false|yes|no|on|off|none|null|nil|undefined)$/i;

function pythonAssignmentInsideString(content: string, masked: string, valueIndex: number): boolean {
  let op = valueIndex - 2;
  while (op > 0 && /\s/.test(content[op] ?? '')) op -= 1;
  return (content[op] === '=' || content[op] === ':') && masked[op] !== content[op];
}

function plainWordsAreNotSecretsIn(filePath: string, extension: string): boolean {
  const posix = filePath.replace(/\\/g, '/');
  const name = posix.slice(posix.lastIndexOf('/') + 1);
  if (extension === '.html') return true;
  if (/(?:^|\/)\.github\/workflows\/|(?:^|\/)\.circleci\/|(?:^|\/)\.gitlab-ci\.ya?ml$|(?:^|\/)(?:azure|bitbucket)-pipelines\.ya?ml$/.test(posix)) return true;
  return /^(?:playwright|vitest|jest|cypress|karma)(?:\.[\w-]+)*\.config\.[cm]?[jt]s$/.test(name);
}

const SIGNING_SECRET_EXPLANATION =
  'A secret that signs logins, sessions or tokens is written in your code as a plain word. Anyone who reads the code, or guesses the word, can forge a login or a session for any user. Use a long random value kept in an environment variable instead.';
const SIGNING_SECRET_FIX =
  'Generate a long random secret (32 or more random bytes), set it as an environment variable on the server, and read it from there with no fallback. Changing it signs everyone out once.';
const FALLBACK_EXPLANATION =
  'When the environment variable is not set, this code falls back to a secret written in the code. Anyone who reads the code can then use that word to forge logins or sessions, or to read what it protects.';
const FALLBACK_FIX =
  'Remove the fallback: read the secret from the environment only, and stop the app from starting when it is missing.';
const ENCRYPTION_KEY_EXPLANATION =
  'The key that encrypts this data is written in your code, so anyone who reads the code can decrypt it.';
const ENCRYPTION_KEY_FIX =
  'Load the key from an environment variable that is set only on the server. If it encrypts passwords, hash them instead (bcrypt or argon2), because a password should never be decryptable.';
const DATABASE_PASSWORD_EXPLANATION =
  'A database password is written in your code. Anyone who reads the code can use it to reach the database wherever it accepts connections, and people often reuse passwords.';
const DATABASE_PASSWORD_FIX =
  'Change the database password, set the new one as an environment variable on the server, and read it from there.';

// Whole-value placeholders only, so a real password containing one still fires.
const PLACEHOLDER_CONNECTION_PASSWORD =
  /^(?:pass|passwd|password|passwort|pwd|secret|mysecret|supersecret|super_secret|test|testing|admin|root|postgres|postgresql|mysql|mongo|mongodb|redis|user|username|db|database|changeme|change_me|changethis|letmein|hunter2|abc123|pass123|123456|12345678|dbpass|db_pass|db_password|mypassword|yourpassword|your_password|localdev|devpass)$/i;

const LOCAL_OR_RESERVED_DB_HOST =
  /@(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|host\d*|hostname|db|database|postgres|postgresql|mysql|mongo|mongodb|redis)(?:[:,/?]|$)|@[^\s/'"`]*\.(?:example\.(?:com|org|net)|test|invalid|localhost|local|internal|db)(?:[:,/?]|$)/i;

// A placeholder default for a password setting is not a leaked secret.
const PASSWORD_FALLBACK_PLACEHOLDER = new RegExp(
  String.raw`(?:PASSWORD|PASSWD)['"]?\s*\]?\s*(?:,\s*|\)\s*or\s+|\|\||\?\?)\s*['"]${PLACEHOLDER_CONNECTION_PASSWORD.source.slice(1, -1)}['"]`,
  'i',
);

export const SECRET_PATTERNS: SecretPattern[] = [
  { name: 'Stripe live secret key', pattern: /(?<![A-Za-z0-9_-])sk_live_[A-Za-z0-9]{16,}/g, severity: 'critical', confidence: 'high', formatValidated: true },
  { name: 'Stripe test secret key', pattern: /(?<![A-Za-z0-9_-])sk_test_[A-Za-z0-9]{16,}/g, severity: 'medium', confidence: 'high', formatValidated: true },
  { name: 'OpenAI API key', pattern: /(?<![A-Za-z0-9_-])sk-(?:proj-)?[A-Za-z0-9_-]{20,}/g, severity: 'critical', confidence: 'high', formatValidated: true, aiProvider: true },
  { name: 'Anthropic API key', pattern: /(?<![A-Za-z0-9_-])sk-ant-[A-Za-z0-9_-]{20,}/g, severity: 'critical', confidence: 'high', formatValidated: true, aiProvider: true },
  { name: 'AWS access key id', pattern: /(?<![A-Za-z0-9_-])AKIA[0-9A-Z]{16}/g, severity: 'critical', confidence: 'high', formatValidated: true },
  { name: 'Google API key', pattern: /(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}/g, severity: 'high', confidence: 'high', formatValidated: true },
  { name: 'GitHub token', pattern: /(?<![A-Za-z0-9_-])gh[pousr]_[A-Za-z0-9]{30,}/g, severity: 'critical', confidence: 'high', formatValidated: true },
  {
    name: 'Private key block',
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g,
    severity: 'critical',
    confidence: 'high',
    formatValidated: true,
    demandsKeyMaterial: true,
  },
  { name: 'Supabase personal access token', pattern: /(?<![A-Za-z0-9_-])sbp_(?:v0_)?[A-Za-z0-9]{20,}/g, severity: 'critical', confidence: 'high', formatValidated: true },
  { name: 'Supabase secret key', pattern: /(?<![A-Za-z0-9_-])sb_secret_[A-Za-z0-9_-]{16,}/g, severity: 'critical', confidence: 'high', formatValidated: true },
  { name: 'Polar access token', pattern: /(?<![A-Za-z0-9_-])polar_(?:oat|pat)_[A-Za-z0-9]{16,}/g, severity: 'critical', confidence: 'high', formatValidated: true },
  { name: 'Resend API key', pattern: /(?<![A-Za-z0-9_-])re_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}/g, severity: 'critical', confidence: 'high', formatValidated: true },
  { name: 'Vercel Blob read-write token', pattern: /(?<![A-Za-z0-9_-])vercel_blob_rw_[A-Za-z0-9]{16,}_[A-Za-z0-9]{16,}/g, severity: 'critical', confidence: 'high', formatValidated: true },
  { name: 'Groq API key', pattern: /(?<![A-Za-z0-9_-])gsk_[A-Za-z0-9]{20,}/g, severity: 'critical', confidence: 'high', formatValidated: true, aiProvider: true },
  { name: 'xAI API key', pattern: /(?<![A-Za-z0-9_-])xai-[A-Za-z0-9]{20,}/g, severity: 'critical', confidence: 'high', formatValidated: true, aiProvider: true },
  { name: 'Perplexity API key', pattern: /(?<![A-Za-z0-9_-])pplx-[A-Za-z0-9]{20,}/g, severity: 'critical', confidence: 'high', formatValidated: true, aiProvider: true },
  { name: 'Hugging Face access token', pattern: /(?<![A-Za-z0-9_-])hf_[A-Za-z0-9]{30,}/g, severity: 'critical', confidence: 'high', formatValidated: true, aiProvider: true },
  { name: 'Replicate API token', pattern: /(?<![A-Za-z0-9_-])r8_[A-Za-z0-9]{30,}/g, severity: 'critical', confidence: 'high', formatValidated: true, aiProvider: true },
  { name: 'Telegram bot token', pattern: /(?<![A-Za-z0-9_:-])\d{8,10}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])/g, severity: 'critical', confidence: 'high', formatValidated: true },
  {
    name: 'Database connection string password',
    pattern: /\b(?:postgres|postgresql|mysql|mongodb\+srv|mongodb|redis|rediss|amqps?|mssql):\/\/[^\s:@/'"`]+:([^\s@/'"`]{3,})@[^\s'"`<>]+/g,
    severity: 'critical',
    confidence: 'high',
    rejectValue: PLACEHOLDER_CONNECTION_PASSWORD,
    rejectMatch: LOCAL_OR_RESERVED_DB_HOST,
  },
  {
    name: 'Generic hardcoded credential',
    pattern: /(?:api[_-]?key|secret|token|password|passwd)\s*(?::\s*[A-Za-z_][A-Za-z0-9_.[\]]*)?\s*[:=]\s*(?:(?:Buffer|Uint8Array)\s*\.\s*from\s*\(\s*)?['"]([A-Za-z0-9+/_-]{16,})['"]/gi,
    severity: 'high',
    confidence: 'medium',
  },
  {
    name: 'High-entropy credential in a secret-named assignment',
    pattern: /(?:api[_-]?key|apikey|secret|token|password|passwd|passphrase|credentials?|access[_-]?key|private[_-]?key)\s*(?::\s*[A-Za-z_][A-Za-z0-9_.[\]]*)?\s*[:=]\s*(?:(?:Buffer|Uint8Array)\s*\.\s*from\s*\(\s*)?['"`]([A-Za-z0-9+/=._~-]{20,})['"`]/gi,
    severity: 'high',
    confidence: 'medium',
    entropyGated: true,
  },
  {
    name: 'High-entropy credential in a key-named binding',
    rejectValue: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    pattern:
      /(?<![A-Za-z0-9_])[A-Za-z0-9_]*(?:key|secret|token|password|passphrase|credential)[A-Za-z0-9_]*\s*(?::\s*[A-Za-z_][A-Za-z0-9_.[\]]*)?\s*[:=]\s*(?:(?:Buffer|Uint8Array)\s*\.\s*from\s*\(\s*)?['"`]([A-Za-z0-9+/=._~-]{32,})['"`]/gi,
    severity: 'high',
    confidence: 'medium',
    entropyGated: true,
  },
  {
    name: 'Django SECRET_KEY',
    pattern: /\bSECRET_KEY\b['"]?\s*\]?\s*[:=]\s*['"]((?:django-insecure-)?(?=[a-z0-9!@#$%^&*(\-_=+)]*[!@#$%^&*()])[a-z0-9!@#$%^&*(\-_=+)]{40,})['"]/g,
    severity: 'high',
    confidence: 'medium',
    entropyGated: true,
  },
  {
    name: 'Guessable signing or session secret',
    pattern: new RegExp(String.raw`(?<![A-Za-z0-9_$])[A-Za-z0-9_$]*?${SIGNING_SECRET_NAME}['"]?\s*\]?\s*${PLAIN_ANNOTATION}\s*[:=]\s*${PLAIN_VALUE}`, 'gi'),
    severity: 'high',
    confidence: 'medium',
    plainWord: true,
    explanation: SIGNING_SECRET_EXPLANATION,
    fix: SIGNING_SECRET_FIX,
  },
  {
    name: 'Guessable fallback for a secret setting',
    pattern: new RegExp(String.raw`process\.env(?:\.|\[\s*['"])${SECRET_SETTING_NAME}(?:['"]\s*\])?\s*(?:\|\||\?\?)\s*${PLAIN_VALUE}`, 'g'),
    severity: 'high',
    confidence: 'medium',
    plainWord: true,
    rejectMatch: PASSWORD_FALLBACK_PLACEHOLDER,
    explanation: FALLBACK_EXPLANATION,
    fix: FALLBACK_FIX,
  },
  {
    name: 'Guessable default for a secret setting',
    pattern: new RegExp(String.raw`\b(?:os\.environ\.get|os\.getenv|environ\.get|getenv)\s*\(\s*['"]${SECRET_SETTING_NAME}['"]\s*(?:,\s*|\)\s*or\s+)${PLAIN_VALUE}`, 'g'),
    severity: 'high',
    confidence: 'medium',
    plainWord: true,
    rejectMatch: PASSWORD_FALLBACK_PLACEHOLDER,
    explanation: FALLBACK_EXPLANATION,
    fix: FALLBACK_FIX,
  },
  {
    name: 'Encryption key written in the code',
    pattern: new RegExp(String.raw`(?:\bnew\s+Cryptr\s*\(\s*|\bCryptoJS\s*\.\s*(?:AES|DES|TripleDES|Rabbit|RC4|RC4Drop)\s*\.\s*(?:encrypt|decrypt)\s*\([^,;\r\n]{1,200},\s*)${PLAIN_VALUE}`, 'g'),
    severity: 'high',
    confidence: 'medium',
    plainWord: true,
    explanation: ENCRYPTION_KEY_EXPLANATION,
    fix: ENCRYPTION_KEY_FIX,
  },
  {
    name: 'Database password in the connection settings',
    pattern: new RegExp(String.raw`\b(?:host|HOST|hostname|server)\s*:\s*[^,{}\r\n]{1,160},[^{}]{0,400}?\b(?:password|PASSWORD|passwd|pass|pwd)\s*:\s*${PLAIN_VALUE}`, 'g'),
    severity: 'medium',
    confidence: 'medium',
    plainWord: true,
    rejectValue: PLACEHOLDER_CONNECTION_PASSWORD,
    explanation: DATABASE_PASSWORD_EXPLANATION,
    fix: DATABASE_PASSWORD_FIX,
  },
  {
    name: 'Database password in a database setting',
    pattern: new RegExp(String.raw`(?<![A-Za-z0-9_$])[A-Za-z0-9_$]*?(?:mysql|db|database|postgres|pg|sql|mongo)[_-]?(?:password|passwd|pass|pwd)['"]?\s*\]?\s*${PLAIN_ANNOTATION}\s*[:=]\s*${PLAIN_VALUE}`, 'gi'),
    severity: 'medium',
    confidence: 'medium',
    plainWord: true,
    rejectValue: PLACEHOLDER_CONNECTION_PASSWORD,
    explanation: DATABASE_PASSWORD_EXPLANATION,
    fix: DATABASE_PASSWORD_FIX,
  },
  {
    name: 'Database password in a connect call',
    pattern: new RegExp(String.raw`\b(?:connect|create_engine|Connection)\s*\([^()]{0,400}?\b(?:password|passwd)\s*=\s*${PLAIN_VALUE}`, 'g'),
    severity: 'medium',
    confidence: 'medium',
    plainWord: true,
    rejectValue: PLACEHOLDER_CONNECTION_PASSWORD,
    explanation: DATABASE_PASSWORD_EXPLANATION,
    fix: DATABASE_PASSWORD_FIX,
  },
];

export const JWT_PATTERN = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;

const SCREAMING_OR_KEBAB_UPPER = /^[A-Z][A-Z0-9]*(?:[_-][A-Z0-9]+)+$/;
function looksLikeErrorCodeConstant(value: string): boolean {
  return SCREAMING_OR_KEBAB_UPPER.test(value);
}

const NAME_MODIFIER_WORDS = new Set(['new', 'old', 'current', 'confirm', 'repeat', 'verify', 'again', 'field', 'input', 'id']);

function nameTokens(text: string): string[] {
  return text
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .map((part) => part.toLowerCase())
    .filter((part) => part.length > 0);
}

function assignedNameOf(matchText: string): string | undefined {
  const separator = matchText.search(/[:=]/);
  if (separator <= 0) return undefined;
  return matchText.slice(0, separator).replace(/['"`]/g, '').trim();
}

function valueRestatesItsOwnName(matchText: string, value: string): boolean {
  const name = assignedNameOf(matchText);
  if (name === undefined || name === '') return false;
  const keyTokens = new Set(nameTokens(name));
  if (keyTokens.size === 0) return false;
  const valueTokens = nameTokens(value);
  if (valueTokens.length === 0) return false;
  let sharedWithKey = 0;
  for (const token of valueTokens) {
    if (keyTokens.has(token)) { sharedWithKey += 1; continue; }
    if (NAME_MODIFIER_WORDS.has(token)) continue;
    return false;
  }
  return sharedWithKey > 0;
}
const GENERIC_MIN_LENGTH = 20;
const GENERIC_MIN_ENTROPY = 3.5;

const JWT_SHAPE = /^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;

function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const character of value) counts.set(character, (counts.get(character) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function looksLikePathOrUrl(value: string): boolean {
  if (/^(?:https?|ftp|ftps|file|data|mailto|ws|wss):/i.test(value)) return true;
  if (value.startsWith('/') || value.startsWith('./') || value.startsWith('../')) return true;
  return value.includes('/') && /\.[A-Za-z][A-Za-z0-9]{0,5}$/.test(value);
}

const MAX_LABEL_SEGMENT = 20;
const LABEL_SEGMENT = /^[A-Za-z0-9]{1,20}$/;
const LABEL_WORD = /^[A-Za-z]{3,}$/;
function looksLikeSeparatedLabel(value: string): boolean {
  const segments = value.split(/[-_.]/);
  if (segments.length < 2) return false;
  if (!segments.every((segment) => segment.length <= MAX_LABEL_SEGMENT && LABEL_SEGMENT.test(segment))) return false;
  return segments.some((segment) => LABEL_WORD.test(segment));
}

function passesGenericEntropyGate(value: string): boolean {
  if (value.length < GENERIC_MIN_LENGTH) return false;
  if (!/[A-Za-z]/.test(value) || !/[0-9]/.test(value)) return false;
  if (looksLikePathOrUrl(value)) return false;
  if (JWT_SHAPE.test(value)) return false;
  if (looksLikeSeparatedLabel(value)) return false;
  return shannonEntropy(value) >= GENERIC_MIN_ENTROPY;
}

const CLERK_VARIABLE_NAME = /(?<![A-Za-z0-9_])CLERK_[A-Z0-9_]*(?:SECRET|KEY|TOKEN)/;
const CLERK_LIBRARY = /@clerk\/[a-z-]+|\bclerkClient\b|\bClerkProvider\b|\bcreateClerkClient\b/;
const STRIPE_VARIABLE_NAME = /(?<![A-Za-z0-9_])STRIPE_[A-Z0-9_]*(?:SECRET|KEY|TOKEN)/;
const STRIPE_LIBRARY = /from\s+['"]stripe['"]|require\(\s*['"]stripe['"]\s*\)|@stripe\/|\bnew\s+Stripe\s*\(/;

const LABEL_WINDOW_BEFORE = 400;
const LABEL_WINDOW_AFTER = 200;

const SERVICE_ACCOUNT_TYPE = /"type"\s*:\s*"service_account"/;
const SERVICE_ACCOUNT_SIBLING =
  /"private_key_id"|"client_email"|"token_uri"|"auth_provider_x509_cert_url"|"client_x509_cert_url"/;
const SERVICE_ACCOUNT_WINDOW = 2000;

interface RefinedLabel {
  name: string;
  fixHint: string;
}

function refineSecretLabel(
  patternName: string,
  content: string,
  valueIndex: number,
): RefinedLabel | undefined {
  if (patternName === 'Stripe live secret key' || patternName === 'Stripe test secret key') {
    const window =
      content.slice(Math.max(0, valueIndex - LABEL_WINDOW_BEFORE), valueIndex + LABEL_WINDOW_AFTER);
    const clerk = CLERK_VARIABLE_NAME.test(window) || CLERK_LIBRARY.test(content);
    const stripe = STRIPE_VARIABLE_NAME.test(window) || STRIPE_LIBRARY.test(content);
    if (clerk && !stripe) {
      return {
        name: 'Clerk secret key',
        fixHint:
          'Revoke this secret key in the Clerk dashboard (Configure > API keys), issue a new one, and load it from a server-only environment variable (CLERK_SECRET_KEY). Clerk secret keys share the sk_live_ prefix with Stripe; this one was attributed to Clerk because the surrounding code names Clerk and never names Stripe.',
      };
    }
    return undefined;
  }
  if (patternName === 'Private key block') {
    const window = content.slice(
      Math.max(0, valueIndex - SERVICE_ACCOUNT_WINDOW),
      valueIndex + SERVICE_ACCOUNT_WINDOW,
    );
    if (SERVICE_ACCOUNT_TYPE.test(window) && SERVICE_ACCOUNT_SIBLING.test(window)) {
      return {
        name: 'Google service account private key',
        fixHint:
          'This is the private key from a Google/Firebase service-account JSON, which bypasses Firestore and Storage Security Rules entirely. Delete the key in Google Cloud Console (IAM & Admin > Service Accounts > Keys), create a replacement, and load it from a server-only environment variable or secret manager — never from a file in the repository. This is NOT the AIzaSy browser apiKey, which is public by design and needs no rotation.',
      };
    }
    return undefined;
  }
  return undefined;
}

const PEM_BODY_LINE = /^[A-Za-z0-9+/=]{12,}$/;
const PEM_MATERIAL_WINDOW = 400;
const LEADING_COMMENT_MARKER = /^\s*(?:\/\/+|#+|\*)\s*/;

function hasFollowingKeyMaterial(content: string, afterIndex: number): boolean {
  const window = content.slice(afterIndex, afterIndex + PEM_MATERIAL_WINDOW);
  return window
    .split(/\r?\n|\\r\\n|\\n/)
    .some((line) => PEM_BODY_LINE.test(line.replace(LEADING_COMMENT_MARKER, '').trim()));
}

const SCANNABLE_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.json', '.yaml', '.yml', '.toml', '.html', '.pem', '.key']);

export const hardcodedSecret: ScanRule = {
  id: 'hardcoded_secret',
  title: 'Hardcoded secret in source code',
  category: 'secrets',
  kind: 'basic',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const clientFiles = new Set(context.projectMap.publicClientUsage);

    for (const entry of context.fileMap.entries) {
      if (entry.label === 'env') continue;
      if (!SCANNABLE_EXTENSIONS.has(entry.extension)) continue;
      if (entry.label === 'package_manifest') continue;
      if (!mayVouchForProject(entry.path, context.projectMap.scannerRootPrefix)) continue;

      const reportedOnLine = new Set<string>();

      for (const secretPattern of SECRET_PATTERNS) {
        for (const match of findMatches(entry.content, secretPattern.pattern)) {
          const secretValue = match.groups[0] ?? match.matchText;
          if (secretPattern.formatValidated !== true && isPlaceholderValue(secretValue)) continue;
          if (looksLikeErrorCodeConstant(secretValue)) continue;
          if (secretPattern.formatValidated !== true && valueRestatesItsOwnName(match.matchText, secretValue)) continue;
          if (secretPattern.rejectValue?.test(secretValue) === true) continue;
          if (secretPattern.rejectMatch?.test(match.matchText) === true) continue;
          if (secretPattern.demandsKeyMaterial === true && !hasFollowingKeyMaterial(entry.content, match.index + match.matchText.length)) {
            continue;
          }
          const valueOffset = secretPattern.plainWord === true ? match.matchText.lastIndexOf(secretValue) : match.matchText.indexOf(secretValue);
          const valueIndex = match.index + (valueOffset === -1 ? 0 : valueOffset);
          if (isPublicByDesignSecret(entry.content, valueIndex, secretValue)) continue;
          const line = secretPattern.plainWord === true ? lineNumberAt(entry.content, valueIndex) : match.line;
          if (secretPattern.entropyGated === true) {
            const literal = `${match.line}:${secretValue}`;
            if (reportedOnLine.has(literal)) continue;
            if (!passesGenericEntropyGate(secretValue)) continue;
            if (isInsideComment(entry.content, valueIndex, entry.extension, entry.label)) continue;
          }
          if (secretPattern.plainWord === true) {
            if (reportedOnLine.has(`${line}:${secretValue}`)) continue;
            if (isInsideComment(entry.content, valueIndex, entry.extension, entry.label)) continue;
            if (PLAIN_WORD_NOT_A_SECRET.test(secretValue)) continue;
            if (plainWordsAreNotSecretsIn(entry.path, entry.extension)) continue;
            if (entry.extension === '.py' && pythonAssignmentInsideString(entry.content, pythonMasked(entry.content), valueIndex)) continue;
            if (/^[A-Za-z0-9_$]+['"]/.test(match.matchText) && !/['"]/.test(entry.content[match.index - 1] ?? '')) continue;
          }
          if (secretPattern.aiProvider === true) {
            if (
              isClientExposedAiSecret({
                content: entry.content,
                valueIndex,
                value: secretValue,
                clientReachable: clientFiles.has(entry.path),
              })
            ) {
              continue;
            }
          }
          const refined = refineSecretLabel(secretPattern.name, entry.content, valueIndex);
          const patternName = refined?.name ?? secretPattern.name;
          reportedOnLine.add(`${line}:${secretValue}`);
          findings.push(
            makeFinding({
              ruleId: this.id,
              title: `${this.title}: ${patternName}`,
              severity: secretPattern.severity,
              confidence: secretPattern.confidence,
              filePath: entry.path,
              lineStart: line,
              evidence: redactSecret(secretValue),
              userExplanation:
                secretPattern.explanation ??
                `A value that looks like a ${patternName} is written directly in your code. Anyone with access to the code can use it. Move it into an environment variable on the server and revoke the exposed key.`,
              technicalExplanation:
                `Pattern match for "${patternName}" in ${entry.path}:${line}. Secrets embedded in source are exposed through version control, builds, and client bundles. Rotate the credential and load it from server-side configuration instead.`,
              fixHint:
                refined?.fixHint ??
                secretPattern.fix ??
                `Revoke and rotate this ${patternName} with its provider, then replace the literal with an environment variable (e.g. process.env.MY_KEY) that is set only in server-side configuration and never committed.`,
              category: this.category,
            }),
          );
        }
      }

      for (const match of findMatches(entry.content, JWT_PATTERN)) {
        const payload = decodeJwtPayload(match.matchText);
        if (payload === undefined) continue;
        if (payload['role'] !== 'service_role') continue;
        if (isSupabaseLocalDemoKey(payload)) continue;
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: `${this.title}: Supabase service role JWT`,
            severity: 'critical',
            confidence: 'high',
            filePath: entry.path,
            lineStart: match.line,
            evidence: redactSecret(match.matchText),
            userExplanation:
              'A Supabase service role key is written directly in your code. This key bypasses all row-level security and gives full database access. Rotate it immediately and keep it only in server-side environment variables.',
            technicalExplanation:
              `A JWT whose payload contains "role": "service_role" was found in ${entry.path}:${match.line}. The service role key bypasses RLS entirely; it must never appear in source or client bundles.`,
            fixHint:
              'Rotate the service role key in the Supabase dashboard (Settings > API), store the new key only in server-side environment variables, and access it exclusively from server code.',
            category: this.category,
          }),
        );
      }
    }
    return findings;
  },
};
