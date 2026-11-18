// Prefixes that mark a value as shipped to the browser on purpose.
export const PUBLIC_PREFIX =
  /^(VITE_|NEXT_PUBLIC_|EXPO_PUBLIC_|PUBLIC_|REACT_APP_|GATSBY_|VUE_APP_|NG_|NX_PUBLIC_|STORYBOOK_)/;

export const PUBLIC_NAME =
  /(anon_key|publishable_key|public_key|_url$|_uri$|project_id|project_ref|\bport\b|node_env|base_url|site_url)/i;

export const SECRET_NAME =
  /(service_role|service_key|secret|private_key|passwd|password|_pass$|client_secret|access_key|secret_key|auth_token|refresh_token|database_url|\bdb_url\b|\bdsn\b|smtp|sendgrid|mailgun|stripe_secret|jwt_secret|session_secret|encryption_key|openai|anthropic|admin_key)/i;

export const SECRET_VALUE =
  /sk-[A-Za-z0-9_-]{16,}|sk_(?:live|test)_[A-Za-z0-9]+|gsk_[A-Za-z0-9]{20,}|xai-[A-Za-z0-9]{20,}|pplx-[A-Za-z0-9]{20,}|hf_[A-Za-z0-9]{30,}|r8_[A-Za-z0-9]{30,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|"role"\s*:\s*"service_role"|role":"service_role|xox[bp]-[A-Za-z0-9-]+|ghp_[A-Za-z0-9]{20,}|:\/\/[^:@\s]+:[^@\s]+@/;

export function isPublicByDesignName(key: string): boolean {
  return PUBLIC_PREFIX.test(key) || PUBLIC_NAME.test(key);
}

// Keys the provider marks publishable (sb_publishable_, pk_) are not secrets.
const PUBLISHABLE_VALUE = /^(?:sb_publishable_[A-Za-z0-9_-]+|pk_(?:live|test)_[A-Za-z0-9]{16,})$/;

export function isPublishableProviderValue(value: string): boolean {
  return PUBLISHABLE_VALUE.test(value);
}

// AIza alone is any Google key: only a Firebase config object makes it public.
const FIREBASE_CONFIG_SIBLINGS = [
  /\bauthDomain\s*['"]?\s*:/,
  /\bprojectId\s*['"]?\s*:/,
  /\bstorageBucket\s*['"]?\s*:/,
  /\bmessagingSenderId\s*['"]?\s*:/,
  /\bappId\s*['"]?\s*:/,
  /\bmeasurementId\s*['"]?\s*:/,
  /\bdatabaseURL\s*['"]?\s*:/,
];
const API_KEY_BINDING = /["']?\bapiKey["']?\s*:\s*["']?$/;
const INITIALIZE_APP = /\binitializeApp\s*\(/;

const CONFIG_WINDOW_BEFORE = 600;
const CONFIG_WINDOW_AFTER = 500;

export function isFirebaseWebConfigApiKey(content: string, matchIndex: number): boolean {
  const before = content.slice(Math.max(0, matchIndex - CONFIG_WINDOW_BEFORE), matchIndex);
  if (!API_KEY_BINDING.test(before)) return false;
  const window = before + content.slice(matchIndex, matchIndex + CONFIG_WINDOW_AFTER);
  if (INITIALIZE_APP.test(before)) return true;
  const siblings = FIREBASE_CONFIG_SIBLINGS.filter((pattern) => pattern.test(window)).length;
  return siblings >= 2;
}

// The nearest variable name before a value decides whether it is public.
const ENV_NAME_TOKEN = /(?<![A-Za-z0-9_])([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)(?![A-Za-z0-9])/g;
const BINDING_WINDOW = 240;

export function bindingNameIsPublic(content: string, matchIndex: number): boolean {
  const start = Math.max(0, matchIndex - BINDING_WINDOW);
  let before = content.slice(start, matchIndex);
  const newlines = [...before.matchAll(/\n/g)].map((m) => m.index ?? 0);
  if (newlines.length > 1) before = before.slice((newlines[newlines.length - 2] ?? 0) + 1);
  const names = [...before.matchAll(ENV_NAME_TOKEN)].map((m) => m[1] ?? '');
  const last = names[names.length - 1];
  if (last === undefined) return false;
  return PUBLIC_PREFIX.test(last) && !SECRET_NAME.test(last.replace(PUBLIC_PREFIX, ''));
}

const PROTOCOL_PUBLIC_NAME =
  /(?<![A-Za-z0-9_])(?:index[_-]?now(?:[_-]?key)?|(?:application[_-]?server|vapid(?:[_-]?public)?)[_-]?key|firebase[_-]?vapid[_-]?key)(?![A-Za-z0-9_])/i;
const PROTOCOL_PRIVATE_NAME = /(?<![A-Za-z0-9_])(?:private|secret)(?![A-Za-z0-9_])/i;
const PROTOCOL_NAME_WINDOW = 120;

export function protocolPublicKeyName(content: string, matchIndex: number): boolean {
  const before = content.slice(Math.max(0, matchIndex - PROTOCOL_NAME_WINDOW), matchIndex);
  const line = before.slice(before.lastIndexOf('\n') + 1);
  return PROTOCOL_PUBLIC_NAME.test(line) && !PROTOCOL_PRIVATE_NAME.test(line);
}

export function isPublicByDesignSecret(
  content: string,
  matchIndex: number,
  value: string,
): boolean {
  // A provider-format secret is never public, whatever its name says.
  if (SECRET_VALUE.test(value)) return false;
  return (
    isPublishableProviderValue(value) ||
    isFirebaseWebConfigApiKey(content, matchIndex) ||
    protocolPublicKeyName(content, matchIndex) ||
    bindingNameIsPublic(content, matchIndex)
  );
}

// Supabase's local demo keys are published constants, not leaks.
export function isSupabaseLocalDemoKey(payload: Record<string, unknown>): boolean {
  return payload['iss'] === 'supabase-demo';
}
