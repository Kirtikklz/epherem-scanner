export const USER_INPUT_PATTERN =
  /\breq(?:uest)?\.(?:body|query|params|headers|cookies|url|originalUrl|json|text|formData)\b|\bctx\.(?:request|query|params)\b|\bsearchParams\.get\s*\(|\bawait\s+request\.(?:json|text|formData)\s*\(|\bnew\s+URL\s*\(\s*req|\bevent\.(?:body|queryStringParameters|pathParameters)\b|\bflask\.request\.|\brequest\.(?:args|form|files|values|json)\b|\bprocess\.argv\b/;

export const NEXT_INPUT_PATTERN =
  /\bparams\.\w+|\bsearchParams\b|\bformData\.get\s*\(|\bawait\s+req\.(?:json|text|formData)\s*\(/;

const LOCAL_PARAMS_BINDING =
  /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*new\s+URLSearchParams\s*\(([^)]*)/g;

const DIRTY_SEED =
  /\blocation\s*\.\s*(?:search|href|hash)\b|\bsearchParams\b|\bprops\b|\b[A-Za-z_$][\w$]*\.(?:url|search|query)\b|^\s*[A-Za-z_$][\w$]*(?:\s*\?\?[^)]*)?\s*$/;

const SERIALIZE_METHOD = '(?:toString|set|append|delete)\\b\\s*\\(?';

const NON_READ_ACCESSOR = '(?:size\\b|entries\\s*\\(|keys\\s*\\(|values\\s*\\(|forEach\\s*\\(|sort\\s*\\()';

function withoutLocalSearchParams(text: string, constructionScope: string): string {
  if (!constructionScope.includes('URLSearchParams')) return text;

  const clean = new Set<string>();
  LOCAL_PARAMS_BINDING.lastIndex = 0;
  for (let m = LOCAL_PARAMS_BINDING.exec(constructionScope); m !== null; m = LOCAL_PARAMS_BINDING.exec(constructionScope)) {
    const name = m[1];
    const seed = m[2] ?? '';
    if (name === undefined) continue;
    if (USER_INPUT_PATTERN.test(seed) || DIRTY_SEED.test(seed)) continue;
    clean.add(name);
  }

  let out = text;
  for (const name of clean) {
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    out = out.replace(
      new RegExp(`\\b${escaped}\\.(?:${SERIALIZE_METHOD}|${NON_READ_ACCESSOR})`, 'g'),
      'urlSearchParamsLocal_',
    );
  }
  return out;
}

export function referencesUserInput(text: string, constructionScope: string = text): boolean {
  const scoped = withoutLocalSearchParams(text, constructionScope);
  return USER_INPUT_PATTERN.test(scoped) || NEXT_INPUT_PATTERN.test(scoped);
}

export function windowAround(content: string, index: number, radius = 240): string {
  const start = Math.max(0, index - radius);
  const end = Math.min(content.length, index + radius);
  return content.slice(start, end);
}
