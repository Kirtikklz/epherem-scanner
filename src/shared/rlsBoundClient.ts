import { stripCommentsOnly } from './source.js';

const PRIVILEGED_CLIENT_EVIDENCE =
  /service[_-]?role|service[_-]?key|service[_-]?account|supabase[_-]?admin|admin[_-]?supabase|supabase[_-]?service|service[_-]?supabase|admin[_-]?client|service[_-]?client|bypass[_-]?rls/i;

const PRIVILEGED_RECEIVER =
  /\b(?:supabaseAdmin|adminSupabase|supabaseService|serviceSupabase|adminClient|serviceClient|serviceRoleClient|admin|service)\s*(?:\.\s*schema\s*\([^)]*\)\s*)?\.\s*from\s*\(\s*['"`][^'"`]*['"`]\s*\)[\s\S]{0,400}?$/i;

let strippedCacheKey: string | undefined;
let strippedCacheValue = '';
function codeOnly(fileContent: string): string {
  if (strippedCacheKey !== fileContent) {
    strippedCacheKey = fileContent;
    strippedCacheValue = stripCommentsOnly(fileContent);
  }
  return strippedCacheValue;
}

const RECEIVER_WINDOW = 600;

export function operationBypassesRls(fileContent: string, index: number): boolean {
  const code = codeOnly(fileContent);
  if (PRIVILEGED_CLIENT_EVIDENCE.test(code)) return true;
  const preceding = code.slice(Math.max(0, index - RECEIVER_WINDOW), index);
  return PRIVILEGED_RECEIVER.test(preceding);
}
