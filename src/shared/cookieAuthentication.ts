import type { RuleContext } from './types.js';

export const COOKIE_SESSION_HINT =
  /cookie-session|express-session|connect\.sid|req\.session\b|cookies\(\)\.set|res\.cookie\s*\(/i;

const AMBIENT_CREDENTIAL_HINT =
  /credentials\s*:\s*['"]include['"]|withCredentials\s*:\s*true|cookies\(\)\s*\.\s*get\s*\(|req(?:uest)?\.cookies\b|next-auth|iron-session|@supabase\/ssr/i;

export function cookieAuthenticationIn(entries: readonly { content: string }[]): boolean {
  return entries.some(
    (entry) => COOKIE_SESSION_HINT.test(entry.content) || AMBIENT_CREDENTIAL_HINT.test(entry.content),
  );
}

export function usesCookieAuthentication(context: RuleContext): boolean {
  return cookieAuthenticationIn(context.fileMap.entries);
}

export function deploymentUnitOf(filePath: string): string | undefined {
  const supabase = /(^|\/)(supabase\/functions\/[^/]+)\//.exec(filePath);
  if (supabase?.[2] !== undefined) return supabase[2];
  const netlify = /(^|\/)(netlify\/functions)\//.exec(filePath);
  if (netlify?.[2] !== undefined) return netlify[2];
  const firebase = /(^|\/)(functions\/src)\//.exec(filePath);
  if (firebase?.[2] !== undefined) return firebase[2];
  return undefined;
}
