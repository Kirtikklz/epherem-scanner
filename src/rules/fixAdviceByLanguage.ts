const OTHER_LANGUAGE_SOURCE: ReadonlySet<string> = new Set(['.py']);

export function isOtherLanguageSource(filePath: string): boolean {
  const dot = filePath.lastIndexOf('.');
  return dot > filePath.lastIndexOf('/') && OTHER_LANGUAGE_SOURCE.has(filePath.slice(dot).toLowerCase());
}

export const NEUTRAL_FIX_PHRASES: readonly (readonly [string, string])[] = [
  [
    'Add a fileFilter that allowlists expected MIME types/extensions, set limits: { fileSize }, generate random stored filenames',
    'Allowlist the file types you expect (check both the extension and the content type), cap the upload size, generate random stored filenames',
  ],
  [
    'or resolve against your origin with new URL(dest, base) and confirm url.origin equals your origin',
    'or parse the URL and confirm its scheme and host are your own',
  ],
  ['Note that path.resolve() alone does not help', 'Note that resolving the path alone does not help'],
  [
    'Resolve the path against a fixed base, then confirm it stays inside: e.g. const full = path.resolve(base, name); if (!full.startsWith(base + path.sep)) throw. Or reduce the input to path.basename() when only a filename is valid.',
    'Resolve the path against a fixed base directory, then confirm the resolved path is still inside that directory and refuse it otherwise. Or reduce the input to a bare file name when only a filename is valid.',
  ],
  [' (e.g. const p = path.resolve(BASE, userPath); if (!p.startsWith(BASE + path.sep)) reject)', ''],
  ['never pass raw request input to fs.*/res.sendFile', 'never pass raw request input to a call that opens or sends a file'],
  [
    'Use the array form of spawn/execFile (no shell), pass user values as separate arguments',
    'Run the command without a shell, as a list of arguments with user values as separate items',
  ],
  ['(execFile/spawn with an argument array and shell:false)', '(the command and its arguments as a list, with no shell)'],
  [
    "Set the cookie with httpOnly: true, secure: true, and sameSite: 'lax' (or 'strict' for sensitive flows).",
    'Set the cookie\'s HttpOnly and Secure flags, and SameSite=Lax (or Strict for sensitive flows).',
  ],
  [
    "In the session middleware options set cookie: { httpOnly: true, secure: true, sameSite: 'lax' }. If you develop over plain HTTP, gate secure on NODE_ENV === 'production' rather than leaving it off.",
    'In the session settings, make the session cookie HttpOnly and Secure with SameSite=Lax. If you develop over plain HTTP, turn Secure on for production rather than leaving it off.',
  ],
  [
    'Never log req.body, headers, cookies, or process.env wholesale.',
    'Never log the request body, headers, cookies, or the whole environment.',
  ],
  ['sanitize with DOMPurify or a proven equivalent', 'sanitize it with a maintained HTML sanitizer'],
  [' (for example escape-html: `${escapeHtml(q)}`)', ''],
  [
    ' (getServerSession(), supabase.auth.getUser(), or jwt.verify on the request token)',
    ' from a session or token the server verifies',
  ],
  [' (getServerSession(), supabase.auth.getUser(), Clerk getAuth(req), or jwt.verify on the request token)', ''],
  [' (e.g. where: { id, userId: session.user.id })', ' (put the signed-in user\'s id in the query\'s filter)'],
  [
    '(e.g. .eq("user_id", session.user.id), where: { id, userId: session.user.id }, or AND user_id = $trustedUserId)',
    '(e.g. AND user_id = $trustedUserId in the delete\'s filter)',
  ],
  [' (e.g. app.post("/login", loginLimiter, handler))', ', keyed by IP or user,'],
  [' (zod, joi, yup, celebrate, express-validator)', ''],
  [' Next.js server actions already compare Origin with Host, so add the check to API route handlers.', ''],
  [", e.g. res.setHeader('Access-Control-Allow-Origin', 'https://yourapp.com')", ' in the Access-Control-Allow-Origin header'],
  [' — e.g. `if (ALLOWED_ORIGINS.includes(origin))`', ''],
  [
    "Generate the token with crypto.randomBytes(32).toString('hex') or crypto.randomUUID() - never from a hash of a timestamp, a counter, an email or Math.random().",
    'Generate the token from a cryptographically secure random source (32 random bytes or more) - never from a hash of a timestamp, a counter, an email or an ordinary random-number function.',
  ],
  [
    'Generate tokens with crypto.randomBytes/randomUUID or Web Crypto getRandomValues',
    'Generate tokens from a cryptographically secure random source',
  ],
  ['Pass the secret from process.env (never a literal)', 'Read the secret from an environment variable (never a literal)'],
  [' (e.g. process.env.MY_KEY)', ''],
];

export function adviceFor(filePath: string, text: string): string {
  if (!isOtherLanguageSource(filePath)) return text;
  let out = text;
  for (const [javascript, neutral] of NEUTRAL_FIX_PHRASES) out = out.split(javascript).join(neutral);
  return out;
}
