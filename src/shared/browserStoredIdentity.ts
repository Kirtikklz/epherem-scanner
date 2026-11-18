export const BROWSER_STORAGE_READ =
  /\b(?:window\s*\.\s*|globalThis\s*\.\s*)?(localStorage|sessionStorage)\s*\.\s*getItem\s*\(\s*(['"`][^'"`\n]{0,200}['"`]|[A-Za-z_$][\w$]*)\s*\)/g;

export const DOCUMENT_COOKIE_READ = /\bdocument\s*\.\s*cookie\b/g;

export const STRING_CONSTANT_DECLARATION =
  /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(['"`])([^'"`\n]{0,200})\2/g;

const IDENTITY_KEY_WORDS: ReadonlySet<string> = new Set([
  'user',
  'users',
  'currentuser',
  'authuser',
  'loggeduser',
  'session',
  'auth',
  'account',
  'profile',
  'role',
  'roles',
  'admin',
  'isadmin',
  'loggedin',
  'isloggedin',
  'signedin',
  'issignedin',
  'authenticated',
  'isauthenticated',
  'identity',
  'principal',
  'whoami',
  'me',
]);

export function isIdentityStorageKey(key: string): boolean {
  const words = key
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .map((word) => word.toLowerCase())
    .filter((word) => word.length > 0);
  for (let i = 0; i < words.length; i += 1) {
    const word = words[i] as string;
    if (IDENTITY_KEY_WORDS.has(word)) return true;
    const next = words[i + 1];
    if (next !== undefined && IDENTITY_KEY_WORDS.has(`${word}${next}`)) return true;
  }
  return false;
}

export const IDENTITY_SETTER_CALL =
  /\bset(User|Users|CurrentUser|AuthUser|Session|Auth|Account|Profile|Role|Roles|IsAdmin|Admin|LoggedIn|IsLoggedIn|SignedIn|IsSignedIn|Authenticated|IsAuthenticated|Identity|Principal|Me)\s*\(\s*([^;\n]{0,200})/g;

const IDENTITY_BINDING_NAME =
  /^(?:user|users|currentUser|authUser|loggedUser|session|auth|account|profile|role|roles|isAdmin|admin|loggedIn|isLoggedIn|signedIn|isSignedIn|authenticated|isAuthenticated|identity|principal|me)$/i;

export function isIdentityBindingName(name: string): boolean {
  return IDENTITY_BINDING_NAME.test(name.trim());
}

export const SERVER_BACKED_IDENTITY = new RegExp(
  [
    String.raw`from\s*['"]next-auth`,
    String.raw`require\(\s*['"]next-auth`,
    String.raw`\bgetServerSession\s*\(`,
    String.raw`\buseSession\s*\(`,
    String.raw`from\s*['"]@clerk\/`,
    String.raw`require\(\s*['"]@clerk\/`,
    String.raw`\bclerkClient\b`,
    String.raw`\bauth\s*(?:\(\s*\))?\s*\.\s*protect\s*\(`,
    String.raw`from\s*['"]@supabase\/`,
    String.raw`require\(\s*['"]@supabase\/`,
    String.raw`\.\s*auth\s*\.\s*(?:getUser|getSession|onAuthStateChange|refreshSession|setSession)\s*\(`,
    String.raw`from\s*['"]firebase\/auth['"]`,
    String.raw`\bonAuthStateChanged\s*\(`,
    String.raw`from\s*['"]better-auth`,
    String.raw`\bauthClient\s*\.\s*(?:useSession|getSession)\s*\(`,
    String.raw`from\s*['"]@auth0\/`,
    String.raw`\buseAuth0\s*\(`,
    String.raw`from\s*['"](?:aws-amplify|@aws-amplify\/)`,
    String.raw`\bfetchAuthSession\s*\(`,
    String.raw`from\s*['"]@workos-inc\/`,
    String.raw`from\s*['"]@descope\/`,
    String.raw`from\s*['"]@stytch\/`,
    String.raw`from\s*['"]@kinde-oss\/`,
    String.raw`from\s*['"]@propelauth\/`,
    String.raw`\bjwt\s*\.\s*verify\s*\(`,
    String.raw`\bverify(?:IdToken|Token|Session|Jwt|JWT)\s*\(`,
    String.raw`\bgetAuth\s*\(\s*(?:req|request|ctx|context)\b`,
  ].join('|'),
);

export const ACCESS_DENIED_CONSEQUENCE = new RegExp(
  [
    String.raw`\breturn\s*\(?\s*<\s*(?:Login|SignIn|Signin|SignUp|Auth(?:Screen|Page|Form|Gate|Required)|Unauthorized|Unauthorised|Forbidden|AccessDenied|NotAuthorized|NotAuthorised|Landing|Welcome)\w*`,
    String.raw`<\s*Navigate\b`,
    String.raw`\bthrow\s+redirect\s*\(`,
    String.raw`\b(?:redirect|permanentRedirect|navigate)\s*\(`,
    String.raw`\brouter\s*\.\s*(?:push|replace)\s*\(`,
    String.raw`\bnavigation\s*\.\s*(?:navigate|replace|reset)\s*\(`,
    String.raw`\bwindow\s*\.\s*location\s*(?:\.\s*(?:href|replace|assign)\s*[=(])`,
  ].join('|'),
  'i',
);
