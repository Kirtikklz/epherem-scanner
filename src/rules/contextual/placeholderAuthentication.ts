import { mayVouchForProject } from '../../input/fileFilters.js';
import { stripCommentsOnly, usesHashComments } from '../../shared/source.js';
import { findMatches, lineAt } from '../../shared/utils.js';
import { makeFinding } from '../../shared/findingFactory.js';
import type { Finding, FileMapEntry, RuleContext, ScanRule } from '../../shared/types.js';

const MAX_TRIVIAL_BODY_CHARS = 400;
// Bounded brace walk, so a malformed file cannot hang the scan.
const MAX_BODY_SCAN_CHARS = 20_000;

type PlaceholderShape =
  | 'returns_true'
  | 'returns_hardcoded_identity'
  | 'unconditional_next'
  | 'empty_body'
  | 'todo_only_body';

interface PlaceholderGuard {
  name: string;
  line: number;
  shape: PlaceholderShape;
  snippet: string;
  bodySnippet: string;
  reachedAs: string;
}

export const placeholderAuthentication: ScanRule = {
  id: 'placeholder_authentication',
  title: 'Authentication check is an unfinished placeholder',
  category: 'authentication',
  kind: 'contextual',
  run(context: RuleContext): Finding[] {
    const entries = [...context.fileMap.entries].sort((a, b) => a.path.localeCompare(b.path));
    const registered = collectRegisteredGuardNames(entries, context.projectMap.scannerRootPrefix);

    const findings: Finding[] = [];
    for (const entry of entries) {
      if (!isAnalysableSource(entry, context.projectMap.scannerRootPrefix)) continue;
      for (const guard of findPlaceholderGuards(entry, registered)) {
        const decidesNothing = guard.shape === 'empty_body' || guard.shape === 'todo_only_body';
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: this.title,
            severity: 'high',
            confidence: 'high',
            filePath: entry.path,
            lineStart: guard.line,
            evidence:
              `"${guard.name}" @ line ${guard.line} is named as an authentication guard ` +
              `(${guard.snippet}) but its body ${describeShape(guard.shape)}: ${guard.bodySnippet}; ` +
              `no session lookup, token verification or identity conditional anywhere in it; ` +
              `reachable as a guard (${guard.reachedAs})`,
            userExplanation:
              `Your code has a function called "${guard.name}". The name says it checks whether ` +
              'someone is allowed in, and it is set up so other parts of the application can use it ' +
              `for exactly that. But the function ${describeShapePlainly(guard.shape)}. ` +
              (decidesNothing
                ? 'It never looks at who is making the request and never reads a session or a token. ' +
                  'Whether that lets everyone in or keeps everyone out depends on how the code that ' +
                  'calls it uses the result; either way, nobody is actually being checked. '
                : 'It never looks at who is making the request, never reads a session or a token, and ' +
                  'never turns anyone away. Everyone passes, every time. ') +
              'This is what an unfinished security check looks like: the ' +
              'scaffolding was written and the actual check was never filled in, which is easy to do ' +
              'when code is generated quickly. ' +
              (decidesNothing
                ? 'If the calling code treats it as a pass, the screens and endpoints sitting behind it ' +
                  'are open to anyone who knows their address, even though the code reads as though ' +
                  'they are protected. '
                : 'The screens and endpoints sitting behind it are open to anyone who knows their ' +
                  'address, even though the code reads as though they are protected. ') +
              'Nothing else in your application will warn you about this, because from ' +
              'the outside a guard IS present — it simply does not do anything.',
            technicalExplanation:
              `${entry.path}:${guard.line} declares "${guard.name}", a name in the authentication/` +
              `authorization guard vocabulary, and ${describeShape(guard.shape)} (${guard.bodySnippet}). ` +
              'The body contains no protective authentication signal — no getUser/getSession/' +
              'getServerSession/getAuth(request), no jwt.verify or token verification, no ' +
              'req.session or session-cookie read, no provider call, no credential comparison and no ' +
              'database lookup of a principal — and no conditional whose test references a request, ' +
              'session, token, role or user value. ' +
              (decidesNothing
                ? 'It therefore decides nothing: whether a caller is allowed depends only on how call ' +
                  'sites treat its empty or fixed result. '
                : 'It is therefore unconditionally permissive: every caller receives the allow result. ') +
              'The guard is not dead code — it is ' +
              `${guard.reachedAs} — so callers and route registrations that name it are relying on a ` +
              'check that does not exist. This is reported as a present-and-fake control rather than ' +
              'a missing one: absence-based rules see a guard on the route and stay silent.',
            fixHint:
              `Implement the check inside "${guard.name}", or delete it and remove every route that ` +
              'relies on it. A real guard resolves the caller from a server-verified session — ' +
              'getServerSession / supabase.auth.getUser() / Clerk getAuth(request) / jwt.verify on ' +
              'the request token — refuses the request with 401 when that identity is absent, and, ' +
              'for a role or ownership guard, compares the resolved identity against the resource ' +
              'before allowing the call through. Until it does, treat every endpoint behind it as ' +
              'unprotected.',
            category: this.category,
            extraFixRequirements: [
              'Do not make the guard return false by default and rely on callers to interpret it — the guard must itself reject the request (401/403, throw, or refuse to call next()).',
              'A guard is not fixed by checking that a request field, header or body value merely exists; the identity must come from a session or token the server issued and verifies.',
              'Every route currently registered with this guard must be re-checked after the fix: none of them has had a real identity check for as long as the placeholder has been in place.',
            ],
          }),
        );
      }
    }
    return findings;
  },
};

const GUARD_NAME =
  /^(?:(?:require|ensure|assert|check|verify|validate|must)(?:Auth|Auth[A-Z]\w*|Authed|Authenticated|Authentication|Authorized|Authorization|Admin|Admin[A-Z]\w*|User|Users|Session|Login|LoggedIn|SignedIn|Owner|Ownership|Role|Roles|Member|Membership|Permission|Permissions|Access)|(?:is|has|can)(?:Auth|Authed|Authenticated|Authorized|Admin|SuperAdmin|AdminUser|LoggedIn|SignedIn|Owner|Permission|Permissions|Access|Role)|with(?:Auth|Auth[A-Z]\w*|Admin|Session|Permission|Permissions|Role)|auth(?:Guard|Middleware|Check|Checker|Required|Only|orize|orise|orized|enticate)?|admin(?:Only|Guard|Middleware|Check|Required|Auth)|protect(?:Route|Page|Api|Handler)?|(?:route|api|page|permission|role|owner|access)Guard|getAuthenticatedUser|getCurrentUser|getSessionUser|getUserFromRequest|getUserFromToken|requiresAuth|needsAuth)$/;

// signIn/login and UI names are features, not gates; checked first.
const FEATURE_OR_UI_NAME =
  /^(?:sign(?:In|Up|Out)|log(?:in|out)|register|signup|signin|signout|resetPassword|forgotPassword|changePassword|handle[A-Z]\w*|use[A-Z]\w*|[A-Z][\w$]*(?:Page|Layout|Screen|View|Provider|Context|Panel|Route|Component|Form|Dialog|Modal|Button|Card|List|Table|Header|Footer|Wrapper|Boundary))$|Error$/;

const PROTECTIVE_SIGNAL =
  /\.getUser\s*\(|\bgetUser\s*\(|\bgetAuth\s*\(\s*(?:req|request|ctx|context)\b|\.getSession\s*\(|\bgetSession\s*\(|\bgetServerSession\s*\(|jwt\.verify\s*\(|\bverify(?:IdToken|Token|Session|Jwt|JWT|Auth\w*)\s*\(|\.\s*isAuthenticated\s*\(|\bpassport\s*\.\s*authenticate\s*\(|\bcurrentUser\b|\breq\.session\b|\brequest\.session\b|\breq\.cookies\b|\brequest\.cookies\b|\bcookies\s*\(\s*\)\s*\.\s*get|\bcookies\.get\s*\(|\.\s*protect\s*\(|\bthrow\b|\bbcrypt\b|\bargon2\b|\bscrypt\b|\bcompare(?:Sync)?\s*\(|\bsupabase\b|\bclerk\b|\bfirebase\b|next-?auth|\bprisma\b|\bmongoose\b|\bknex\b|\bfind(?:Unique|One|First|ByPk|ById|Many)\s*\(|\bawait\b|\bfetch\s*\(|\bheaders\b|\bauthorization\b|\bdecode\s*\(|\bdb\s*\.|\bquery\s*\(/i;

const CONDITIONAL_TEST = /\b(?:if|switch|while|for)\s*\(([^\n]{0,300})|([^\n?]{1,160})\?[^:\n]{1,160}:|(?:&&|\|\|)([^\n]{0,160})/g;
const IDENTITY_REFERENCE =
  /\b(?:user|users|session|token|auth|authed|uid|claims|account|identity|jwt|principal|role|roles|admin|owner|member|permission|permissions|scope|scopes|cookie|cookies|req|request|ctx|context|headers|pathname|url|email|userId|sub)\b/i;

const RETURNS_LITERAL_TRUTHY = /^\s*return\s+(?:true|1|!0|!!1|Boolean\s*\(\s*(?:true|1)\s*\))\s*;?\s*$/m;
const RETURNS_OBJECT_LITERAL = /^\s*return\s*(\{[\s\S]{0,400}?\})\s*;?\s*$/m;
const HARDCODED_IDENTITY_FIELD =
  /\b(?:id|userId|uid|role|roles|isAdmin|admin|isAuthenticated|authenticated|authorized|email|name|username|permissions?|scopes?)\s*:\s*(?:['"`][^'"`\n]{0,80}['"`]|true|1|\[[^\]\n]{0,160}\])/i;
const CALLS_NEXT = /(?:^|[^\w$.])(?:return\s+)?next\s*\(\s*\)\s*;?/m;
const NO_OP_RETURN = /^\s*return(?:\s+(?:null|undefined|void\s+0))?\s*;?\s*$/m;
const TODO_MARKER =
  /\b(?:TODO|FIXME|XXX|HACK)\b|\badd\s+(?:the\s+)?auth\w*\b|\bimplement\b|\bnot\s+implemented\b|\bfor\s+now\b|\bplaceholder\b|\bstub\b|\balways\s+(?:true|allow|passes)\b|\bskip(?:ping)?\s+(?:the\s+)?(?:auth\w*|check|permission)/i;
const COMMENTED_OUT_CHECK = /^\s*(?:\/\/|#)\s*(?:if\s*\(|return\s|throw\s|const\s+[\w$]+\s*=|await\s|res\.)/m;
// Returning markup means a component, not a guard.
const RETURNS_JSX = /return\s*\(?\s*</;

const ROUTER_REGISTRATION =
  /\b(?:app|router|server|api|route)\s*\.\s*(?:use|all|get|post|put|patch|delete|head|options)\s*\(([^)]{0,400})\)|\b(?:middleware|guards?|beforeEnter|onRequest|preHandler)\s*:\s*\[?([^\],\n]{0,200})|@UseGuards\s*\(([^)]{0,200})\)/g;

const DECLARATIONS: RegExp[] = [
  /(?:^|\n)[ \t]*(?:export\s+(?:default\s+)?)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(([^)]{0,400})\)\s*(?::[^{\n]{0,200})?\{/g,
  /(?:^|\n)[ \t]*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]{0,250})?=\s*(?:async\s*)?(?:function\s*\*?\s*)?\(([^)]{0,400})\)\s*(?::[^=>{\n]{0,150})?(?:=>\s*)?\{/g,
  /(?:^|\n)[ \t]*(?:module\.)?exports\.([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\s*\*?\s*)?\(([^)]{0,400})\)\s*(?:=>\s*)?\{/g,
  /(?:^|\n)[ \t]*this\.([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\s*\*?\s*)?\(([^)]{0,400})\)\s*(?:=>\s*)?\{/g,
  /(?:^|\n)[ \t]*(?:(?:public|private|protected|static|async)\s+){0,3}([A-Za-z_$][\w$]*)\s*\(([^)]{0,400})\)\s*(?::[^{\n]{0,200})?\{/g,
  /(?:^|\n)[ \t]*([A-Za-z_$][\w$]*)\s*:\s*(?:async\s*)?(?:function\s*\*?\s*)?\(([^)]{0,400})\)\s*(?:=>\s*)?\{/g,
];

const CONCISE_ARROW =
  /(?:^|\n)[ \t]*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]{0,200})?=\s*(?:async\s*)?\(([^)]{0,200})\)\s*(?::[^=>\n]{0,120})?=>\s*([^\n;{][^\n;]{0,200})/g;

const JS_TS_EXTENSIONS: ReadonlySet<string> = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.mts', '.cts',
]);

function isAnalysableSource(entry: FileMapEntry, scannerRootPrefix?: string): boolean {
  if (!JS_TS_EXTENSIONS.has(entry.extension)) return false;
  return mayVouchForProject(entry.path, scannerRootPrefix);
}

function collectRegisteredGuardNames(
  entries: readonly FileMapEntry[],
  scannerRootPrefix?: string,
): Set<string> {
  const names = new Set<string>();
  for (const entry of entries) {
    if (!isAnalysableSource(entry, scannerRootPrefix)) continue;
    const source = stripCommentsOnly(entry.content, usesHashComments(entry.extension, entry.label));
    for (const match of findMatches(source, ROUTER_REGISTRATION)) {
      const argumentText = match.groups[0] ?? match.groups[1] ?? match.groups[2] ?? '';
      for (const identifier of argumentText.matchAll(/[A-Za-z_$][\w$]*/g)) {
        const name = identifier[0];
        if (name !== undefined) names.add(name);
      }
    }
  }
  return names;
}

function findPlaceholderGuards(entry: FileMapEntry, registered: ReadonlySet<string>): PlaceholderGuard[] {
  const source = entry.content;
  const guards: PlaceholderGuard[] = [];
  const seen = new Set<number>();

  for (const pattern of DECLARATIONS) {
    for (const match of findMatches(source, pattern)) {
      const name = match.groups[0];
      const parameters = match.groups[1] ?? '';
      if (name === undefined || seen.has(match.line)) continue;
      if (!isGuardName(name)) continue;

      const openBrace = source.lastIndexOf('{', match.index + match.matchText.length);
      if (openBrace < 0) continue;
      const body = extractBody(source, openBrace);
      if (body === undefined) continue;

      const shape = classifyBody(body, parameters);
      if (shape === undefined) continue;

      const reachedAs = reachability(source, name, registered);
      if (reachedAs === undefined) continue;

      seen.add(match.line);
      guards.push({
        name,
        line: match.line,
        shape,
        snippet: lineAt(entry.content, match.line).trim().slice(0, 160),
        bodySnippet: condense(body),
        reachedAs,
      });
    }
  }

  for (const match of findMatches(source, CONCISE_ARROW)) {
    const name = match.groups[0];
    const expression = (match.groups[2] ?? '').trim();
    if (name === undefined || seen.has(match.line)) continue;
    if (!isGuardName(name)) continue;
    if (!/^(?:true|1|!0)\s*;?$/.test(expression)) continue;
    if (PROTECTIVE_SIGNAL.test(expression) || hasIdentityConditional(expression)) continue;
    const reachedAs = reachability(source, name, registered);
    if (reachedAs === undefined) continue;
    seen.add(match.line);
    guards.push({
      name,
      line: match.line,
      shape: 'returns_true',
      snippet: lineAt(entry.content, match.line).trim().slice(0, 160),
      bodySnippet: expression.slice(0, 120),
      reachedAs,
    });
  }

  guards.sort((a, b) => a.line - b.line);
  return guards;
}

function isGuardName(name: string): boolean {
  if (FEATURE_OR_UI_NAME.test(name)) return false;
  return GUARD_NAME.test(name);
}

function extractBody(source: string, openBrace: number): string | undefined {
  let depth = 0;
  const limit = Math.min(source.length, openBrace + MAX_BODY_SCAN_CHARS);
  for (let index = openBrace; index < limit; index += 1) {
    const character = source[index];
    if (character === '{') depth += 1;
    else if (character === '}') {
      depth -= 1;
      if (depth === 0) return source.slice(openBrace + 1, index);
    }
  }
  return undefined;
}

function classifyBody(body: string, parameters: string): PlaceholderShape | undefined {
  if (RETURNS_JSX.test(body)) return undefined;
  const code = stripCommentsOnly(body, false).trim();
  if (code.length > MAX_TRIVIAL_BODY_CHARS) return undefined;
  if (PROTECTIVE_SIGNAL.test(code)) return undefined;
  if (hasIdentityConditional(code)) return undefined;

  const hasTodo = TODO_MARKER.test(body) || COMMENTED_OUT_CHECK.test(body);
  const isMiddleware = /\bnext\b/.test(parameters);

  if (code === '') return hasTodo ? 'todo_only_body' : 'empty_body';
  if (RETURNS_LITERAL_TRUTHY.test(code) && code.length < 60) return 'returns_true';
  const returnedObject = RETURNS_OBJECT_LITERAL.exec(code);
  if (returnedObject?.[1] !== undefined && HARDCODED_IDENTITY_FIELD.test(returnedObject[1])) {
    return 'returns_hardcoded_identity';
  }
  if (CALLS_NEXT.test(code) && code.length < 120) return 'unconditional_next';
  if (NO_OP_RETURN.test(code) && code.length < 30 && isMiddleware) return 'empty_body';
  if (hasTodo && code.length < 60) return 'todo_only_body';
  return undefined;
}

function hasIdentityConditional(code: string): boolean {
  for (const match of findMatches(code, CONDITIONAL_TEST)) {
    const test = match.groups[0] ?? match.groups[1] ?? match.groups[2] ?? match.matchText;
    if (IDENTITY_REFERENCE.test(test)) return true;
  }
  return false;
}

function reachability(source: string, name: string, registered: ReadonlySet<string>): string | undefined {
  const exported = new RegExp(
    `\\bexport\\s+(?:default\\s+)?(?:async\\s+)?(?:function|const|let|var|class)\\s+${name}\\b` +
      `|\\bexport\\s*\\{[^}]{0,400}\\b${name}\\b|\\b(?:module\\.)?exports\\.${name}\\s*=` +
      `|\\bexports\\s*\\[\\s*['"\`]${name}['"\`]\\s*\\]`,
  );
  if (exported.test(source)) return 'exported';
  if (registered.has(name)) return 'registered on a route or middleware chain';
  return undefined;
}

function condense(body: string): string {
  return body.replace(/\s+/g, ' ').trim().slice(0, 200) || '(empty)';
}

function describeShape(shape: PlaceholderShape): string {
  switch (shape) {
    case 'returns_true':
      return 'returns a literal truthy value unconditionally';
    case 'returns_hardcoded_identity':
      return 'returns a hard-coded user/role object';
    case 'unconditional_next':
      return 'calls next() with nothing gating it';
    case 'empty_body':
      return 'is empty or a no-op return';
    case 'todo_only_body':
      return 'contains only a TODO or a commented-out check';
  }
}

function describeShapePlainly(shape: PlaceholderShape): string {
  switch (shape) {
    case 'returns_true':
      return 'simply answers "yes, allowed" every single time, no matter who is asking';
    case 'returns_hardcoded_identity':
      return 'hands back a fixed, made-up user (often an administrator) instead of looking up who is actually there';
    case 'unconditional_next':
      return 'waves every request straight through to the next step without looking at it';
    case 'empty_body':
      return 'is empty — there is nothing inside it at all';
    case 'todo_only_body':
      return 'contains only a note saying the check still needs to be written (or the old check commented out), plus at most a fixed answer such as return false, with nothing that actually checks anyone';
  }
}
