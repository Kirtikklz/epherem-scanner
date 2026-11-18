import { describe, expect, it } from 'vitest';
import { placeholderAuthentication } from '../../src/rules/contextual/placeholderAuthentication.js';
import { runContextualRules } from '../../src/rules/index.js';
import { memoryContext } from './helpers.js';

const PKG: [string, string] = ['package.json', '{"name":"x","dependencies":{"express":"4.18.0"}}'];

describe('placeholder_authentication — the guard that never checks anything', () => {
  it('SHAPE A: fires on a guard that returns a literal truthy value', () => {
    const findings = placeholderAuthentication.run(
      memoryContext([PKG, ['lib/auth.js', 'export function requireAuth(req) {\n  return true;\n}\n']]),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.filePath).toBe('lib/auth.js');
    expect(findings[0]?.lineStart).toBe(1);
    expect(findings[0]?.severity).toBe('high');
    expect(findings[0]?.confidence).toBe('high');
    expect(findings[0]?.category).toBe('authentication');
    expect(findings[0]?.evidence).toContain('returns a literal truthy value unconditionally');
    expect(findings[0]?.evidence).toContain('exported');
  });

  it('SHAPE A2: fires on a concise arrow guard that returns true', () => {
    const findings = placeholderAuthentication.run(
      memoryContext([PKG, ['lib/roles.ts', 'export const isAdmin = (user) => true;\n']]),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain('isAdmin');
  });

  it('SHAPE B: fires on a guard that returns a hard-coded user/role object', () => {
    const findings = placeholderAuthentication.run(
      memoryContext([
        PKG,
        [
          'lib/session.ts',
          'export function getAuthenticatedUser(req) {\n' +
            '  return { id: "1", email: "admin@example.com", role: "admin" };\n' +
            '}\n',
        ],
      ]),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain('hard-coded user/role object');
  });

  it('SHAPE C: fires on middleware that calls next() with nothing gating it', () => {
    const findings = placeholderAuthentication.run(
      memoryContext([
        PKG,
        ['middleware/auth.js', 'export const authMiddleware = (req, res, next) => {\n  next();\n};\n'],
      ]),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain('calls next() with nothing gating it');
  });

  it('SHAPE D: fires on an empty guard body', () => {
    const findings = placeholderAuthentication.run(
      memoryContext([PKG, ['middleware/admin.js', 'export function requireAdmin(req, res, next) {\n}\n']]),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain('is empty or a no-op return');
  });

  it('SHAPE D2: fires on a no-op return in a middleware guard', () => {
    const findings = placeholderAuthentication.run(
      memoryContext([PKG, ['middleware/guard.js', 'export const authGuard = (req, res, next) => {\n  return;\n};\n']]),
    );
    expect(findings).toHaveLength(1);
  });

  it('SHAPE E: fires on a guard whose only content is a TODO', () => {
    const findings = placeholderAuthentication.run(
      memoryContext([
        PKG,
        [
          'lib/permissions.ts',
          'export async function checkPermission(userId, action) {\n' +
            '  // TODO: check permissions against the database\n' +
            '}\n',
        ],
      ]),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain('TODO or a commented-out check');
  });

  it('SHAPE E2: fires when the real check is commented out above an unconditional next()', () => {
    const findings = placeholderAuthentication.run(
      memoryContext([
        PKG,
        [
          'middleware/ensure.js',
          'export function ensureAuthenticated(req, res, next) {\n' +
            '  // if (!req.session.userId) return res.status(401).end();\n' +
            '  next();\n' +
            '}\n',
        ],
      ]),
    );
    expect(findings).toHaveLength(1);
  });

  it('N2: a real guard with a session lookup is silent', () => {
    const findings = placeholderAuthentication.run(
      memoryContext([
        PKG,
        [
          'lib/auth.ts',
          'export async function requireAuth(req) {\n' +
            '  const session = await getServerSession(authOptions);\n' +
            '  if (!session) throw new Error("Unauthorized");\n' +
            '  return session.user;\n' +
            '}\n',
        ],
      ]),
    );
    expect(findings).toHaveLength(0);
  });

  it('N3: an auth callback ending in `return true` is silent (real conditional)', () => {
    const findings = placeholderAuthentication.run(
      memoryContext([
        PKG,
        [
          'auth.ts',
          'export const authorized = ({ request, auth }) => {\n' +
            '  const { pathname } = request.nextUrl;\n' +
            '  if (pathname === "/middleware-example") return !!auth;\n' +
            '  return true;\n' +
            '};\n',
        ],
      ]),
    );
    expect(findings).toHaveLength(0);
  });

  it('N3b: `if (scopes.includes("*")) return true` is silent', () => {
    const findings = placeholderAuthentication.run(
      memoryContext([
        PKG,
        [
          'shared/AuthenticationHelper.ts',
          'export function canAccess(path, scopes) {\n' +
            '  if (scopes.includes("*")) {\n' +
            '    return true;\n' +
            '  }\n' +
            '  return false;\n' +
            '}\n',
        ],
      ]),
    );
    expect(findings).toHaveLength(0);
  });

  it('N4: a role comparison is a real check, not a permissive shape', () => {
    const findings = placeholderAuthentication.run(
      memoryContext([PKG, ['lib/roles.js', 'export function isAdmin(user) {\n  return user.role === "admin";\n}\n']]),
    );
    expect(findings).toHaveLength(0);
  });

  it('N1: `return true` in a NON-auth-named function is silent', () => {
    const findings = placeholderAuthentication.run(
      memoryContext([PKG, ['lib/portal.ts', 'export function checkRateLimit(ip) {\n  return true;\n}\n']]),
    );
    expect(findings).toHaveLength(0);
  });

  it('N1b: an unfinished signIn/signOut is an unfinished LOGIN, not a fake guard', () => {
    const findings = placeholderAuthentication.run(
      memoryContext([
        PKG,
        [
          'components/header.tsx',
          'export const signOut = (auth) => {\n  // TODO: complete function\n};\n' +
            'export const signIn = async (auth) => {\n  // TODO: complete function\n};\n',
        ],
      ]),
    );
    expect(findings).toHaveLength(0);
  });

  it('N1c: a React component named for a protected area is silent', () => {
    const findings = placeholderAuthentication.run(
      memoryContext([
        PKG,
        [
          'app/layout.tsx',
          'export default function ProtectedLayout({ children }) {\n' +
            '  return (<div>{children}</div>);\n' +
            '}\n',
        ],
        ['app/admin/page.tsx', 'export default function AdminPage() {\n  // Redirect page.\n}\n'],
      ]),
    );
    expect(findings).toHaveLength(0);
  });

  it('N4b: a commented-out check inside a function that does real work is silent', () => {
    const findings = placeholderAuthentication.run(
      memoryContext([
        PKG,
        [
          'server/request-2fa.ts',
          'export async function requireAccess(recipient, user) {\n' +
            '  // if (user && recipient.email !== user.email) {\n' +
            '  //   throw new TRPCError({ code: "UNAUTHORIZED" });\n' +
            '  // }\n' +
            '  const token = createToken(recipient);\n' +
            '  await sendEmail(recipient.email, token);\n' +
            '  return token;\n' +
            '}\n',
        ],
      ]),
    );
    expect(findings).toHaveLength(0);
  });

  it('N1d: a name that merely CONTAINS "session" is silent', () => {
    const findings = placeholderAuthentication.run(
      memoryContext([
        PKG,
        [
          'hooks/use-analytics.ts',
          'export const startSessionRecording = (eventFlag) => {\n' +
            '  return;\n' +
            '  // const enabled = featureFlags.getFlag(FLAG);\n' +
            '};\n',
        ],
      ]),
    );
    expect(findings).toHaveLength(0);
  });

  it('N5: a permissive guard that is neither exported nor registered is silent', () => {
    const findings = placeholderAuthentication.run(
      memoryContext([PKG, ['lib/dead.js', 'function requireAuth(req) {\n  return true;\n}\n']]),
    );
    expect(findings).toHaveLength(0);
  });

  it('N5b: a non-exported guard REGISTERED on a router is reported', () => {
    const findings = placeholderAuthentication.run(
      memoryContext([
        PKG,
        ['middleware/auth.js', 'function requireAuth(req, res, next) {\n  next();\n}\n'],
        ['server.js', 'const requireAuth = require("./middleware/auth");\napp.use(requireAuth);\n'],
      ]),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain('registered on a route or middleware chain');
  });

  it('a stub in a TEST/mock file never fires (central non-production exclusion)', () => {
    const result = runContextualRules(
      memoryContext([PKG, ['tests/mocks/auth.ts', 'export function requireAuth(req) {\n  return true;\n}\n']]),
    );
    expect(result.findings.filter((finding) => finding.ruleId === 'placeholder_authentication')).toHaveLength(0);
  });
});
