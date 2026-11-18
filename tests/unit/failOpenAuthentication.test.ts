import { describe, expect, it } from 'vitest';
import { failOpenAuthentication } from '../../src/rules/contextual/failOpenAuthentication.js';
import { runContextualRules } from '../../src/rules/index.js';
import { memoryContext } from './helpers.js';

const PKG: [string, string] = ['package.json', '{"name":"x","dependencies":{"express":"4.18.0"}}'];

const fire = (file: string, source: string): ReturnType<typeof failOpenAuthentication.run> =>
  failOpenAuthentication.run(memoryContext([PKG, [file, source]]));

describe('fail_open_authentication — the error that lets the request through', () => {
  it('SHAPE A (swallowed_catch): a verification in a try, an empty catch, protected work after', () => {
    const findings = fire(
      'api/notes.js',
      [
        'export async function handler(req, res) {',
        '  let account;',
        '  try {',
        '    account = await verifyToken(req.headers.token);',
        '    if (!account) return res.status(401).json({ error: "no" });',
        '  } catch (e) {',
        '  }',
        '  const notes = await db.notes.findMany({ where: { ownerId: req.query.owner } });',
        '  res.json(notes);',
        '}',
      ].join('\n'),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.filePath).toBe('api/notes.js');
    expect(findings[0]?.lineStart).toBe(3);
    expect(findings[0]?.severity).toBe('high');
    expect(findings[0]?.confidence).toBe('high');
    expect(findings[0]?.category).toBe('authentication');
    expect(findings[0]?.evidence).toContain('swallows the error without refusing the request');
    expect(findings[0]?.evidence).toContain('verifyToken(');
  });

  it('SHAPE A2 (swallowed_catch): a catch that only logs is still a swallow', () => {
    const findings = fire(
      'api/orders.js',
      [
        'export async function handler(req, res) {',
        '  try {',
        '    const session = await getServerSession(req);',
        '    if (!session) return res.status(401).end();',
        '  } catch (err) {',
        '    console.error("auth failed", err);',
        '  }',
        '  const orders = await db.orders.findMany();',
        '  res.json(orders);',
        '}',
      ].join('\n'),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain('getServerSession(');
  });

  it('SHAPE B (catch_calls_next): middleware whose catch calls a bare next()', () => {
    const findings = fire(
      'middleware/auth.js',
      [
        'module.exports = async function requireAuth(req, res, next) {',
        '  try {',
        '    req.user = await verifySession(req.cookies.sid);',
        '  } catch (e) {',
        '    next();',
        '  }',
        '};',
      ].join('\n'),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain('calls next() with no argument');
  });

  it('SHAPE C (catch_returns_authorized): a promise .catch that returns true', () => {
    const findings = fire(
      'lib/guard.ts',
      [
        'export async function mayEdit(req) {',
        '  const ok = await verifyToken(req.token).catch(() => true);',
        '  return db.documents.update({ where: { id: req.body.id }, data: req.body });',
        '}',
      ].join('\n'),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain('returns a value that asserts the caller is authorised');
  });

  it('SHAPE D (inverted_error_branch): if (error) that proceeds anyway', () => {
    const findings = fire(
      'app/api/admin/route.ts',
      [
        'export async function POST(request) {',
        '  const { data, error } = await supabase.auth.getUser();',
        '  if (error) {',
        '  }',
        '  const rows = await db.invoices.findMany();',
        '  return Response.json(rows);',
        '}',
      ].join('\n'),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain('tests for the error and then proceeds anyway');
  });

  it('N2: a catch that returns 401 never fires', () => {
    expect(
      fire(
        'api/a.js',
        [
          'export async function handler(req, res) {',
          '  try {',
          '    const user = await getUser(req);',
          '    if (!user) return res.status(401).end();',
          '  } catch (e) {',
          '    return res.status(401).json({ error: "unauthorized" });',
          '  }',
          '  const rows = await db.rows.findMany();',
          '  res.json(rows);',
          '}',
        ].join('\n'),
      ),
    ).toHaveLength(0);
  });

  it('N2: a catch that re-throws never fires', () => {
    expect(
      fire(
        'api/b.js',
        [
          'export async function handler(req, res) {',
          '  try {',
          '    const user = await getUser(req);',
          '  } catch (e) {',
          '    console.error(e);',
          '    throw e;',
          '  }',
          '  const rows = await db.rows.findMany();',
          '  res.json(rows);',
          '}',
        ].join('\n'),
      ),
    ).toHaveLength(0);
  });

  it('N2: .catch(err => next(err)) is a denial, not a bare next()', () => {
    expect(
      fire(
        'middleware/auth.js',
        [
          'module.exports = (req, res, next) =>',
          '  new Promise((resolve, reject) => {',
          '    passport.authenticate("jwt", { session: false }, cb(req, resolve, reject))(req, res, next);',
          '  })',
          '    .then(() => next())',
          '    .catch((err) => next(err));',
        ].join('\n'),
      ),
    ).toHaveLength(0);
  });

  it('N3 (LOAD-BEARING): the 500-handler — a catch that ends the handler never fires', () => {
    expect(
      fire(
        'app/api/spotify/status/route.ts',
        [
          'export async function GET() {',
          '  try {',
          '    const session = await auth.api.getSession({ headers: await headers() })',
          '    if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 })',
          '    const account = await db.select().from(spotifyAccount)',
          '    return NextResponse.json({ connected: true })',
          '  } catch (error) {',
          '    console.error(error)',
          '    return NextResponse.json({ error: "Internal server error" }, { status: 500 })',
          '  }',
          '}',
        ].join('\n'),
      ),
    ).toHaveLength(0);
  });

  it('N3 (LOAD-BEARING): a server shape — catch body is only handleError(error, res)', () => {
    expect(
      fire(
        'backend/routes.ts',
        [
          'router.get("/api/scans", async (req, res) => {',
          '  try {',
          '    const user = await requireUser(req);',
          '    const scans = await db.scans.findMany({ where: { userId: user.id } });',
          '    res.json(scans);',
          '  } catch (error) {',
          '    handleError(error, res);',
          '  }',
          '});',
        ].join('\n'),
      ),
    ).toHaveLength(0);
  });

  it('N3(b) ALONE: a protected operation in a finally runs on BOTH paths', () => {
    expect(
      fire(
        'api/scan.ts',
        [
          'export async function handler(req, res) {',
          '  try {',
          '    const user = await requireUser(req);',
          '  } catch (error) {',
          '    console.error(error);',
          '  } finally {',
          '    await db.audit.create({ data: { event: "scan", at: Date.now() } });',
          '  }',
          '}',
        ].join('\n'),
      ),
    ).toHaveLength(0);
  });

  it('SHAPE A3 (swallowed_catch): an error helper that answers but does NOT return', () => {
    const findings = fire(
      'backend/scans.ts',
      [
        'router.get("/api/scans", async (req, res) => {',
        '  try {',
        '    const user = await requireUser(req);',
        '  } catch (error) {',
        '    handleError(error, res);',
        '  }',
        '  const scans = await db.scans.findMany();',
        '  res.json(scans);',
        '});',
      ].join('\n'),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain('requireUser(');
  });

  it('N3(b): the SAME helper is silent when the catch ends the handler (26 of ours)', () => {
    expect(
      fire(
        'backend/scans-ok.ts',
        [
          'router.get("/api/scans", async (req, res) => {',
          '  try {',
          '    const user = await requireUser(req);',
          '    const scans = await db.scans.findMany({ where: { userId: user.id } });',
          '    res.json(scans);',
          '  } catch (error) {',
          '    handleError(error, res);',
          '  }',
          '});',
        ].join('\n'),
      ),
    ).toHaveLength(0);
  });

  it('N6: our own accessControl.ts — a next() classified by error type is delegation, not a swallow', () => {
    expect(
      fire(
        'backend/accessControl.ts',
        [
          'export function productionLockdownGate() {',
          '  return async (req, res, next) => {',
          '    let user;',
          '    try {',
          '      user = await requireUser(req);',
          '    } catch (error) {',
          '      if (error instanceof AuthError) { next(); return; }',
          '      next(error);',
          '      return;',
          '    }',
          '    if (isAllowedUser(user)) { next(); return; }',
          '    res.status(403).json({ error: LOCKDOWN_MESSAGE });',
          '  };',
          '}',
        ].join('\n'),
      ),
    ).toHaveLength(0);
  });

  it('N0: db.authenticate() is a database connection check, not authentication', () => {
    expect(
      fire(
        'server/storage/database.ts',
        [
          'export const checkConnection = async (db) => {',
          '  try {',
          '    await db.authenticate();',
          '  } catch (error) {',
          '    Logger.info("database connection unavailable");',
          '  }',
          '  const rows = await db.query("select 1");',
          '  return rows;',
          '};',
        ].join('\n'),
      ),
    ).toHaveLength(0);
  });

  it('N0/N1: a try around JSON.parse or a non-auth database call never fires', () => {
    expect(
      fire(
        'api/c.js',
        [
          'export async function handler(req, res) {',
          '  let body = {};',
          '  try {',
          '    body = JSON.parse(req.rawBody);',
          '  } catch (e) {',
          '  }',
          '  const rows = await db.rows.findMany({ where: body });',
          '  res.json(rows);',
          '}',
        ].join('\n'),
      ),
    ).toHaveLength(0);
  });

  it('N1: the auth call sits ABOVE the try, so the try cannot swallow it', () => {
    expect(
      fire(
        'app/api/courses/route.js',
        [
          'export async function POST(req) {',
          '  const { userId } = getAuth(req);',
          '  const data = await req.json();',
          '  try {',
          '    const course = await Course.create({ courseName: data.name, ownerId: userId });',
          '    return NextResponse.json(course);',
          '  } catch (err) {',
          '    console.log(err);',
          '  }',
          '}',
        ].join('\n'),
      ),
    ).toHaveLength(0);
  });

  it('N1/N4: .catch(() => null) on a downstream fetch that mentions a session id', () => {
    expect(
      fire(
        'server/api/detect-fields.ts',
        [
          'export async function loader({ request }) {',
          '  const session = await getSession(request);',
          '  const team = await getTeamById({ userId: session.user.id, teamId }).catch(() => null);',
          '  if (!team) return new Response(null, { status: 404 });',
          '  return Response.json(await db.fields.findMany({ where: { teamId: team.id } }));',
          '}',
        ].join('\n'),
      ),
    ).toHaveLength(0);
  });

  it('N4: returning the ABSENT or least-privileged value is a refusal', () => {
    expect(
      fire(
        'lib/tier.ts',
        [
          'export async function getUserTier(req) {',
          '  const tier = await verifySession(req.cookies.sid).catch(() => USER_TIERS.FREE);',
          '  return db.limits.findFirst({ where: { tier } });',
          '}',
        ].join('\n'),
      ),
    ).toHaveLength(0);
  });

  it('N5/N8: NotifAI useDeleteAccount:78 — the continuation is local cleanup and sign-out', () => {
    expect(
      fire(
        'hooks/useDeleteAccount.ts',
        [
          'export async function deleteAccount() {',
          '  try {',
          '    const { data: { session } } = await supabase.auth.getSession();',
          '    if (!session?.access_token) throw new Error("No valid session found");',
          '  } catch (authError) {',
          '    console.warn("Auth deletion failed, continuing with local cleanup");',
          '  }',
          '  try { await AsyncStorage.clear(); } catch (e) { console.error(e); }',
          '  try { await supabase.auth.signOut(); } catch (e) { console.error(e); }',
          '}',
        ].join('\n'),
      ),
    ).toHaveLength(0);
  });

  it('N8: NotifAI AuthContext:37 — an optional-auth public path that proceeds with a null identity', () => {
    expect(
      fire(
        'contexts/AuthContext.tsx',
        [
          'export async function initializeAuth(setUser) {',
          '  const { data: { session: currentSession }, error } = await supabase.auth.getSession();',
          '  if (error) {',
          '  }',
          '  setUser(currentSession?.user ?? null);',
          '  const posts = await db.posts.findMany({ where: { isPublic: true } });',
          '  return posts;',
          '}',
        ].join('\n'),
      ),
    ).toHaveLength(0);
  });

  it('N1: a multer error callback is not an auth error', () => {
    expect(
      fire(
        'controllers/api.js',
        [
          'exports.postFileUpload = (req, res) => {',
          '  return req.session.save(() => res.redirect("/api/upload"));',
          '};',
          '',
          'exports.uploadMiddleware = (req, res, next) => {',
          '  const upload = multer({ dest: "../uploads", limits: { fileSize: 1024 } });',
          '  upload.single("myFile")(req, res, (err) => {',
          '    if (err) {',
          '      req.multerError = err;',
          '    }',
          '    next();',
          '  });',
          '};',
        ].join('\n'),
      ),
    ).toHaveLength(0);
  });

  it('N7: a fail-open stub in a test/mock file never fires (strict frozen provenance)', () => {
    const result = runContextualRules(
      memoryContext([
        PKG,
        [
          'tests/mocks/auth.js',
          [
            'export async function handler(req, res) {',
            '  try {',
            '    await verifyToken(req.headers.token);',
            '  } catch (e) {',
            '  }',
            '  const rows = await db.rows.findMany();',
            '  res.json(rows);',
            '}',
          ].join('\n'),
        ],
      ]),
    );
    expect(result.findings.filter((f) => f.ruleId === 'fail_open_authentication')).toHaveLength(0);
  });
});
