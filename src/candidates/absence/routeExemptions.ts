import type { AbsenceRoute } from './routeModel.js';
import { PARAM, hasWebhookOrCronSegment, segments } from '../../shared/routePath.js';

const NEUTRAL_PREFIX = new Set(['api', 'account', 'accounts']);
const AUTH_NAMESPACE = new Set(['auth', 'authn', 'authentication', 'oauth', 'oauth2', 'oidc', 'sso']);
const VERSION = /^v\d+$/;

const AUTH_FLOW_HEAD = new Set([
  'login',
  'logon',
  'signin',
  'logout',
  'logoff',
  'signout',
  'signup',
  'register',
  'registration',
  'forgot',
  'forgotpassword',
  'forgotpw',
  'resetpassword',
  'resetpw',
  'passwordreset',
  'recoverpassword',
  'refresh',
  'refreshtoken',
  'refreshtokens',
  'revoke',
  'revocation',
  'verifyemail',
  'emailverification',
  'confirmemail',
  'magiclink',
  'passkey',
  'passkeys',
  'webauthn',
  '2fa',
  'twofa',
  'twofactor',
  'mfa',
  'totp',
  'introspect',
]);

const AUTH_FLOW_HEAD_NAMESPACED = new Set([
  'token',
  'tokens',
  'callback',
  'verify',
  'verification',
  'confirm',
  'confirmation',
  'activate',
  'activation',
  'email',
  'otp',
  'code',
  'authorize',
]);

const SESSION_RESOURCE = new Set(['session', 'sessions']);

const PASSWORD_FLOW_TAIL = new Set(['reset', 'forgot', 'recover', 'recovery']);

const AUTH_DIRECTORY = /(^|\/)(auth|authn|authentication|oauth|oauth2|oidc|passport|sso)\//i;

export function isAuthFlowRoute(route: Pick<AbsenceRoute, 'fullPath' | 'relPath' | 'filePath'>): boolean {
  const segs = segments(route.fullPath || route.relPath);
  if (segs.length === 0) return false;

  let index = 0;
  let namespaced = AUTH_DIRECTORY.test(route.filePath);
  for (; index < segs.length; index += 1) {
    const seg = segs[index] ?? '';
    if (AUTH_NAMESPACE.has(seg)) namespaced = true;
    else if (!NEUTRAL_PREFIX.has(seg) && !VERSION.test(seg)) break;
  }
  const head = segs[index];
  const next = segs[index + 1];
  const last = segs[segs.length - 1];

  if (head === undefined) return false;
  if (AUTH_FLOW_HEAD.has(head)) return true;
  if (head === 'reset' && next === PARAM) return true;
  if (head === 'password' && next !== undefined && PASSWORD_FLOW_TAIL.has(next)) return true;
  if (SESSION_RESOURCE.has(head) && (next === undefined || (next === PARAM && segs.length === index + 2))) return true;
  if (namespaced && AUTH_FLOW_HEAD_NAMESPACED.has(head)) return true;
  if (last === 'callback' && (head === PARAM || namespaced)) return true;
  return false;
}

const WEBHOOK_OR_CRON_IDENTIFIER = /(?:^|[^A-Za-z])(?:[Ww]ebhooks?|[Cc]ron)(?![a-z])|(?:Webhooks?|Cron)(?![a-z])/;

export function isWebhookOrCronRoute(
  route: Pick<AbsenceRoute, 'fullPath' | 'relPath' | 'middlewares' | 'handlerToken'>,
): boolean {
  if (hasWebhookOrCronSegment(route.fullPath || route.relPath)) return true;
  const identifiers = [...route.middlewares, ...(route.handlerToken !== undefined ? [route.handlerToken] : [])];
  return identifiers.some((token) => WEBHOOK_OR_CRON_IDENTIFIER.test(token));
}

export function isCatchAllRoute(route: Pick<AbsenceRoute, 'relPath'>): boolean {
  return /^\/?\*$|^\/?\(\.\*\)$|^\/?\*\*$/.test(route.relPath.trim());
}
