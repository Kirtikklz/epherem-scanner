import type { ScanRule } from '../../shared/types.js';
import { patternRule } from './patternRule.js';

export const oauthMisconfiguration: ScanRule = patternRule({
  id: 'oauth_misconfiguration',
  title: 'OAuth flow appears weakly configured',
  category: 'authentication',
  probes: [
    {
      pattern: /authorizationUrl\s*\([\s\S]{0,260}(?:state\s*:\s*(?:undefined|null|false|['"]['"])|redirect_uri\s*:\s*(?:req|request)\.(?:query|body)|callbackURL\s*:\s*(?:req|request)\.(?:query|body))/gi,
      title: 'missing state or user-controlled redirect URI', severity: 'high', confidence: 'medium',
      explanation: 'This OAuth authorization flow appears to omit state protection or lets the request choose the redirect URI. That can enable CSRF, account linking attacks, or token theft.',
      technical: 'OAuth authorization parameters include missing/empty state or request-derived redirect/callback URI.',
      fix: 'Generate and verify a high-entropy state value, bind it to the user session, and use a fixed server-side redirect URI allowlist.',
    },
    {
      pattern: /passport\.(?:use|authenticate)\s*\([\s\S]{0,260}callbackURL\s*:\s*(?:req|request)\.(?:query|body)/gi,
      title: 'request-controlled callback URL', severity: 'high', confidence: 'medium',
      explanation: 'This OAuth callback URL appears to come from the incoming request. Attackers may redirect tokens or authorization codes to their own endpoint.',
      technical: 'OAuth strategy/authenticate configuration uses request-derived callbackURL.',
      fix: 'Use a fixed callback URL from server configuration and validate any post-login return path separately as a same-origin relative path.',
    },
  ],
});
