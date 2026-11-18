import type { ScanRule } from '../../shared/types.js';
import { patternRule } from './patternRule.js';

export const weakSessionHandling: ScanRule = patternRule({
  id: 'weak_session_handling',
  title: 'Session handling may be insecure',
  category: 'authentication',
  probes: [
    {
      pattern: /session\s*\([\s\S]{0,260}secret\s*:\s*['"][^'"$]{1,20}['"]/gi,
      title: 'weak hardcoded session secret', severity: 'high', confidence: 'high',
      explanation: 'The app uses a short hardcoded session secret. Attackers who guess or learn it can forge or tamper with signed session cookies.',
      technical: 'express-session/cookie-session appears to use a short literal secret.',
      fix: 'Use a long random secret from a server-only environment variable or secret manager, and rotate existing sessions after changing it.',
    },
    {
      pattern: /req\.session\.(?:user|userId|uid|accountId)\s*=\s*[^;\n]+;[\s\S]{0,240}(?!req\.session\.regenerate\s*\()/gi,
      title: 'login without session regeneration', severity: 'medium', confidence: 'low',
      explanation: 'The app writes an authenticated identity into the session without visible session regeneration. This can leave session fixation bugs in login flows.',
      technical: 'A session identity assignment was found without req.session.regenerate nearby.',
      fix: 'Regenerate the session id after successful login before storing the authenticated identity, then save the session.',
    },
  ],
});
