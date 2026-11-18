import { makeFinding } from '../../shared/findingFactory.js';
import type { Finding, RuleContext, ScanRule } from '../../shared/types.js';
import { findMatches, lineAt } from '../../shared/utils.js';
import { enclosingFunctionScopeRange, routeHandlerScope } from '../../shared/handlerScope.js';
import { stripCommentsAndStrings } from '../../shared/source.js';
import { resolvesToSignatureCheck } from '../../shared/handlerGuardCall.js';
import { routeControlProven } from '../../shared/routeControlModel.js';
import { SIGNATURE_HEADER } from '../../shared/webhookSignature.js';
import { isPythonTestModule } from '../../input/fileFilters.js';
import { pythonWebhookVerified } from '../../shared/pythonWebhook.js';

const CODE_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py']);
const WEBHOOK_HINT = /webhook|stripe|paddle|razorpay|shopify|github|svix|clerk|paypal|twilio|supabase|polar/i;
const HANDLER_AUTH_GUARD =
  /\b(?:getUser|getSession|getServerSession|requireUser|requireAuth|requireAdmin|requireSession|currentUser)\s*\(|jwt\.verify\s*\(|\breq\.session\b/i;
const BODY_ANCHOR =
  /req(?:uest)?\.(?:body|json|text)|constructEvent|\bpayload\b|\brawBody\b/gi;
const REAL_VERIFY_ACTION = /constructEvent\s*\(|webhooks?\.(?:verify|constructEvent|verifySignature)\s*\(|verifyHeader\s*\(|createHmac\s*\(|timingSafeEqual\s*\(|new\s+Webhook\s*\(|\.verify\s*\(/i;
const PROCESSING_HINT = /(?:create|update|insert|delete|fulfill|grant|activate|provision|send|charge|subscription|payment|invoice|user)\w*\s*\(|\.\s*(?:create|update|insert|delete|upsert)\s*\(/i;
const REJECT_ON_FAILURE = /catch\s*\(|if\s*\([^)]*!|throw\b|return\s+(?:new\s+Response|Response\.json)[\s\S]{0,120}status\s*:\s*40[013]|\.status\s*\(\s*40[013]\s*\)|return\s+false/i;

function helperBody(content: string, name: string): string | undefined {
  const escaped = name.replace(/[$]/g, '\\$&');
  const patterns = [
    new RegExp(`function\\s+${escaped}\\s*\\([^)]*\\)\\s*\\{([\\s\\S]{0,900}?)\\}`, 'i'),
    new RegExp(`(?:const|let|var)\\s+${escaped}\\s*=\\s*(?:async\\s*)?(?:\\([^)]*\\)|[A-Za-z_$][\\w$]*)\\s*=>\\s*\\{([\\s\\S]{0,900}?)\\}`, 'i'),
  ];
  for (const pattern of patterns) {
    const match = pattern.exec(content);
    if (match?.[1] !== undefined) return match[1];
  }
  return undefined;
}

function customVerificationIsReal(scope: string, fileContent: string): boolean {
  const name = /\b(verify\w*(?:Signature|Webhook|Event)|assert\w*(?:Signature|Webhook)|check\w*Signature)\s*\(/i.exec(scope)?.[1];
  if (name === undefined) return false;
  const body = helperBody(fileContent, name);
  if (body === undefined) return false;
  if (/return\s+true\s*;?\s*$/i.test(body.trim())) return false;
  return (REAL_VERIFY_ACTION.test(body) || /hmac|sha256|digest|timingSafeEqual|standardwebhooks|svix/i.test(body)) && REJECT_ON_FAILURE.test(body);
}

function hasEffectiveVerification(scope: string, fileContent: string): boolean {
  const customIsReal = customVerificationIsReal(scope, fileContent) || (/\bverify\w*(?:Signature|Webhook|Event)\s*\(/i.test(scope) && /createHmac\s*\(|timingSafeEqual\s*\(|constructEvent\s*\(|new\s+Webhook\s*\(/i.test(fileContent));
  if (customIsReal && SIGNATURE_HEADER.test(scope)) return true;
  const verificationMatch = REAL_VERIFY_ACTION.exec(scope);
  const customMatch = customIsReal ? /verify|assert|check/i.exec(scope) : null;
  const verifierIndex = verificationMatch?.index ?? customMatch?.index;
  if (verifierIndex === undefined) return false;
  if (!SIGNATURE_HEADER.test(scope)) return false;
  const verifierFunctionStart = enclosingFunctionScopeRange(scope, verifierIndex).start;
  if (PROCESSING_HINT.test(scope.slice(verifierFunctionStart, verifierIndex))) return false;
  const verifiedRegion = scope.slice(verifierIndex);
  return REJECT_ON_FAILURE.test(verifiedRegion) || /constructEvent\s*\(|new\s+Webhook\s*\(|webhooks?\.verify/i.test(verifiedRegion) || customMatch !== null;
}

export const missingWebhookVerification: ScanRule = {
  id: 'missing_webhook_verification',
  title: 'Webhook endpoint without signature verification',
  category: 'webhooks',
  kind: 'contextual',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const apiFiles = new Set(context.projectMap.apiRoutes.map((route) => route.filePath));

    for (const entry of context.fileMap.entries) {
      if (!CODE_EXTENSIONS.has(entry.extension)) continue;
      const python = entry.extension === '.py';
      if (python && isPythonTestModule(entry.path)) continue;
      const isApiHandler = apiFiles.has(entry.path) || entry.isLikelyApiRoute;
      const code = stripCommentsAndStrings(entry.content);
      const mentionsWebhook = /webhook/i.test(entry.path) || /webhook/i.test(code);
      const mentionsProvider = WEBHOOK_HINT.test(entry.path) || WEBHOOK_HINT.test(code);
      if (!isApiHandler || !mentionsWebhook || !mentionsProvider) continue;
      if (!/req(?:uest)?\.(?:body|json|text)\b|\bevent\b|\bpayload\b|\brawBody\b|constructEvent/i.test(code)) continue;

      const anchor = findMatches(code, BODY_ANCHOR).find((candidate) => {
        const scope = routeHandlerScope(entry.content, candidate.index);
        if (python && pythonWebhookVerified(context, entry.content, candidate.line)) return false;
        return !hasEffectiveVerification(scope, entry.content) && !HANDLER_AUTH_GUARD.test(scope);
      });
      if (anchor === undefined) continue;
      if (routeControlProven(context, entry.path, anchor.line, 'signature')) continue;
      if (resolvesToSignatureCheck(context, entry.path, routeHandlerScope(entry.content, anchor.index))) continue;
      findings.push(
        makeFinding({
          ruleId: this.id,
          title: this.title,
          severity: 'high',
          confidence: 'medium',
          detectionKind: 'absence',
          filePath: entry.path,
          lineStart: anchor.line,
          evidence: lineAt(entry.content, anchor.line),
          userExplanation:
            'This endpoint receives webhooks but does not prove the request really came from that provider before processing it. Anyone who knows the URL may be able to send fake events. Verify the signature before trusting the payload.',
          technicalExplanation:
            `${entry.path} handles a webhook payload without an effective signature gate before processing: the scanner did not prove raw-body/provider/HMAC verification, a signature header, and rejection on failure in this handler scope.`,
          fixHint:
            'Verify the signature before handling the event: use the provider SDK or recompute an HMAC over the raw body and compare safely. Reject immediately on mismatch before any business action.',
          category: this.category,
        }),
      );
    }
    return findings;
  },
};

