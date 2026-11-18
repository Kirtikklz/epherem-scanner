import { hasStack } from '../../stack-detection/detectStack.js';
import { makeFinding } from '../../shared/findingFactory.js';
import type { Finding, RuleContext, ScanRule } from '../../shared/types.js';
import { basename, findMatches, lineAt } from '../../shared/utils.js';
import { creditEvidence, creditScopedEntries, isScanReport } from '../../shared/creditScope.js';
import { stripCommentsOnly, usesHashComments } from '../../shared/source.js';

const HEADER_EVIDENCE_PATTERN =
  /\bhelmet\s*[.(]|Strict-Transport-Security|Content-Security-Policy|X-Frame-Options|X-Content-Type-Options|async\s+headers\s*\(|headers\s*:\s*\[|setHeader\(\s*['"](Strict-Transport|Content-Security|X-Frame)/;

const HELMET_CALL = /\bhelmet\s*\(/g;
const HELMET_CALL_TEST = new RegExp(HELMET_CALL.source);

const DISABLEABLE_PROTECTIONS: ReadonlyArray<{
  option: string;
  header: string;
  suppliedElsewhere: RegExp;
  risk: string;
}> = [
  {
    option: 'contentSecurityPolicy',
    header: 'Content-Security-Policy',
    suppliedElsewhere: /Content-Security-Policy|contentSecurityPolicy\s*[:(]/i,
    risk: 'nothing constrains where scripts, styles and frames may be loaded from, so an injected script runs with the page’s full privileges',
  },
  {
    option: 'hsts',
    header: 'Strict-Transport-Security',
    suppliedElsewhere: /Strict-Transport-Security|\bhsts\s*[:(]/i,
    risk: 'a browser that has only ever seen the site over HTTPS will still try plain HTTP after a link, a typed address or an attacker’s downgrade',
  },
  {
    option: 'frameguard',
    header: 'X-Frame-Options',
    suppliedElsewhere: /X-Frame-Options|frame-ancestors|\bframeguard\s*[:(]/i,
    risk: 'the pages can be framed by any site, which is what clickjacking needs',
  },
  {
    option: 'noSniff',
    header: 'X-Content-Type-Options',
    suppliedElsewhere: /X-Content-Type-Options|\bnoSniff\s*[:(]/i,
    risk: 'a browser may re-interpret an uploaded file as script because of what is inside it rather than what the Content-Type says',
  },
];

const POWERED_BY_DISABLED = /\b(?:app|server|expressApp)\s*\.\s*disable\s*\(\s*['"`]x-powered-by['"`]\s*\)|\bhidePoweredBy\b|\bremoveHeader\s*\(\s*['"`]x-powered-by['"`]|\bpoweredByHeader\s*:\s*false/i;

const POWERED_BY_RE_ENABLED = /\bhidePoweredBy\s*:\s*false\b/i;

const EXPRESS_APP = /\b(?:const|let|var)\s+\w+\s*=\s*express\s*\(\s*\)|\brequire\s*\(\s*['"]express['"]\s*\)\s*\(\s*\)/;

function balancedParens(text: string, open: number, cap = 4000): { inner: string; end: number } | undefined {
  if (text[open] !== '(') return undefined;
  let depth = 0;
  for (let i = open; i < text.length && i < open + cap; i += 1) {
    const ch = text[i];
    if (ch === '(') depth += 1;
    else if (ch === ')') {
      depth -= 1;
      if (depth === 0) return { inner: text.slice(open + 1, i), end: i };
    }
  }
  return undefined;
}

function optionDisabled(optionsText: string, option: string): boolean {
  return new RegExp(String.raw`(?:^|[{,\s])${option}\s*:\s*false\s*(?:[,}]|$)`).test(optionsText);
}

function evidenceOutsideHelmetCalls(context: RuleContext): string {
  const parts: string[] = [];
  for (const entry of creditScopedEntries(context)) {
    if (isScanReport(entry)) continue;
    const code = stripCommentsOnly(creditEvidence(entry), usesHashComments(entry.extension, entry.label));
    let out = '';
    let cursor = 0;
    HELMET_CALL.lastIndex = 0;
    for (let m = HELMET_CALL.exec(code); m !== null; m = HELMET_CALL.exec(code)) {
      const call = balancedParens(code, m.index + m[0].length - 1);
      if (call === undefined) continue;
      out += code.slice(cursor, m.index);
      cursor = call.end + 1;
      HELMET_CALL.lastIndex = cursor;
    }
    parts.push(out + code.slice(cursor));
  }
  return parts.join('\n');
}

export const missingSecurityHeaders: ScanRule = {
  id: 'missing_security_headers',
  title: 'No security headers configured',
  category: 'headers',
  kind: 'basic',
  run(context: RuleContext): Finding[] {
    const isNext = hasStack(context.stack, 'nextjs');
    const isExpress = hasStack(context.stack, 'express');
    if (!isNext && !isExpress) return [];

    const anyHeaderConfig = creditScopedEntries(context).some(
      (entry) =>
        !isScanReport(entry) &&
        HEADER_EVIDENCE_PATTERN.test(
          stripCommentsOnly(creditEvidence(entry), usesHashComments(entry.extension, entry.label)),
        ),
    );
    if (anyHeaderConfig) return perFeatureFindings(context, isExpress);

    const anchor =
      context.fileMap.entries.find((entry) => /^next\.config\./.test(basename(entry.path))) ??
      context.fileMap.entries.find((entry) => entry.label === 'package_manifest') ??
      context.fileMap.entries[0];
    if (anchor === undefined) return [];

    const framework = isNext ? 'Next.js' : 'Express';
    return [
      makeFinding({
        ruleId: this.id,
        title: this.title,
        severity: 'medium',
        confidence: 'medium',
        filePath: anchor.path,
        lineStart: 1,
        evidence: `No security header configuration found in this ${framework} project`,
        userExplanation:
          'Your app does not appear to set security headers like Content-Security-Policy or X-Frame-Options. These headers protect users from clickjacking and script-injection attacks and are quick to add.',
        technicalExplanation: isNext
          ? 'No headers() config in next.config and no CSP/HSTS/X-Frame-Options strings found anywhere. Add an async headers() function in next.config or set headers in middleware.'
          : 'The Express app does not use helmet or set security headers manually. Add app.use(helmet()) as a baseline.',
        fixHint: isNext
          ? "Add an async headers() function in next.config that sets X-Frame-Options: DENY and X-Content-Type-Options: nosniff for all routes ('/(.*)'). Add a Content-Security-Policy too, but TAILOR it to what your app actually loads (scripts, styles, images, fonts, connect/API origins) and roll it out in Content-Security-Policy-Report-Only first — a blanket restrictive CSP will break inline scripts, styles, and third-party embeds. Do not weaken existing headers."
          : 'Install helmet (npm i helmet) and add app.use(helmet()) before your routes for sensible defaults. If you enable helmet\'s Content-Security-Policy, tailor the directives to the assets your app loads and test in report-only mode first, since a default/blanket CSP can break inline scripts, styles, and third-party embeds.',
        category: this.category,
      }),
    ];
  },
};

function perFeatureFindings(context: RuleContext, isExpress: boolean): Finding[] {
  const findings: Finding[] = [];
  const entries = creditScopedEntries(context).filter((entry) => !isScanReport(entry));
  const elsewhere = evidenceOutsideHelmetCalls(context);

  for (const entry of entries) {
    const code = stripCommentsOnly(creditEvidence(entry), usesHashComments(entry.extension, entry.label));
    for (const call of findMatches(code, HELMET_CALL)) {
      const options = balancedParens(code, call.index + call.matchText.length - 1);
      if (options === undefined) continue;
      for (const protection of DISABLEABLE_PROTECTIONS) {
        if (!optionDisabled(options.inner, protection.option)) continue;
        if (protection.suppliedElsewhere.test(elsewhere)) continue;
        findings.push(
          makeFinding({
            ruleId: missingSecurityHeaders.id,
            title: `Security header turned off: ${protection.header}`,
            severity: protection.option === 'contentSecurityPolicy' ? 'medium' : 'low',
            confidence: 'high',
            filePath: entry.path,
            lineStart: call.line,
            evidence: `${lineAt(entry.content, call.line)} (helmet ${protection.option}: false, and no ${protection.header} set anywhere else)`,
            userExplanation:
              `Your app uses helmet but switches ${protection.header} off, and nothing else sets that header. With it off, ${protection.risk}.`,
            technicalExplanation:
              `${entry.path}:${call.line} calls helmet with ${protection.option}: false and no ${protection.header} is configured anywhere else in the project. Re-enable it, or set the header explicitly with a policy tailored to this app.`,
            fixHint:
              protection.option === 'contentSecurityPolicy'
                ? "Re-enable helmet's contentSecurityPolicy with directives tailored to what this app actually loads, and roll it out with Content-Security-Policy-Report-Only first — the default policy blocks inline scripts, inline styles and third-party embeds, which is why it was turned off in the first place."
                : `Remove the \`${protection.option}: false\` from the helmet options, or set ${protection.header} explicitly if this app needs a different value from helmet's default.`,
            category: missingSecurityHeaders.category,
          }),
        );
      }
    }
  }

  if (!isExpress) return findings;
  const allCode = entries.map((entry) =>
    stripCommentsOnly(creditEvidence(entry), usesHashComments(entry.extension, entry.label)),
  );
  const helmetCovers = allCode.some((code) => HELMET_CALL_TEST.test(code)) && !allCode.some((code) => POWERED_BY_RE_ENABLED.test(code));
  const disabled = allCode.some((code) => POWERED_BY_DISABLED.test(code) && !POWERED_BY_RE_ENABLED.test(code));
  if (helmetCovers || disabled) return findings;
  const appIndex = allCode.findIndex((code) => EXPRESS_APP.test(code));
  if (appIndex === -1) return findings;
  const anchor = entries[appIndex];
  if (anchor === undefined) return findings;
  const appLine = findMatches(allCode[appIndex] ?? '', new RegExp(EXPRESS_APP.source, 'g'))[0]?.line ?? 1;
  findings.push(
    makeFinding({
      ruleId: missingSecurityHeaders.id,
      title: 'Server advertises its framework in X-Powered-By',
      severity: 'low',
      confidence: 'high',
      filePath: anchor.path,
      lineStart: appLine,
      evidence: `${lineAt(anchor.content, appLine)} (no app.disable('x-powered-by') and no helmet hidePoweredBy)`,
      userExplanation:
        'Every response tells the world it is served by Express. That does not break anything on its own, but it hands an attacker the one fact that decides which published vulnerabilities are worth trying against you. One line removes it.',
      technicalExplanation: `${anchor.path}:${appLine} creates an Express app and the project never calls app.disable('x-powered-by'), nor does it get helmet's hidePoweredBy. Express sends X-Powered-By: Express on every response.`,
      fixHint:
        "Add app.disable('x-powered-by') immediately after creating the app, or use helmet(), whose defaults remove the header for you.",
      category: missingSecurityHeaders.category,
    }),
  );
  return findings;
}
