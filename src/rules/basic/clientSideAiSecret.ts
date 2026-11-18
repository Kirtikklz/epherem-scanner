import { makeFinding } from '../../shared/findingFactory.js';
import type { Finding, RuleContext, ScanRule } from '../../shared/types.js';
import { findMatches, redactSecret } from '../../shared/utils.js';
import { isInsideComment } from '../../shared/liveCode.js';
import { stripCommentsAndStrings } from '../../shared/source.js';
import { isClientExposedAiSecret } from '../../shared/clientAiSecret.js';
import { SECRET_PATTERNS, type SecretPattern } from './hardcodedSecret.js';

function aiProviderPatterns(): SecretPattern[] {
  const tagged = SECRET_PATTERNS.filter((pattern) => pattern.aiProvider === true);
  return [...tagged].sort((a, b) => prefixOf(b).length - prefixOf(a).length);
}

function prefixOf(pattern: SecretPattern): string {
  const source = pattern.pattern.source.replace('(?<![A-Za-z0-9_-])', '');
  const head = /^[A-Za-z0-9_-]+/.exec(source);
  return head?.[0] ?? '';
}

const DANGEROUSLY_ALLOW_BROWSER = /["']?\bdangerouslyAllowBrowser["']?\s*[:=]\s*true\b/g;

const CLIENT_CODE_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.html']);

export const clientSideAiSecret: ScanRule = {
  id: 'client_side_ai_secret',
  title: 'AI provider secret is exposed to the browser',
  category: 'secrets',
  kind: 'basic',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const clientFiles = new Set(context.projectMap.publicClientUsage);
    const patterns = aiProviderPatterns();

    for (const entry of context.fileMap.entries) {
      if (entry.label === 'env') continue;
      if (!CLIENT_CODE_EXTENSIONS.has(entry.extension)) continue;

      let stripped: string | undefined;
      for (const match of findMatches(entry.content, DANGEROUSLY_ALLOW_BROWSER)) {
        if (isInsideComment(entry.content, match.index, entry.extension, entry.label)) continue;
        stripped ??= stripCommentsAndStrings(entry.content);
        const trueIndex = match.index + match.matchText.lastIndexOf('true');
        if (stripped[trueIndex] !== entry.content[trueIndex]) continue;
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: 'AI provider client enabled in the browser: dangerouslyAllowBrowser',
            severity: 'critical',
            confidence: 'high',
            filePath: entry.path,
            lineStart: match.line,
            evidence: match.snippet,
            userExplanation:
              'This code turns off the safety check that stops an AI provider\'s SDK from running in the browser. The SDK refuses by default because your API key has to travel with the request, and anything the browser has, every visitor has. If this client is given a real key, whoever finds it can spend your account. Move these calls to a server route and let the browser talk to that instead.',
            technicalExplanation:
              `${entry.path}:${match.line} constructs an AI SDK client with dangerouslyAllowBrowser: true. The flag exists solely to bypass the SDK's browser guard, which is there because the API key is sent as a bearer credential from wherever the client runs. In a browser the key is readable in the bundle and in every network request. Proxy the provider through a server-side endpoint that holds the key and applies your own authentication and rate limits.`,
            fixHint:
              'Delete dangerouslyAllowBrowser and move the AI client into a server-side API route, server action, or edge function that reads the key from server-only environment configuration. Have the browser call that endpoint, and add your own authentication and rate limiting to it. If the key was ever shipped in a deployed build, rotate it with the provider as well.',
            category: this.category,
          }),
        );
      }

      if (!clientFiles.has(entry.path)) continue;

      const reportedOnLine = new Set<string>();

      for (const secretPattern of patterns) {
        for (const match of findMatches(entry.content, secretPattern.pattern)) {
          const secretValue = match.groups[0] ?? match.matchText;
          const literal = `${match.line}:${secretValue}`;
          if (reportedOnLine.has(literal)) continue;
          const valueOffset = match.matchText.indexOf(secretValue);
          const valueIndex = match.index + (valueOffset === -1 ? 0 : valueOffset);
          if (
            !isClientExposedAiSecret({
              content: entry.content,
              valueIndex,
              value: secretValue,
              clientReachable: true,
            })
          ) {
            continue;
          }
          reportedOnLine.add(literal);
          findings.push(
            makeFinding({
              ruleId: this.id,
              title: `${this.title}: ${secretPattern.name}`,
              severity: 'critical',
              confidence: 'high',
              filePath: entry.path,
              lineStart: match.line,
              evidence: redactSecret(secretValue),
              userExplanation:
                `A ${secretPattern.name} is written into a file that is sent to the browser, so it is not hidden from anyone — every visitor can read it out of the page and spend your account with it. Treat it as already public: rotate it with the provider now, then keep the new one on the server and have the browser call your own endpoint.`,
              technicalExplanation:
                `${entry.path}:${match.line} contains a ${secretPattern.name} literal, and this module is inside the client bundle's import closure (project-map publicClientUsage). Bundled source is served verbatim to every visitor, so the credential is disclosed regardless of whether the code path runs. Rotate the key, remove the literal, and call the provider only from server-side code.`,
              fixHint:
                `Rotate this ${secretPattern.name} in the provider's dashboard immediately — assume it is compromised. Delete the literal, move the provider call into a server-side API route or server action that reads the new key from server-only environment configuration, and have this component call that endpoint.`,
              category: this.category,
            }),
          );
        }
      }
    }
    return findings;
  },
};
