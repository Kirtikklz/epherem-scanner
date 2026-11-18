import { makeFinding } from '../../shared/findingFactory.js';
import { SENSITIVE_ENV_NAME_PATTERN } from '../../shared/constants.js';
import type { Finding, RuleContext, ScanRule } from '../../shared/types.js';
import { isPublicEnvName } from '../../shared/utils.js';
import { stripCommentsAndStrings } from '../../shared/source.js';
import { isInsideServerFunctionHandler } from '../../shared/serverFunctionBoundary.js';
import {
  clientBundleFramework,
  isEmbeddedInClientBundle,
  PUBLISHED_SECRET_NAME_PATTERN,
} from '../../shared/clientEnvExposure.js';
import { collectDependencies } from '../../stack-detection/collectDependencies.js';

export const envUsageWithoutServerBoundary: ScanRule = {
  id: 'env_usage_without_server_boundary',
  title: 'Server-only environment variable used in client-side code',
  category: 'data_exposure',
  kind: 'contextual',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const clientFiles = new Set(context.projectMap.publicClientUsage);
    const contentByPath = new Map(context.fileMap.entries.map((e) => [e.path, e.content]));
    const strippedLineCache = new Map<string, string[]>();
    const strippedLine = (filePath: string, line: number): string | undefined => {
      let lines = strippedLineCache.get(filePath);
      if (lines === undefined) {
        const content = contentByPath.get(filePath);
        if (content === undefined) return undefined;
        lines = stripCommentsAndStrings(content).split(/\r?\n/);
        strippedLineCache.set(filePath, lines);
      }
      return lines[line - 1];
    };

    const framework = clientBundleFramework(
      context.stack,
      new Set(collectDependencies(context.fileMap).map((dependency) => dependency.name)),
    );

    for (const usage of context.projectMap.envUsage) {
      if (!clientFiles.has(usage.filePath)) continue;
      if (!isEmbeddedInClientBundle(framework, usage.accessor ?? 'other', usage.name)) continue;
      const publishedByPrefix = isPublicEnvName(usage.name);
      if (publishedByPrefix) {
        if (!PUBLISHED_SECRET_NAME_PATTERN.test(usage.name)) continue;
      } else if (!SENSITIVE_ENV_NAME_PATTERN.test(usage.name)) {
        continue;
      }
      const line = strippedLine(usage.filePath, usage.line);
      if (line !== undefined && !line.includes(usage.name)) continue;
      const content = contentByPath.get(usage.filePath);
      if (content !== undefined && isInsideServerFunctionHandler(content, usage.line)) continue;

      findings.push(
        publishedByPrefix
          ? makeFinding({
              ruleId: this.id,
              title: 'Secret-looking environment variable published through a public prefix',
              severity: 'high',
              confidence: 'high',
              filePath: usage.filePath,
              lineStart: usage.line,
              evidence: `Reads ${usage.name} from a client-facing file`,
              userExplanation:
                `${usage.name} carries a public prefix, which tells the build tool to write its value into the JavaScript every visitor downloads. The rest of the name says it is a secret. If it really is one, it is already published: anyone can read it in the browser. Rotate it, and read it only from server-side code under a name with no public prefix.`,
              technicalExplanation:
                `${usage.filePath}:${usage.line} references ${usage.name} from a client-facing module. The public prefix puts this name on the framework's build-time substitution list, so the literal value is embedded in the shipped bundle by design. A credential-shaped name on that list is a published credential, not a boundary violation.`,
              fixHint:
                `Rotate this value with its provider. Rename the variable without the public prefix, read it only in a server API route, server action, or middleware, and have the client call that endpoint. If the value is genuinely safe to publish, rename it so the name does not claim to be a secret.`,
              category: this.category,
            })
          : makeFinding({
              ruleId: this.id,
              title: this.title,
              severity: 'high',
              confidence: 'high',
              filePath: usage.filePath,
              lineStart: usage.line,
              evidence: `Reads ${usage.name} from a client-facing file`,
              userExplanation:
                `The variable ${usage.name} looks like a server secret, but it is read in code that runs in the browser. Some build setups write these values into the JavaScript every visitor downloads, and this project's setup may be one of them, so the secret could be visible to anyone. Move this code to a server API route or middleware.`,
              technicalExplanation:
                `${usage.filePath}:${usage.line} references ${usage.name} without a public prefix from a client-facing module. Depending on the build configuration (a hand-rolled bundler, a process.env define, or a Node polyfill), the value can be embedded in the shipped bundle. Keep sensitive env reads behind a server boundary.`,
              fixHint:
                `Move the code that reads ${usage.name} into a server-side API route, server action, or middleware, and have the client call that endpoint. If the value is genuinely safe for browsers, rename it with a public prefix (e.g. NEXT_PUBLIC_) to make that explicit.`,
              category: this.category,
            }),
      );
    }
    return findings;
  },
};
