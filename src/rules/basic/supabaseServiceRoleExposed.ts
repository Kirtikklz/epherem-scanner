import { makeFinding } from '../../shared/findingFactory.js';
import { svelteKitLoadReturnedPrivateEnv, svelteKitRouteKind } from '../../shared/frameworkModel.js';
import type { Finding, RuleContext, ScanRule } from '../../shared/types.js';
import { decodeJwtPayload, findMatches, redactSecret } from '../../shared/utils.js';
import { isSupabaseLocalDemoKey } from '../../shared/publicIdentifier.js';
import { insideRegion, jsxElementRegions, payloadRegions } from '../../shared/emittedValue.js';

const SERVICE_ROLE_ENV_REFERENCE = /(?:process\.env|import\.meta\.env)[.[]['"]?(\w*SERVICE_ROLE\w*)/g;
const PUBLIC_PREFIXED_SERVICE_ROLE =
  /(?<![A-Za-z0-9_])(?:NEXT_PUBLIC|PUBLIC|VITE|EXPO_PUBLIC|REACT_APP|NUXT_PUBLIC|GATSBY)_[A-Z0-9_]*SERVICE_ROLE[A-Z0-9_]*/g;
const JWT_PATTERN = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;

const PREFIX_ARM_EXTENSIONS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue', '.svelte', '.astro', '.json', '.yaml', '.yml', '.toml',
]);

const PUBLIC_PREFIXED_ASSIGNMENT =
  /(?<![A-Za-z0-9_])((?:NEXT_PUBLIC|PUBLIC|VITE|EXPO_PUBLIC|REACT_APP|NUXT_PUBLIC|GATSBY)_[A-Z0-9_]+)\s*[:=]\s*(?:process\.env|import\.meta\.env)[.[]['"]?(\w*SERVICE_ROLE\w*)/g;

const RESPONSE_EMITTER =
  /(?:\b(?:NextResponse|Response)\s*\.\s*json\s*\(|\b(?:res|reply)\s*\.\s*(?:json|send)\s*\(|\bResponse\s*\.\s*json\s*\()/g;

const EMITTED_VALUE_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);

export const supabaseServiceRoleExposed: ScanRule = {
  id: 'supabase_service_role_exposed',
  title: 'Supabase service role key exposed to the client',
  category: 'data_exposure',
  kind: 'basic',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const clientFiles = new Set(context.projectMap.publicClientUsage);

    for (const entry of context.fileMap.entries) {
      const publicPrefixLines = new Set<number>();
      const prefixArmApplies = entry.label !== 'env' && PREFIX_ARM_EXTENSIONS.has(entry.extension);
      for (const match of prefixArmApplies ? findMatches(entry.content, PUBLIC_PREFIXED_SERVICE_ROLE) : []) {
        publicPrefixLines.add(match.line);
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: this.title,
            severity: 'critical',
            confidence: 'high',
            filePath: entry.path,
            lineStart: match.line,
            evidence: match.snippet,
            userExplanation:
              'Your Supabase service role key is stored in a variable whose name marks it as public. That prefix tells the build tool to copy the value into the JavaScript every visitor downloads, so the key that bypasses all your database security ships to the browser no matter which file reads it. Rename the variable without the public prefix, move the code that uses it to the server, and rotate the key.',
            technicalExplanation:
              `${entry.path}:${match.line} binds a SERVICE_ROLE key to a build-time public prefix (NEXT_PUBLIC_/PUBLIC_/VITE_/EXPO_PUBLIC_ and similar). Bundlers inline these into the client build unconditionally, so the server/client module boundary does not contain it. The service role key bypasses RLS entirely.`,
            fixHint:
              'Rotate the service role key (Supabase dashboard > Settings > API), rename the environment variable to drop the public prefix, and read it only from a server-side API route or server action. Expose the anon/publishable key to the browser instead.',
            category: this.category,
          }),
        );
      }

      for (const match of prefixArmApplies ? findMatches(entry.content, PUBLIC_PREFIXED_ASSIGNMENT) : []) {
        if (publicPrefixLines.has(match.line)) continue;
        publicPrefixLines.add(match.line);
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: this.title,
            severity: 'critical',
            confidence: 'high',
            filePath: entry.path,
            lineStart: match.line,
            evidence: match.snippet,
            userExplanation:
              'Your Supabase service role key is being copied into a second setting whose name marks it as public. The build tool copies anything with that public prefix into the JavaScript every visitor downloads, so the key that bypasses all your database security ships to the browser — even though the original setting was named correctly. Remove this line, and rotate the key.',
            technicalExplanation:
              `${entry.path}:${match.line} assigns ${match.groups[1] ?? 'a SERVICE_ROLE variable'} to ${match.groups[0] ?? 'a build-time public name'}. Both identifiers are individually correct; the binding republishes the private value under a name bundlers inline into the client build, so the module boundary does not contain it. The service role key bypasses RLS entirely.`,
            fixHint:
              'Delete this binding. If the browser genuinely needs to call the privileged operation, put it behind a server route that reads the service role key itself and authorises the caller. Then rotate the service role key (Supabase dashboard > Settings > API).',
            category: this.category,
          }),
        );
      }

      const readsEmittedValues = EMITTED_VALUE_EXTENSIONS.has(entry.extension);

      const bodyRegions = readsEmittedValues ? payloadRegions(entry.content, RESPONSE_EMITTER) : [];
      const emittedLines = new Set<number>();
      for (const match of bodyRegions.length > 0 ? findMatches(entry.content, SERVICE_ROLE_ENV_REFERENCE) : []) {
        if (publicPrefixLines.has(match.line)) continue;
        if (insideRegion(bodyRegions, match.index) === undefined) continue;
        emittedLines.add(match.line);
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: this.title,
            severity: 'critical',
            confidence: 'high',
            filePath: entry.path,
            lineStart: match.line,
            evidence: match.snippet,
            userExplanation:
              'This endpoint sends your Supabase service role key back to whoever calls it. The file itself is server code, which is correct — but the key is inside the response, so anyone who can reach this URL can read the key that bypasses all your database security. Take it out of the response and rotate the key.',
            technicalExplanation:
              `${entry.path}:${match.line} reads a SERVICE_ROLE environment variable inside a response body. The module never reaches the browser; the VALUE does, to every caller of this endpoint. The service role key bypasses RLS entirely.`,
            fixHint:
              'Remove the service role key from the response payload. Do the privileged work inside this handler and return only its result; if the client needs a Supabase client, send the anon/publishable key instead. Then rotate the service role key in the Supabase dashboard.',
            category: this.category,
          }),
        );
      }

      const elementRegions = readsEmittedValues ? jsxElementRegions(entry.content) : [];
      for (const match of elementRegions.length > 0 ? findMatches(entry.content, SERVICE_ROLE_ENV_REFERENCE) : []) {
        if (publicPrefixLines.has(match.line) || emittedLines.has(match.line)) continue;
        const element = insideRegion(elementRegions, match.index);
        if (element === undefined) continue;
        const target = resolvedComponentPath(context, entry.path, element.name);
        if (target === undefined || !clientFiles.has(target)) continue;
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: this.title,
            severity: 'critical',
            confidence: 'high',
            filePath: entry.path,
            lineStart: match.line,
            evidence: match.snippet,
            userExplanation:
              `This page passes your Supabase service role key to <${element.name}>, which runs in the browser. React sends the values a browser component receives down to the visitor along with the page, so the key that bypasses all your database security is readable by anyone who opens this page. Fetch the data on the server and pass the result instead, then rotate the key.`,
            technicalExplanation:
              `${entry.path}:${match.line} passes a SERVICE_ROLE environment variable as a prop to ${element.name}, which resolves to ${target} — a module in the client closure. Props crossing into a "use client" component are serialised into the RSC payload, so the value ships even though this module does not. The service role key bypasses RLS entirely.`,
            fixHint:
              `Do the privileged Supabase work in this server component (or a server action) and pass ${element.name} only the data it renders. If it must talk to Supabase itself, give it the anon/publishable key and rely on RLS. Then rotate the service role key in the Supabase dashboard.`,
            category: this.category,
          }),
        );
      }

      const svelteRoute = svelteKitRouteKind(entry.path);
      if (svelteRoute !== undefined && svelteRoute.kind !== 'server') {
        for (const leak of svelteKitLoadReturnedPrivateEnv(entry.content, /SERVICE_ROLE/)) {
          findings.push(
            makeFinding({
              ruleId: this.id,
              title: this.title,
              severity: 'critical',
              confidence: 'high',
              filePath: entry.path,
              lineStart: leak.line,
              evidence: leak.name,
              userExplanation:
                'This page sends your Supabase service role key to the browser. The data a SvelteKit server `load` returns is embedded in the page every visitor receives, so the key that bypasses all your database security is public even though the file it is written in never runs in a browser. Return only the data the page needs, and rotate the key.',
              technicalExplanation:
                `${entry.path}:${leak.line} returns ${leak.name}, imported from $env/static/private, from a server \`load\`. A load function's return value is serialised into the page payload, so the service role key — which bypasses RLS — ships to the client. The module boundary is intact; the value crossed it.`,
              fixHint:
                'Remove the service role key from what `load` returns. Do the privileged work inside the server load (or a `+server.ts` endpoint) and return only its result; if the browser needs a Supabase client, give it the anon key from $env/static/public. Then rotate the service role key in the Supabase dashboard.',
              category: this.category,
            }),
          );
        }
      }

      if (!clientFiles.has(entry.path)) continue;

      for (const match of findMatches(entry.content, SERVICE_ROLE_ENV_REFERENCE)) {
        if (publicPrefixLines.has(match.line)) continue;
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: this.title,
            severity: 'critical',
            confidence: 'high',
            filePath: entry.path,
            lineStart: match.line,
            evidence: match.snippet,
            userExplanation:
              'A client-side file reads your Supabase service role key. Depending on how your app is built, a value read in client code can be written into the JavaScript sent to every visitor; if it is, the key that bypasses all your database security becomes public. Move this logic to a server-side API route.',
            technicalExplanation:
              `${entry.path}:${match.line} references a SERVICE_ROLE environment variable from a client-facing module. Depending on the framework and build configuration, referenced env vars can be inlined into the client build; the service role key bypasses RLS and must stay server-only.`,
            fixHint:
              'Move this database operation into a server-side API route or server action that reads the service role key, and have the client call that endpoint instead. Then rotate the key in the Supabase dashboard in case it already shipped.',
            category: this.category,
          }),
        );
      }

      for (const match of findMatches(entry.content, JWT_PATTERN)) {
        const payload = decodeJwtPayload(match.matchText);
        if (payload?.['role'] !== 'service_role') continue;
        if (isSupabaseLocalDemoKey(payload)) continue;
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: this.title,
            severity: 'critical',
            confidence: 'high',
            filePath: entry.path,
            lineStart: match.line,
            evidence: redactSecret(match.matchText),
            userExplanation:
              'A Supabase service role key is embedded in a file that ships to the browser. Every visitor can extract it and gain full database access. Rotate the key and move privileged operations to the server.',
            technicalExplanation:
              `A service_role JWT literal was found in client-facing file ${entry.path}:${match.line}. Rotate the key and restrict privileged Supabase clients to server-side code.`,
            fixHint:
              'Rotate the service role key immediately (Supabase dashboard > Settings > API), delete the literal from this file, and perform privileged operations only from server-side code that reads the key from environment configuration.',
            category: this.category,
          }),
        );
      }
    }
    return findings;
  },
};

function resolvedComponentPath(
  context: RuleContext,
  fromPath: string,
  elementName: string,
): string | undefined {
  const root = elementName.split('.')[0];
  if (root === undefined || root === '') return undefined;
  const fileImports = context.projectMap.imports.find((entry) => entry.filePath === fromPath);
  if (fileImports === undefined) return undefined;
  for (const importRef of fileImports.imports) {
    if (importRef.resolvedPath === undefined) continue;
    if (importRef.bindings?.includes(root) === true) return importRef.resolvedPath;
  }
  return undefined;
}
