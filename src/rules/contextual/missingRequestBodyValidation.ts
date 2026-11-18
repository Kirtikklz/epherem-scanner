import { makeFinding } from '../../shared/findingFactory.js';
import type { Confidence, Finding, RuleContext, ScanRule } from '../../shared/types.js';
import { findMatches } from '../../shared/utils.js';
import { routeHandlerScope, routeHandlerScopeForLine } from '../../shared/handlerScope.js';
import { WEBHOOK_SIGNATURE_VERIFIED } from '../../shared/webhookSignature.js';
import { projectUsesMongo } from '../../shared/dataStores.js';
import {
  DANGEROUS_SINK_WORDING,
  manualControlWithoutDangerousSink,
  type DangerousSinkReason,
} from '../../shared/requestBodyControl.js';
import { routeControlProven } from '../../shared/routeControlModel.js';

const CODE = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py']);
const BODY_USE = /\b(?:req\.body|request\.(?:json\s*\(|form|data)|await\s+request\.json\s*\(|Body\s*\()/;
const VALIDATION =
  /(?:\bvalidate\w*\s*\(|\b\w*schema\w*\.(?:parse|safeParse|validate)\s*\(|\.safeParse\s*\(|\.parseAsync\s*\(|\.validateAsync\s*\(|\bajv\.compile\s*\(|\bz\.(?:object|string|number|boolean|array|enum|union|discriminatedUnion|record|tuple|literal|coerce|intersection|instanceof)\s*\(|\bzodResolver\s*\(|\b(?:yup|joi|Joi|valibot)\.(?:object|string|number)\s*\(|\b(?:pydantic|BaseModel|marshmallow|serializer\.is_valid)\b)/i;
const MANUAL_VALIDATION =
  /\btypeof\s+[^;\n{]*\b(?:req|request|body|payload|params|input)\b|\bNumber\.(?:isInteger|isFinite|isNaN|isSafeInteger)\s*\(|\bArray\.isArray\s*\(|(?:res|response)\.status\s*\(\s*4\d\d\s*\)|\bstatus\s*:\s*4\d\d\b|\.length\s*(?:>=|<=|>|<|===|!==)|\b\w*(?:isValid\w*|isAllowed\w*|is[A-Z]\w*Id|validate\w*|assert\w*)\s*\(|\.(?:includes|has)\s*\(|\benum\b|\.trim\s*\(\s*\)\s*(?:\.length|===|!==)/i;
const MUTATION = /\b(?:post|put|patch|delete)\b/i;

type BodyValidationCase =
  | { readonly kind: 'unchecked' }
  | { readonly kind: 'unconfirmed' }
  | {
      readonly kind: 'checked-but-sink';
      readonly credit: 'guard' | 'field-helper';
      readonly sinks: readonly DangerousSinkReason[];
    };

function bodyValidationCase(
  control: ReturnType<typeof manualControlWithoutDangerousSink> | undefined,
  checkShaped: boolean,
): BodyValidationCase {
  if (control !== undefined && control.credit !== 'none' && control.sinks.length > 0) {
    return { kind: 'checked-but-sink', credit: control.credit, sinks: control.sinks };
  }
  return checkShaped ? { kind: 'unconfirmed' } : { kind: 'unchecked' };
}

function listed(phrases: readonly string[]): string {
  if (phrases.length <= 1) return phrases[0] ?? '';
  return `${phrases.slice(0, -1).join(', ')} and ${phrases[phrases.length - 1]}`;
}

function bodyValidationEvidence(route: string, found: BodyValidationCase): string {
  switch (found.kind) {
    case 'unchecked':
      return `${route} uses request-body data without validation in its invoked call path`;
    case 'unconfirmed':
      return `${route} uses request-body data with no schema validator, and no check covering the submitted fields was confirmed in its invoked call path`;
    case 'checked-but-sink': {
      const plain = [...new Set(found.sinks.map((sink) => DANGEROUS_SINK_WORDING[sink].plain))];
      return `${route} checks the request body by hand, but ${listed(plain)} in its invoked call path`;
    }
  }
}

const CREDITED_AS: Readonly<Record<'guard' | 'field-helper', string>> = {
  guard: 'a guard in the handler tests a body field and rejects the request when it fails',
  'field-helper': 'its fields pass through a helper that tests them and refuses bad values',
};

function bodyValidationExplanation(subject: string, found: BodyValidationCase, unchecked: string): string {
  switch (found.kind) {
    case 'unchecked':
      return unchecked;
    case 'unconfirmed':
      return `${subject} consumes a request body with no schema parser. Code shaped like a check is present in the handler (a typeof, length or allowlist test, a validate or assert call, or a 4xx response), but none was confirmed to test a submitted field and reject the request when it fails: it may belong to something else, such as a not-found error mapped to a 404. Confirm every field is checked before trusting the body.`;
    case 'checked-but-sink':
      return `${subject} consumes a request body with no schema parser. It is checked by hand (${CREDITED_AS[found.credit]}), but ${listed(found.sinks.map((sink) => DANGEROUS_SINK_WORDING[sink].technical))}. A hand check proves only what it tests: it does not stop unexpected fields or values reaching that point, and a strict schema at the route boundary does.`;
  }
}

export const missingRequestBodyValidation: ScanRule = {
  id: 'missing_request_body_validation',
  title: 'Request body is used without schema validation',
  category: 'injection',
  kind: 'contextual',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const sinkOptions = { mongo: projectUsesMongo(context) };
    const profiledFiles = new Set<string>();
    for (const profile of context.projectMap.routeSecurityProfiles ?? []) {
      if (profile.analysisStatus !== 'complete') continue;
      profiledFiles.add(profile.filePath);
      if (profile.inputValidation.status !== 'absent') continue;
      const profileEntry = context.fileMap.entries.find((candidate) => candidate.path === profile.filePath);
      const profileScope =
        profileEntry !== undefined ? routeHandlerScopeForLine(profileEntry.content, profile.line) : '';
      if (WEBHOOK_SIGNATURE_VERIFIED.test(profileScope)) continue;
      if (routeControlProven(context, profile.filePath, profile.line, 'validation')) continue;
      if (VALIDATION.test(profileScope)) continue;
      const control =
        profileEntry !== undefined
          ? manualControlWithoutDangerousSink(profileScope, sinkOptions, {
            resolution: context,
            filePath: profile.filePath,
          })
          : undefined;
      if (control?.suppress === true) continue;
      const manuallyValidated = profileEntry !== undefined && MANUAL_VALIDATION.test(profileScope);
      const confidence: Confidence = manuallyValidated ? 'low' : 'high';
      const found = bodyValidationCase(control, manuallyValidated);
      const route = `${profile.method} ${profile.routePath}`;
      findings.push(makeFinding({
        ruleId: this.id,
        title: this.title,
        severity: 'medium',
        confidence,
        detectionKind: 'absence',
        filePath: profile.filePath,
        lineStart: profile.line,
        evidence: bodyValidationEvidence(route, found),
        userExplanation: 'This API endpoint uses submitted data without visible schema validation. Unexpected fields, types, or oversized values can reach sensitive application logic.',
        technicalExplanation: bodyValidationExplanation(
          route,
          found,
          `${route} consumes a request body, but its route-level call graph contains no recognized schema parser or validator.`,
        ),
        fixHint: 'Validate the complete body with a strict schema at the route boundary, reject unknown fields, enforce type/length/range limits, and use only the parsed result.',
        category: this.category,
      }));
    }
    for (const entry of context.fileMap.entries) {
      if (!CODE.has(entry.extension) || !entry.isLikelyApiRoute) continue;
      if (profiledFiles.has(entry.path)) continue;
      if (!BODY_USE.test(entry.content)) continue;
      const route = context.projectMap.apiRoutes.find((candidate) => candidate.filePath === entry.path);
      if (route !== undefined && !route.methods.some((method) => MUTATION.test(method))) continue;
      const candidate = findMatches(entry.content, /\b(?:req\.body|request\.(?:json|form|data)|await\s+request\.json\s*\(|Body\s*\()/g)
        .find((hit) => {
          const scope = routeHandlerScope(entry.content, hit.index);
          return !VALIDATION.test(scope) && !WEBHOOK_SIGNATURE_VERIFIED.test(scope);
        });
      if (candidate === undefined) continue;
      if (routeControlProven(context, entry.path, candidate.line, 'validation')) continue;
      const candidateScope = routeHandlerScope(entry.content, candidate.index);
      const control = manualControlWithoutDangerousSink(candidateScope, sinkOptions, {
        resolution: context,
        filePath: entry.path,
      });
      if (control.suppress) continue;
      const manuallyValidated = MANUAL_VALIDATION.test(candidateScope);
      const found = bodyValidationCase(control, manuallyValidated);
      const at = `${entry.path}:${candidate.line}`;
      findings.push(makeFinding({
        ruleId: this.id,
        title: this.title,
        severity: 'medium',
        confidence: manuallyValidated ? 'low' : 'medium',
        detectionKind: 'absence',
        filePath: entry.path,
        lineStart: candidate.line,
        evidence: candidate.snippet,
        userExplanation: 'This API endpoint uses submitted data without visible schema validation. Unexpected fields, types, or oversized values can reach sensitive application logic.',
        technicalExplanation: bodyValidationExplanation(
          `${at}: a state-changing route`,
          found,
          `${at}: a state-changing route consumes a request body, but no recognized schema parser or validator was found in the handler file.`,
        ),
        fixHint: 'Validate the complete body with a strict schema at the route boundary, reject unknown fields, enforce type/length/range limits, and use only the parsed result.',
        category: this.category,
      }));
    }
    return findings;
  },
};
