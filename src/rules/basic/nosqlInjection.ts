import { makeFinding } from '../../shared/findingFactory.js';
import type { Finding, RuleContext, ScanRule } from '../../shared/types.js';
import { findMatches, lineAt } from '../../shared/utils.js';
import { analyzeTaint, usesUserInput, type TaintMap } from '../../shared/taint.js';
import { referencesUserInput } from '../../shared/userInput.js';
import { scalarSafeLocals, type ScalarSafeLocals } from '../../shared/sinkSafety.js';
import { projectUsesMongo } from '../../shared/dataStores.js';

const CODE = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);

const NOSQL_SINK =
  /(\w+)\s*\.\s*(find|findOne|updateOne|updateMany|deleteOne|deleteMany|countDocuments|aggregate)\s*\(/g;

const ARRAY_LIKE_RECEIVER =
  /^(?:arr|array|list|items|rows|entries|results|values|keys|matches|parts|lines|tokens|args|files|chars|elements|options|cookies|headers|segments|indexes|existingindexes|docs|records)$/i;

const DANGEROUS_OPERATOR = /\$where\s*:|\$function\s*:|\$accumulator\s*:|\$expr\s*:/;

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function firstCallArg(content: string, start: number): string {
  let depth = 1;
  const limit = Math.min(content.length, start + 2000);
  let end = limit;
  for (let i = start; i < limit; i += 1) {
    const char = content[i];
    if (char === '(' || char === '[' || char === '{') depth += 1;
    else if (char === ')' || char === ']' || char === '}') {
      depth -= 1;
      if (depth === 0) { end = i; break; }
    } else if (char === ',' && depth === 1) { end = i; break; }
  }
  return content.slice(start, end);
}

function argumentIsFunction(arg: string): boolean {
  const trimmed = arg.trimStart();
  return (
    /^(?:async\s+)?function\b/.test(trimmed) ||
    /^(?:async\s*)?\([^)]*\)\s*=>/.test(trimmed) ||
    /^(?:async\s+)?[A-Za-z_$][\w$]*\s*=>/.test(trimmed)
  );
}

function stripScalarForced(arg: string): string {
  return arg
    .replace(/\$(?:eq|in|nin|all|size)\s*:\s*(?:\[[^\]]*\]|[^,}\]]+)/g, ' ')
    .replace(/\b(?:String|Number|Boolean|ObjectId|parseInt|parseFloat|Date)\s*\([^)]*\)/g, ' ')
    .replace(
      /[\w.$?\[\]'"]+\s*\.\s*(?:toString|toLowerCase|toUpperCase|trim|normalizeEmail|toHexString|charAt|slice|substring|substr|padStart|padEnd)\s*\([^)]*\)/g,
      ' ',
    );
}

function classifyArg(
  arg: string,
  taint: TaintMap,
  safe: ScalarSafeLocals,
  at: number,
): 'critical' | 'high' | 'safe' {
  const bare = arg.trim();
  if (/^[A-Za-z_$][\w$]*$/.test(bare) && safe.typedObject.has(bare)) return 'safe';

  const hasRequestInput = referencesUserInput(arg) || usesUserInput(arg, taint, at);
  if (!hasRequestInput) return 'safe';

  if (DANGEROUS_OPERATOR.test(arg)) {
    const dangerous = /\$(?:where|function|accumulator|expr)\s*:\s*([^,}]+)/.exec(arg);
    if (dangerous && (referencesUserInput(dangerous[1] ?? '') || usesUserInput(dangerous[1] ?? '', taint, at))) {
      return 'critical';
    }
  }

  let residual = stripScalarForced(arg);
  for (const source of safe.scalarSources) residual = residual.replace(source, ' ');
  for (const name of safe.scalar) residual = residual.replace(new RegExp(`\\b${escapeRegExp(name)}\\b`, 'g'), ' ');
  for (const name of safe.typedObject) residual = residual.replace(new RegExp(`\\b${escapeRegExp(name)}\\b`, 'g'), ' ');
  if (referencesUserInput(residual) || usesUserInput(residual, taint, at)) return 'high';
  return 'safe';
}

export const nosqlInjection: ScanRule = {
  id: 'nosql_injection',
  title: 'Possible NoSQL injection from untrusted query object',
  category: 'injection',
  kind: 'basic',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    if (!projectUsesMongo(context)) return findings;

    for (const entry of context.fileMap.entries) {
      if (!CODE.has(entry.extension)) continue;
      const taint = analyzeTaint(entry.content);
      const safe = scalarSafeLocals(entry.content);
      for (const match of findMatches(entry.content, NOSQL_SINK)) {
        const receiver = match.groups[0] ?? '';
        if (ARRAY_LIKE_RECEIVER.test(receiver)) continue;

        const argStart = match.index + match.matchText.length;
        const arg = firstCallArg(entry.content, argStart);
        if (argumentIsFunction(arg)) continue;

        const verdict = classifyArg(arg, taint, safe, match.index);
        if (verdict === 'safe') continue;

        findings.push(
          makeFinding({
            ruleId: this.id,
            title: this.title,
            severity: verdict === 'critical' ? 'critical' : 'high',
            confidence: verdict === 'critical' ? 'high' : 'medium',
            filePath: entry.path,
            lineStart: match.line,
            evidence: lineAt(entry.content, match.line),
            userExplanation:
              verdict === 'critical'
                ? 'This query passes request input into a $where/$expr operator, which can execute attacker-controlled logic against the database. Never build these from user input.'
                : 'This database query uses a request value directly as a NoSQL filter. If it is an object, an attacker can smuggle operators such as $ne or $gt to change what the query matches. Force it to a scalar (e.g. wrap it in { $eq: value } or cast it) or validate it first.',
            technicalExplanation: `${entry.path}:${match.line} passes a raw request value into a Mongo query object without scalar-forcing ($eq/$in), a primitive cast, or schema validation.`,
            fixHint:
              'Coerce untrusted values to scalars before querying — wrap them as { $eq: value }, cast with String()/Number()/ObjectId(), or validate the request with a schema (zod/Joi) that rejects object values and keys starting with $.',
            category: this.category,
          }),
        );
      }
    }
    return findings;
  },
};
