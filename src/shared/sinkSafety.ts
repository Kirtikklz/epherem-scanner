export const SCHEMA_VALIDATION =
  /\bz\s*\.\s*(?:object|string|number|boolean|array|coerce|enum|record|union|discriminatedUnion)\b|\b(?:Joi|yup)\s*\.\s*(?:object|string|number|boolean|array)\b|\.\s*(?:parse|safeParse|validateAsync|validate|cast)\s*\(/;

const SCALAR_FORCING_RHS =
  /\bz\s*\.\s*(?:coerce\s*\.\s*)?(?:string|number|boolean|bigint|date|enum|nativeEnum|literal)\b|\b(?:Joi|yup)\s*\.\s*(?:string|number|boolean|date)\b|^\s*(?:await\s+)?(?:String|Number|Boolean|BigInt|parseInt|parseFloat)\s*\(|\.\s*(?:toString|toLowerCase|toUpperCase|trim|normalizeEmail|toHexString)\s*\(/;

const TYPED_OBJECT_SCHEMA_RHS = /\bz\s*\.\s*object\s*\(/;
const OBJECT_SCHEMA_ESCAPE = /\.\s*(?:passthrough|catchall|and|merge)\s*\(/;
const RECORD_SCHEMA = /\bz\s*\.\s*record\s*\(/;

const SCALAR_ONLY_REQUEST_RHS =
  /^\s*(?:await\s+)?\(?\s*(?:await\s+)?params\s*\)?\s*(?:\?\.|\.)\s*[A-Za-z_$][\w$]*\s*$|\bsearchParams\s*(?:\?\.|\.)\s*get\s*\(/;

const PARAMS_AS_FUNCTION_PARAMETER =
  /\(\s*(?:[A-Za-z_$][\w$]*\s*(?::[^,()]+)?\s*,\s*)?\{\s*params\s*[},:]/;

const PARAMS_REBOUND_FROM_REQUEST =
  /\b(?:const|let|var)\s+params\s*(?::[^=\n]+)?=\s*[^\n;]*\breq(?:uest)?\s*(?:\?\.|\.)\s*(?:body|query|json|text|formData|headers|cookies)\b/;

function fileHasNextRouteParams(content: string): boolean {
  return PARAMS_AS_FUNCTION_PARAMETER.test(content) && !PARAMS_REBOUND_FROM_REQUEST.test(content);
}

export function rhsIsGuaranteedScalarSource(rhs: string, allowParams: boolean): boolean {
  const value = rhs.trim();
  if (/\bsearchParams\s*(?:\?\.|\.)\s*get\s*\(/.test(value)) return true;
  if (!allowParams) return false;
  return SCALAR_ONLY_REQUEST_RHS.test(value);
}

const DECLARATION =
  /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*([^\n;]+)/g;

const PARAMS_DESTRUCTURE =
  /\b(?:const|let|var)\s+\{([^{}]*)\}\s*=\s*(?:await\s+)?\(?\s*(?:await\s+)?params\s*\)?\s*[;\n]/g;

function flatPatternNames(inner: string): string[] {
  const names: string[] = [];
  for (const rawPart of inner.split(',')) {
    const part = rawPart.trim();
    if (part === '' || part.startsWith('...')) continue;
    const aliased = /^[A-Za-z_$][\w$]*\s*:\s*([A-Za-z_$][\w$]*)/.exec(part);
    if (aliased?.[1] !== undefined) {
      names.push(aliased[1]);
      continue;
    }
    const bare = /^([A-Za-z_$][\w$]*)/.exec(part);
    if (bare?.[1] !== undefined) names.push(bare[1]);
  }
  return names;
}

export function rhsForcesScalar(rhs: string): boolean {
  if (/\bz\s*\.\s*(?:object|array|record|tuple|map|set)\s*\(/.test(rhs)) return false;
  return SCALAR_FORCING_RHS.test(rhs);
}

export function rhsIsTypedObjectSchema(rhs: string): boolean {
  return TYPED_OBJECT_SCHEMA_RHS.test(rhs) && !OBJECT_SCHEMA_ESCAPE.test(rhs) && !RECORD_SCHEMA.test(rhs);
}

export interface ScalarSafeLocals {
  scalar: Set<string>;
  typedObject: Set<string>;
  scalarSources: RegExp[];
}

export function scalarSafeLocals(content: string): ScalarSafeLocals {
  const scalar = new Set<string>();
  const typedObject = new Set<string>();
  const allowParams = fileHasNextRouteParams(content);

  DECLARATION.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = DECLARATION.exec(content)) !== null) {
    const name = match[1];
    const rhs = match[2];
    if (name === undefined || rhs === undefined) continue;
    if (rhsForcesScalar(rhs)) scalar.add(name);
    else if (rhsIsTypedObjectSchema(rhs)) typedObject.add(name);
    else if (rhsIsGuaranteedScalarSource(rhs, allowParams)) scalar.add(name);
  }

  if (allowParams) {
    PARAMS_DESTRUCTURE.lastIndex = 0;
    let pattern: RegExpExecArray | null;
    while ((pattern = PARAMS_DESTRUCTURE.exec(content)) !== null) {
      const inner = pattern[1];
      if (inner === undefined) continue;
      for (const name of flatPatternNames(inner)) scalar.add(name);
    }
  }

  const scalarSources: RegExp[] = [/\bsearchParams\s*(?:\?\.|\.)\s*get\s*\([^)]*\)/g];
  if (allowParams) scalarSources.push(/\bparams\s*(?:\?\.|\.)\s*[A-Za-z_$][\w$]*/g);
  return { scalar, typedObject, scalarSources };
}
