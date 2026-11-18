export type SensitiveTier = 'critical' | 'high';

export type SensitiveKind = 'column' | 'expression';

export interface SensitiveClassification {
  sensitive: boolean;
  category: string | undefined;
  tier: SensitiveTier | undefined;
}

export interface SensitiveContext {
  kind?: SensitiveKind;
  scope?: readonly string[];
}

export interface SensitiveColumnMatch {
  critical: string[];
  high: string[];
}

interface Category {
  label: string;
  test: RegExp;
}

const CRITICAL: Category[] = [
  { label: 'location', test: /(^|_)(lat|lng|latitude|longitude|geo|coordinates?|location|geolocation)($|_)/i },
  { label: 'date of birth', test: /(^|_)(dob|date_of_birth|birth_?date|birthday|born_on)($|_)/i },
  { label: 'phone', test: /(^|_)(phone|phone_?number|mobile|mobile_?number|msisdn|whatsapp)($|_)/i },
  { label: 'national id', test: /(^|_)(ssn|social_?security|national_?id|passport|passport_?number|drivers?_?licen[cs]e|tax_?id|nino|aadhaar)($|_)/i },
  { label: 'credential', test: /(^|_)(password|passwd|pwd|password_?hash|pass_?hash|secret|api_?key|apikey|token|access_?token|refresh_?token|auth_?token|session_?token|private_?key|client_?secret)($|_)|(^|_)hash($|_)/i },
  { label: 'one-time secret', test: /(^|_)(otp|one_?time_?(code|password|token)|verification_?code|confirmation_?code|reset_?code|reset_?token|invite_?code|invitation_?code|magic_?link|nonce|challenge)($|_)/i },
  { label: 'protected characteristic', test: /(^|_)(religion|religious|ethnicity|ethnic_?origin|race|nationality|citizenship|gender|sexual_?orientation|political_?(view|affiliation)s?)($|_)/i },
  { label: 'financial', test: /(^|_)(card_?number|card_?no|cc_?number|cvv|cvc|iban|bank_?account|account_?number|routing_?number|sort_?code|stripe_?(customer|account|secret)|salary|income|net_?worth|balance)($|_)|(^|_)(card|bank)_/i },
  { label: 'medical', test: /(^|_)(medical|diagnosis|health|blood_?type|prescription|disability|condition|allerg(y|ies))($|_)/i },
  { label: 'credential', test: /(^|_)(senha|contrasena|contrase\u00f1a|clave|palavra_?passe)($|_)/i },
  { label: 'national id', test: /(^|_)(cpf|cnpj|\brg\b|dni|nie|nif|curp|rfc|documento|numero_?documento|passaporte|pasaporte)($|_)/i },
  { label: 'phone', test: /(^|_)(telefone|telefono|tel\u00e9fono|celular|movil|m\u00f3vil|whatsapp_?numero)($|_)/i },
  { label: 'date of birth', test: /(^|_)(data_?nascimento|nascimento|fecha_?nacimiento|nacimiento|aniversario)($|_)/i },
  { label: 'financial', test: /(^|_)(salario|sal\u00e1rio|renda|patrimonio|patrim\u00f3nio|saldo|conta_?bancaria|cartao|cart\u00e3o|tarjeta)($|_)/i },
  { label: 'medical', test: /(^|_)(saude|sa\u00fade|salud|diagnostico|diagn\u00f3stico|prontuario|prontu\u00e1rio|alergia|alergias)($|_)/i },
];

const HIGH: Category[] = [
  { label: 'email', test: /(^|_)(email|e_?mail|email_?address)($|_)/i },
  { label: 'postal address', test: /(^|_)(address|street|street_?address|postcode|post_?code|zip|zip_?code|postal_?code)($|_)/i },
  { label: 'ip address', test: /(^|_)(ip|ip_?address|client_?ip|remote_?ip)($|_)/i },
  // Full or legal names only: first and last names alone are too common.
  { label: 'name', test: /(^|_)(full_?name|legal_?name|maiden_?name)($|_)/i },
  // Words for published content (titles, bodies) are deliberately left out.
  { label: 'free text', test: /(^|_)(notes?|remarks?|feedback|message_?body|internal_?note|private_?note|admin_?note)($|_)/i },
  { label: 'authorization', test: /(^|_)(is_?admin|is_?staff|is_?superuser|is_?owner|role|roles|permissions?|scopes?|privileges?|access_?level)($|_)/i },
  { label: 'name', test: /(^|_)(nome|nombre)$|(^|_)(nome_?completo|nombre_?completo|sobrenome|apellidos?|razao_?social)($|_)/i },
  { label: 'postal address', test: /(^|_)(endereco|endere\u00e7o|direccion|direcci\u00f3n|morada|cep|codigo_?postal|c\u00f3digo_?postal|bairro|logradouro)($|_)/i },
  { label: 'email', test: /(^|_)(correo|correo_?electronico|corrreo)($|_)/i },
  { label: 'occupation', test: /(^|_)(profissao|profiss\u00e3o|profesion|profesi\u00f3n|ocupacao|ocupa\u00e7\u00e3o|ocupacion|cargo)($|_)/i },
  { label: 'free text', test: /(^|_)(dados|datos|observacoes|observa\u00e7\u00f5es|observaciones|anotacoes|anota\u00e7\u00f5es|comentarios_?internos)($|_)/i },
];


export function classifySensitiveColumns(columns: readonly string[]): SensitiveColumnMatch {
  const critical: string[] = [];
  const high: string[] = [];
  for (const column of columns) {
    if (CRITICAL.some((c) => c.test.test(column))) critical.push(column);
    else if (HIGH.some((c) => c.test.test(column))) high.push(column);
  }
  return { critical: [...new Set(critical)].sort(), high: [...new Set(high)].sort() };
}

export function sensitiveCategories(columns: readonly string[]): string[] {
  const labels = new Set<string>();
  for (const column of columns) {
    for (const c of [...CRITICAL, ...HIGH]) if (c.test.test(column)) labels.add(c.label);
  }
  return [...labels].sort();
}

const DERIVED_OR_SCALAR_ACCESSOR =
  /\.\s*(?:id|length|count|size|name|type|status|page|index|slug|createdAt|updatedAt|expiresAt)\s*$/;

export function nameIsBooleanFlag(name: string): boolean {
  return /^(?:has|is|was|should|can|had|include[sd]?|with|without|require[sd]?)[_A-Z]/.test(name);
}

export function isDerivedOrScalarAccessor(expression: string): boolean {
  return DERIVED_OR_SCALAR_ACCESSOR.test(expression);
}

const VALUE_IS_A_BOOLEAN =
  /^(?:!!|Boolean\s*\(|!\s*!|typeof\s)|^[A-Za-z_$][\w$.]*\s*(?:!==|===|!=|==)\s*(?:null|undefined|''|""|0)$|^(?:true|false)$|^[A-Za-z_$][\w$.]*\s*(?:!==|===)\s*(?:null|undefined)$/;

const VALUE_IS_A_REDACTION =
  /^['"`]?(?:\[?(?:REDACTED|redacted|HIDDEN|hidden|MASKED|masked|FILTERED|filtered|SENSITIVE|sensitive|SET|set|PRESENT|present|omitted|OMITTED)\]?|\*{2,}|x{3,}|X{3,}|•{2,}|\.{3,}|<[^>]*>|-{3,})['"`]?$/;

const VALUE_IS_A_DERIVATION =
  /\.(?:length|size|count)\s*$|\.slice\s*\(\s*-?\d+|\.substring\s*\(|\.substr\s*\(|^Object\.keys\s*\(|\bmask\w*\s*\(|\bredact\w*\s*\(|\bobfuscate\w*\s*\(/;

const VALUE_IS_EMPTY = /^['"`]?\s*['"`]?$/;

export function valueProvesNotSensitive(value: string | undefined): boolean {
  if (value === undefined) return false;
  const trimmed = value.trim();
  if (trimmed === '') return true;
  return (
    VALUE_IS_EMPTY.test(trimmed) ||
    VALUE_IS_A_BOOLEAN.test(trimmed) ||
    VALUE_IS_A_REDACTION.test(trimmed) ||
    VALUE_IS_A_DERIVATION.test(trimmed)
  );
}

export function classifySensitive(
  name: string,
  value?: string,
  context?: SensitiveContext,
): SensitiveClassification {
  const NOT_SENSITIVE: SensitiveClassification = {
    sensitive: false,
    category: undefined,
    tier: undefined,
  };
  if (name === '') return NOT_SENSITIVE;

  if (valueProvesNotSensitive(value)) return NOT_SENSITIVE;

  const kind = context?.kind ?? 'column';

  if (kind === 'expression') {
    if (isDerivedOrScalarAccessor(name)) return NOT_SENSITIVE;
    if (nameIsBooleanFlag(name)) return NOT_SENSITIVE;
  }

  const scope = context?.scope;
  const inScope = (label: string): boolean => scope === undefined || scope.includes(label);
  for (const category of CRITICAL) {
    if (inScope(category.label) && category.test.test(name)) {
      return { sensitive: true, category: category.label, tier: 'critical' };
    }
  }
  for (const category of HIGH) {
    if (inScope(category.label) && category.test.test(name)) {
      return { sensitive: true, category: category.label, tier: 'high' };
    }
  }
  return NOT_SENSITIVE;
}

export const LOG_SENSITIVE_VALUE =
  /\b(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization|auth[_-]?token|access[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key|ssn|credit[_-]?card|card[_-]?number|cvv)\b/i;

export const LOG_SENSITIVE_IN_TEMPLATE =
  /\b(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization|access[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key|cookie|session)\b/i;

export const LOG_SAFE_SCALAR_PROP = DERIVED_OR_SCALAR_ACCESSOR;

export const RESERVED_HOST =
  /(?:^|[@/.])(?:example\.(?:com|org|net)|localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(?:[:/]|$)|\.(?:test|invalid|localhost|example)(?:[:/]|$)/i;

export const TRIVIAL_NUMERIC = /^[0-9]{1,8}[;,]?$/;

export const PLACEHOLDER_PREFIX =
  /^(?:your|placeholder|change_?me|xxx|<|example|dummy|sample|todo|fixme|replace|insert|redacted|test|fake|fixture|none|null|undefined)(?:[^A-Za-z0-9]|$)/i;

export const REPEATED_BODY = /^[A-Za-z0-9_-]{0,12}?([A-Za-z0-9])\1{7,}[A-Za-z0-9_-]{0,4}$/;

export function valueEchoesKey(key: string, value: string): boolean {
  const flatten = (text: string): string => text.toLowerCase().replace(/[^a-z0-9]/g, '');
  const k = flatten(key);
  const v = flatten(value);
  return v.length >= 3 && k.length >= 3 && (k.includes(v) || v.includes(k));
}

export function isPlaceholderEnvValue(key: string, value: string): boolean {
  return (
    value === '' ||
    PLACEHOLDER_PREFIX.test(value) ||
    TRIVIAL_NUMERIC.test(value) ||
    REPEATED_BODY.test(value) ||
    RESERVED_HOST.test(value) ||
    valueEchoesKey(key, value)
  );
}

export const MASS_ASSIGNMENT_TARGET_OBJECTS = ['user', 'account', 'profile', 'record', 'model'] as const;
