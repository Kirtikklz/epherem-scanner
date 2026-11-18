const REQ = '(?:req|request|ctx|context)';

const BODY_READ: readonly RegExp[] = [
  /\b(?:req|request)\s*\.\s*(?:body|file|files|rawBody|fields)\b/,
  /\b(?:ctx|context)\s*\.\s*(?:request\s*\.\s*(?:body|file|files|rawBody|fields)|input)\b/,
  /\b(?:req|request)\s*\.\s*(?:json|formData|text|arrayBuffer|blob)\s*\(/,
  new RegExp(`\\{[^}]*(?:\\bbody\\b|\\bfiles?\\b|\\brawBody\\b|\\bfields\\b|\\.\\.\\.)[^}]*\\}\\s*=\\s*${REQ}(?:\\s*\\.\\s*request)?\\b(?!\\s*\\.)`),
  /\b(?:multer|busboy|formidable|multiparty|fileUpload|IncomingForm)\b/,
  new RegExp(`\\b(?:req|request)\\s*\\.\\s*(?:pipe|on|read|setEncoding)\\s*\\(|\\bctx\\s*\\.\\s*req\\b`),
];

const REQ_FORWARDED = new RegExp(`[(,]\\s*${REQ}\\s*[,)]`);

const PARAM_LISTS = new RegExp(
  `(?:\\bfunction\\b[^(]*|\\basync\\s*)?\\(\\s*${REQ}\\b[^()]*\\)\\s*(?::[^{=]*)?(?:=>|\\{)|\\b${REQ}\\s*=>`,
  'g',
);

export function readsRequestBody(handlerText: string): boolean {
  if (BODY_READ.some((re) => re.test(handlerText))) return true;
  const withoutParams = handlerText.replace(PARAM_LISTS, ' ');
  return REQ_FORWARDED.test(withoutParams);
}

const VALIDATOR_HEAD = /^(?:validator|Validator|joi|Joi|yup|Yup|z|zod|ajv|Ajv|celebrate|Celebrate|vine|valibot|superstruct|typebox)$/;

const VALIDATING_METHOD = /^(?:parse|safeParse|parseAsync|safeParseAsync|validate|validateAsync|validateSync|validateAt|assert)$/;
const PARSER_RECEIVER = /^(?:JSON|Date|URL|url|path|qs|querystring|Number|parseInt|parseFloat|marked|cheerio|moment|dayjs|yaml|YAML|csv|xml|xml2js|libxmljs|acorn|babel|esprima|semver|cookie|cookieParser|crypto|Buffer|BigInt|parser|Parser|markdown|md|toml|ini|dotenv|argparse|commander|yargs|minimist|multer|busboy|formidable|bodyParser|jwt|jsonwebtoken|jose|bcrypt|serialize|unserialize|papaparse|Papa)$/;

const VALIDATOR_BARE = /^(?:isEmail|isLength|isEmpty|isMobilePhone|isURL|isUUID|isInt|isFloat|isAlphanumeric|isStrongPassword|isHexadecimal|isJSON|isDate|isNumeric|isIn|checkSchema|validationResult|matchedData|sanitize|sanitizeBody)$/;

const VALIDATOR_WORD = /valid|schema|zod|joi|yup|celebrate|checkschema|sanitiz/i;

const CALLEE_SOURCE = /([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\(/.source;

export function validatesInHandler(handlerText: string): boolean {
  const calls = new RegExp(CALLEE_SOURCE, 'g');
  for (let m = calls.exec(handlerText); m !== null; m = calls.exec(handlerText)) {
    if (/\bnew\s+$/.test(handlerText.slice(Math.max(0, m.index - 8), m.index))) continue;
    const callee = (m[1] ?? '').replace(/\s+/g, '');
    const segments = callee.split('.');
    const head = segments[0] ?? '';
    const last = segments[segments.length - 1] ?? '';
    if (segments.length > 1) {
      if (VALIDATOR_HEAD.test(head)) return true;
      if (VALIDATING_METHOD.test(last) && !PARSER_RECEIVER.test(segments[segments.length - 2] ?? '')) return true;
    } else if (VALIDATOR_BARE.test(head)) {
      return true;
    }
    if (VALIDATOR_WORD.test(last) && !/Error$/.test(last) && !/^(?:push|pop|shift|map|filter|forEach|join|some|every|length)$/.test(last)) {
      return true;
    }
  }
  return false;
}

const PASSPORT_HANDLER = /^passport(?:[A-Z_.]|$)/;
const RPC_TRANSPORT = /\b\w*ServerTransport\b|\bJSONRPC\w*Server\b|\bjayson\b|\bjson-rpc-2\.0\b/;

export function isFrameworkHandledBodyRoute(
  route: { handlerToken?: string },
  handlerText: string | undefined,
): boolean {
  if (route.handlerToken !== undefined && PASSPORT_HANDLER.test(route.handlerToken)) return true;
  return handlerText !== undefined && RPC_TRANSPORT.test(handlerText);
}

export function spanText(content: string, line: number, endLine: number): string {
  const lines = content.split('\n');
  return lines.slice(Math.max(0, line - 1), Math.max(line, endLine)).join('\n');
}
