type Context = 'text' | 'tag' | 'attr-dq' | 'attr-sq' | 'attr-unquoted' | 'opaque-element' | 'comment';
interface State { context: Context; attribute: string; opaqueElement: string }

const UNSAFE_ATTRIBUTE = /^(?:on\w+|href|src|srcset|action|formaction|xlink:href|style|srcdoc|data|code|codebase|poster|background|lowsrc|dynsrc)$/i;

function advance(state: State, text: string): State {
  let { context, attribute, opaqueElement } = state;
  let i = 0;
  while (i < text.length) {
    const c = text[i]!;
    switch (context) {
      case 'text':
        if (text.startsWith('<!--', i)) { context = 'comment'; i += 4; continue; }
        if (c === '<' && /[A-Za-z/]/.test(text[i + 1] ?? '')) {
          const name = /^<\/?([A-Za-z][\w-]*)/.exec(text.slice(i))?.[1]?.toLowerCase() ?? '';
          opaqueElement = text[i + 1] !== '/' && (name === 'script' || name === 'style') ? name : '';
          context = 'tag';
          i += 1;
          continue;
        }
        break;
      case 'comment':
        if (text.startsWith('-->', i)) { context = 'text'; i += 3; continue; }
        break;
      case 'opaque-element':
        if (text.slice(i, i + opaqueElement.length + 2).toLowerCase() === `</${opaqueElement}`) { context = 'tag'; opaqueElement = ''; i += 2; continue; }
        break;
      case 'tag': {
        if (c === '>') { context = opaqueElement !== '' ? 'opaque-element' : 'text'; i += 1; continue; }
        const attr = /^([^\s=>/"']+)\s*=\s*(["']?)/.exec(text.slice(i));
        if (attr !== null && /\s|^/.test(text[i - 1] ?? ' ')) {
          attribute = attr[1]!;
          context = attr[2] === '"' ? 'attr-dq' : attr[2] === "'" ? 'attr-sq' : 'attr-unquoted';
          i += attr[0].length;
          continue;
        }
        break;
      }
      case 'attr-dq':
        if (c === '"') { context = 'tag'; attribute = ''; }
        break;
      case 'attr-sq':
        if (c === "'") { context = 'tag'; attribute = ''; }
        break;
      case 'attr-unquoted':
        if (/\s/.test(c)) { context = 'tag'; attribute = ''; }
        if (c === '>') { context = opaqueElement !== '' ? 'opaque-element' : 'text'; attribute = ''; }
        break;
    }
    i += 1;
  }
  return { context, attribute, opaqueElement };
}

const sameState = (a: State, b: State): boolean => a.context === b.context && a.attribute === b.attribute && a.opaqueElement === b.opaqueElement;

function literalBody(token: string): string {
  return token.slice(1, -1).replace(/\\(.)/g, '$1');
}

function splitTop(text: string, separator: string): string[] | undefined {
  const parts: string[] = [];
  let depth = 0;
  let quote = '';
  let start = 0;
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i]!;
    if (quote !== '') {
      if (c === '\\') { i += 1; continue; }
      if (c === quote) quote = '';
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { quote = c; continue; }
    if (c === '(' || c === '[' || c === '{') depth += 1;
    if (c === ')' || c === ']' || c === '}') { depth -= 1; if (depth < 0) return undefined; }
    if (depth === 0 && c === separator) {
      parts.push(text.slice(start, i));
      start = i + 1;
    }
  }
  if (quote !== '' || depth !== 0) return undefined;
  parts.push(text.slice(start));
  return parts;
}

function splitConditional(text: string): [string, string, string] | undefined {
  let depth = 0;
  let quote = '';
  let question = -1;
  let nested = 0;
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i]!;
    if (quote !== '') {
      if (c === '\\') { i += 1; continue; }
      if (c === quote) quote = '';
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { quote = c; continue; }
    if (c === '(' || c === '[' || c === '{') depth += 1;
    if (c === ')' || c === ']' || c === '}') depth -= 1;
    if (depth !== 0) continue;
    if (c === '?' && text[i + 1] !== '.' && text[i + 1] !== '?' && text[i - 1] !== '?') {
      if (question < 0) question = i; else nested += 1;
    } else if (c === ':' && question >= 0) {
      if (nested > 0) { nested -= 1; continue; }
      return [text.slice(0, question), text.slice(question + 1, i), text.slice(i + 1)];
    }
  }
  return undefined;
}

function stripParens(text: string): string {
  let t = text.trim();
  for (;;) {
    if (!t.startsWith('(') || !t.endsWith(')')) return t;
    const inner = t.slice(1, -1);
    if (splitTop(inner, ',') === undefined) return t;
    let depth = 0;
    let ok = true;
    let quote = '';
    for (let i = 0; i < inner.length; i += 1) {
      const c = inner[i]!;
      if (quote !== '') { if (c === '\\') i += 1; else if (c === quote) quote = ''; continue; }
      if (c === '"' || c === "'" || c === '`') { quote = c; continue; }
      if (c === '(') depth += 1;
      if (c === ')') { depth -= 1; if (depth < 0) { ok = false; break; } }
    }
    if (!ok) return t;
    t = inner.trim();
  }
}

const COMPUTED_NUMBER = /^(?:(?:Number|parseInt|parseFloat|Math\s*\.\s*\w+)\s*\([^]*\)|[\w$.[\]]+\s*\.\s*toFixed\s*\(\s*\d*\s*\)|[\w$.]+\s*\.\s*length|-?\d+(?:\.\d+)?)$/;

function helperBody(content: string, name: string): string | undefined {
  const escaped = name.replace(/[$]/g, '\\$&');
  const head = new RegExp(`(?:function\\s+${escaped}\\s*\\([^)]*\\)\\s*\\{|(?:const|let|var)\\s+${escaped}\\s*=\\s*(?:function\\s*)?\\([^)]*\\)\\s*(?:=>\\s*)?\\{?)`).exec(content);
  if (head === null) return undefined;
  const body = content.slice(head.index + head[0].length, head.index + head[0].length + 600);
  const end = body.search(/\n\s*\}|\n(?:function|const|let|var)\b/);
  return end >= 0 ? body.slice(0, end) : body;
}

function escapesAllThree(content: string, name: string): boolean {
  const text = helperBody(content, name);
  if (text === undefined) return false;
  return /&amp;/.test(text) && /&lt;/.test(text) && /&gt;/.test(text) && /\.replace\s*\(/.test(text);
}

function escapesQuote(content: string, name: string, context: 'attr-dq' | 'attr-sq'): boolean {
  const text = helperBody(content, name) ?? '';
  return context === 'attr-dq' ? /&quot;|&#34;|&#x22;/i.test(text) : /&#39;|&#x27;|&apos;/i.test(text);
}

function isConstantTable(content: string, name: string): boolean {
  const escaped = name.replace(/[$]/g, '\\$&');
  const declarations = [...content.matchAll(new RegExp(`\\b(?:const|let|var)\\s+${escaped}\\s*=\\s*`, 'g'))];
  if (declarations.length !== 1) return false;
  const writes = new RegExp(`(?<![\\w$.])${escaped}\\s*(?:\\[[^\\]]*\\]|\\.\\s*[\\w$]+)*\\s*(?:[-+*/]?=(?!=)|\\.\\s*(?:push|unshift|splice|assign)\\s*\\()|Object\\s*\\.\\s*assign\\s*\\(\\s*${escaped}\\b`, 'g');
  const declarationAt = declarations[0]!.index!;
  for (const write of content.matchAll(writes)) if (write.index !== declarationAt + declarations[0]![0].indexOf(name)) return false;
  const start = declarationAt + declarations[0]![0].length;
  if (content[start] !== '{' && content[start] !== '[') return false;
  let depth = 0;
  let quote = '';
  for (let i = start; i < content.length && i - start < 20_000; i += 1) {
    const c = content[i]!;
    if (quote !== '') { if (c === '\\') i += 1; else if (c === quote) quote = ''; continue; }
    if (c === '"' || c === "'" || c === '`') { quote = c; continue; }
    if (c === '{' || c === '[' || c === '(') depth += 1;
    if (c === '}' || c === ']' || c === ')') {
      depth -= 1;
      if (depth === 0) {
        const stripped = content.slice(start, i + 1)
          .replace(/`(?:\\.|[^`\\$])*`/g, ' ')
          .replace(/'(?:\\.|[^'\\])*'/g, ' ')
          .replace(/"(?:\\.|[^"\\])*"/g, ' ')
          .replace(/(?<![.\w$])[A-Za-z_$][\w$]*\s*:/g, ' ')
          .replace(/\b(?:true|false|null|undefined)\b/g, ' ')
          .replace(/\b\d[\d_.eE+-]*\b/g, ' ');
        return !/[A-Za-z_$`]/.test(stripped);
      }
    }
  }
  return false;
}

function isNumberLocal(content: string, name: string): boolean {
  const escaped = name.replace(/[$]/g, '\\$&');
  const declarations = [...content.matchAll(new RegExp(`\\b(?:const|let|var)\\s+${escaped}\\s*=(?!=)`, 'g'))];
  const declaration = declarations[0];
  if (declaration === undefined) return false;
  const value = assignedValue(content, declaration.index! + declaration[0].length);
  if (value === undefined || !COMPUTED_NUMBER.test(value.trim())) return false;
  const own = declaration.index! + declaration[0].length - declaration[0].replace(/^[\s\S]*?\b(?:const|let|var)\s+/, '').length;
  const word = `(?<![\\w$.])${escaped}(?![\\w$])`;
  if (new RegExp(`function\\s*[\\w$]*\\s*\\([^)]*${word}[^)]*\\)|\\([^()]*${word}[^()]*\\)\\s*=>|${word}\\s*=>|catch\\s*\\(\\s*${escaped}\\s*\\)`).test(content)) return false;
  for (const use of content.matchAll(new RegExp(word, 'g'))) {
    if (use.index! === own) continue;
    const before = content.slice(Math.max(0, use.index! - 80), use.index!);
    const after = content.slice(use.index! + name.length, use.index! + name.length + 40);
    if (/^\s*[\]}]*\s*(?:[-+*/%&|^]|\*\*|<<|>>>?|\?\?|&&|\|\|)?=(?!=)/.test(after) || /^\s*(?:\+\+|--)/.test(after) || /(?:\+\+|--)\s*$/.test(before)) return false;
    if (/\bfor\s*\(\s*(?:let|var|const)?\s*[[{]?[^;)]*$/.test(before) && /^\s*[\]}]*\s*(?:of|in)\b/.test(after)) return false;
  }
  return true;
}

interface Verdict { inert: boolean; state: State }

function classify(content: string, expression: string, state: State, depth: number): Verdict {
  const fail: Verdict = { inert: false, state };
  if (depth > 12) return fail;
  const text = stripParens(expression);
  if (text === '') return fail;
  const conditional = splitConditional(text);
  if (conditional !== undefined) {
    const a = classify(content, conditional[1], state, depth + 1);
    const b = classify(content, conditional[2], state, depth + 1);
    if (!a.inert || !b.inert || !sameState(a.state, b.state)) return fail;
    return a;
  }
  const parts = splitTop(text, '+');
  if (parts === undefined) return fail;
  if (parts.length > 1) {
    let current = state;
    for (const part of parts) {
      if (part.trim() === '') return fail;
      const verdict = classify(content, part, current, depth + 1);
      if (!verdict.inert) return fail;
      current = verdict.state;
    }
    return { inert: true, state: current };
  }
  if (/^(['"])(?:\\.|(?!\1)[^\\\n])*\1$/.test(text)) return { inert: true, state: advance(state, literalBody(text)) };
  if (/^`[^`]*`$/.test(text)) {
    let current = state;
    const body = text.slice(1, -1);
    let i = 0;
    while (i < body.length) {
      const open = body.indexOf('${', i);
      const chunk = open < 0 ? body.slice(i) : body.slice(i, open);
      current = advance(current, chunk.replace(/\\(.)/g, '$1'));
      if (open < 0) break;
      let braces = 1;
      let j = open + 2;
      while (j < body.length && braces > 0) { if (body[j] === '{') braces += 1; if (body[j] === '}') braces -= 1; j += 1; }
      if (braces !== 0) return fail;
      const inner = classify(content, body.slice(open + 2, j - 1), current, depth + 1);
      if (!inner.inert) return fail;
      current = inner.state;
      i = j;
    }
    return { inert: true, state: current };
  }
  if (COMPUTED_NUMBER.test(text) || /^[\w$.]+(?:\s*[-*/%]\s*[\w$.]+)+$/.test(text) && /[-*/%]/.test(text)) return { inert: true, state };
  if (/^[A-Za-z_$][\w$]*$/.test(text) && isNumberLocal(content, text)) return { inert: true, state };
  const lookup = /^([A-Za-z_$][\w$]*)(?:\s*\[[^\]]*\]|\s*\.\s*[A-Za-z_$][\w$]*)+$/.exec(text);
  if (lookup !== null && isConstantTable(content, lookup[1]!)) return { inert: true, state };
  const helper = /^([A-Za-z_$][\w$]*)\s*\(([^]*)\)$/.exec(text);
  if (helper !== null && escapesAllThree(content, helper[1]!)) {
    const safeContext = state.context === 'text'
      || ((state.context === 'attr-dq' || state.context === 'attr-sq') && !UNSAFE_ATTRIBUTE.test(state.attribute)
        && escapesQuote(content, helper[1]!, state.context));
    return safeContext ? { inert: true, state } : fail;
  }
  return fail;
}

export function assignedValue(content: string, from: number): string | undefined {
  let depth = 0;
  let quote = '';
  for (let i = from; i < content.length && i - from < 4000; i += 1) {
    const c = content[i]!;
    if (quote !== '') {
      if (c === '\\') { i += 1; continue; }
      if (c === quote) quote = '';
      else if (c === '\n' && quote !== '`') return undefined;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { quote = c; continue; }
    if (c === '(' || c === '[' || c === '{') depth += 1;
    if (c === ')' || c === ']' || c === '}') { depth -= 1; if (depth < 0) return content.slice(from, i); }
    if (depth === 0 && c === ';') return content.slice(from, i);
    if (depth === 0 && c === '\n') {
      const before = content.slice(from, i).trimEnd();
      const after = content.slice(i + 1).trimStart();
      if (!/[+?:(,&|=]$/.test(before) && !/^[+?:.&|)]/.test(after)) return content.slice(from, i);
    }
  }
  return undefined;
}

export function innerHtmlValueIsInert(content: string, index: number, matchText: string): boolean {
  const assign = /^\.(?:innerHTML|outerHTML)\s*=(?!=)/.exec(matchText);
  if (assign === null) return false;
  const value = assignedValue(content, index + assign[0].length);
  if (value === undefined || value.trim() === '') return false;
  if (reserialisesItself(content, index, value)) return true;
  return classify(content, value, { context: 'text', attribute: '', opaqueElement: '' }, 0).inert;
}

function reserialisesItself(content: string, index: number, value: string): boolean {
  const receiver = /([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*$/.exec(content.slice(Math.max(0, index - 200), index))?.[1];
  if (receiver === undefined) return false;
  const same = receiver.replace(/\s+/g, '').replace(/[.$]/g, '\\$&');
  const call = new RegExp(`^\\s*${same}\\s*\\.\\s*innerHTML\\s*\\.\\s*replace(?:All)?\\s*\\(([\\s\\S]*)\\)\\s*$`).exec(value.replace(/\s*\.\s*/g, '.'));
  if (call === null) return false;
  const args = splitTop(call[1]!, ',');
  if (args === undefined || args.length !== 2) return false;
  const replacement = args[1]!.trim();
  const SAFE_TEXT = /^[\w\- .]*$/;
  if (/^(['"])(?:\\.|(?!\1)[^\\\n])*\1$/.test(replacement)) return SAFE_TEXT.test(literalBody(replacement));
  if (!/^`[^`]*`$/.test(replacement)) return false;
  const body = replacement.slice(1, -1);
  const chunks = body.split(/\$\{([^{}]*)\}/);
  return chunks.every((chunk, i) => i % 2 === 0
    ? SAFE_TEXT.test(chunk)
    : COMPUTED_NUMBER.test(chunk.trim()) || (/^[A-Za-z_$][\w$]*$/.test(chunk.trim()) && isNumberLocal(content, chunk.trim())));
}
