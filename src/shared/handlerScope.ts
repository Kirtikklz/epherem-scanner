export function routeHandlerScope(content: string, offset: number): string {
  const boundary = /(?:^|\n)\s*(?:export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b|export\s+const\s+(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b|(?:app|router)\.(?:get|post|put|patch|delete|all)\s*\(|@(?:app|router|bp)\.(?:get|post|put|patch|delete|route)\s*\()/gim;
  const starts: number[] = [];
  let match: RegExpExecArray | null;
  while ((match = boundary.exec(content)) !== null) starts.push(match.index);
  if (starts.length === 0) return content;

  let start = 0;
  let end = content.length;
  for (let i = 0; i < starts.length; i += 1) {
    const candidate = starts[i] ?? 0;
    const next = starts[i + 1] ?? content.length;
    if (offset >= candidate && offset < next) {
      start = candidate;
      end = next;
      break;
    }
  }
  return content.slice(start, end);
}

export function routeHandlerScopeForLine(content: string, line: number): string {
  let offset = 0;
  for (let current = 1; current < line; current += 1) {
    const next = content.indexOf('\n', offset);
    if (next === -1) break;
    offset = next + 1;
  }
  return routeHandlerScope(content, offset);
}

const DECLARATION_BOUNDARY =
  /(?:^|\n)\s*(?:export\s+(?:default\s+)?)?(?:async\s+)?function\s+\w+|(?:^|\n)\s*(?:export\s+)?const\s+\w+\s*(?::[^=\n]+)?=\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*(?::[^=>\n]{0,120})?=>|[A-Za-z_$][\w$]*\s*=>|\w*[Pp]rocedure\b)|(?:^|\n)\s*(?:app|router|bp)\.(?:get|post|put|patch|delete|all|route)\s*\(/gim;

export function enclosingFunctionScopeRange(
  content: string,
  offset: number,
): { start: number; end: number } {
  const starts: number[] = [];
  let match: RegExpExecArray | null;
  DECLARATION_BOUNDARY.lastIndex = 0;
  while ((match = DECLARATION_BOUNDARY.exec(content)) !== null) starts.push(match.index);
  if (starts.length === 0) return { start: 0, end: content.length };

  let start = 0;
  let end = content.length;
  for (let i = 0; i < starts.length; i += 1) {
    const candidate = starts[i] ?? 0;
    const next = starts[i + 1] ?? content.length;
    if (offset >= candidate && offset < next) {
      start = candidate;
      end = next;
      break;
    }
    if (candidate > offset) break;
    start = candidate;
    end = next;
  }
  return { start, end };
}

export function enclosingFunctionScope(content: string, offset: number): string {
  const { start, end } = enclosingFunctionScopeRange(content, offset);
  return content.slice(start, end);
}
