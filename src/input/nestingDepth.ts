export function exceedsNestingDepth(content: string, limit: number): boolean {
  const length = content.length;
  let index = 0;
  let depth = 0;
  const templateSubstitutions: number[] = [];
  let inTemplateText = false;
  const templateStack: boolean[] = [];

  while (index < length) {
    const char = content[index];

    if (inTemplateText) {
      if (char === '\\') { index += 2; continue; }
      if (char === '`') {
        inTemplateText = templateStack.pop() ?? false;
        index += 1;
        continue;
      }
      if (char === '$' && content[index + 1] === '{') {
        depth += 1;
        if (depth > limit) return true;
        templateSubstitutions.push(depth);
        templateStack.push(true);
        inTemplateText = false;
        index += 2;
        continue;
      }
      index += 1;
      continue;
    }

    if (char === '/' && content[index + 1] === '/') {
      const newline = content.indexOf('\n', index + 2);
      index = newline === -1 ? length : newline + 1;
      continue;
    }
    if (char === '/' && content[index + 1] === '*') {
      const end = content.indexOf('*/', index + 2);
      index = end === -1 ? length : end + 2;
      continue;
    }
    if (char === '"' || char === "'") {
      index += 1;
      while (index < length) {
        const inner = content[index];
        if (inner === '\\') { index += 2; continue; }
        if (inner === char || inner === '\n') { index += 1; break; }
        index += 1;
      }
      continue;
    }
    if (char === '`') {
      templateStack.push(inTemplateText);
      inTemplateText = true;
      index += 1;
      continue;
    }
    if (char === '(' || char === '[' || char === '{') {
      depth += 1;
      if (depth > limit) return true;
      index += 1;
      continue;
    }
    if (char === ')' || char === ']') {
      if (depth > 0) depth -= 1;
      index += 1;
      continue;
    }
    if (char === '}') {
      const openedAt = templateSubstitutions[templateSubstitutions.length - 1];
      if (openedAt !== undefined && depth === openedAt) {
        templateSubstitutions.pop();
        inTemplateText = templateStack.pop() ?? false;
      }
      if (depth > 0) depth -= 1;
      index += 1;
      continue;
    }
    index += 1;
  }
  return false;
}

export function measureNestingDepth(content: string): number {
  let low = 0;
  let high = 1;
  while (exceedsNestingDepth(content, high)) {
    low = high;
    high *= 2;
    if (high > content.length) return content.length;
  }
  while (low + 1 < high) {
    const mid = Math.floor((low + high) / 2);
    if (exceedsNestingDepth(content, mid)) low = mid;
    else high = mid;
  }
  return exceedsNestingDepth(content, low) ? high : low;
}
