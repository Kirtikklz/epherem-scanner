export const MAX_FILES_NAMED = 5;

export class CappedNames {
  private readonly seen = new Set<string>();
  private readonly list: string[] = [];

  constructor(readonly cap: number = MAX_FILES_NAMED) {}

  add(name: string, identity: string = name): boolean {
    if (this.seen.has(identity)) return false;
    this.seen.add(identity);
    if (this.list.length >= this.cap) return false;
    this.list.push(name);
    return true;
  }

  get named(): readonly string[] {
    return this.list;
  }

  get total(): number {
    return this.seen.size;
  }

  get unnamed(): number {
    return this.seen.size - this.list.length;
  }
}

export function andMoreFiles(unnamed: number, purpose: string): string | undefined {
  if (unnamed <= 0) return undefined;
  return `…and ${unnamed} more file${unnamed === 1 ? '' : 's'} could not be analysed for ${purpose}.`;
}

export function quotedListWithRemainder(names: { readonly named: readonly string[]; readonly total: number }): string {
  const list = names.named.map((name) => `"${name}"`).join(', ');
  const unnamed = names.total - names.named.length;
  return unnamed <= 0 ? list : `${list}… and ${unnamed} more`;
}
