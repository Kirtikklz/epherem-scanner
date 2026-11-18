// Parses Python as data only: project code is never run or imported.
import { readFileSync, existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { embeddedAssets } from './embeddedAssets.js';

export const MAX_PY_FILE_CHARS = 400_000;
export const MAX_PY_LINE_CHARS = 10_000;
export const MAX_PY_NODES = 250_000;
export const MAX_PY_DEPTH = 400;
export const MAX_PY_PARSE_MS = 2_000;
export const MAX_PY_NODES_PER_SCAN = 5_000_000;
export const MAX_PY_CACHED_NODES = 1_500_000;
const PY_WASM_INITIAL_BYTES = 32 * 1024 * 1024;
export const MAX_PY_WASM_BYTES = 128 * 1024 * 1024;

export type PyFallbackReason =
  | 'not-ready'
  | 'too-large'
  | 'long-line'
  | 'too-slow'
  | 'parse-error'
  | 'too-many-nodes'
  | 'too-deep'
  | 'scan-budget'
  | 'parser-failure';

interface TsCursor {
  readonly nodeTypeId: number;
  readonly nodeIsNamed: boolean;
  readonly currentFieldId: number;
  readonly startIndex: number;
  readonly endIndex: number;
  gotoFirstChild(): boolean;
  gotoNextSibling(): boolean;
  gotoParent(): boolean;
  delete(): void;
}
interface TsTree { readonly rootNode: { readonly hasError: boolean }; walk(): TsCursor; delete(): void }
interface TsLanguage { readonly types: string[]; fieldNameForId(id: number): string | null; readonly fieldCount: number }
interface TsParser {
  setLanguage(language: TsLanguage): void;
  parse(input: string, old: null, options: { progressCallback: () => boolean }): TsTree | null;
  delete(): void;
}
interface TsModule {
  Parser: { init(options: object): Promise<void>; new (): TsParser };
  Language: { load(bytes: Uint8Array): Promise<TsLanguage> };
}

interface Reader {
  parser: TsParser;
  types: string[];
  fields: string[];
  memory: WasmMemory;
}

interface WasmMemory { readonly buffer: { readonly byteLength: number } }
const WasmMemoryConstructor = (globalThis as unknown as { WebAssembly: { Memory: new (descriptor: { initial: number; maximum: number }) => WasmMemory } }).WebAssembly.Memory;

let reader: Reader | undefined;
let holders = 0;
let broken = false;
let loading: Promise<Reader | undefined> | undefined;
let assetDirOverride: string | undefined;

function assetDir(): string | undefined {
  if (assetDirOverride !== undefined) return assetDirOverride;
  const here = dirname(fileURLToPath(import.meta.url));
  const built = join(here, '..', 'python-reader');
  if (existsSync(join(built, 'tree-sitter-python.wasm'))) return built;
  try {
    const pkg = createRequire(import.meta.url).resolve('@vscode/tree-sitter-wasm/package.json');
    const dir = join(dirname(pkg), 'wasm');
    return existsSync(join(dir, 'tree-sitter-python.wasm')) ? dir : undefined;
  } catch {
    return undefined;
  }
}

function loadAssets(): { runtime: TsModule; parserWasm: Uint8Array; grammarWasm: Uint8Array; dir: string } | undefined {
  const carried = embeddedAssets().pythonReader;
  if (carried !== undefined) {
    return { runtime: carried.runtime as TsModule, parserWasm: carried.parserWasm, grammarWasm: carried.grammarWasm, dir: '' };
  }
  const dir = assetDir();
  if (dir === undefined) return undefined;
  const runtimeFile = existsSync(join(dir, 'tree-sitter.cjs')) ? 'tree-sitter.cjs' : 'tree-sitter.js';
  return {
    runtime: createRequire(import.meta.url)(join(dir, runtimeFile)) as TsModule,
    parserWasm: readFileSync(join(dir, 'tree-sitter.wasm')),
    grammarWasm: new Uint8Array(readFileSync(join(dir, 'tree-sitter-python.wasm'))),
    dir,
  };
}

async function load(): Promise<Reader | undefined> {
  const assets = loadAssets();
  if (assets === undefined) return undefined;
  const { runtime, dir } = assets;
  // The parser gets a capped memory it cannot grow past.
  const memory = new WasmMemoryConstructor({ initial: PY_WASM_INITIAL_BYTES / 65536, maximum: MAX_PY_WASM_BYTES / 65536 });
  // Runtime and grammar are passed as bytes: nothing is fetched.
  await runtime.Parser.init({
    wasmBinary: assets.parserWasm,
    wasmMemory: memory,
    locateFile: (file: string) => join(dir, file),
  });
  const language = await runtime.Language.load(assets.grammarWasm);
  const parser = new runtime.Parser();
  parser.setLanguage(language);
  const fields: string[] = [''];
  for (let id = 1; id <= language.fieldCount; id += 1) fields.push(language.fieldNameForId(id) ?? '');
  return { parser, types: language.types, fields, memory };
}

// Never throws: if the parser cannot load, Python is read by patterns.
export async function preparePythonReader(): Promise<boolean> {
  if (holders === 0) scanNodes = 0;
  holders += 1;
  if (broken) return false;
  if (reader !== undefined) return true;
  loading ??= load().catch(() => undefined);
  const loaded = await loading;
  loading = undefined;
  if (loaded === undefined) return false;
  if (reader === undefined) reader = loaded;
  return true;
}

export function releasePythonReader(): void {
  holders = Math.max(0, holders - 1);
  if (holders > 0) return;
  freeReader();
}

function freeReader(): void {
  if (reader !== undefined) {
    try { reader.parser.delete(); } catch {  }
  }
  reader = undefined;
  heldTrees = new WeakMap();
  heldNodes = 0;
  heldOrder.length = 0;
}

export class PyTree {
   readonly typeIds: Uint16Array;
   readonly named: Uint8Array;
   readonly fieldIds: Uint8Array;
   readonly starts: Int32Array;
   readonly ends: Int32Array;
   readonly parents: Int32Array;
   readonly firstChild: Int32Array;
   readonly nextSibling: Int32Array;
  private lineStarts: number[] | undefined;

  constructor(
    readonly text: string,
    readonly size: number,
     readonly types: string[],
     readonly fields: string[],
    arrays: { typeIds: Uint16Array; named: Uint8Array; fieldIds: Uint8Array; starts: Int32Array; ends: Int32Array; parents: Int32Array; firstChild: Int32Array; nextSibling: Int32Array },
  ) {
    this.typeIds = arrays.typeIds;
    this.named = arrays.named;
    this.fieldIds = arrays.fieldIds;
    this.starts = arrays.starts;
    this.ends = arrays.ends;
    this.parents = arrays.parents;
    this.firstChild = arrays.firstChild;
    this.nextSibling = arrays.nextSibling;
  }

  get root(): PyNode { return new PyNode(this, 0); }

  lineOf(index: number): number {
    if (this.lineStarts === undefined) {
      const starts = [0];
      for (let i = 0; i < this.text.length; i += 1) if (this.text.charCodeAt(i) === 10) starts.push(i + 1);
      this.lineStarts = starts;
    }
    const starts = this.lineStarts;
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (starts[mid]! <= index) lo = mid; else hi = mid - 1; }
    return lo + 1;
  }

  find(test: (node: PyNode) => boolean): PyNode[] {
    const out: PyNode[] = [];
    for (let i = 0; i < this.size; i += 1) {
      const node = new PyNode(this, i);
      if (test(node)) out.push(node);
    }
    return out;
  }
}

export class PyNode {
  constructor(readonly tree: PyTree, readonly id: number) {}

  get type(): string { return this.tree.types[this.tree.typeIds[this.id]!] ?? 'ERROR'; }
  get isNamed(): boolean { return this.tree.named[this.id] === 1; }
  get field(): string { return this.tree.fields[this.tree.fieldIds[this.id]!] ?? ''; }
  get start(): number { return this.tree.starts[this.id]!; }
  get end(): number { return this.tree.ends[this.id]!; }
  get text(): string { return this.tree.text.slice(this.start, this.end); }
  get line(): number { return this.tree.lineOf(this.start); }
  get endLine(): number { return this.tree.lineOf(Math.max(this.start, this.end - 1)); }
  get parent(): PyNode | undefined {
    const p = this.tree.parents[this.id]!;
    return p < 0 ? undefined : new PyNode(this.tree, p);
  }

  get children(): PyNode[] {
    const out: PyNode[] = [];
    for (let c = this.tree.firstChild[this.id]!; c >= 0; c = this.tree.nextSibling[c]!) out.push(new PyNode(this.tree, c));
    return out;
  }

  get namedChildren(): PyNode[] { return this.children.filter((child) => child.isNamed && child.type !== 'comment'); }

  child(field: string): PyNode | undefined { return this.children.find((child) => child.field === field); }

  childrenOf(field: string): PyNode[] { return this.children.filter((child) => child.field === field); }

  descendants(): PyNode[] {
    const out: PyNode[] = [];
    const end = this.end;
    for (let i = this.id + 1; i < this.tree.size && this.tree.starts[i]! < end; i += 1) {
      if (this.contains(i)) out.push(new PyNode(this.tree, i));
    }
    return out;
  }

  contains(id: number): boolean {
    for (let i: number = id; i >= 0; i = this.tree.parents[i]!) if (i === this.id) return true;
    return false;
  }

  same(other: PyNode | undefined): boolean { return other !== undefined && other.tree === this.tree && other.id === this.id; }
}

export type PyRead = { tree: PyTree; fallback?: undefined } | { tree?: undefined; fallback: PyFallbackReason };

let heldTrees = new WeakMap<object, PyRead>();
const heldOrder: Array<{ key: WeakRef<object>; nodes: number }> = [];
let heldNodes = 0;

export interface PythonReaderStats {
  parsed: number;
  nodes: number;
  fallbacks: Record<PyFallbackReason, number>;
  fellBack: Array<{ path: string; reason: PyFallbackReason }>;
  wasmPeakBytes: number;
}

const emptyFallbacks = (): Record<PyFallbackReason, number> => ({
  'not-ready': 0, 'too-large': 0, 'long-line': 0, 'too-slow': 0, 'parse-error': 0,
  'too-many-nodes': 0, 'too-deep': 0, 'scan-budget': 0, 'parser-failure': 0,
});
let stats: PythonReaderStats = { parsed: 0, nodes: 0, fallbacks: emptyFallbacks(), fellBack: [], wasmPeakBytes: 0 };
let scanNodes = 0;

export function pythonReaderStats(): PythonReaderStats {
  return { ...stats, fallbacks: { ...stats.fallbacks }, fellBack: [...stats.fellBack] };
}

export function resetPythonReaderStats(): void {
  stats = { parsed: 0, nodes: 0, fallbacks: emptyFallbacks(), fellBack: [], wasmPeakBytes: reader?.memory.buffer.byteLength ?? 0 };
}

function fallBack(path: string, reason: PyFallbackReason): PyRead {
  stats.fallbacks[reason] += 1;
  if (stats.fellBack.length < 20) stats.fellBack.push({ path, reason });
  return { fallback: reason };
}

export const pythonReaderTesting = {
  setAssetDir(dir: string | undefined): void { assetDirOverride = dir; },
  reset(): void { freeReader(); holders = 0; broken = false; loading = undefined; scanNodes = 0; },
  budgets: { nodes: MAX_PY_NODES, depth: MAX_PY_DEPTH, parseMs: MAX_PY_PARSE_MS, scanNodes: MAX_PY_NODES_PER_SCAN, cachedNodes: MAX_PY_CACHED_NODES } as Record<'nodes' | 'depth' | 'parseMs' | 'scanNodes' | 'cachedNodes', number>,
  failNext: false,
  wasmMemoryWritten(): boolean {
    const buffer = reader?.memory.buffer as ArrayBuffer | undefined;
    return buffer !== undefined && new Uint8Array(buffer).some((byte) => byte !== 0);
  },
};

function hasLongLine(text: string): boolean {
  let from = 0;
  for (;;) {
    const next = text.indexOf('\n', from);
    const end = next < 0 ? text.length : next;
    if (end - from > MAX_PY_LINE_CHARS) return true;
    if (next < 0) return false;
    from = next + 1;
  }
}

export function readPythonTree(entry: { path: string; content: string }): PyRead {
  const cached = heldTrees.get(entry);
  if (cached !== undefined) return cached;
  const result = readUncached(entry.path, entry.content);
  if (result.fallback !== 'not-ready') remember(entry, result);
  return result;
}

function remember(entry: object, result: PyRead): void {
  const nodes = result.tree?.size ?? 0;
  heldTrees.set(entry, result);
  heldOrder.push({ key: new WeakRef(entry), nodes });
  heldNodes += nodes;
  while (heldNodes > pythonReaderTesting.budgets.cachedNodes && heldOrder.length > 1) {
    const oldest = heldOrder.shift()!;
    heldNodes -= oldest.nodes;
    const key = oldest.key.deref();
    if (key !== undefined) heldTrees.delete(key);
  }
}

function readUncached(path: string, text: string): PyRead {
  const budgets = pythonReaderTesting.budgets;
  if (reader === undefined || broken) return fallBack(path, 'not-ready');
  if (text.length > MAX_PY_FILE_CHARS) return fallBack(path, 'too-large');
  if (hasLongLine(text)) return fallBack(path, 'long-line');
  if (scanNodes >= budgets.scanNodes) return fallBack(path, 'scan-budget');
  const current = reader;
  let tree: TsTree | null = null;
  let cursor: TsCursor | undefined;
  try {
    if (pythonReaderTesting.failNext) {
      pythonReaderTesting.failNext = false;
      throw new Error('simulated parser failure');
    }
    const started = Date.now();
    let cancelled = false;
    tree = current.parser.parse(text, null, {
      progressCallback: () => {
        if (Date.now() - started > budgets.parseMs) cancelled = true;
        return cancelled;
      },
    });
    stats.wasmPeakBytes = Math.max(stats.wasmPeakBytes, current.memory.buffer.byteLength);
    if (tree === null || cancelled) return fallBack(path, 'too-slow');
    if (tree.rootNode.hasError) return fallBack(path, 'parse-error');
    cursor = tree.walk();
    const copied = copyTree(cursor, current, text, budgets.nodes, budgets.depth);
    if (typeof copied === 'string') return fallBack(path, copied);
    scanNodes += copied.size;
    stats.parsed += 1;
    stats.nodes += copied.size;
    return { tree: copied };
  } catch {
    broken = true;
    freeReader();
    return fallBack(path, 'parser-failure');
  } finally {
    try { cursor?.delete(); tree?.delete(); } catch { broken = true; }
  }
}

function copyTree(cursor: TsCursor, current: Reader, text: string, maxNodes: number, maxDepth: number): PyTree | 'too-many-nodes' | 'too-deep' {
  let capacity = 1024;
  let typeIds: Uint16Array = new Uint16Array(capacity);
  let named: Uint8Array = new Uint8Array(capacity);
  let fieldIds: Uint8Array = new Uint8Array(capacity);
  let starts: Int32Array = new Int32Array(capacity);
  let ends: Int32Array = new Int32Array(capacity);
  let parents: Int32Array = new Int32Array(capacity);
  let firstChild: Int32Array = new Int32Array(capacity);
  let nextSibling: Int32Array = new Int32Array(capacity);
  const grow = (): void => {
    capacity *= 2;
    const g16 = (a: Uint16Array): Uint16Array => { const b = new Uint16Array(capacity); b.set(a); return b; };
    const g8 = (a: Uint8Array): Uint8Array => { const b = new Uint8Array(capacity); b.set(a); return b; };
    const g32 = (a: Int32Array): Int32Array => { const b = new Int32Array(capacity); b.set(a); return b; };
    typeIds = g16(typeIds); named = g8(named); fieldIds = g8(fieldIds);
    starts = g32(starts); ends = g32(ends); parents = g32(parents); firstChild = g32(firstChild); nextSibling = g32(nextSibling);
  };
  let size = 0;
  const path: number[] = [];
  const lastChild: number[] = [];
  let depth = 0;
  for (;;) {
    if (size >= maxNodes) return 'too-many-nodes';
    if (depth >= maxDepth) return 'too-deep';
    if (size === capacity) grow();
    const id = size;
    size += 1;
    typeIds[id] = cursor.nodeTypeId;
    named[id] = cursor.nodeIsNamed ? 1 : 0;
    fieldIds[id] = cursor.currentFieldId;
    starts[id] = cursor.startIndex;
    ends[id] = cursor.endIndex;
    const parent = depth === 0 ? -1 : path[depth - 1]!;
    parents[id] = parent;
    firstChild[id] = -1;
    nextSibling[id] = -1;
    if (parent >= 0) {
      const previous = lastChild[depth - 1]!;
      if (previous < 0) firstChild[parent] = id;
      else nextSibling[previous] = id;
      lastChild[depth - 1] = id;
    }
    path[depth] = id;
    lastChild[depth] = -1;
    if (cursor.gotoFirstChild()) { depth += 1; continue; }
    for (;;) {
      if (cursor.gotoNextSibling()) break;
      if (depth === 0 || !cursor.gotoParent()) {
        return new PyTree(text, size, current.types, current.fields, {
          typeIds: typeIds.slice(0, size), named: named.slice(0, size), fieldIds: fieldIds.slice(0, size),
          starts: starts.slice(0, size), ends: ends.slice(0, size), parents: parents.slice(0, size),
          firstChild: firstChild.slice(0, size), nextSibling: nextSibling.slice(0, size),
        });
      }
      depth -= 1;
    }
  }
}
