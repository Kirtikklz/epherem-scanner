export interface EmbeddedAssets {
  readonly osvCache?: unknown;
  readonly pythonReader?: {
    readonly runtime: unknown;
    readonly parserWasm: Uint8Array;
    readonly grammarWasm: Uint8Array;
  };
}

// Set only by the single-file build; library builds read assets from disk.
let embedded: EmbeddedAssets = {};

export function embedAssets(assets: EmbeddedAssets): void {
  embedded = assets;
}

export function embeddedAssets(): EmbeddedAssets {
  return embedded;
}
