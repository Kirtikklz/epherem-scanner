import type { FileMap } from './types.js';

export interface SupabaseFunctionAuth {
  name: string;
  filePath?: string;
  verifyJwt: boolean;
  source: 'config.toml' | 'supabase-default';
}

export function detectSupabaseFunctionAuth(fileMap: FileMap): SupabaseFunctionAuth[] {
  const functionDir = /(?:^|\/)supabase\/functions\/([^/]+)\//;
  const entryByName = new Map<string, string>();
  for (const entry of fileMap.entries) {
    const match = functionDir.exec(entry.path);
    const name = match?.[1];
    if (name === undefined || name.startsWith('_')) continue;
    const existing = entryByName.get(name);
    if (existing === undefined || /\/index\.[cm]?[jt]sx?$/.test(entry.path)) entryByName.set(name, entry.path);
  }
  if (entryByName.size === 0) return [];

  const configured = new Map<string, boolean>();
  const config = fileMap.entries.find((entry) => /(?:^|\/)supabase\/config\.toml$/.test(entry.path));
  if (config !== undefined) {
    let current: string | undefined;
    for (const raw of config.content.split('\n')) {
      const line = raw.trim();
      const section = /^\[functions\.([^\]]+)\]$/.exec(line);
      if (section !== null) {
        current = section[1];
        continue;
      }
      if (/^\[/.test(line)) {
        current = undefined;
        continue;
      }
      const verify = /^verify_jwt\s*=\s*(true|false)\b/.exec(line);
      if (verify !== null && current !== undefined) configured.set(current, verify[1] === 'true');
    }
  }

  return [...entryByName.entries()]
    .map(([name, filePath]): SupabaseFunctionAuth => {
      const declared = configured.get(name);
      return {
        name,
        filePath,
        verifyJwt: declared ?? true,
        source: declared === undefined ? 'supabase-default' : 'config.toml',
      };
    })
    .sort((a, b) => a.name.localeCompare(b.name));
}
