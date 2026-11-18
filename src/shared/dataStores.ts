import type { RuleContext } from './types.js';

const CODE = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);
const MONGO_PACKAGES = ['mongodb', 'mongoose', 'mongojs', '@mongodb-js/', 'connect-mongo', 'mongoist'];

export function projectUsesMongo(context: Pick<RuleContext, 'fileMap'>): boolean {
  for (const entry of context.fileMap.entries) {
    const name = entry.path.toLowerCase();
    if (name.endsWith('package.json')) {
      for (const pkg of MONGO_PACKAGES) {
        if (new RegExp(`"${pkg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}[^"]*"\\s*:`).test(entry.content)) return true;
      }
    }
    if (name.endsWith('requirements.txt') && /^\s*(pymongo|motor|mongoengine)\b/im.test(entry.content)) return true;
  }
  for (const entry of context.fileMap.entries) {
    if (!CODE.has(entry.extension)) continue;
    if (/\b(?:from|require\s*\()\s*['"](?:mongodb|mongoose|mongojs|mongoist)['"]/.test(entry.content)) return true;
  }
  return false;
}
