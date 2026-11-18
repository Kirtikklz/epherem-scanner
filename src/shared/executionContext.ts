import type { FileMapEntry } from './types.js';

const SERVICE_WORKER_LIFECYCLE =
  /(?<![.\w$])skipWaiting\s*\(|\bself\s*\.\s*skipWaiting\b|\bclients\s*\.\s*claim\s*\(|\bServiceWorkerGlobalScope\b|\bself\s*\.\s*registration\b/;

const SERVICE_WORKER_BEHAVIOUR = /\bcaches\s*\.\s*(?:open|match|keys|delete)\s*\(|\brespondWith\s*\(/;

export function isBrowserServiceWorker(entry: Pick<FileMapEntry, 'content'>): boolean {
  return SERVICE_WORKER_LIFECYCLE.test(entry.content) && SERVICE_WORKER_BEHAVIOUR.test(entry.content);
}
