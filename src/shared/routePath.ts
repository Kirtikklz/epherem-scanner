export const PARAM = ':param';

export function normalise(segment: string): string {
  return segment.toLowerCase().replace(/[-_]/g, '');
}

export function segments(path: string): string[] {
  const out: string[] = [];
  const collapsed = path.replace(/\$\{[^}]*\}/g, PARAM);
  for (const raw of collapsed.split(/[/.]/)) {
    const trimmed = raw.trim();
    if (trimmed === '') continue;
    if (trimmed.startsWith(':') || trimmed === PARAM) out.push(PARAM);
    else out.push(normalise(trimmed));
  }
  return out;
}

const WEBHOOK_OR_CRON_SEGMENT = new Set(['webhook', 'webhooks', 'hook', 'hooks', 'cron', 'crons', 'cronjob', 'cronjobs']);

export function hasWebhookOrCronSegment(path: string): boolean {
  return segments(path).some((segment) => WEBHOOK_OR_CRON_SEGMENT.has(segment));
}
