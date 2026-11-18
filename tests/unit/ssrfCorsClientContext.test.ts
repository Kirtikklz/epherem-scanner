import { describe, expect, it } from 'vitest';
import { serverSideRequestForgery } from '../../src/rules/basic/ssrf.js';
import { dangerousCorsWildcard } from '../../src/rules/basic/dangerousCorsWildcard.js';
import { memoryContext } from './helpers.js';

const ssrfOn = (files: [string, string][]): ReturnType<typeof serverSideRequestForgery.run> =>
  serverSideRequestForgery.run(memoryContext(files));
const corsOn = (files: [string, string][]): ReturnType<typeof dangerousCorsWildcard.run> =>
  dangerousCorsWildcard.run(memoryContext(files));

describe('ssrf: execution context', () => {
  it('stays silent in a browser service worker', () => {
    const worker = `
      self.addEventListener('install', (event) => { self.skipWaiting(); });
      self.addEventListener('activate', (event) => { event.waitUntil(clients.claim()); });
      self.addEventListener('fetch', (event) => {
        event.respondWith(
          caches.match(event.request).then((cached) => cached || fetch(event.request))
        );
      });
    `;
    expect(ssrfOn([['public/sw.js', worker]])).toHaveLength(0);
  });

  it('STILL fires in a Cloudflare Worker, which registers a fetch listener the same way', () => {
    const cfWorker = `
      addEventListener('fetch', (event) => {
        const target = new URL(event.request.url).searchParams.get('url');
        event.respondWith(fetch(target));
      });
    `;
    expect(ssrfOn([['worker/src/index.js', cfWorker]]).length).toBeGreaterThan(0);
  });
});

describe('ssrf: a handler signature is not an outbound call', () => {
  it('stays silent on the Cloudflare Worker entrypoint signature', () => {
    const entry = `
      export default {
        async fetch(request, env, ctx): Promise<Response> {
          const url = new URL(request.url);
          return env.ASSETS.fetch(request);
        }
      };
    `;
    expect(ssrfOn([['worker/src/index.ts', entry]])).toHaveLength(0);
  });

  it('stays silent on an untyped handler signature and on a stub in a test file', () => {
    const stub = `
      export default { async fetch(request) { return new Response('ok'); } };
    `;
    expect(ssrfOn([['worker/src/checkout.test.mjs', stub]])).toHaveLength(0);
  });

  it('STILL fires on a real outbound call inside the same entrypoint', () => {
    const entry = `
      export default {
        async fetch(request, env) {
          const target = new URL(request.url).searchParams.get('next');
          return fetch(target);
        }
      };
    `;
    expect(ssrfOn([['worker/src/index.ts', entry]]).length).toBeGreaterThan(0);
  });

  it('STILL fires on a call that merely SITS in a declaration position', () => {
    const entry = `
      export default {
        async fetch(request, env) {
          const target = new URL(request.url).searchParams.get('next');
          fetch(target);
          return new Response('queued');
        }
      };
    `;
    expect(ssrfOn([['worker/src/index.ts', entry]]).length).toBeGreaterThan(0);
  });
});

describe('ssrf: a name this file defines is not an HTTP client', () => {
  it('stays silent when the file declares the helper itself', () => {
    const test = `
      async function request(query: string) {
        return handler(new Request('http://test/api/oauth/authorize?' + query));
      }
      const a = await request(authorizeQuery({ scope: 'read' }));
      const b = await request(authorizeQuery({ scope: req.query.scope }));
    `;
    expect(ssrfOn([['tests/integration/oauth.integration.test.ts', test]])).toHaveLength(0);
  });

  it('STILL fires when the name is imported from a real client', () => {
    const real = `
      import request from 'request';
      export async function proxy(req) { return request(req.query.url); }
    `;
    expect(ssrfOn([['server/proxy.ts', real]]).length).toBeGreaterThan(0);
  });

  it('STILL fires when the file BOTH imports the client and binds the name locally', () => {
    const both = `
      import request from 'request';
      export async function proxy(req) {
        const target = req.query.url;
        return request(target);
      }
      export function makeLocalTransport() {
        const request = (u) => localTransport(u);
        return request;
      }
    `;
    expect(ssrfOn([['server/proxy.ts', both]]).length).toBeGreaterThan(0);
  });
});

describe('ssrf: the destination credit follows one binding', () => {
  it('stays silent on a fixed host reached through new URL(...) and .toString()', () => {
    const client = `
      const SPANSH_BASE = 'https://spansh.co.uk/api';
      export async function search(options) {
        const url = new URL(\`\${SPANSH_BASE}/search\`);
        url.searchParams.set('q', options.q);
        const res = await fetch(url.toString(), { headers: { Accept: 'application/json' } });
        return res.json();
      }
    `;
    expect(ssrfOn([['src/lib/server/spansh.ts', client]])).toHaveLength(0);
  });

  it('stays silent on a root-relative path, which carries no authority', () => {
    const svc = `
      export async function search(params, req) {
        const response = await fetch(\`/api/products/search?\${new URLSearchParams(req.query).toString()}\`);
        return response.json();
      }
    `;
    expect(ssrfOn([['src/lib/services/products.ts', svc]])).toHaveLength(0);
  });

  it('STILL fires on a protocol-relative head, which leaves the origin', () => {
    const svc = `
      export async function go(req) {
        const response = await fetch(\`//\${req.query.host}/api\`);
        return response.json();
      }
    `;
    expect(ssrfOn([['src/lib/services/go.ts', svc]]).length).toBeGreaterThan(0);
  });

  it('STILL fires when the base of new URL(path, base) is the request Host header', () => {
    const wake = `import { WORKER_PATH } from '../../server/utils/notification-worker-dispatch'

export default async (request: Request) => {
  const response = await fetch(new URL(WORKER_PATH, request.url), {
    method: 'POST',
    body: JSON.stringify({ wakeAll: true }),
  })
  if (!response.ok) throw new Error('worker failed')
  return new Response(null, { status: 204 })
}
`;
    expect(ssrfOn([['netlify/functions/notifications-wake.ts', wake]]).length).toBeGreaterThan(0);

    const relativePath = `export default async (request: Request) => {
  const id = new URL(request.url).searchParams.get('id')
  const r = await fetch(new URL(\`/api/items/\${id}\`, request.url), { method: 'POST' })
  return r
}
`;
    expect(ssrfOn([['netlify/functions/wake2.ts', relativePath]]).length).toBeGreaterThan(0);
  });

  it('STILL fires when one assignment to the credited identifier is request input', () => {
    const mixed = `
      const API_BASE = 'https://api.example.com';
      export async function handler(req) {
        let url = API_BASE + '/v1/items';
        url = req.query.target;
        const res = await fetch(url);
        return res.json();
      }
    `;
    expect(ssrfOn([['server/handler.ts', mixed]]).length).toBeGreaterThan(0);
  });

  it('STILL fires when the credited identifier has no readable assignment at all', () => {
    const forward = `
      import fetch from 'node-fetch';
      export async function forward(req, targetUrl) {
        const body = req.body;
        const res = await fetch(targetUrl, { method: 'POST', body });
        return res.text();
      }
    `;
    expect(ssrfOn([['server/proxy.ts', forward]]).length).toBeGreaterThan(0);
  });

  it('STILL fires when the identifier is bound by destructuring the request URL', () => {
    const callback = `
      export async function GET(request) {
        const { searchParams, origin } = new URL(request.url);
        await fetch(\`\${origin}/api/auth/ensure-profile\`, { method: 'POST' });
        return new Response('ok');
      }
    `;
    expect(ssrfOn([['app/api/auth/callback/route.ts', callback]]).length).toBeGreaterThan(0);
  });
});

describe('dangerous_cors_wildcard: credentials and allowlists', () => {
  const wildcard = (extra = '') => `
    export default async function handler(req, res) {
      res.setHeader('Access-Control-Allow-Origin', '*');
      ${extra}
      res.end('ok');
    }
  `;

  it('STILL fires, at low, naming the evidence, when Allow-Credentials is set alongside the literal wildcard', () => {
    const findings = corsOn([['server/api/x.ts', wildcard("res.setHeader('Access-Control-Allow-Credentials', 'true');")]]);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]?.severity).toBe('low');
    expect(findings[0]?.technicalExplanation).toContain('this file sets Access-Control-Allow-Credentials: true');
  });

  it('STILL fires, at low under the ordinary title, on cors({ origin: "*", credentials: true })', () => {
    const app = `
      import cors from 'cors';
      app.use(cors({ origin: '*', credentials: true }));
    `;
    const findings = corsOn([['server.js', app]]);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]?.severity).toBe('low');
    expect(findings[0]?.title).toBe('CORS allows all origins');
  });

  it('goes to low - NOT silent - on a Bearer-only wildcard with no credentials', () => {
    const findings = corsOn([['server/api/x.ts', wildcard("const token = req.headers.authorization;")]]);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]?.severity).toBe('low');
  });

  it('goes silent when the handler validates Origin against an explicit allowlist', () => {
    const guarded = `
      const ALLOWED_ORIGINS = ['https://app.example.com', 'https://admin.example.com'];
      export default async function handler(request) {
        const origin = request.headers.get('origin');
        if (!ALLOWED_ORIGINS.includes(origin)) {
          return new Response('forbidden', { status: 403 });
        }
        return new Response('ok', { headers: { 'Access-Control-Allow-Origin': '*' } });
      }
    `;
    expect(corsOn([['api/submit.ts', guarded]])).toHaveLength(0);
  });

  it('STILL fires when an allowlist is TESTED but the request Origin is never read', () => {
    const named = `
      const ALLOWED_ORIGINS = ['https://app.example.com'];
      export default async function handler(req, res) {
        if (!ALLOWED_ORIGINS.includes(req.query.site)) return res.status(403).end();
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.end('ok');
      }
    `;
    expect(corsOn([['server/api/x.ts', named]]).length).toBeGreaterThan(0);
  });

  it('an edge function that reads cookies ITSELF still counts as credentials evidence', () => {
    const app = `import { createServerClient } from '@supabase/ssr'; export const c = createServerClient();`;
    const edge = `
      const corsHeaders = { 'Access-Control-Allow-Origin': '*' };
      Deno.serve(async (req) => {
        const sid = req.cookies['session'];
        return new Response('ok', { headers: corsHeaders });
      });
    `;
    const findings = corsOn([['src/lib/supabase.ts', app], ['supabase/functions/f/index.ts', edge]]);
    const edgeFinding = findings.find((f) => f.filePath === 'supabase/functions/f/index.ts');
    expect(edgeFinding?.severity).toBe('low');
    expect(edgeFinding?.userExplanation).toContain('Your project signs users in with cookies');
  });

  it('a Supabase edge function does not inherit the web app’s cookie session', () => {
    const app = `import { createServerClient } from '@supabase/ssr'; export const c = createServerClient();`;
    const edge = `
      const corsHeaders = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'authorization' };
      Deno.serve(async (req) => {
        const auth = req.headers.get('Authorization');
        return new Response('ok', { headers: corsHeaders });
      });
    `;
    const findings = corsOn([['src/lib/supabase.ts', app], ['supabase/functions/heart-ai/index.ts', edge]]);
    const edgeFinding = findings.find((f) => f.filePath === 'supabase/functions/heart-ai/index.ts');
    expect(edgeFinding).toBeDefined();
    expect(edgeFinding?.severity).toBe('low');
  });

  it('an edge function that sets Allow-Credentials ITSELF still counts as credentials evidence', () => {
    const edge = `
      const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': 'true',
      };
      Deno.serve(async (req) => new Response('ok', { headers: corsHeaders }));
    `;
    const findings = corsOn([['supabase/functions/x/index.ts', edge]]);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]?.severity).toBe('low');
    expect(findings[0]?.userExplanation).toContain('Credentials are switched on');
  });

  it('still reports every occurrence - de-duplication is a finding-identity decision, not this rule’s', () => {
    const repeated = `
      const corsHeaders = { 'Access-Control-Allow-Origin': '*' };
      Deno.serve(async (req) => {
        if (req.method === 'OPTIONS') return new Response('ok', { headers: { 'Access-Control-Allow-Origin': '*' } });
        if (req.method === 'PUT') return new Response('no', { headers: { 'Access-Control-Allow-Origin': '*' } });
        return new Response('ok', { headers: { 'Access-Control-Allow-Origin': '*' } });
      });
    `;
    const findings = corsOn([['supabase/functions/receipt-scan/index.ts', repeated]]);
    expect(findings).toHaveLength(4);
    expect(findings.every((f) => f.severity === 'low')).toBe(true);
  });
});
