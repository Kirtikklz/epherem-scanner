import { describe, expect, it } from 'vitest';
import { missingWebhookVerification } from '../../src/rules/contextual/missingWebhookVerification.js';
import { memoryContext } from './helpers.js';

const PKG: [string, string] = ['package.json', '{"name":"x","dependencies":{"next":"14.0.0"}}'];
const run = (code: string) => missingWebhookVerification.run(memoryContext([PKG, ['app/api/webhook/stripe/route.ts', code]]));

describe('missing_webhook_verification (keyword != verification)', () => {
  it('reading the signature header without verifying is still flagged', () => {
    expect(
      run('export async function POST(req){ const sig = req.headers.get("stripe-signature"); const event = await req.json(); return Response.json({ received: true, sig }); }\n'),
    ).toHaveLength(1);
  });
  it('an actual constructEvent verification is safe', () => {
    expect(
      run('import Stripe from "stripe";\nconst stripe = new Stripe(process.env.SK);\nexport async function POST(req){ const sig = req.headers.get("stripe-signature"); const event = stripe.webhooks.constructEvent(await req.text(), sig, process.env.WHSEC); return Response.json({ received: true }); }\n'),
    ).toHaveLength(0);
  });
  it('does not let verification in one handler suppress an unsafe sibling handler', () => {
    expect(run([
      'export async function GET(req){ stripe.webhooks.constructEvent(await req.text(), "sig", "secret"); }',
      'export async function POST(req){ const payload = await req.json(); return Response.json(payload); }',
    ].join('\n'))).toHaveLength(1);
  });
});

describe('missing_webhook_verification effective proof', () => {
  it('does not trust an always-true verifyWebhook helper', () => {
    expect(run('function verifyWebhook(){ return true; }\nexport async function POST(req){ const sig = req.headers.get("stripe-signature"); const payload = await req.json(); verifyWebhook(payload, sig); await db.payment.create({ data: payload }); return Response.json({ ok: true }); }\n')).toHaveLength(1);
  });

  it('flags business processing before verification', () => {
    expect(run('export async function POST(req){ const sig = req.headers.get("stripe-signature"); const raw = await req.text(); await db.payment.create({ data: {} }); stripe.webhooks.constructEvent(raw, sig, process.env.WHSEC); return Response.json({ ok: true }); }\n')).toHaveLength(1);
  });
});
