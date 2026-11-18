import { describe, expect, it } from 'vitest';
import { apiMutationWithoutAuth } from '../../src/rules/contextual/apiMutationWithoutAuth.js';
import { missingWebhookVerification } from '../../src/rules/contextual/missingWebhookVerification.js';
import { memoryContext } from './helpers.js';

const NEXT_PKG: [string, string] = ['package.json', '{"name":"x","dependencies":{"next":"14.0.0"}}'];
const run = (files: [string, string][]) => apiMutationWithoutAuth.run(memoryContext([NEXT_PKG, ...files]));

const VERIFIED_WEBHOOK = [
  'import Stripe from "stripe";',
  'const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);',
  'export async function POST(request){',
  '  const payload = await request.text();',
  '  const sig = request.headers.get("stripe-signature");',
  '  let event;',
  '  try { event = stripe.webhooks.constructEvent(payload, sig, process.env.STRIPE_WEBHOOK_SECRET); }',
  '  catch (err) { return Response.json({ message: "bad signature" }, { status: 400 }); }',
  '  await handleSubscriptionCreated(event.data.object);',
  '  return Response.json({ received: true });',
  '}',
  'async function handleSubscriptionCreated(subscription){',
  '  await supabase.from("subscriptions").insert([{ id: subscription.id }]);',
  '  await supabase.from("billing_events").update({ done: true }).eq("id", subscription.id);',
  '}',
].join('\n');

const UNVERIFIED_WEBHOOK = [
  'export async function POST(request){',
  '  const event = await request.json();',
  '  await supabase.from("subscriptions").insert([{ id: event.id }]);',
  '  return Response.json({ received: true });',
  '}',
].join('\n');

const PLAIN_CRUD = [
  'export async function POST(request){',
  '  const body = await request.json();',
  '  await supabase.from("items").insert([body]);',
  '  return Response.json({ ok: true });',
  '}',
].join('\n');

describe('api_mutation_without_auth exempts signature-verified webhooks', () => {
  it('clears a webhook that verifies its signature before mutating, helpers included', () => {
    expect(run([['app/api/webhooks/stripe/route.ts', VERIFIED_WEBHOOK]])).toHaveLength(0);
  });

  it('clears a signature-verified webhook that lives at an ORDINARY path', () => {
    expect(run([['app/api/stripe/route.ts', VERIFIED_WEBHOOK]])).toHaveLength(0);
  });

  it('leaves an UNVERIFIED webhook to missing_webhook_verification, and does not double-report it', () => {
    const files: [string, string][] = [['app/api/webhooks/stripe/route.ts', UNVERIFIED_WEBHOOK]];
    expect(missingWebhookVerification.run(memoryContext([NEXT_PKG, ...files]))).toHaveLength(1);
    expect(run(files)).toHaveLength(0);
  });

  it('still flags a plain unauthenticated CRUD route', () => {
    expect(run([['app/api/items/route.ts', PLAIN_CRUD]]).length).toBeGreaterThan(0);
  });

  it('does not exempt a route merely because the word "signature" appears', () => {
    const eSignature = PLAIN_CRUD.replace('const body', 'const signature = request.headers.get("x-signature");\n  const body');
    expect(run([['app/api/documents/route.ts', eSignature]]).length).toBeGreaterThan(0);
  });

  it('does not exempt a path that merely CONTAINS the word webhook', () => {
    expect(run([['app/api/webhookish/route.ts', PLAIN_CRUD]]).length).toBeGreaterThan(0);
  });
});
