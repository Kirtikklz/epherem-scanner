export const WEBHOOK_SIGNATURE_VERIFIED =
  /\b(?:verif\w*(?:Signature|Webhook|Event)|constructEvent|assertValidSignature|validateSignature|constructWebhookEvent)\s*\(|new\s+Webhook\s*\(|\bsvix\b|standardwebhooks/i;

export const SIGNATURE_HEADER =
  /signature|svix-|webhook-id|webhook-timestamp|x-hub-signature|stripe-signature|polar-signature|clerk-signature|x-supabase-signature/i;
