import { supabaseAdmin } from '../../../../lib/supabaseAdmin';

// Insecure on purpose: admin mutation, no auth, delete filtered only by id.
export async function DELETE(request: Request) {
  const { id } = (await request.json()) as { id: string };
  await supabaseAdmin.from('users').delete().eq('id', id);
  return Response.json({ ok: true });
}
