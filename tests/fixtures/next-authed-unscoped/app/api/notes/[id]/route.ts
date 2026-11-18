import { prisma } from '../../../../lib/prisma';
import { getServerSession } from '../../../../lib/session';

// Authenticated but unscoped: any signed-in user can read or delete any note.
export async function GET(request: Request, { params }: { params: { id: string } }) {
  const session = await getServerSession();
  if (!session) {
    return new Response('Unauthorized', { status: 401 });
  }

  // Bug: session.user.id is unused.
  const note = await prisma.note.findUnique({ where: { id: params.id } });
  return Response.json(note);
}

export async function DELETE(request: Request, { params }: { params: { id: string } }) {
  const session = await getServerSession();
  if (!session) {
    return new Response('Unauthorized', { status: 401 });
  }

  // Bug: deletes by id alone.
  await prisma.note.delete({ where: { id: params.id } });
  return Response.json({ ok: true });
}
