import { getServerSession } from 'next-auth';
import { prisma } from '../../../../lib/prisma';

export async function POST(request: Request) {
  const session = await getServerSession();
  if (!session) return new Response('Unauthorized', { status: 401 });
  const body = await request.json();
  await prisma.user.create({ data: { name: body.name } });
  return Response.json({ ok: true });
}
