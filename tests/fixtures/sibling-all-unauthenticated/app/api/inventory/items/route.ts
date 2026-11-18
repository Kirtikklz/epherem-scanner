import { prisma } from '../../../../lib/prisma';

export async function POST(request: Request) {
  const body = await request.json();
  await prisma.items.create({ data: { name: body.name } });
  return Response.json({ ok: true });
}
