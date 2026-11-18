import { prisma } from '../../../../lib/prisma';

export async function POST(request: Request) {
  const body = await request.json();
  await prisma.setting.update({ where: { id: body.id }, data: { value: body.value } });
  return Response.json({ ok: true });
}
