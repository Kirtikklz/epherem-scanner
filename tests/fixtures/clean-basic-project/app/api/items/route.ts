import { getServerSession } from 'next-auth';

function validateCreateItemBody(value: unknown): { name: string } {
  if (
    typeof value !== 'object' || value === null ||
    !('name' in value) || typeof value.name !== 'string' ||
    value.name.length < 1 || value.name.length > 100
  ) {
    throw new TypeError('Invalid request body');
  }
  return { name: value.name };
}

export async function POST(request: Request) {
  const session = await getServerSession();
  if (!session?.user) {
    return new Response('Unauthorized', { status: 401 });
  }
  const body = validateCreateItemBody(await request.json());
  return Response.json({ created: body.name, owner: session.user.email });
}
