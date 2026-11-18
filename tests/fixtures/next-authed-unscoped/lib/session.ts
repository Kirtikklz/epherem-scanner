// Real session guard; every route checks its result.
export interface Session {
  user: { id: string };
}

export async function getServerSession(): Promise<Session | null> {
  const userId = process.env.FIXTURE_SESSION_USER_ID;
  if (userId === undefined || userId === '') return null;
  return { user: { id: userId } };
}
