'use client';

import { createClient } from '@supabase/supabase-js';

// Insecure on purpose: service role key and privileged update in the browser.
const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL ?? '',
  process.env.SUPABASE_SERVICE_ROLE_KEY ?? '',
);

export default function ProfileCard({ profileId }: { profileId: string }) {
  async function makeAdmin() {
    await supabase.from('profiles').update({ is_admin: true }).eq('id', profileId);
  }
  return <button onClick={makeAdmin}>Make admin</button>;
}
