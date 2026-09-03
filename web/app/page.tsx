import { redirect } from 'next/navigation';

import { chatGPTSignOutPath, getChatGPTUser } from './chatgpt-auth';
import { DashboardShell } from './dashboard-shell';

export const dynamic = 'force-dynamic';

export default async function Home() {
  const user = await getChatGPTUser();
  if (!user) redirect('/login');

  return (
    <DashboardShell
      user={{
        displayName: user.displayName,
        email: user.email,
      }}
      signOutHref={chatGPTSignOutPath('/')}
    />
  );
}
