import { proxyControlPlane } from '@/lib/control-plane-route';

export async function GET() {
  return proxyControlPlane('/api/v1/audit-events?limit=20');
}
