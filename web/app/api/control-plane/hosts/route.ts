import { proxyJSONMutation } from '@/lib/control-plane-json';
import { proxyControlPlane } from '@/lib/control-plane-route';

const maxBodyBytes = 64 * 1024;

export async function GET() {
  return proxyControlPlane('/api/v1/hosts');
}

export async function POST(request: Request) {
  return proxyJSONMutation(request, '/api/v1/hosts', maxBodyBytes);
}
