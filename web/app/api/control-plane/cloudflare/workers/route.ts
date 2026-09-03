import { proxyJSONMutation } from '@/lib/control-plane-json';
import { proxyControlPlane } from '@/lib/control-plane-route';

export async function GET() {
  return proxyControlPlane('/api/v1/cloudflare/workers');
}

export async function POST(request: Request) {
  return proxyJSONMutation(request, '/api/v1/cloudflare/workers', 32 * 1024, {
    method: 'POST',
  });
}
