import { proxyJSONMutation } from '@/lib/control-plane-json';
import { proxyControlPlane } from '@/lib/control-plane-route';

type RouteContext = { params: Promise<{ workerId: string }> };

export async function GET(_request: Request, context: RouteContext) {
  const { workerId } = await context.params;
  return proxyControlPlane(
    `/api/v1/cloudflare/workers/${encodeURIComponent(workerId)}/deployments`,
  );
}

export async function POST(request: Request, context: RouteContext) {
  const { workerId } = await context.params;
  return proxyJSONMutation(
    request,
    `/api/v1/cloudflare/workers/${encodeURIComponent(workerId)}/deployments`,
    16 * 1024,
    { method: 'POST' },
  );
}
