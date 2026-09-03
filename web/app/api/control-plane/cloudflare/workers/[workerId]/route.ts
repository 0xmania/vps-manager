import { proxyControlPlane } from '@/lib/control-plane-route';

type RouteContext = { params: Promise<{ workerId: string }> };

export async function GET(_request: Request, context: RouteContext) {
  const { workerId } = await context.params;
  return proxyControlPlane(
    `/api/v1/cloudflare/workers/${encodeURIComponent(workerId)}`,
  );
}
