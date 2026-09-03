import { proxyControlPlane } from '@/lib/control-plane-route';

type RouteContext = { params: Promise<{ jobId: string }> };

export async function GET(_request: Request, context: RouteContext) {
  const { jobId } = await context.params;
  return proxyControlPlane(`/api/v1/jobs/${encodeURIComponent(jobId)}`);
}
