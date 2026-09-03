import { proxyJSONMutation } from '@/lib/control-plane-json';

type RouteContext = {
  params: Promise<{ workerId: string; deploymentId: string }>;
};

export async function POST(request: Request, context: RouteContext) {
  const { workerId, deploymentId } = await context.params;
  return proxyJSONMutation(
    request,
    `/api/v1/cloudflare/workers/${encodeURIComponent(workerId)}/deployments/${encodeURIComponent(deploymentId)}/execute`,
    1024,
    {
      method: 'POST',
      signal: AbortSignal.timeout(75_000),
    },
  );
}
