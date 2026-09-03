import { proxyJSONMutation } from '@/lib/control-plane-json';

type RouteContext = { params: Promise<{ jobId: string }> };

export async function POST(request: Request, context: RouteContext) {
  const { jobId } = await context.params;
  return proxyJSONMutation(
    request,
    `/api/v1/jobs/${encodeURIComponent(jobId)}/runbook-execute`,
    8 * 1024,
    {
      method: 'POST',
      signal: AbortSignal.timeout(105_000),
    },
  );
}
