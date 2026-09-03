import { proxySameOriginMutation } from '@/lib/control-plane-route';

type RouteContext = { params: Promise<{ hostId: string }> };

export async function POST(request: Request, context: RouteContext) {
  const { hostId } = await context.params;
  return proxySameOriginMutation(
    request,
    `/api/v1/hosts/${encodeURIComponent(hostId)}/host-key/probe`,
    { signal: AbortSignal.timeout(15_000) },
  );
}
