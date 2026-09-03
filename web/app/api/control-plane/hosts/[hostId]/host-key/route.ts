import { proxyJSONMutation } from '@/lib/control-plane-json';

const maxBodyBytes = 32 * 1024;
type RouteContext = { params: Promise<{ hostId: string }> };

export async function PUT(request: Request, context: RouteContext) {
  const { hostId } = await context.params;
  return proxyJSONMutation(
    request,
    `/api/v1/hosts/${encodeURIComponent(hostId)}/host-key`,
    maxBodyBytes,
  );
}
