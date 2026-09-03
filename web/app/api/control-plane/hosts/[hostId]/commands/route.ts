import { proxyJSONMutation } from '@/lib/control-plane-json';

type RouteContext = { params: Promise<{ hostId: string }> };

export async function POST(request: Request, context: RouteContext) {
  const { hostId } = await context.params;
  return proxyJSONMutation(
    request,
    `/api/v1/hosts/${encodeURIComponent(hostId)}/commands`,
    16 * 1024,
    { method: 'POST' },
  );
}
