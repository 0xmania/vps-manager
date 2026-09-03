import { proxyJSONMutation } from '@/lib/control-plane-json';
import {
  proxyControlPlane,
  proxySameOriginMutation,
} from '@/lib/control-plane-route';

type RouteContext = { params: Promise<{ hostId: string }> };

export async function GET(_request: Request, context: RouteContext) {
  const { hostId } = await context.params;
  return proxyControlPlane(
    `/api/v1/hosts/${encodeURIComponent(hostId)}/credential`,
  );
}

export async function POST(request: Request, context: RouteContext) {
  const { hostId } = await context.params;
  return proxyJSONMutation(
    request,
    `/api/v1/hosts/${encodeURIComponent(hostId)}/credential`,
    272 * 1024,
    { method: 'POST' },
  );
}

export async function DELETE(request: Request, context: RouteContext) {
  const { hostId } = await context.params;
  return proxySameOriginMutation(
    request,
    `/api/v1/hosts/${encodeURIComponent(hostId)}/credential`,
    { method: 'DELETE' },
  );
}
