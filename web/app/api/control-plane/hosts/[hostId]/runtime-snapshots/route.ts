import {
  jsonError,
  proxyControlPlane,
  sameOriginMutation,
} from '@/lib/control-plane-route';

type RouteContext = { params: Promise<{ hostId: string }> };

export async function POST(request: Request, context: RouteContext) {
  if (!sameOriginMutation(request)) {
    return jsonError(403, 'csrf_rejected', '请求来源校验失败');
  }
  const { hostId } = await context.params;
  return proxyControlPlane(
    `/api/v1/hosts/${encodeURIComponent(hostId)}/runtime-snapshots`,
    { method: 'POST' },
  );
}
