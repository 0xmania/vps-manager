import { getChatGPTUser } from '@/app/chatgpt-auth';
import type { ChatGPTUser } from '@/app/chatgpt-auth';
import {
  controlPlaneFetch,
  ControlPlaneUnavailableError,
} from '@/lib/control-plane';

export function jsonError(status: number, code: string, message: string) {
  return Response.json({ error: { code, message } }, { status });
}

export function sameOriginMutation(request: Request) {
  const origin = request.headers.get('origin');
  return origin !== null && origin === new URL(request.url).origin;
}

async function relay(upstream: Response) {
  const headers = new Headers();
  headers.set(
    'content-type',
    upstream.headers.get('content-type') ?? 'application/json; charset=utf-8',
  );
  const requestId = upstream.headers.get('x-request-id');
  if (requestId) headers.set('x-request-id', requestId);
  return new Response(upstream.body, { status: upstream.status, headers });
}

export async function proxyControlPlane(path: string, init?: RequestInit) {
  const user = await getChatGPTUser();
  if (!user) return jsonError(401, 'unauthorized', '请先登录');

  return proxyControlPlaneForUser(user, path, init);
}

export async function proxySameOriginMutation(
  request: Request,
  path: string,
  init: RequestInit = {},
) {
  if (!sameOriginMutation(request)) {
    return jsonError(403, 'csrf_rejected', '请求来源校验失败');
  }
  return proxyControlPlane(path, {
    ...init,
    method: init.method ?? request.method,
  });
}

export async function proxyControlPlaneForUser(
  user: ChatGPTUser,
  path: string,
  init?: RequestInit,
) {
  try {
    return relay(await controlPlaneFetch(user, path, init));
  } catch (error) {
    if (error instanceof DOMException && error.name === 'TimeoutError') {
      return jsonError(504, 'control_plane_timeout', '控制面请求超时');
    }
    if (error instanceof ControlPlaneUnavailableError) {
      return jsonError(503, 'control_plane_unavailable', '本地控制面尚未连接');
    }
    throw error;
  }
}
