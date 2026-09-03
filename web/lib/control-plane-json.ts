import { getChatGPTUser } from '@/app/chatgpt-auth';
import {
  jsonError,
  proxyControlPlaneForUser,
  sameOriginMutation,
} from '@/lib/control-plane-route';
import { readLimitedBody } from '@/lib/request-body';

type JSONMutationResult =
  | { ok: true; body: string }
  | { ok: false; response: Response };

async function readJSONBody(
  request: Request,
  maxBodyBytes: number,
): Promise<JSONMutationResult> {
  if (!sameOriginMutation(request)) {
    return {
      ok: false,
      response: jsonError(403, 'csrf_rejected', '请求来源校验失败'),
    };
  }

  if (
    request.headers.get('content-type')?.split(';', 1)[0] !== 'application/json'
  ) {
    return {
      ok: false,
      response: jsonError(415, 'unsupported_media_type', '仅接受 JSON 请求'),
    };
  }

  const declaredLength = Number(request.headers.get('content-length') ?? 0);
  if (!Number.isFinite(declaredLength) || declaredLength > maxBodyBytes) {
    return {
      ok: false,
      response: jsonError(413, 'payload_too_large', '请求体过大'),
    };
  }

  const bytes = await readLimitedBody(request, maxBodyBytes);
  if (bytes === null) {
    return {
      ok: false,
      response: jsonError(413, 'payload_too_large', '请求体过大'),
    };
  }

  let body: string;
  try {
    body = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return {
      ok: false,
      response: jsonError(400, 'invalid_encoding', '请求必须使用 UTF-8 编码'),
    };
  }

  return { ok: true, body };
}

export async function proxyJSONMutation(
  request: Request,
  path: string,
  maxBodyBytes: number,
  init: RequestInit = {},
) {
  const user = await getChatGPTUser();
  if (!user) return jsonError(401, 'unauthorized', '请先登录');

  const input = await readJSONBody(request, maxBodyBytes);
  if (!input.ok) return input.response;

  const headers = new Headers(init.headers);
  headers.set('content-type', 'application/json');
  return proxyControlPlaneForUser(user, path, {
    ...init,
    method: init.method ?? request.method,
    headers,
    body: input.body,
  });
}
