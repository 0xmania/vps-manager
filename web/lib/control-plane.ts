import type { ChatGPTUser } from '@/app/chatgpt-auth';
import { issueIdentityBridgeSession } from '@/lib/identity-bridge';

const allowedDevRoles = new Set(['viewer', 'operator', 'admin', 'auditor']);
const developmentSessions = new Map<
  string,
  { token: string; expiresAt: number }
>();

export class ControlPlaneUnavailableError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'ControlPlaneUnavailableError';
  }
}

function controlPlaneBaseUrl(): URL {
  const configured = process.env.CONTROL_PLANE_URL;
  if (!configured) {
    throw new ControlPlaneUnavailableError(
      'CONTROL_PLANE_URL is not configured',
    );
  }

  let url: URL;
  try {
    url = new URL(configured);
  } catch {
    throw new ControlPlaneUnavailableError('CONTROL_PLANE_URL is invalid');
  }
  if (
    !['http:', 'https:'].includes(url.protocol) ||
    url.username ||
    url.password ||
    url.pathname !== '/' ||
    url.search ||
    url.hash
  ) {
    throw new ControlPlaneUnavailableError(
      'CONTROL_PLANE_URL must be an HTTP(S) origin',
    );
  }
  return url;
}

async function issueDevelopmentSession(user: ChatGPTUser, baseUrl: URL) {
  const bootstrap = process.env.CONTROL_PLANE_DEV_BOOTSTRAP;
  if (!bootstrap || bootstrap.length < 32) {
    throw new ControlPlaneUnavailableError(
      'The local control-plane development bridge is disabled',
    );
  }

  const configuredRole = process.env.CONTROL_PLANE_DEV_ROLE;
  if (!configuredRole || !allowedDevRoles.has(configuredRole)) {
    throw new ControlPlaneUnavailableError('CONTROL_PLANE_DEV_ROLE is invalid');
  }

  const cacheKey = `${baseUrl.origin}\u0000${configuredRole}\u0000${user.userId}`;
  const now = Date.now();
  const cached = developmentSessions.get(cacheKey);
  if (cached && cached.expiresAt > now + 10_000) return cached.token;

  const response = await fetch(new URL('/api/v1/dev/sessions', baseUrl), {
    method: 'POST',
    cache: 'no-store',
    headers: {
      'content-type': 'application/json',
      'x-dev-bootstrap': bootstrap,
    },
    body: JSON.stringify({
      subject: `sites:${user.userId}`.slice(0, 128),
      role: configuredRole,
      allHosts: true,
    }),
    signal: AbortSignal.timeout(4_000),
  });

  if (!response.ok) {
    throw new ControlPlaneUnavailableError(
      `The local control plane rejected the development bridge (${response.status})`,
    );
  }

  const payload = (await response.json()) as {
    token?: unknown;
    expiresAt?: unknown;
  };
  if (typeof payload.token !== 'string' || payload.token.length < 32) {
    throw new ControlPlaneUnavailableError(
      'The local control plane returned an invalid session',
    );
  }
  const expiresAt =
    typeof payload.expiresAt === 'string'
      ? Date.parse(payload.expiresAt)
      : Number.NaN;
  if (!Number.isFinite(expiresAt) || expiresAt <= now + 10_000) {
    throw new ControlPlaneUnavailableError(
      'The local control plane returned an invalid session',
    );
  }
  developmentSessions.set(cacheKey, {
    token: payload.token,
    expiresAt,
  });
  if (developmentSessions.size > 128) {
    for (const [key, session] of developmentSessions) {
      if (session.expiresAt <= now) developmentSessions.delete(key);
    }
    while (developmentSessions.size > 128) {
      const oldestKey = developmentSessions.keys().next().value;
      if (typeof oldestKey !== 'string') break;
      developmentSessions.delete(oldestKey);
    }
  }
  return payload.token;
}

export async function controlPlaneFetch(
  user: ChatGPTUser,
  path: string,
  init: RequestInit = {},
) {
  if (!path.startsWith('/') || path.startsWith('//')) {
    throw new TypeError(
      'Control-plane path must be relative to its configured origin',
    );
  }

  const baseUrl = controlPlaneBaseUrl();
  let token: string;
  try {
    const productionSession = await issueIdentityBridgeSession(user, baseUrl);
    token =
      productionSession?.token ??
      (await issueDevelopmentSession(user, baseUrl));
  } catch (error) {
    if (error instanceof ControlPlaneUnavailableError) throw error;
    throw new ControlPlaneUnavailableError(
      'The control-plane identity bridge is unavailable',
      { cause: error },
    );
  }
  const headers = new Headers(init.headers);
  headers.set('authorization', `Bearer ${token}`);
  headers.set('accept', 'application/json');

  try {
    return await fetch(new URL(path, baseUrl), {
      ...init,
      headers,
      cache: 'no-store',
      signal: init.signal ?? AbortSignal.timeout(10_000),
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === 'TimeoutError') {
      throw error;
    }
    throw new ControlPlaneUnavailableError(
      'The control plane is unavailable',
      { cause: error },
    );
  }
}
