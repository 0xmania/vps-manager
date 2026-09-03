import type { ChatGPTUser } from '@/app/chatgpt-auth';

const allowedRoles = new Set(['viewer', 'operator', 'admin', 'auditor']);
const assertionLifetimeSeconds = 30;
const maxBindingsBytes = 32 << 10;
const maxJwkBytes = 8 << 10;
const encoder = new TextEncoder();

type IdentityBinding = {
  role: 'viewer' | 'operator' | 'admin' | 'auditor';
  allHosts: boolean;
  hostIds: string[];
};

type IdentityConfiguration = {
  issuer: string;
  audience: string;
  keyId: string;
  privateJwk: JsonWebKey;
  binding: IdentityBinding;
};

type CachedSession = { token: string; expiresAt: number };

const sessions = new Map<string, CachedSession>();
let importedKey: { raw: string; key: CryptoKey } | undefined;

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function ownValue(object: Record<string, unknown>, key: string): unknown {
  return Object.prototype.hasOwnProperty.call(object, key)
    ? object[key]
    : undefined;
}

function parseBinding(value: unknown): IdentityBinding {
  if (!record(value)) throw new Error('The identity binding is invalid');
  const allowedFields = new Set(['role', 'allHosts', 'hostIds']);
  if (Object.keys(value).some((key) => !allowedFields.has(key))) {
    throw new Error('The identity binding contains unsupported fields');
  }
  const role = ownValue(value, 'role');
  const allHosts = ownValue(value, 'allHosts');
  const rawHostIds = ownValue(value, 'hostIds') ?? [];
  if (
    typeof role !== 'string' ||
    !allowedRoles.has(role) ||
    typeof allHosts !== 'boolean' ||
    !Array.isArray(rawHostIds) ||
    rawHostIds.length > 256
  ) {
    throw new Error('The identity binding is invalid');
  }
  const hostIds: string[] = [];
  const seen = new Set<string>();
  for (const hostId of rawHostIds) {
    if (
      typeof hostId !== 'string' ||
      !/^host_[A-Za-z0-9_-]{1,123}$/.test(hostId) ||
      seen.has(hostId)
    ) {
      throw new Error('The identity host scope is invalid');
    }
    seen.add(hostId);
    hostIds.push(hostId);
  }
  if (allHosts && hostIds.length > 0) {
    throw new Error('The identity host scope is ambiguous');
  }
  return {
    role: role as IdentityBinding['role'],
    allHosts,
    hostIds,
  };
}

function parseConfiguration(user: ChatGPTUser): IdentityConfiguration | null {
  const issuer = process.env.CONTROL_PLANE_IDENTITY_ISSUER?.trim() ?? '';
  const audience = process.env.CONTROL_PLANE_IDENTITY_AUDIENCE?.trim() ?? '';
  const keyId = process.env.CONTROL_PLANE_IDENTITY_KEY_ID?.trim() ?? '';
  const rawJwk = process.env.CONTROL_PLANE_IDENTITY_PRIVATE_JWK?.trim() ?? '';
  const rawBindings =
    process.env.CONTROL_PLANE_IDENTITY_BINDINGS_JSON?.trim() ?? '';
  const configured = [issuer, audience, keyId, rawJwk, rawBindings].some(
    Boolean,
  );
  if (!configured) return null;
  if (
    !issuer ||
    issuer.length > 256 ||
    !audience ||
    audience.length > 256 ||
    !keyId ||
    keyId.length > 128 ||
    /[\r\n]/.test(keyId) ||
    !rawJwk ||
    rawJwk.length > maxJwkBytes ||
    !rawBindings ||
    rawBindings.length > maxBindingsBytes
  ) {
    throw new Error('The production identity bridge is incomplete');
  }

  let parsedJwk: unknown;
  let bindings: unknown;
  try {
    parsedJwk = JSON.parse(rawJwk);
    bindings = JSON.parse(rawBindings);
  } catch {
    throw new Error('The production identity bridge configuration is invalid');
  }
  if (
    !record(parsedJwk) ||
    parsedJwk.kty !== 'OKP' ||
    parsedJwk.crv !== 'Ed25519' ||
    typeof parsedJwk.x !== 'string' ||
    typeof parsedJwk.d !== 'string' ||
    (parsedJwk.alg !== undefined && parsedJwk.alg !== 'EdDSA') ||
    !record(bindings)
  ) {
    throw new Error('The production identity key or bindings are invalid');
  }

  const byUser = ownValue(bindings, `user:${user.userId}`);
  const byEmail = ownValue(bindings, `email:${user.email.toLowerCase()}`);
  const bindingValue = byUser ?? byEmail;
  if (bindingValue === undefined) {
    throw new Error('The signed-in user has no control-plane binding');
  }
  return {
    issuer,
    audience,
    keyId,
    privateJwk: parsedJwk as JsonWebKey,
    binding: parseBinding(bindingValue),
  };
}

function base64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary)
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/u, '');
}

async function signingKey(rawJwk: string, jwk: JsonWebKey): Promise<CryptoKey> {
  if (importedKey?.raw === rawJwk) return importedKey.key;
  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'Ed25519' },
      false,
      ['sign'],
    );
  } catch {
    throw new Error('The production identity signing key is unusable');
  }
  importedKey = { raw: rawJwk, key };
  return key;
}

async function assertion(
  user: ChatGPTUser,
  configuration: IdentityConfiguration,
): Promise<string> {
  const rawJwk = process.env.CONTROL_PLANE_IDENTITY_PRIVATE_JWK?.trim() ?? '';
  const key = await signingKey(rawJwk, configuration.privateJwk);
  const now = Math.floor(Date.now() / 1000);
  const header = base64Url(
    encoder.encode(
      JSON.stringify({
        alg: 'EdDSA',
        kid: configuration.keyId,
        typ: 'VPSMGR+JWT',
      }),
    ),
  );
  const payload = base64Url(
    encoder.encode(
      JSON.stringify({
        iss: configuration.issuer,
        aud: configuration.audience,
        sub: `sites:${user.userId}`.slice(0, 128),
        role: configuration.binding.role,
        allHosts: configuration.binding.allHosts,
        hostIds: configuration.binding.hostIds,
        iat: now,
        exp: now + assertionLifetimeSeconds,
        jti: crypto.randomUUID(),
      }),
    ),
  );
  const signingInput = `${header}.${payload}`;
  const signature = await crypto.subtle.sign(
    { name: 'Ed25519' },
    key,
    encoder.encode(signingInput),
  );
  return `${signingInput}.${base64Url(new Uint8Array(signature))}`;
}

export async function issueIdentityBridgeSession(
  user: ChatGPTUser,
  baseUrl: URL,
): Promise<CachedSession | null> {
  const configuration = parseConfiguration(user);
  if (!configuration) return null;
  const scope = JSON.stringify(configuration.binding);
  const cacheKey = `${baseUrl.origin}\u0000${configuration.issuer}\u0000${configuration.audience}\u0000${configuration.keyId}\u0000${user.userId}\u0000${scope}`;
  const now = Date.now();
  const cached = sessions.get(cacheKey);
  if (cached && cached.expiresAt > now + 10_000) return cached;

  const signedAssertion = await assertion(user, configuration);
  const response = await fetch(new URL('/api/v1/identity/sessions', baseUrl), {
    method: 'POST',
    cache: 'no-store',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ assertion: signedAssertion }),
    signal: AbortSignal.timeout(4_000),
  });
  if (!response.ok) {
    throw new Error(
      `The control plane rejected the identity bridge (${response.status})`,
    );
  }
  const body = await response.text();
  if (body.length > 64 << 10) {
    throw new Error('The control-plane identity response is too large');
  }
  let payload: unknown;
  try {
    payload = JSON.parse(body);
  } catch {
    throw new Error('The control-plane identity response is invalid');
  }
  if (!record(payload)) {
    throw new Error('The control-plane identity response is invalid');
  }
  const token = payload.token;
  const expiresAtValue = payload.expiresAt;
  const expiresAt =
    typeof expiresAtValue === 'string'
      ? Date.parse(expiresAtValue)
      : Number.NaN;
  if (
    typeof token !== 'string' ||
    token.length < 32 ||
    !Number.isFinite(expiresAt) ||
    expiresAt <= now + 10_000
  ) {
    throw new Error('The control plane returned an invalid identity session');
  }
  const session = { token, expiresAt };
  sessions.set(cacheKey, session);
  if (sessions.size > 128) {
    for (const [key, value] of sessions) {
      if (value.expiresAt <= now) sessions.delete(key);
    }
    while (sessions.size > 128) {
      const oldest = sessions.keys().next().value;
      if (typeof oldest !== 'string') break;
      sessions.delete(oldest);
    }
  }
  return session;
}
