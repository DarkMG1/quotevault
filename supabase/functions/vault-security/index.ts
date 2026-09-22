import { createClient } from 'npm:@supabase/supabase-js@2';

const base64urlBytes = (value: unknown): Uint8Array | null => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) return null;
  try {
    const binary = atob(value.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((value.length + 3) % 4));
    const bytes = Uint8Array.from(binary, char => char.charCodeAt(0));
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') === value ? bytes : null;
  } catch {
    return null;
  }
};

const base64Bytes = (value: unknown): Uint8Array | null => {
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) return null;
  try {
    const binary = atob(value);
    return btoa(binary) === value ? Uint8Array.from(binary, char => char.charCodeAt(0)) : null;
  } catch {
    return null;
  }
};

const base64url = (bytes: Uint8Array): string => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const source = (bytes: Uint8Array): BufferSource => bytes as unknown as BufferSource;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const canonicalLeasePayload = (claims: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(claims));
const reply = (status: number, body: Record<string, unknown>) => new Response(JSON.stringify(body), {
  status, headers: { 'content-type': 'application/json', 'access-control-allow-origin': 'https://quotes.darkmg1.dev', 'vary': 'Origin' },
});

const validEncryptedPrivateKey = (value: unknown): value is Record<string, unknown> => {
  if (!value || typeof value !== 'object') return false;
  const bundle = value as Record<string, unknown>;
  const iv = base64Bytes(bundle.iv);
  const data = base64Bytes(bundle.data);
  return bundle.version === 2 && iv?.byteLength === 12 && data !== null && data.byteLength >= 16;
};

const validKdf = (value: unknown): value is Record<string, unknown> => {
  if (!value || typeof value !== 'object') return false;
  const kdf = value as Record<string, unknown>;
  if (kdf.version !== 1 || kdf.iterations !== 600000 || typeof kdf.salt !== 'string') return false;
  const salt = base64Bytes(kdf.salt);
  return salt !== null && salt.byteLength >= 16 && salt.byteLength <= 64;
};

const validRecoveryPublicJwk = (value: unknown): value is JsonWebKey => {
  if (!value || typeof value !== 'object') return false;
  const jwk = value as JsonWebKey;
  const modulus = base64urlBytes(jwk.n);
  return jwk.kty === 'RSA' && jwk.e === 'AQAB' && !['d', 'p', 'q', 'dp', 'dq', 'qi'].some(name => name in jwk)
    && modulus?.byteLength === 384 && modulus[0] >= 128;
};

const validLeaseClaims = (claims: unknown, deviceId: string, ownerId: string): claims is readonly [1, string, string, string, number, number, string] => {
  if (!Array.isArray(claims) || claims.length !== 7 || claims[0] !== 1 || claims[1] !== deviceId || claims[2] !== ownerId
    || !claims.slice(1, 4).every(value => typeof value === 'string' && value.length > 0)
    || !Number.isSafeInteger(claims[4]) || !Number.isSafeInteger(claims[5]) || claims[5] - claims[4] !== 30 * 24 * 60 * 60 * 1000
    || typeof claims[6] !== 'string') return false;
  return base64urlBytes(claims[6])?.byteLength === 32;
};

export const signLease = async (privateJwk: JsonWebKey, claims: unknown): Promise<Uint8Array> => {
  const privateKey = await crypto.subtle.importKey('jwk', privateJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, source(canonicalLeasePayload(claims))));
};

export const encryptRecoveryChallenge = async (publicJwk: JsonWebKey, challenge: Uint8Array): Promise<Uint8Array> => {
  const key = await crypto.subtle.importKey('jwk', publicJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
  return new Uint8Array(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, source(challenge)));
};

export const recoveryPublicKeyFingerprint = async (publicJwk: JsonWebKey): Promise<string> => {
  const payload = new TextEncoder().encode(JSON.stringify([1, 'RSA-OAEP', 'SHA-256', publicJwk.n, publicJwk.e]));
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', source(payload)));
  try {
    return base64url(digest);
  } finally {
    digest.fill(0);
  }
};

export const encryptedRecoveryResponse = async (value: unknown): Promise<Record<string, unknown> | null> => {
  if (!value || typeof value !== 'object') return null;
  const data = value as Record<string, unknown>;
  if (typeof data.challenge_id !== 'string' || typeof data.recovery_key_id !== 'string' || !UUID.test(data.recovery_key_id)
    || typeof data.public_key_fingerprint !== 'string' || base64urlBytes(data.public_key_fingerprint)?.byteLength !== 32 || !validRecoveryPublicJwk(data.public_jwk)
    || !validEncryptedPrivateKey(data.encrypted_private_key) || !validKdf(data.kdf)) return null;
  if (await recoveryPublicKeyFingerprint(data.public_jwk) !== data.public_key_fingerprint) return null;
  const challenge = base64urlBytes(data.challenge);
  if (!challenge || challenge.byteLength !== 32) return null;
  try {
    const ciphertext = await encryptRecoveryChallenge(data.public_jwk, challenge);
    try {
      return { challengeId: data.challenge_id, recoveryKeyId: data.recovery_key_id, publicKeyFingerprint: data.public_key_fingerprint,
        ciphertext: base64url(ciphertext), encryptedPrivateKey: data.encrypted_private_key, kdf: data.kdf };
    } finally {
      ciphertext.fill(0);
    }
  } finally {
    challenge.fill(0);
  }
};

export const webauthnChallenge = (purpose: unknown): { purpose: 'registration' | 'restoration'; challenge: string } | null => {
  if (purpose !== 'registration' && purpose !== 'restoration') return null;
  return { purpose, challenge: base64url(crypto.getRandomValues(new Uint8Array(32))) };
};

export const validSessionInvalidation = (value: unknown, ownerId: string): boolean => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const result = value as Record<string, unknown>;
  return Object.keys(result).length === 2 && result.owner_id === ownerId && result.status === 'removed';
};

const serve = async (request: Request): Promise<Response> => {
  if (request.method === 'OPTIONS') return new Response(null, { headers: { 'access-control-allow-origin': 'https://quotes.darkmg1.dev', 'access-control-allow-headers': 'authorization, content-type', 'access-control-allow-methods': 'POST, OPTIONS', 'vary': 'Origin' } });
  if (request.method !== 'POST') return reply(405, { error: 'method_not_allowed' });
  const url = Deno.env.get('SUPABASE_URL');
  const anonKey = Deno.env.get('SUPABASE_ANON_KEY');
  const authorization = request.headers.get('authorization');
  if (!authorization || !/^Bearer\s+\S+$/.test(authorization)) return reply(401, { error: 'unauthorized' });
  if (!url || !anonKey) return reply(500, { error: 'configuration_error' });
  let body: { action?: unknown; deviceId?: unknown; token?: unknown; purpose?: unknown; ownerId?: unknown };
  try { body = await request.json(); } catch { return reply(400, { error: 'invalid_request' }); }
  if (typeof body.action !== 'string') return reply(400, { error: 'invalid_request' });
  const userClient = createClient(url, anonKey, { global: { headers: { authorization } } });
  const { data: userData, error: userError } = await userClient.auth.getUser();
  if (userError || !userData.user) return reply(401, { error: 'unauthorized' });
  if (body.action === 'renew') {
    if (typeof body.deviceId !== 'string' || typeof body.token !== 'string') return reply(400, { error: 'invalid_request' });
    const signingJwk = Deno.env.get('DEVICE_LEASE_PRIVATE_JWK');
    if (!signingJwk) return reply(500, { error: 'configuration_error' });
    const { data: claims, error } = await userClient.rpc('renew_device_lease', { p_device_id: body.deviceId, p_token: body.token });
    if (error || !validLeaseClaims(claims, body.deviceId, userData.user.id)) return reply(403, { error: 'lease_denied' });
    try {
      const signature = await signLease(JSON.parse(signingJwk), claims);
      try { return reply(200, { version: 1, claims, signature: btoa(String.fromCharCode(...signature)) }); }
      finally { signature.fill(0); }
    } catch { return reply(500, { error: 'signing_error' }); }
  }
  if (body.action === 'begin_recovery') {
    const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
    if (!serviceKey) return reply(500, { error: 'configuration_error' });
    const serviceClient = createClient(url, serviceKey);
    const { data, error } = await serviceClient.rpc('begin_recovery', { p_owner_id: userData.user.id });
    if (error) return reply(403, { error: 'recovery_denied' });
    try {
      const response = await encryptedRecoveryResponse(data);
      return response ? reply(200, response) : reply(403, { error: 'recovery_denied' });
    } catch { return reply(500, { error: 'recovery_error' }); }
  }
  if (body.action === 'invalidate_member_session') {
    if (typeof body.ownerId !== 'string' || !UUID.test(body.ownerId)) return reply(400, { error: 'invalid_request' });
    const { data: verified, error: verificationError } = await userClient.rpc('verify_member_session_invalidation', { p_owner_id: body.ownerId });
    if (verificationError || !validSessionInvalidation(verified, body.ownerId)) return reply(403, { error: 'session_invalidation_denied' });
    const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
    if (!serviceKey) return reply(500, { error: 'configuration_error' });
    const serviceClient = createClient(url, serviceKey);
    const { error } = await serviceClient.auth.admin.signOut(body.ownerId, 'global');
    if (error) return reply(502, { error: 'session_invalidation_failed' });
    return reply(200, { ownerId: body.ownerId, status: 'invalidated' });
  }
  if (body.action === 'webauthn_challenge') {
    const challenge = webauthnChallenge(body.purpose);
    if (!challenge) return reply(400, { error: 'invalid_request' });
    const { data, error } = await userClient.rpc('get_vault_bootstrap_state');
    return !error && data ? reply(200, challenge) : reply(403, { error: 'webauthn_denied' });
  }
  return reply(404, { error: 'unknown_action' });
};

if (import.meta.main) Deno.serve(serve);
