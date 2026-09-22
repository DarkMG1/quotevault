import { createClient } from 'npm:@supabase/supabase-js@2';
import { canonicalLeasePayload } from '../../../src/lib/lease.ts';

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

const base64url = (bytes: Uint8Array): string => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const source = (bytes: Uint8Array): BufferSource => bytes as unknown as BufferSource;
const reply = (status: number, body: Record<string, unknown>) => new Response(JSON.stringify(body), {
  status, headers: { 'content-type': 'application/json', 'access-control-allow-origin': 'https://quotes.darkmg1.dev', 'vary': 'Origin' },
});

Deno.serve(async request => {
  if (request.method === 'OPTIONS') return new Response(null, { headers: { 'access-control-allow-origin': 'https://quotes.darkmg1.dev', 'access-control-allow-headers': 'authorization, content-type', 'access-control-allow-methods': 'POST, OPTIONS', 'vary': 'Origin' } });
  if (request.method !== 'POST') return reply(405, { error: 'method_not_allowed' });
  const url = Deno.env.get('SUPABASE_URL');
  const anonKey = Deno.env.get('SUPABASE_ANON_KEY');
  const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
  const signingJwk = Deno.env.get('DEVICE_LEASE_PRIVATE_JWK');
  const authorization = request.headers.get('authorization');
  if (!url || !anonKey || !serviceKey || !signingJwk || !authorization?.startsWith('Bearer ')) return reply(500, { error: 'configuration_error' });
  let body: { action?: unknown; deviceId?: unknown; token?: unknown };
  try { body = await request.json(); } catch { return reply(400, { error: 'invalid_request' }); }
  if (typeof body.action !== 'string') return reply(400, { error: 'invalid_request' });
  const userClient = createClient(url, anonKey, { global: { headers: { authorization } } });
  const { data: userData, error: userError } = await userClient.auth.getUser();
  if (userError || !userData.user) return reply(401, { error: 'unauthorized' });
  if (body.action === 'renew') {
    if (typeof body.deviceId !== 'string' || typeof body.token !== 'string') return reply(400, { error: 'invalid_request' });
    const { data: claims, error } = await userClient.rpc('renew_device_lease', { p_device_id: body.deviceId, p_token: body.token });
    if (error || !Array.isArray(claims) || claims.length !== 7 || claims[0] !== 1 || claims[1] !== body.deviceId || claims[2] !== userData.user.id) return reply(403, { error: 'lease_denied' });
    try {
      const privateKey = await crypto.subtle.importKey('jwk', JSON.parse(signingJwk), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
      const signature = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, source(canonicalLeasePayload(claims as unknown as Parameters<typeof canonicalLeasePayload>[0]))));
      try { return reply(200, { version: 1, claims, signature: btoa(String.fromCharCode(...signature)) }); }
      finally { signature.fill(0); }
    } catch { return reply(500, { error: 'signing_error' }); }
  }
  if (body.action === 'begin_recovery') {
    const serviceClient = createClient(url, serviceKey);
    const { data, error } = await serviceClient.rpc('begin_recovery', { p_owner_id: userData.user.id });
    if (error || !data || typeof data.challenge_id !== 'string' || !data.public_jwk) return reply(403, { error: 'recovery_denied' });
    const challenge = base64urlBytes(data.challenge);
    if (!challenge || challenge.byteLength !== 32) return reply(403, { error: 'recovery_denied' });
    try {
      const key = await crypto.subtle.importKey('jwk', data.public_jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
      const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, source(challenge)));
      try { return reply(200, { challengeId: data.challenge_id, ciphertext: base64url(ciphertext) }); }
      finally { ciphertext.fill(0); }
    } catch { return reply(500, { error: 'recovery_error' }); }
    finally { challenge.fill(0); }
  }
  return reply(404, { error: 'unknown_action' });
});
