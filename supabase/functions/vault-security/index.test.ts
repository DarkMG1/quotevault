import { encryptedRecoveryResponse, recoveryPublicKeyFingerprint, signLease, validSessionInvalidation, webauthnChallenge } from './index.ts';
import { verifyDeviceLeaseWithPublicKey } from '../../../src/lib/lease.ts';
import type { DeviceLease, DeviceLeaseClaims } from '../../../src/types/index.ts';

Deno.test('Edge signatures verify in the browser verifier and recovery ciphertext decrypts', async () => {
  const signingPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const publicSigningJwk = await crypto.subtle.exportKey('jwk', signingPair.publicKey);
  const privateSigningJwk = await crypto.subtle.exportKey('jwk', signingPair.privateKey);
  const claims: DeviceLeaseClaims = [1, 'device-a', 'account-a', 'generation-a', 1_800_000_000_000, 1_802_592_000_000, 'fingerprint-a'];
  const signature = await signLease(privateSigningJwk, claims);
  const lease: DeviceLease = { version: 1, claims, signature: btoa(String.fromCharCode(...signature)) };
  if (!await verifyDeviceLeaseWithPublicKey(lease, publicSigningJwk, {
    now: claims[4] + 1,
    deviceId: 'device-a', accountId: 'account-a', generation: 'generation-a', publicKeyFingerprint: 'fingerprint-a',
  })) throw new Error('browser verifier rejected Edge signature');

  const recoveryPair = await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
  const publicRecoveryJwk = await crypto.subtle.exportKey('jwk', recoveryPair.publicKey);
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const encryptedPrivateKey = { version: 2, iv: btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(12)))), data: btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16)))) };
  const kdf = { version: 1, iterations: 600000, salt: btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16)))) };
  const serviceResult = {
    challenge_id: 'challenge-a', challenge: btoa(String.fromCharCode(...challenge)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
    recovery_key_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', public_key_fingerprint: await recoveryPublicKeyFingerprint(publicRecoveryJwk), public_jwk: publicRecoveryJwk,
    encrypted_private_key: encryptedPrivateKey, kdf,
  };
  const response = await encryptedRecoveryResponse(serviceResult);
  if (!response || 'challenge' in response || 'public_jwk' in response || response.encryptedPrivateKey !== encryptedPrivateKey || response.kdf !== kdf
    || response.recoveryKeyId !== serviceResult.recovery_key_id || response.publicKeyFingerprint !== serviceResult.public_key_fingerprint) throw new Error('recovery response exposed or changed service-only material');
  const substituted = `${serviceResult.public_key_fingerprint.slice(0, -1)}${serviceResult.public_key_fingerprint.endsWith('A') ? 'E' : 'A'}`;
  if (await encryptedRecoveryResponse({ ...serviceResult, public_key_fingerprint: substituted }) !== null
    || await encryptedRecoveryResponse(({ ...serviceResult, recovery_key_id: undefined })) !== null) throw new Error('recovery response accepted missing or substituted AAD metadata');
  const ciphertext = Uint8Array.from(atob((response.ciphertext as string).replace(/-/g, '+').replace(/_/g, '/')), char => char.charCodeAt(0));
  const plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, recoveryPair.privateKey, ciphertext as unknown as BufferSource));
  if (plaintext.byteLength !== 32 || !plaintext.every((byte, index) => byte === challenge[index])) throw new Error('recovery ciphertext did not decrypt to the challenge');
  challenge.fill(0);
  ciphertext.fill(0);
  plaintext.fill(0);
  signature.fill(0);
});

Deno.test('WebAuthn challenges are fresh canonical 256-bit values for exact purposes', () => {
  const registration = webauthnChallenge('registration');
  const restoration = webauthnChallenge('restoration');
  if (!registration || !restoration || registration.challenge === restoration.challenge
    || !/^[A-Za-z0-9_-]{43}$/.test(registration.challenge)
    || registration.purpose !== 'registration' || restoration.purpose !== 'restoration'
    || webauthnChallenge('anything-else') !== null) throw new Error('invalid WebAuthn challenge response');
});

Deno.test('session invalidation accepts only the exact server proof for the requested owner', () => {
  const ownerId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  if (!validSessionInvalidation({ owner_id: ownerId, status: 'removed' }, ownerId)
    || validSessionInvalidation(null, ownerId)
    || validSessionInvalidation({ owner_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', status: 'removed' }, ownerId)
    || validSessionInvalidation({ owner_id: ownerId, status: 'active' }, ownerId)
    || validSessionInvalidation({ owner_id: ownerId, status: 'removed', extra: true }, ownerId)) throw new Error('session invalidation proof was not exact');
});

Deno.test('CORS preflight allows every header supabase-js sends', async () => {
  const { serve } = await import('./index.ts');
  const response = await serve(new Request('https://edge.invalid/vault-security', { method: 'OPTIONS', headers: { origin: 'https://quotes.darkmg1.dev', 'access-control-request-headers': 'apikey, authorization, content-type, x-client-info' } }));
  const allowed = (response.headers.get('access-control-allow-headers') ?? '').split(',').map(value => value.trim().toLowerCase());
  for (const header of ['apikey', 'authorization', 'content-type', 'x-client-info']) if (!allowed.includes(header)) throw new Error(`preflight rejects ${header}`);
});
