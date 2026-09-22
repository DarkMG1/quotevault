import { encryptedRecoveryResponse, signLease } from './index.ts';
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
  const response = await encryptedRecoveryResponse({ challenge_id: 'challenge-a', challenge: btoa(String.fromCharCode(...challenge)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''), public_jwk: publicRecoveryJwk, encrypted_private_key: encryptedPrivateKey, kdf });
  if (!response || 'challenge' in response || 'public_jwk' in response || response.encryptedPrivateKey !== encryptedPrivateKey || response.kdf !== kdf) throw new Error('recovery response exposed or changed service-only material');
  const ciphertext = Uint8Array.from(atob((response.ciphertext as string).replace(/-/g, '+').replace(/_/g, '/')), char => char.charCodeAt(0));
  const plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, recoveryPair.privateKey, ciphertext as unknown as BufferSource));
  if (plaintext.byteLength !== 32 || !plaintext.every((byte, index) => byte === challenge[index])) throw new Error('recovery ciphertext did not decrypt to the challenge');
  challenge.fill(0);
  ciphertext.fill(0);
  plaintext.fill(0);
  signature.fill(0);
});
