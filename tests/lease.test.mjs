import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { loadModule } from './load-module.mjs';

const leaseApi = loadModule('src/lib/lease.ts', {}, { crypto: webcrypto, TextEncoder, atob, btoa });
const DAY = 24 * 60 * 60 * 1000;
const NOW = 1_800_000_000_000;

const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const publicJwk = await webcrypto.subtle.exportKey('jwk', pair.publicKey);

const signFixture = async (overrides = {}) => {
  const claims = [1, 'device-a', 'account-a', 'generation-a', NOW, NOW + 30 * DAY, 'fingerprint-a'];
  Object.assign(claims, overrides);
  const signature = await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, leaseApi.canonicalLeasePayload(claims));
  return { version: 1, claims, signature: Buffer.from(signature).toString('base64') };
};

test('lease verification rejects another device and the thirty-day boundary', async () => {
  const lease = await signFixture();
  assert.equal(await leaseApi.verifyDeviceLease(lease, publicJwk, { now: NOW + 30 * DAY - 1, deviceId: 'device-a' }), true);
  assert.equal(await leaseApi.verifyDeviceLease(lease, publicJwk, { now: NOW, deviceId: 'device-a', publicKeyFingerprint: 'fingerprint-a' }), true);
  assert.equal(await leaseApi.verifyDeviceLease(lease, publicJwk, { now: NOW + 30 * DAY, deviceId: 'device-a' }), false);
  assert.equal(await leaseApi.verifyDeviceLease(lease, publicJwk, { now: NOW, deviceId: 'device-b' }), false);
});

test('lease verification rejects invalid signatures and bound claims', async () => {
  const lease = await signFixture();
  assert.equal(await leaseApi.verifyDeviceLease({ ...lease, signature: `${lease.signature.slice(0, -1)}A` }, publicJwk, { now: NOW, deviceId: 'device-a' }), false);
  assert.equal(await leaseApi.verifyDeviceLease(lease, publicJwk, { now: NOW, deviceId: 'device-a', accountId: 'account-b' }), false);
  assert.equal(await leaseApi.verifyDeviceLease(lease, publicJwk, { now: NOW, deviceId: 'device-a', generation: 'generation-b' }), false);
  assert.equal(await leaseApi.verifyDeviceLease(lease, publicJwk, { now: NOW, deviceId: 'device-a', publicKeyFingerprint: 'fingerprint-b' }), false);
  assert.equal(await leaseApi.verifyDeviceLease(await signFixture({ 4: NOW + 1 }), publicJwk, { now: NOW, deviceId: 'device-a' }), false);
  assert.equal(await leaseApi.verifyDeviceLease(await signFixture({ 5: NOW + 29 * DAY }), publicJwk, { now: NOW, deviceId: 'device-a' }), false);
});
