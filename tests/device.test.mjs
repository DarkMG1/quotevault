import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { loadModule } from './load-module.mjs';

const accountA = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const accountB = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const deviceId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const generation = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const bundle = { version: 2, iv: 'AAAAAAAAAAAAAAAA', data: 'AAAAAAAAAAAAAAAAAAAAAA==' };
const digest = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const wrapper = 'A'.repeat(512);
const token = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';

function table() {
  const rows = new Map();
  return {
    rows,
    async get(id) { return structuredClone(rows.get(id)); },
    async put(value) { rows.set(value.accountId, structuredClone(value)); },
    async delete(id) { rows.delete(id); },
    async clear() { rows.clear(); },
  };
}

function setup(reply) {
  const deviceState = table();
  const calls = [];
  const supabase = { rpc: async (name, args) => { calls.push({ name, args }); return { data: reply(name, args), error: null }; } };
  const device = loadModule('src/lib/device.ts', {
    './db': { db: { deviceState } },
    './supabase': { supabase },
    './crypto': { arrayBufferToBase64: value => Buffer.from(value).toString('base64'), base64ToArrayBuffer: value => Uint8Array.from(Buffer.from(value, 'base64')).buffer },
    './device-crypto': { digestAuthorizationToken: async value => `digest:${value}`, fingerprintPublicJwk: async () => digest },
  }, { crypto: webcrypto, TextEncoder, TextDecoder, atob, btoa, structuredClone });
  return { device, deviceState, calls };
}

const rememberedKey = await webcrypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
const initial = { accountId: accountA, deviceId, protectionMode: 'remembered', protection: { version: 1, mode: 'remembered' }, encryptedPrivateBundle: bundle, wrapper: { generation, wrappedKey: wrapper } };

{
  const { device } = setup(() => null);
  const hmac = await webcrypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256', length: 256 }, false, ['sign', 'verify']);
  await assert.rejects(device.saveDeviceState({ ...initial, rememberedKey: hmac }), /remembered device key/i);
  await assert.rejects(device.saveDeviceState({ ...initial, rememberedKey: { extractable: false, algorithm: { name: 'AES-GCM', length: 256 }, usages: ['encrypt', 'decrypt'] } }), /remembered device key/i);
}

{
  const { device } = setup(() => null);
  const first = await device.enrollmentFingerprint({ accountId: accountA, publicKeyFingerprint: digest, tokenDigest: token, protectionMode: 'remembered', protection: { nested: { z: 1, a: true }, mode: 'remembered' } });
  const second = await device.enrollmentFingerprint({ accountId: accountA, publicKeyFingerprint: digest, tokenDigest: token, protectionMode: 'remembered', protection: { mode: 'remembered', nested: { a: true, z: 1 } } });
  const withRuntimeExtra = await device.enrollmentFingerprint({ accountId: accountA, publicKeyFingerprint: digest, tokenDigest: token, protectionMode: 'remembered', protection: { mode: 'remembered', nested: { z: 1, a: true } }, encryptedPrivateBundle: { ignored: true } });
  const withoutRuntimeExtra = await device.enrollmentFingerprint({ accountId: accountA, publicKeyFingerprint: digest, tokenDigest: token, protectionMode: 'remembered', protection: { mode: 'remembered', nested: { z: 1, a: true } } });
  assert.equal(first, second);
  assert.equal(withRuntimeExtra, withoutRuntimeExtra, 'runtime bundle properties do not affect enrollment fingerprint');
}

{
  const publicJwk = { kty: 'RSA', n: 'n', e: 'AQAB' };
  const input = { deviceId, ownerId: accountA, label: 'Browser', publicJwk, publicKeyFingerprint: digest, tokenDigest: token, protectionMode: 'remembered', protection: { mode: 'remembered' }, encryptedPrivateBundle: bundle, requestKind: 'first' };
  let response;
  const { device, calls } = setup((name, args) => {
    if (name !== 'request_device') return null;
    response = { request_id: deviceId, device_id: deviceId, enrollment_fingerprint: args.p_enrollment_fingerprint, expires_at: '2030-01-01T00:00:00.000Z' };
    return response;
  });
  const result = await device.requestDevice(input);
  assert.equal(result.enrollmentFingerprint, calls[0].args.p_enrollment_fingerprint);
  assert.equal(calls[0].args.p_public_key_fingerprint, digest);
  const { device: substituted } = setup(() => ({ request_id: accountB, device_id: deviceId, enrollment_fingerprint: digest, expires_at: '2030-01-01T00:00:00.000Z' }));
  await assert.rejects(substituted.requestDevice(input), /request response/i);
}

{
  const protection = { nested: { a: true, z: 1 }, mode: 'remembered' };
  const enrollment = await setup(() => null).device.enrollmentFingerprint({ accountId: accountA, publicKeyFingerprint: digest, tokenDigest: token, protectionMode: 'remembered', protection });
  const reply = { request_id: deviceId, owner_id: accountA, request_kind: 'first', label: 'Browser', public_jwk: { kty: 'RSA', n: 'n', e: 'AQAB' }, public_key_fingerprint: digest, authorization_token_digest: token, enrollment_fingerprint: enrollment, protection_mode: 'remembered', protection, expires_at: '2030-01-01T00:00:00.000Z' };
  const { device } = setup(() => reply);
  const result = await device.getDeviceRequest(deviceId);
  assert.equal(result.enrollmentFingerprint, enrollment);
  const altered = { ...reply, protection: { mode: 'passkey-prf' } };
  await assert.rejects(setup(() => altered).device.getDeviceRequest(deviceId), /request response/i);
  await assert.rejects(setup(() => ({ ...reply, encrypted_private_bundle: bundle })).device.getDeviceRequest(deviceId), /request response/i);
}

{
  const passkeyState = { ...initial, protectionMode: 'passkey-prf' };
  const { device, deviceState, calls } = setup(() => ({ device_id: deviceId, generation, wrapped_key: wrapper, lease_expires_at: '2030-01-01T00:00:00.000Z' }));
  await device.saveDeviceState(passkeyState);
  const result = await device.completeDevice(accountA, deviceId, token);
  assert.equal('rememberedKey' in result, false);
  assert.equal('rememberedKey' in deviceState.rows.get(accountA), false);
  await assert.rejects(device.completeDevice(accountA, deviceId, token, rememberedKey), /transient key/i);
  assert.equal(calls.length, 1);
}

{
  const malformed = { id: 'bad', status: 'active', label: 'Browser', protection_mode: 'remembered', created_at: '2030-01-01T00:00:00.000Z', last_sync_at: null, lease_expires_at: null, revoked_at: null };
  await assert.rejects(setup(() => [malformed]).device.listOwnDevices(), /Invalid device/i);
  const { device, deviceState } = setup(() => null);
  await deviceState.put({ ...initial, accountId: accountA, encryptedPrivateBundle: { version: 2, iv: 'bad', data: 'bad' } });
  await assert.rejects(device.loadDeviceState(accountA), /encrypted device bundle/i);
}

{
  const { device, deviceState } = setup(() => null);
  await device.saveDeviceState({ ...initial, authorizationToken: token });
  assert.equal(JSON.stringify(deviceState.rows.get(accountA)).includes(token), false);
}

for (const [label, reply] of [
  ['wrong device', { device_id: accountB, generation, wrapped_key: wrapper, lease_expires_at: '2030-01-01T00:00:00.000Z' }],
  ['wrong generation', { device_id: deviceId, generation: accountB, wrapped_key: wrapper, lease_expires_at: '2030-01-01T00:00:00.000Z' }],
  ['bad wrapper', { device_id: deviceId, generation, wrapped_key: 'bad', lease_expires_at: '2030-01-01T00:00:00.000Z' }],
  ['bad expiry', { device_id: deviceId, generation, wrapped_key: wrapper, lease_expires_at: 'invalid' }],
]) {
  const { device, calls } = setup(() => reply);
  await device.saveDeviceState(initial);
  await assert.rejects(device.completeDevice(accountA, deviceId, token, rememberedKey), /Invalid device/);
  assert.equal(calls.length, 1, `${label} reached the RPC`);
}

{
  const { device, deviceState, calls } = setup((name) => name === 'complete_device' ? { device_id: deviceId, generation, wrapped_key: 'A'.repeat(512), lease_expires_at: '2030-01-01T00:00:00.000Z' } : null);
  await device.saveDeviceState(initial);
  const state = await device.completeDevice(accountA, deviceId, token, rememberedKey);
  assert.equal(state.accountId, accountA);
  assert.equal(state.rememberedKey.extractable, false);
  assert.equal(JSON.stringify(state).includes(token), false);
  assert.equal(await device.loadDeviceState(accountB), null);
  assert.equal(JSON.stringify(calls[0]), JSON.stringify({ name: 'complete_device', args: { p_device_id: deviceId, p_token: token, p_generation: generation } }));
  assert.equal(deviceState.rows.size, 1);
}

{
  const { device, calls } = setup((name) => name === 'approve_device' ? { status: 'approved', device_id: deviceId, generation } : null);
  await device.approveDevice({ requestId: deviceId, ownerId: accountA, publicKeyFingerprint: digest, enrollmentFingerprint: digest, wrappedKey: wrapper, generation, approverDeviceId: deviceId, approverToken: digest });
  assert.equal(JSON.stringify(calls[0]), JSON.stringify({ name: 'approve_device', args: {
    p_request_id: deviceId, p_owner_id: accountA, p_public_key_fingerprint: digest, p_enrollment_fingerprint: digest,
    p_wrapped_key: wrapper, p_generation: generation, p_approver_device_id: deviceId, p_approver_token: digest
  } }));
}

{
  const { device, calls } = setup(() => ({ device_id: 'not-a-uuid', generation, wrapped_key: 'bad', lease_expires_at: '2030-01-01T00:00:00.000Z' }));
  await device.saveDeviceState(initial);
  await assert.rejects(device.completeDevice(accountA, deviceId, token, rememberedKey), /Invalid device/);
  assert.equal(calls.length, 1);
}

{
  const { device, deviceState } = setup(() => null);
  await device.saveDeviceState(initial);
  await device.saveDeviceState({ ...initial, accountId: accountB });
  await device.deleteDeviceState(accountA);
  assert.equal(deviceState.rows.has(accountA), false);
  assert.equal(deviceState.rows.has(accountB), true);
  await device.deleteDeviceState(accountB);
  assert.equal(deviceState.rows.size, 0);
}

console.log('device tests passed');
