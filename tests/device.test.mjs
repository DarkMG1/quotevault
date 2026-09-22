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
