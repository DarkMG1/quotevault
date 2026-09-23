import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { loadModule } from './load-module.mjs';

const accountA = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const accountB = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const deviceId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const generation = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const recoveryKeyId = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
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
const initial = { accountId: accountA, deviceId, publicKeyFingerprint: digest, protectionMode: 'remembered', protection: { version: 1, mode: 'remembered' }, encryptedPrivateBundle: bundle, wrapper: { generation, wrappedKey: wrapper } };

{
  const { device } = setup(() => null);
  const hmac = await webcrypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256', length: 256 }, false, ['sign', 'verify']);
  await assert.rejects(device.saveDeviceState({ ...initial, rememberedKey: hmac }), /remembered device key/i);
  await assert.rejects(device.saveDeviceState({ ...initial, rememberedKey: { extractable: false, algorithm: { name: 'AES-GCM', length: 256 }, usages: ['encrypt', 'decrypt'] } }), /remembered device key/i);
}

{
  const { device } = setup(() => null);
  const exactRemembered = { version: 1, mode: 'remembered' };
  await device.saveDeviceState({ ...initial, protection: exactRemembered, rememberedKey });
  for (const protection of [
    { version: 1, mode: 'remembered', extra: true },
    { version: 1 },
    { version: 2, mode: 'remembered' },
    { version: 1, mode: 'passkey-prf' },
  ]) await assert.rejects(device.saveDeviceState({ ...initial, protection, rememberedKey }), /protection/i);
  const passkey = { version: 1, rpId: 'quotes.darkmg1.dev', credentialId: token, prfSalt: digest, kdf: 'HKDF-SHA-256' };
  await device.saveDeviceState({ ...initial, protectionMode: 'passkey-prf', protection: passkey });
  for (const protection of [
    { ...passkey, extra: true },
    { ...passkey, rpId: 'evil.example' },
    { ...passkey, credentialId: 'AA==' },
    { ...passkey, prfSalt: digest.slice(1) },
    { ...passkey, kdf: 'PBKDF2' },
  ]) await assert.rejects(device.saveDeviceState({ ...initial, protectionMode: 'passkey-prf', protection }), /protection/i);
}

{
  const { device } = setup(() => null);
  const protection = { version: 1, mode: 'remembered' };
  const first = await device.enrollmentFingerprint({ accountId: accountA, publicKeyFingerprint: digest, tokenDigest: token, protectionMode: 'remembered', protection });
  const second = await device.enrollmentFingerprint({ accountId: accountA, publicKeyFingerprint: digest, tokenDigest: token, protectionMode: 'remembered', protection: { mode: 'remembered', version: 1 } });
  const withRuntimeExtra = await device.enrollmentFingerprint({ accountId: accountA, publicKeyFingerprint: digest, tokenDigest: token, protectionMode: 'remembered', protection, encryptedPrivateBundle: { ignored: true } });
  const withoutRuntimeExtra = await device.enrollmentFingerprint({ accountId: accountA, publicKeyFingerprint: digest, tokenDigest: token, protectionMode: 'remembered', protection });
  assert.equal(first, second);
  assert.equal(withRuntimeExtra, withoutRuntimeExtra, 'runtime bundle properties do not affect enrollment fingerprint');
}

{
  const publicJwk = { kty: 'RSA', n: 'n', e: 'AQAB' };
  const input = { deviceId, ownerId: accountA, label: 'Browser', publicJwk, publicKeyFingerprint: digest, tokenDigest: token, protectionMode: 'remembered', protection: { version: 1, mode: 'remembered' }, encryptedPrivateBundle: bundle, requestKind: 'first' };
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
  const protection = { version: 1, mode: 'remembered' };
  const enrollment = await setup(() => null).device.enrollmentFingerprint({ accountId: accountA, publicKeyFingerprint: digest, tokenDigest: token, protectionMode: 'remembered', protection });
  const reply = { request_id: deviceId, owner_id: accountA, request_kind: 'first', label: 'Browser', public_jwk: { kty: 'RSA', n: 'n', e: 'AQAB' }, public_key_fingerprint: digest, authorization_token_digest: token, enrollment_fingerprint: enrollment, protection_mode: 'remembered', protection, expires_at: '2030-01-01T00:00:00.000Z' };
  const { device } = setup(() => reply);
  const result = await device.getDeviceRequest(deviceId);
  assert.equal(result.enrollmentFingerprint, enrollment);
  const altered = { ...reply, protection: { version: 1, mode: 'remembered', extra: true } };
  await assert.rejects(setup(() => altered).device.getDeviceRequest(deviceId), /protection/i);
  await assert.rejects(setup(() => ({ ...reply, encrypted_private_bundle: bundle })).device.getDeviceRequest(deviceId), /request response/i);
}

{
  const passkeyState = { ...initial, protectionMode: 'passkey-prf', protection: { version: 1, rpId: 'quotes.darkmg1.dev', credentialId: token, prfSalt: digest, kdf: 'HKDF-SHA-256' } };
  const { device, deviceState, calls } = setup(() => ({ device_id: deviceId, generation, wrapped_key: wrapper, lease_expires_at: '2030-01-01T00:00:00.000Z', recovery_setup_required: false, active_recovery_key_id: recoveryKeyId }));
  await device.saveDeviceState(passkeyState);
  const result = await device.completeDevice(accountA, deviceId, token);
  assert.equal('rememberedKey' in result, false);
  assert.equal('recoverySetupRequired' in result, false);
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

{
  const { device } = setup(() => null);
  const vaultGate = loadModule('src/components/VaultGate.tsx', {}, { crypto: webcrypto, TextEncoder, TextDecoder, atob, btoa });
  await device.saveDeviceState({ ...initial, recoverySetupRequired: true });
  assert.equal((await device.loadDeviceState(accountA)).recoverySetupRequired, true, 'server-required recovery setup survives lock and reload');
  assert.equal(vaultGate.vaultGateState({ recovery: device.needsRecoverySetup(await device.loadDeviceState(accountA)), device: true, key: true, leaseValid: true }), 'recovery-setup', 'a cleared-site passkey restore with server=true reaches recovery setup before quote UI');
  assert.equal(device.needsRecoverySetup(initial), false);
  assert.equal(device.recoverySetupRetryOutcome(false, recoveryKeyId, recoveryKeyId), 'committed');
  assert.equal(device.recoverySetupRetryOutcome(true, recoveryKeyId, recoveryKeyId), 'committed', 'a replacement can only recover its own proven commit');
  assert.equal(device.recoverySetupRetryOutcome(false, recoveryKeyId, deviceId), 'other');
  assert.equal(device.recoverySetupRetryOutcome(true, recoveryKeyId, deviceId), 'original', 'recovery replacement must retain another device failure');
  assert.equal(device.recoverySetupRetryOutcome(false, recoveryKeyId, null), 'original');
  await assert.rejects(device.saveDeviceState({ ...initial, recoverySetupRequired: 'yes' }), /local state/i);
}

{
  const { device, deviceState } = setup(() => ({ device_id: deviceId, generation, wrapped_key: wrapper, lease_expires_at: '2030-01-01T00:00:00.000Z', recovery_setup_required: false, active_recovery_key_id: recoveryKeyId }));
  await device.saveDeviceState(initial);
  const completed = await device.completeDevice(accountA, deviceId, token, rememberedKey);
  assert.equal('recoverySetupRequired' in completed, false, 'an active recovery key clears the local setup marker');
  assert.equal(completed.activeRecoveryKeyId, recoveryKeyId, 'completion exposes the active recovery identity only to the caller');
  assert.equal('recoverySetupRequired' in deviceState.rows.get(accountA), false);
  assert.equal(JSON.stringify(deviceState.rows.get(accountA)).includes(recoveryKeyId), false, 'recovery identity is not persisted locally');
  const malformed = setup(() => ({ device_id: deviceId, generation, wrapped_key: wrapper, lease_expires_at: '2030-01-01T00:00:00.000Z', recovery_setup_required: 'true', active_recovery_key_id: recoveryKeyId }));
  await malformed.device.saveDeviceState(initial);
  await assert.rejects(malformed.device.completeDevice(accountA, deviceId, token, rememberedKey), /Invalid device/);
  const malformedIdentity = setup(() => ({ device_id: deviceId, generation, wrapped_key: wrapper, lease_expires_at: '2030-01-01T00:00:00.000Z', recovery_setup_required: false, active_recovery_key_id: 'not-a-uuid' }));
  await malformedIdentity.device.saveDeviceState(initial);
  await assert.rejects(malformedIdentity.device.completeDevice(accountA, deviceId, token, rememberedKey), /Invalid device/);
}

{
  const { device } = setup(() => ({ device_id: deviceId, generation, wrapped_key: wrapper, lease_expires_at: '2030-01-01T00:00:00.000Z', recovery_setup_required: true, active_recovery_key_id: null }));
  await device.saveDeviceState(initial);
  assert.equal((await device.completeDevice(accountA, deviceId, token, rememberedKey)).recoverySetupRequired, true, 'only a server response without an active recovery key may require recovery setup');
}

for (const [label, reply] of [
  ['wrong device', { device_id: accountB, generation, wrapped_key: wrapper, lease_expires_at: '2030-01-01T00:00:00.000Z', recovery_setup_required: false, active_recovery_key_id: recoveryKeyId }],
  ['wrong generation', { device_id: deviceId, generation: accountB, wrapped_key: wrapper, lease_expires_at: '2030-01-01T00:00:00.000Z', recovery_setup_required: false, active_recovery_key_id: recoveryKeyId }],
  ['bad wrapper', { device_id: deviceId, generation, wrapped_key: 'bad', lease_expires_at: '2030-01-01T00:00:00.000Z', recovery_setup_required: false, active_recovery_key_id: recoveryKeyId }],
  ['bad expiry', { device_id: deviceId, generation, wrapped_key: wrapper, lease_expires_at: 'invalid', recovery_setup_required: false, active_recovery_key_id: recoveryKeyId }],
]) {
  const { device, calls } = setup(() => reply);
  await device.saveDeviceState(initial);
  await assert.rejects(device.completeDevice(accountA, deviceId, token, rememberedKey), /Invalid device/);
  assert.equal(calls.length, 1, `${label} reached the RPC`);
}

{
  const { device, deviceState, calls } = setup((name) => name === 'complete_device' ? { device_id: deviceId, generation, wrapped_key: 'A'.repeat(512), lease_expires_at: '2030-01-01T00:00:00.000Z', recovery_setup_required: false, active_recovery_key_id: recoveryKeyId } : null);
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
  const lease = { version: 1, claims: [1, deviceId, accountA, generation, 1, 2, digest], signature: 'AA==' };
  const { device, deviceState } = setup(() => ({ device_id: deviceId, generation, wrapped_key: wrapper, lease_expires_at: '2030-01-01T00:00:00.000Z', recovery_setup_required: false, active_recovery_key_id: recoveryKeyId }));
  await device.saveDeviceState({ ...initial, lease, rememberedKey });
  const complete = await device.completeDevice(accountA, deviceId, token, rememberedKey);
  assert.equal(JSON.stringify(complete.lease), JSON.stringify(lease), 'completion keeps the signed lease verified before wrapper retrieval');
  assert.equal(JSON.stringify(deviceState.rows.get(accountA).lease), JSON.stringify(lease));
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
  const { device, calls } = setup(() => ({ device_id: 'not-a-uuid', generation, wrapped_key: 'bad', lease_expires_at: '2030-01-01T00:00:00.000Z', recovery_setup_required: false, active_recovery_key_id: recoveryKeyId }));
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
  await device.deleteDeviceState(accountB, true);
  assert.equal(deviceState.rows.size, 0);
}

{
  const { device } = setup(() => null);
  const old = { ...initial, wrapper: { generation: accountB, wrappedKey: wrapper } };
  assert.equal(device.needsDeviceCompletion(old, generation), true, 'an old local wrapper must be fetched again after cutover');
  assert.equal(device.needsDeviceCompletion({ ...old, wrapper: { ...old.wrapper, generation } }, generation), false);
  const rotating = { ...old, preparedWrapper: { generation, wrappedKey: wrapper } };
  assert.equal(device.needsDeviceCompletion(rotating, generation), false, 'a locally retained prepared wrapper survives rotation reload');
  assert.equal(device.deviceWrapperForGeneration(rotating, generation), rotating.preparedWrapper);
  assert.equal(device.deviceWrapperForGeneration(rotating, accountB), rotating.wrapper);
}

console.log('device tests passed');
