import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { loadModule } from './load-module.mjs';

const accountId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const deviceId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const generation = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const fingerprint = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const token = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
const bundle = { version: 2, iv: 'AAAAAAAAAAAAAAAA', data: 'AAAAAAAAAAAAAAAAAAAAAA==' };

function setup({ rpcReply = () => null, edgeReply = () => null, navigatorValue = undefined } = {}) {
  const states = new Map();
  const calls = [];
  const device = {
    validateDeviceProtection(value, mode) { if (mode === 'remembered' && JSON.stringify(value) === JSON.stringify({ version: 1, mode: 'remembered' })) return value; if (mode === 'passkey-prf' && value?.version === 1 && value.rpId === 'quotes.darkmg1.dev' && value.kdf === 'HKDF-SHA-256' && typeof value.credentialId === 'string' && typeof value.prfSalt === 'string' && Object.keys(value).length === 5) return value; throw new Error('Invalid device protection.'); },
    async saveDeviceState(value) { states.set(value.accountId, structuredClone(value)); },
    async loadDeviceState(id) { return structuredClone(states.get(id) ?? null); },
    async requestDevice(input) { calls.push(['request_device', input]); return { requestId: input.deviceId, deviceId: input.deviceId, enrollmentFingerprint: fingerprint, expiresAt: '2030-01-01T00:00:00.000Z' }; },
  };
  const api = loadModule('src/lib/device-security.ts', {
    './device': device,
    './device-crypto': {
      generateWrappingKeyPair: async () => webcrypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']),
      generateAuthorizationToken: () => token,
      digestAuthorizationToken: async () => fingerprint,
      fingerprintPublicJwk: async () => fingerprint,
      encryptPrivateBundle: async () => bundle,
      decryptPrivateBundle: async () => ({ version: 1, privateJwk: { kty: 'RSA' }, authorizationToken: token }),
    },
    './lease': { verifyDeviceLease: async () => true },
    './supabase': { supabase: { rpc: async (name, args) => ({ data: rpcReply(name, args), error: null }), functions: { invoke: async (name, input) => ({ data: edgeReply(name, input), error: null }) } } },
    './crypto': { arrayBufferToBase64: value => Buffer.from(value).toString('base64'), base64ToArrayBuffer: value => Uint8Array.from(Buffer.from(value, 'base64')).buffer },
  }, { crypto: webcrypto, TextEncoder, TextDecoder, atob, btoa, structuredClone, navigator: navigatorValue });
  return { api, states, calls };
}

test('passkey restore metadata rejects server wrappers, tokens, and malformed protection', async () => {
  const good = { generation, devices: [{ device_id: deviceId, protection_mode: 'passkey-prf', protection: { version: 1, rpId: 'quotes.darkmg1.dev', credentialId: token, prfSalt: fingerprint, kdf: 'HKDF-SHA-256' }, public_key_fingerprint: fingerprint, encrypted_private_bundle: bundle }] };
  const { api } = setup({ rpcReply: () => good });
  const result = await api.getPasskeyRestoreDevices();
  assert.equal(result[0].deviceId, deviceId);
  await assert.rejects(setup({ rpcReply: () => ({ ...good, devices: [{ ...good.devices[0], wrapped_key: 'A'.repeat(512) }] }) }).api.getPasskeyRestoreDevices(), /restore/i);
  await assert.rejects(setup({ rpcReply: () => ({ ...good, devices: [{ ...good.devices[0], protection: { ...good.devices[0].protection, extra: true } }] }) }).api.getPasskeyRestoreDevices(), /protection/i);
});

test('lease renewal verifies and caches only the signed matching lease', async () => {
  const lease = { version: 1, claims: [1, deviceId, accountId, generation, 1, 2, fingerprint], signature: 'AA==' };
  const { api, states } = setup({ edgeReply: () => lease });
  states.set(accountId, { accountId, deviceId, publicKeyFingerprint: fingerprint, protectionMode: 'remembered', protection: { version: 1, mode: 'remembered' }, encryptedPrivateBundle: bundle });
  assert.equal((await api.renewDeviceLease({ accountId, deviceId, token, generation, publicKeyFingerprint: fingerprint, now: 1 })).lease.signature, 'AA==');
  assert.equal(states.get(accountId).lease.signature, 'AA==');
  const invalid = setup({ edgeReply: () => ({ ...lease, signature: 'not base64' }) });
  invalid.states.set(accountId, { accountId, deviceId, publicKeyFingerprint: fingerprint, protectionMode: 'remembered', protection: { version: 1, mode: 'remembered' }, encryptedPrivateBundle: bundle });
  await assert.rejects(invalid.api.renewDeviceLease({ accountId, deviceId, token, generation, publicKeyFingerprint: fingerprint, now: 1 }), /Invalid device/i);
});

test('passkey unlock requires a PRF result and accepts a local challenge offline', async () => {
  const calls = [];
  const credential = { rawId: Uint8Array.from([1, 2, 3]).buffer, getClientExtensionResults: () => ({ prf: { results: { first: new Uint8Array(32).buffer } } }) };
  const { api } = setup({ navigatorValue: { credentials: { get: async options => { calls.push(options); return credential; } } } });
  const protection = { version: 1, rpId: 'quotes.darkmg1.dev', credentialId: 'AQID', prfSalt: fingerprint, kdf: 'HKDF-SHA-256' };
  const key = await api.unlockPasskey(protection);
  const second = await api.unlockPasskey(protection);
  assert.equal(key.extractable, false);
  assert.equal(calls[0].publicKey.userVerification, 'required');
  const iv = new Uint8Array(12);
  const ciphertext = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode('bundle'));
  assert.equal(new TextDecoder().decode(await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv }, second, ciphertext)), 'bundle');
  const direct = await webcrypto.subtle.importKey('raw', new Uint8Array(32), 'AES-GCM', false, ['decrypt']);
  await assert.rejects(webcrypto.subtle.decrypt({ name: 'AES-GCM', iv }, direct, ciphertext));
  await assert.rejects(setup({ navigatorValue: { credentials: { get: async () => null } } }).api.unlockPasskey(protection), /Passkey/i);
});

test('passkey registration uses an Edge challenge bound to its purpose, fixed RP, UV, and PRF result', async () => {
  const calls = [];
  const credential = { rawId: Uint8Array.from([1, 2, 3]).buffer, getClientExtensionResults: () => ({ prf: { enabled: true, results: { first: new Uint8Array(32).buffer } } }) };
  const { api } = setup({ edgeReply: (_name, input) => ({ purpose: input.body.purpose, challenge: fingerprint }), navigatorValue: { credentials: { create: async options => { calls.push(options); return credential; }, get: async () => credential } } });
  const result = await api.registerPasskey({ userId: accountId, userName: 'member@example.com', displayName: 'Member' });
  assert.equal(result.rpId, 'quotes.darkmg1.dev');
  assert.equal(calls[0].publicKey.authenticatorSelection.userVerification, 'required');
  assert.equal(calls[0].publicKey.attestation, 'none');
  await assert.rejects(setup({ edgeReply: () => ({ purpose: 'restoration', challenge: fingerprint }) }).api.webauthnChallenge('registration'), /challenge/i);
  await assert.rejects(setup({ edgeReply: () => ({ purpose: 'registration', challenge: fingerprint }), navigatorValue: { credentials: { create: async () => null } } }).api.registerPasskey({ userId: accountId, userName: 'member@example.com', displayName: 'Member' }), /Passkey/i);
});

test('recovery contracts bind IDs and reject malformed secret-bearing responses', async () => {
  const begin = { challengeId: deviceId, recoveryKeyId: accountId, publicKeyFingerprint: fingerprint, ciphertext: 'A'.repeat(512), encryptedPrivateKey: bundle, kdf: { version: 1, salt: 'AAAAAAAAAAAAAAAAAAAAAA==', iterations: 600000 } };
  const { api } = setup({ edgeReply: () => begin, rpcReply: name => name === 'complete_recovery' ? { recovery_key_id: accountId, generation, wrapped_key: 'A'.repeat(512), transition_token: token } : { device_id: deviceId, generation } });
  assert.equal((await api.beginRecovery()).recoveryKeyId, accountId);
  assert.equal((await api.completeRecovery({ challengeId: deviceId, response: token })).generation, generation);
  assert.equal((await api.activateRecoveredDevice({ challengeId: deviceId, transitionToken: token, requestId: deviceId, enrollmentFingerprint: fingerprint, generation, wrappedKey: 'A'.repeat(512) })).deviceId, deviceId);
  await assert.rejects(setup({ edgeReply: () => ({ ...begin, token: token }) }).api.beginRecovery(), /recovery/i);
});

test('recovery key RPC binds the public key fingerprint and response identifiers', async () => {
  const pair = await webcrypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
  const publicJwk = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
  const { api } = setup({ rpcReply: () => ({ recovery_key_id: accountId, generation }) });
  await assert.rejects(api.createRecoveryKey({ recoveryKeyId: accountId, publicJwk, publicKeyFingerprint: `B${fingerprint.slice(1)}`, encryptedPrivateKey: bundle, kdf: { version: 1, salt: 'AAAAAAAAAAAAAAAAAAAAAA==', iterations: 600000 }, generation, wrappedKey: 'A'.repeat(512), deviceId, token }), /recovery/i);
  const mismatched = setup({ rpcReply: () => ({ recovery_key_id: deviceId, generation }) });
  await assert.rejects(mismatched.api.createRecoveryKey({ recoveryKeyId: accountId, publicJwk, publicKeyFingerprint: fingerprint, encryptedPrivateKey: bundle, kdf: { version: 1, salt: 'AAAAAAAAAAAAAAAAAAAAAA==', iterations: 600000 }, generation, wrappedKey: 'A'.repeat(512), deviceId, token }), /recovery/i);
});
