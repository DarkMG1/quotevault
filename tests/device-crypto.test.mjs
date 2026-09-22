import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { loadModule } from './load-module.mjs';

const cryptoModule = loadModule('src/lib/crypto.ts', {}, { crypto: webcrypto, TextEncoder, TextDecoder, btoa, atob });
const cryptoApi = loadModule('src/lib/device-crypto.ts', { './crypto': cryptoModule }, { crypto: webcrypto, TextEncoder, TextDecoder, btoa, atob, Object });

const GENERATION_A = 'd4c3b2a1-0000-4000-8000-000000000001';
const GENERATION_B = 'd4c3b2a1-0000-4000-8000-000000000002';

test('quote keys and ciphertext are bound to their generation and record', async () => {
  const master = cryptoApi.generateVaultMasterKey();
  const key = await cryptoApi.deriveQuoteKey(master, GENERATION_A);
  const encrypted = await cryptoApi.encryptEnvelope('private', key, `quote:q1:${GENERATION_A}`);
  assert.equal(await cryptoApi.decryptEnvelope(encrypted, key, `quote:q1:${GENERATION_A}`), 'private');
  await assert.rejects(cryptoApi.decryptEnvelope(encrypted, key, `quote:q2:${GENERATION_A}`));
  await assert.rejects(cryptoApi.decryptEnvelope(encrypted, key, `quote:q1:${GENERATION_B}`));
  await assert.rejects(cryptoApi.deriveQuoteKey(new Uint8Array(), GENERATION_A));
  await assert.rejects(cryptoApi.deriveQuoteKey(new Uint8Array(31), GENERATION_A));
});

test('a wrapped vault key validates its target and generation', async () => {
  const pair = await cryptoApi.generateWrappingKeyPair();
  const publicJwk = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
  const fingerprint = await cryptoApi.fingerprintPublicJwk(publicJwk);
  const masterKey = cryptoApi.generateVaultMasterKey();
  const wrapped = await cryptoApi.wrapVaultKey({
    version: 1, vaultId: 'quotevault', generation: GENERATION_A,
    targetFingerprint: fingerprint, masterKey,
  }, pair.publicKey);
  assert.deepEqual(await cryptoApi.unwrapVaultKey(wrapped, pair.privateKey, {
    vaultId: 'quotevault', generation: GENERATION_A, targetFingerprint: fingerprint,
  }), masterKey);
  await assert.rejects(cryptoApi.unwrapVaultKey(wrapped, pair.privateKey, {
    vaultId: 'quotevault', generation: GENERATION_B, targetFingerprint: fingerprint,
  }));
  await assert.rejects(cryptoApi.wrapVaultKey({
    version: 1, vaultId: 'quotevault', generation: GENERATION_A,
    targetFingerprint: fingerprint, masterKey: new Uint8Array(33),
  }, pair.publicKey));
  const backing = new masterKey.constructor(64);
  const slicedMasterKey = backing.subarray(16, 48);
  webcrypto.getRandomValues(slicedMasterKey);
  const sliced = await cryptoApi.wrapVaultKey({
    version: 1, vaultId: 'quotevault', generation: GENERATION_A,
    targetFingerprint: fingerprint, masterKey: slicedMasterKey,
  }, pair.publicKey);
  assert.deepEqual(await cryptoApi.unwrapVaultKey(sliced, pair.privateKey, {
    vaultId: 'quotevault', generation: GENERATION_A, targetFingerprint: fingerprint,
  }), slicedMasterKey);
});

test('wrapping keys use the required RSA-OAEP parameters', async () => {
  const pair = await cryptoApi.generateWrappingKeyPair();
  assert.equal(pair.publicKey.algorithm.name, 'RSA-OAEP');
  assert.equal(pair.publicKey.algorithm.modulusLength, 3072);
  assert.equal(pair.publicKey.algorithm.hash.name, 'SHA-256');
  assert.deepEqual([...pair.publicKey.algorithm.publicExponent], [1, 0, 1]);
});

test('public JWK fingerprints are stable and reject malformed material', async () => {
  const pair = await cryptoApi.generateWrappingKeyPair();
  const jwk = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
  const fingerprint = await cryptoApi.fingerprintPublicJwk(jwk);
  assert.equal(fingerprint, await cryptoApi.fingerprintPublicJwk({ use: 'enc', alg: 'RSA-OAEP-256', e: jwk.e, n: jwk.n, kty: 'RSA' }));
  await assert.rejects(cryptoApi.fingerprintPublicJwk({ ...jwk, n: `${jwk.n}=` }));
  await assert.rejects(cryptoApi.fingerprintPublicJwk({ ...jwk, n: jwk.n.slice(1) }));
  await assert.rejects(cryptoApi.fingerprintPublicJwk({ ...jwk, e: 'Aw' }));
  await assert.rejects(cryptoApi.fingerprintPublicJwk({ ...jwk, kty: 'EC' }));
});

test('authorization tokens have exact entropy, canonical encoding, and stable digests', async () => {
  const token = cryptoApi.generateAuthorizationToken();
  assert.match(token, /^[A-Za-z0-9_-]{43}$/);
  const digest = await cryptoApi.digestAuthorizationToken(token);
  assert.equal(digest, await cryptoApi.digestAuthorizationToken(token));
  assert.notEqual(digest, token);
  await assert.rejects(cryptoApi.digestAuthorizationToken(`${token}=`));
  await assert.rejects(cryptoApi.digestAuthorizationToken('AA'));
});

test('recovery KDF enforces the fixed PBKDF2 policy', async () => {
  const kdf = { version: 1, salt: 'AAAAAAAAAAAAAAAAAAAAAA==', iterations: 600000 };
  const key = await cryptoApi.deriveRecoveryBundleKey('recovery phrase', kdf);
  assert.equal(key.algorithm.name, 'AES-GCM');
  assert.equal(key.extractable, false);
  await assert.rejects(cryptoApi.deriveRecoveryBundleKey('recovery phrase', { ...kdf, iterations: 599999 }));
  await assert.rejects(cryptoApi.deriveRecoveryBundleKey('recovery phrase', { ...kdf, iterations: 600001 }));
  await assert.rejects(cryptoApi.deriveRecoveryBundleKey('recovery phrase', { ...kdf, salt: 'AA==' }));
});

test('private bundles authenticate their binding and reject malformed base64', async () => {
  const pair = await cryptoApi.generateWrappingKeyPair();
  const publicJwk = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
  const fingerprint = await cryptoApi.fingerprintPublicJwk(publicJwk);
  const token = cryptoApi.generateAuthorizationToken();
  const recoveryKdf = { version: 1, salt: 'AAAAAAAAAAAAAAAAAAAAAA==', iterations: 600000 };
  const key = await cryptoApi.deriveRecoveryBundleKey('recovery phrase', recoveryKdf);
  const binding = { accountId: 'account-a', recordId: 'device-a', publicKeyFingerprint: fingerprint, protectionMode: 'recovery', version: 1, recoveryKdf };
  const bundle = { version: 1, privateJwk: await webcrypto.subtle.exportKey('jwk', pair.privateKey), authorizationToken: token };
  const encrypted = await cryptoApi.encryptPrivateBundle(bundle, key, binding);
  assert.equal(JSON.stringify(await cryptoApi.decryptPrivateBundle(encrypted, key, binding)), JSON.stringify(bundle));
  await assert.rejects(cryptoApi.encryptPrivateBundle({ ...bundle, privateJwk: { ...bundle.privateJwk, d: undefined } }, key, binding));
  const otherPair = await cryptoApi.generateWrappingKeyPair();
  const otherPrivateJwk = await webcrypto.subtle.exportKey('jwk', otherPair.privateKey);
  await assert.rejects(cryptoApi.encryptPrivateBundle({ ...bundle, privateJwk: otherPrivateJwk }, key, binding));
  const forged = await cryptoApi.encryptEnvelope(JSON.stringify({ ...bundle, privateJwk: otherPrivateJwk }), key,
    JSON.stringify([1, binding.accountId, binding.recordId, binding.publicKeyFingerprint, binding.protectionMode, binding.version, [recoveryKdf.version, recoveryKdf.salt, recoveryKdf.iterations]]));
  await assert.rejects(cryptoApi.decryptPrivateBundle(forged, key, binding));
  await assert.rejects(cryptoApi.decryptPrivateBundle(encrypted, key, { ...binding, accountId: 'account-b' }));
  await assert.rejects(cryptoApi.decryptPrivateBundle({ ...encrypted, iv: '*' }, key, binding));
  await assert.rejects(cryptoApi.decryptPrivateBundle({ ...encrypted, data: `${encrypted.data}*` }, key, binding));
});

test('recovery bundle AAD requires canonical KDF metadata', async () => {
  const pair = await cryptoApi.generateWrappingKeyPair();
  const publicJwk = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
  const fingerprint = await cryptoApi.fingerprintPublicJwk(publicJwk);
  const recoveryKdf = { version: 1, salt: 'AAAAAAAAAAAAAAAAAAAAAA==', iterations: 600000 };
  const key = await cryptoApi.deriveRecoveryBundleKey('recovery phrase', recoveryKdf);
  const bundle = { version: 1, privateJwk: await webcrypto.subtle.exportKey('jwk', pair.privateKey), authorizationToken: cryptoApi.generateAuthorizationToken() };
  const binding = { accountId: 'account-a', recordId: 'recovery-a', publicKeyFingerprint: fingerprint, protectionMode: 'recovery', version: 1, recoveryKdf };
  const encrypted = await cryptoApi.encryptPrivateBundle(bundle, key, binding);

  await assert.rejects(cryptoApi.encryptPrivateBundle(bundle, key, { ...binding, recoveryKdf: undefined }));
  await assert.rejects(cryptoApi.decryptPrivateBundle(encrypted, key, { ...binding, recoveryKdf: { ...recoveryKdf, salt: 'AQAAAAAAAAAAAAAAAAAAAA==' } }));
  await assert.rejects(cryptoApi.encryptPrivateBundle(bundle, key, { ...binding, recoveryKdf: { ...recoveryKdf, version: 2 } }));
  await assert.rejects(cryptoApi.encryptPrivateBundle(bundle, key, { ...binding, recoveryKdf: { ...recoveryKdf, salt: 'AA==' } }));
  await assert.rejects(cryptoApi.encryptPrivateBundle(bundle, key, { ...binding, recoveryKdf: { ...recoveryKdf, salt: 'AAAAAAAAAAAAAAAAAAAAAB==' } }));
  await assert.rejects(cryptoApi.encryptPrivateBundle(bundle, key, { ...binding, recoveryKdf: { ...recoveryKdf, iterations: 599999 } }));
  await assert.rejects(cryptoApi.encryptPrivateBundle(bundle, key, { ...binding, recoveryKdf: { ...recoveryKdf, algorithm: 'PBKDF2' } }));
  const inheritedKdf = Object.assign(Object.create({ algorithm: 'PBKDF2' }), recoveryKdf);
  await assert.rejects(cryptoApi.encryptPrivateBundle(bundle, key, { ...binding, recoveryKdf: inheritedKdf }));
  const hiddenKdf = { ...recoveryKdf };
  Object.defineProperty(hiddenKdf, 'algorithm', { value: 'PBKDF2' });
  await assert.rejects(cryptoApi.encryptPrivateBundle(bundle, key, { ...binding, recoveryKdf: hiddenKdf }));
  const passkeyProtection = { version: 1, rpId: 'quotes.darkmg1.dev', credentialId: 'AQIDBA', prfSalt: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', kdf: 'HKDF-SHA-256' };
  const recoveryAad = JSON.stringify([1, binding.accountId, binding.recordId, binding.publicKeyFingerprint, binding.protectionMode, binding.version, [recoveryKdf.version, recoveryKdf.salt, recoveryKdf.iterations]]);
  const recoveryEncrypted = await cryptoApi.encryptEnvelope(JSON.stringify(bundle), key, recoveryAad);
  assert.equal(JSON.stringify(await cryptoApi.decryptPrivateBundle(recoveryEncrypted, key, binding)), JSON.stringify(bundle));
  await assert.rejects(cryptoApi.encryptPrivateBundle(bundle, key, { ...binding, protection: passkeyProtection }));

  const rememberedBinding = { ...binding, protectionMode: 'remembered', recoveryKdf: undefined };
  const rememberedKey = await webcrypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const legacyAad = JSON.stringify([1, rememberedBinding.accountId, rememberedBinding.recordId, rememberedBinding.publicKeyFingerprint, rememberedBinding.protectionMode, rememberedBinding.version]);
  const legacyEncrypted = await cryptoApi.encryptEnvelope(JSON.stringify(bundle), rememberedKey, legacyAad);
  assert.equal(JSON.stringify(await cryptoApi.decryptPrivateBundle(legacyEncrypted, rememberedKey, rememberedBinding)), JSON.stringify(bundle));
  await assert.rejects(cryptoApi.encryptPrivateBundle(bundle, rememberedKey, { ...rememberedBinding, recoveryKdf }));
  await assert.rejects(cryptoApi.decryptPrivateBundle(legacyEncrypted, rememberedKey, { ...rememberedBinding, recoveryKdf }));
  await assert.rejects(cryptoApi.encryptPrivateBundle(bundle, rememberedKey, { ...rememberedBinding, protection: passkeyProtection }));
});

test('passkey bundle AAD requires exact PRF protection metadata', async () => {
  const pair = await cryptoApi.generateWrappingKeyPair();
  const fingerprint = await cryptoApi.fingerprintPublicJwk(await webcrypto.subtle.exportKey('jwk', pair.publicKey));
  const key = await webcrypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const protection = { version: 1, rpId: 'quotes.darkmg1.dev', credentialId: 'AQIDBA', prfSalt: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', kdf: 'HKDF-SHA-256' };
  const binding = { accountId: 'account-a', recordId: 'device-a', publicKeyFingerprint: fingerprint, protectionMode: 'passkey-prf', version: 1, protection };
  const bundle = { version: 1, privateJwk: await webcrypto.subtle.exportKey('jwk', pair.privateKey), authorizationToken: cryptoApi.generateAuthorizationToken() };
  const encrypted = await cryptoApi.encryptPrivateBundle(bundle, key, binding);
  assert.equal(JSON.stringify(await cryptoApi.decryptPrivateBundle(encrypted, key, binding)), JSON.stringify(bundle));

  await assert.rejects(cryptoApi.encryptPrivateBundle(bundle, key, { ...binding, protection: undefined }));
  await assert.rejects(cryptoApi.decryptPrivateBundle(encrypted, key, { ...binding, protection: { ...protection, version: 2 } }));
  await assert.rejects(cryptoApi.decryptPrivateBundle(encrypted, key, { ...binding, protection: { ...protection, rpId: 'example.com' } }));
  await assert.rejects(cryptoApi.decryptPrivateBundle(encrypted, key, { ...binding, protection: { ...protection, credentialId: 'BQYHCA' } }));
  await assert.rejects(cryptoApi.decryptPrivateBundle(encrypted, key, { ...binding, protection: { ...protection, prfSalt: 'BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' } }));
  await assert.rejects(cryptoApi.decryptPrivateBundle(encrypted, key, { ...binding, protection: { ...protection, kdf: 'PBKDF2' } }));
  await assert.rejects(cryptoApi.encryptPrivateBundle(bundle, key, { ...binding, protection: { ...protection, algorithm: 'PRF' } }));
  const { credentialId, ...missingCredential } = protection;
  await assert.rejects(cryptoApi.encryptPrivateBundle(bundle, key, { ...binding, protection: missingCredential }));
  await assert.rejects(cryptoApi.encryptPrivateBundle(bundle, key, { ...binding, protection: { ...protection, credentialId: 'AQ==' } }));
  await assert.rejects(cryptoApi.encryptPrivateBundle(bundle, key, { ...binding, protection: { ...protection, prfSalt: `${protection.prfSalt}=` } }));
});
