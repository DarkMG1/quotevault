import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { webcrypto } from 'node:crypto';
import ts from 'typescript';

const source = readFileSync(new URL('../src/lib/crypto.ts', import.meta.url), 'utf8');
const exports = {};
runInNewContext(ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText,
  { exports, crypto: webcrypto, TextEncoder, TextDecoder, btoa, atob, console });
const { deriveEncryptionKey, encryptData, decryptData } = exports;

test('different vault salts prevent decryption with the same password', async () => {
  const first = { salt: 'AAAAAAAAAAAAAAAAAAAAAA==', iterations: 100000 };
  const second = { salt: 'AQEBAQEBAQEBAQEBAQEBAQ==', iterations: 100000 };
  const data = await encryptData('private 🔒', await deriveEncryptionKey('test-only-password', first));
  assert.equal(await decryptData(data, await deriveEncryptionKey('test-only-password', first)), 'private 🔒');
  await assert.rejects(decryptData(data, await deriveEncryptionKey('test-only-password', second)));
});

test('rejects malicious derivation metadata before expensive work', async () => {
  await assert.rejects(deriveEncryptionKey('test', { salt: 'AA==', iterations: 100000 }));
  await assert.rejects(deriveEncryptionKey('test', { salt: 'AAAAAAAAAAAAAAAAAAAAAA==', iterations: 999999999 }));
});

test('ciphertext tampering is rejected', async () => {
  const key = await deriveEncryptionKey('test-only-password');
  const payload = await encryptData('café', key);
  const bytes = Buffer.from(payload.data, 'base64');
  bytes[0] ^= 1;
  await assert.rejects(decryptData({ ...payload, data: bytes.toString('base64') }, key));
});

test('new vault verification supports offline unlock and rejects the wrong secret', async () => {
  const { kdf, verifier } = await exports.createVaultConfig('test-only-passphrase');
  const key = await exports.unlockWithVerifier('test-only-passphrase', kdf, verifier);
  assert.equal(await decryptData(await encryptData('quote', key), key), 'quote');
  await assert.rejects(exports.unlockWithVerifier('different-passphrase', kdf, verifier));
  await assert.rejects(exports.createVaultConfig('1234'));
});

test('legacy ciphertext can verify the existing key without a fast password hash', async () => {
  const key = await deriveEncryptionKey('old-test-key');
  const verifier = await encryptData(JSON.stringify({ text: 'existing quote', author: 'Test' }), key);
  const unlocked = await exports.unlockWithVerifier('old-test-key', exports.LEGACY_KDF, verifier);
  assert.equal(await decryptData(verifier, unlocked), JSON.stringify({ text: 'existing quote', author: 'Test' }));
});
