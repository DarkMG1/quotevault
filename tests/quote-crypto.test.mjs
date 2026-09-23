import assert from 'node:assert/strict';
import test from 'node:test';
import { webcrypto } from 'node:crypto';
import { loadModule } from './load-module.mjs';

const cryptoApi = loadModule('src/lib/crypto.ts', {}, {
  crypto: webcrypto, TextEncoder, TextDecoder, btoa, atob,
});
const deviceCrypto = loadModule('src/lib/device-crypto.ts', { './crypto': cryptoApi }, {
  crypto: webcrypto, TextEncoder, TextDecoder, btoa, atob,
});
const quoteCrypto = loadModule('src/lib/quote-crypto.ts', {
  './crypto': cryptoApi,
  './device-crypto': deviceCrypto,
}, {
  crypto: webcrypto, TextEncoder, TextDecoder, btoa, atob,
});

const visible = {
  id: 'quote-1', vault_generation: 'generation-1', user_id: 'user-1',
  created_at: '2026-09-22T15:00:00.000Z', quote_date: '2026-09-21',
};
const privateFields = {
  text: 'The private quote', author: 'Ada & Grace', context: 'A private note',
  source_sender: 'Original Sender', import_source_id: 'a'.repeat(64),
};

test('writes a v2 sentinel envelope and preserves every private field', async () => {
  const key = await cryptoApi.deriveEncryptionKey('test-passphrase');
  const stored = await quoteCrypto.encryptQuoteRecord(privateFields, visible, key);

  assert.equal(stored.text.startsWith('$$E2E$$'), true);
  assert.equal(JSON.parse(stored.text.slice(7)).version, 2);
  assert.deepEqual(JSON.parse(JSON.stringify(await quoteCrypto.decryptQuoteRecord(stored, key))), { ...visible, ...privateFields });
});

test('rejects every authenticated metadata mismatch', async () => {
  const key = await cryptoApi.deriveEncryptionKey('test-passphrase');
  const stored = await quoteCrypto.encryptQuoteRecord(privateFields, visible, key);
  for (const field of ['id', 'vault_generation', 'user_id', 'created_at', 'quote_date']) {
    const changed = { ...stored, [field]: field === 'quote_date' ? '2030-01-01' : field === 'created_at' ? '2030-01-01T00:00:00Z' : `different-${field}` };
    await assert.rejects(quoteCrypto.decryptQuoteRecord(changed, key), /authenticated metadata/);
  }
});

test('canonicalizes equivalent timestamp spellings and rejects invalid timestamps', async () => {
  const key = await cryptoApi.deriveEncryptionKey('test-passphrase');
  const stored = await quoteCrypto.encryptQuoteRecord(privateFields, visible, key);
  const equivalent = { ...stored, created_at: '2026-09-22T15:00:00+00:00' };
  const decrypted = await quoteCrypto.decryptQuoteRecord(equivalent, key);
  assert.equal(decrypted.created_at, equivalent.created_at, 'server-visible timestamp is retained');
  const precise = await quoteCrypto.encryptQuoteRecord(privateFields, { ...visible, created_at: '2026-09-22T15:00:00.123000Z' }, key);
  const preciseEquivalent = { ...precise, created_at: '2026-09-22T15:00:00.123+00:00' };
  assert.equal((await quoteCrypto.decryptQuoteRecord(preciseEquivalent, key)).created_at, preciseEquivalent.created_at);
  await assert.rejects(quoteCrypto.decryptQuoteRecord({ ...precise, created_at: '2026-09-22T15:00:00.123001+00:00' }, key), /authenticated metadata/);
  for (const created_at of ['2026-02-30T00:00:00Z', '2025-02-29T00:00:00Z', '0000-01-01T00:00:00Z', '2026-09-22T15:00:00.1234567Z', '2026-09-22T15:00:00-04:00', 'not-a-timestamp']) {
    await assert.rejects(quoteCrypto.encryptQuoteRecord(privateFields, { ...visible, created_at }, key), /Invalid quote metadata/);
  }
});

test('reads legacy sentinel ciphertext during migration', async () => {
  const key = await cryptoApi.deriveEncryptionKey('test-passphrase');
  const bundle = await cryptoApi.encryptData(JSON.stringify({ text: 'Legacy', author: 'Ada', context: 'Old' }), key);
  const stored = { ...visible, text: `$$E2E$$${JSON.stringify(bundle)}` };

  assert.deepEqual(JSON.parse(JSON.stringify(await quoteCrypto.decryptQuoteRecord(stored, key))), {
    ...visible, text: 'Legacy', author: 'Ada', context: 'Old',
  });
});

test('legacy v1 text decrypts through the a1bb840 display path and the current reader', async () => {
  const key = await cryptoApi.deriveEncryptionKey('legacy-reversion-test-key');
  const fields = { text: 'first line\nsecond line', author: 'Ada & Grace', context: 'A context', source_sender: 'Original sender', import_source_id: '1'.padStart(64, '0') };
  const text = await quoteCrypto.encryptLegacyQuoteText(fields, key);
  assert.ok(text.startsWith('$$E2E$$'));
  const bundle = JSON.parse(text.slice('$$E2E$$'.length));
  assert.equal(Object.hasOwn(bundle, 'version'), false, 'a1bb840 treats any bundle as v1');
  // a1bb840 src/components/ui.ts decryptQuoteForDisplay: decryptData(bundle, key) then isDecryptedPayload.
  const legacy = JSON.parse(await cryptoApi.decryptData(bundle, key));
  assert.equal(JSON.stringify(legacy), JSON.stringify(fields));
  const current = await quoteCrypto.decryptQuoteRecord({ id: '11111111-1111-4111-8111-111111111111', text, user_id: '22222222-2222-4222-8222-222222222222', vault_generation: '33333333-3333-4333-8333-333333333333', created_at: '2026-09-23T00:00:00.000Z', quote_date: null }, key);
  for (const [name, value] of Object.entries(fields)) assert.equal(current[name], value);
});
