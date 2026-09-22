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
    const changed = { ...stored, [field]: field === 'quote_date' ? '2030-01-01' : `different-${field}` };
    await assert.rejects(quoteCrypto.decryptQuoteRecord(changed, key), /authenticated metadata/);
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
