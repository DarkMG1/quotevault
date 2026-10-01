import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { loadModule } from './load-module.mjs';

const globals = { crypto: webcrypto, TextEncoder, TextDecoder, btoa, atob, console };
const crypto = loadModule('src/lib/crypto.ts', {}, globals);
let decryptCalls = 0;
const countingCrypto = { ...crypto, decryptData: (...args) => { decryptCalls++; return crypto.decryptData(...args); } };
const ui = loadModule('src/components/ui.ts', { react: {}, '../lib/crypto': countingCrypto }, globals);
const { decryptForFeed } = loadModule('src/components/feed-decrypt.ts', { './ui': ui }, globals);

const key = await crypto.deriveEncryptionKey('test-only-password', crypto.LEGACY_KDF);
const otherKey = await crypto.deriveEncryptionKey('another-test-password', crypto.LEGACY_KDF);
const seal = async (payload, sealKey = key) => '$$E2E$$' + JSON.stringify(await crypto.encryptData(JSON.stringify(payload), sealKey));
const row = (id, text, extra = {}) => ({
  id, text, author: 'ENCRYPTED', context: 'ENCRYPTED', created_at: '2026-09-20T12:00:00Z',
  user_id: 'user-a', vault_generation: 'g1', sync_status: 'synced', ...extra,
});
const quotes = [
  row('a', await seal({ text: 'First', author: 'Ada', context: 'letter', source_sender: 'Grace' })),
  row('b', await seal({ text: 'Second', author: 'Grace' }), { sync_status: 'pending' }),
  row('c', await seal({ text: 'Wrong key', author: 'Eve' }, otherKey)),
  { ...row('d', 'Legacy plaintext'), author: 'Old', context: null, source_sender: 'stale' },
];
const direct = async (rows, rowKey = key) => JSON.stringify(await Promise.all(rows.map(quote => ui.decryptQuoteForDisplay(quote, rowKey))));
const copies = rows => rows.map(quote => ({ ...quote }));
// Runs one feed decryption; returns its cache, JSON output and the decrypts it made.
const feed = async (...args) => {
  decryptCalls = 0;
  const { cache, decrypted } = decryptForFeed(...args);
  const output = JSON.stringify(await decrypted);
  return { cache, output, calls: decryptCalls };
};

const first = await feed(quotes, key);
assert.equal(first.output, await direct(quotes), 'matches decrypting each quote directly, including failures and plaintext rows');
assert.equal(first.calls, 3);

const synced = copies(quotes);
synced[1].sync_status = 'synced';
const second = await feed(synced, key, first.cache);
assert.equal(second.output, await direct(synced), 'cached plaintext merges onto the latest row');
assert.equal(second.calls, 0, 'an unchanged list decrypts nothing again');

const edited = copies(synced).slice(0, 3);
edited[0].text = await seal({ text: 'First, edited', author: 'Ada' });
const third = await feed(edited, key, second.cache);
assert.equal(third.output, await direct(edited));
assert.equal(third.calls, 1, 'only the changed ciphertext is decrypted');
assert.equal(third.cache.entries.size, 3, 'removed quotes leave the cache');

const rekeyed = await feed(edited, otherKey, third.cache);
assert.equal(rekeyed.output, await direct(edited, otherKey));
assert.equal(rekeyed.calls, 3, 'a different key decrypts everything again');

console.log('Feed decryption reuses in-memory plaintext for unchanged ciphertext and drops it for a new key.');
