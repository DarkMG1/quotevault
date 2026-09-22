import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { loadModule } from './load-module.mjs';
const crypt = loadModule('src/lib/crypto.ts', {}, { crypto: webcrypto, TextEncoder, TextDecoder, btoa, atob });
const deviceCrypt = loadModule('src/lib/device-crypto.ts', { './crypto': crypt }, { crypto: webcrypto, TextEncoder, TextDecoder, btoa, atob });
const quoteCrypt = loadModule('src/lib/quote-crypto.ts', { './crypto': crypt, './device-crypto': deviceCrypt }, { crypto: webcrypto, TextEncoder, TextDecoder, btoa, atob });
const key = await crypt.deriveEncryptionKey('synthetic-import-key');
const ui = loadModule('src/components/ui.ts', { react: {}, '../lib/quote-crypto': quoteCrypt });
const storage = new Map();
const queue = [];
let handler;
const calls = [];
const db = { metadata: { get: async id => storage.get(id), put: async value => storage.set(value.id, value), delete: async id => storage.delete(id) },
  syncQueue: { toArray: async () => queue }, transaction: async (...args) => args.at(-1)() };
const context = { actorId: '22222222-2222-4222-8222-222222222222', generation: '11111111-1111-4111-8111-111111111111' };
const importer = loadModule('src/lib/quote-import.ts', {
  './crypto': crypt, './quote-crypto': quoteCrypt, './db': { db }, '../components/ui': ui, './sync': { processSyncQueue: async () => true },
  './supabase': { supabase: { rpc: (name, args) => ({ abortSignal: async () => { calls.push({name, args}); return handler(name, args); } }) } },
}, { crypto: webcrypto, TextEncoder, AbortController, setTimeout, clearTimeout, navigator: { onLine: true } });
const raw = { text: 'Synthetic private words', author: 'Ada', context: 'Synthetic context', source_sender: 'Grace',
  source: { id: 'a'.repeat(64), timestamp: 'Sep 21, 2026  1:00:00 PM' } };
const file = value => JSON.stringify({ format: 'quotevault-reviewed-quotes', version: 1, quotes: value });
const rows = importer.parseImportFile(file([raw]));
assert.equal(rows[0].quote_date, '2026-09-21');
assert.equal(rows[0].selected, true);
assert.throws(() => importer.parseImportFile(file([{ ...raw, quote_date: '2026-02-30' }])), /date/);
assert.throws(() => importer.parseImportFile(file([{ ...raw, text: {} }])), /text/);
assert.throws(() => importer.parseImportFile(file([{ ...raw, source: { id: 'invalid' } }])), /identity/);
assert.throws(() => importer.parseImportFile(file(Array(501).fill(raw))), /500/);
assert.equal(importer.checkImports(rows, [{text: ' synthetic  PRIVATE words ', author: 'ADA'}])[0].duplicate, true);
assert.equal(importer.checkImports(rows, [{text: 'User changed the wording', author: 'Different', import_source_id: 'a'.repeat(64)}])[0].duplicate, true);
assert.equal(importer.checkImports([...rows, ...rows], [])[1].duplicate, true);
assert.equal(importer.checkImports([{...rows[0], author: 'Ada & Grace'}], [{text: raw.text, author: 'Grace & Ada'}])[0].duplicate, true);
assert.equal(importer.checkImports([{...rows[0], author: 'Ada & Grace'}], [{text: raw.text, author: 'Ada & Someone else'}])[0].duplicate, false);
assert.ok(importer.checkImports(rows, [{text: raw.text, author: 'Different person'}])[0].similar);
const encrypted = await crypt.encryptData(JSON.stringify({text: 'Existing', author: 'Ada'}), key);
handler = async () => ({ data: { generation: context.generation, revision: 3, quotes: [{ vault_generation: context.generation, text: '$$E2E$$' + JSON.stringify(encrypted) }] } });
const snapshot = await importer.loadImportSnapshot(context, key);
assert.equal(snapshot.quotes[0].text, 'Existing');
queue.push({ actor_id: context.actorId, vault_generation: context.generation });
await assert.rejects(importer.loadImportSnapshot(context, key), /pending/);
queue.length = 0;
let active = true;
const cancelled = importer.prepareImport(rows, snapshot, context, key, () => active);
active = false;
await assert.rejects(cancelled, /access changed/);
assert.equal(storage.size, 0);
const pending = await importer.prepareImport(rows, snapshot, context, key, () => true);
for (const secret of [raw.text, raw.author, raw.context, raw.source_sender, raw.source.id]) {
  assert.equal(JSON.stringify([...storage]).includes(secret), false, 'saved retry data must be encrypted');
  assert.equal(JSON.stringify(pending.operations).includes(secret), false, 'wire operations must be encrypted');
}
const recovered = await importer.readPendingImport(context, key);
assert.deepEqual(JSON.parse(JSON.stringify(recovered)), JSON.parse(JSON.stringify(pending)));
await assert.rejects(importer.prepareImport(rows, snapshot, context, key, () => true), /saved import/);
handler = async () => { throw new Error('Network interrupted after request'); };
await assert.rejects(importer.sendPendingImport(pending, context), /Network interrupted/);
assert.equal(storage.size, 1, 'uncertain import remains recoverable');
const originalRequest = JSON.stringify(calls.at(-1).args);
handler = async (_name, args) => ({ data: { generation: context.generation, results: args.p_operations.map(op => ({ operation_id: op.operation_id, status: 'ok' })) } });
assert.equal(await importer.sendPendingImport(recovered, context), 1);
assert.equal(JSON.stringify(calls.at(-1).args), originalRequest, 'uncertain retry uses exactly the original ciphertext and operation IDs');
assert.equal(storage.size, 0);
const conflict = await importer.prepareImport(rows, snapshot, context, key, () => true);
handler = async () => ({ error: { code: '40001', message: 'Vault changed' } });
await assert.rejects(importer.sendPendingImport(conflict, context), /Vault changed/);
assert.equal(storage.size, 0, 'confirmed rollback permits a new review');
await assert.rejects(importer.sendPendingImport(pending, { ...context, generation: 'other' }), /another vault/);
console.log('Import validation, duplicate detection, encryption, cancellation, and retry checks passed.');
