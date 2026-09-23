import assert from 'node:assert/strict';
import test from 'node:test';
import { webcrypto } from 'node:crypto';
import { loadModule } from './load-module.mjs';

const globals = { crypto: webcrypto, TextEncoder, TextDecoder, btoa, atob, navigator: { onLine: true } };
const cryptoApi = loadModule('src/lib/crypto.ts', {}, globals);
const deviceCrypto = loadModule('src/lib/device-crypto.ts', { './crypto': cryptoApi }, globals);
const quoteCrypto = loadModule('src/lib/quote-crypto.ts', { './crypto': cryptoApi, './device-crypto': deviceCrypto }, globals);
const GEN = '11111111-1111-4111-8111-111111111111';
const USER = '33333333-3333-4333-8333-333333333333';
const REVERSION = '44444444-4444-4444-8444-444444444444';
const TARGET = '55555555-5555-4555-8555-555555555555';

function load(rpc) {
  const supabase = { supabase: { rpc: async (name, args) => rpc(name, args) } };
  const migration = loadModule('src/lib/vault-migration.ts', { './crypto': cryptoApi, './device-crypto': deviceCrypto, './quote-crypto': quoteCrypto, './supabase': supabase }, globals);
  return loadModule('src/lib/legacy-reversion.ts', { './crypto': cryptoApi, './quote-crypto': quoteCrypto, './vault-migration': migration, './supabase': supabase }, globals);
}
const ok = data => ({ data, error: null });
const fields = index => ({ text: `Private quote ${index}`, author: index % 2 ? 'Ada & Grace' : 'Ada', context: `Context ${index}`, source_sender: 'Original sender', import_source_id: String(index).padStart(64, '0') });

async function vault(count) {
  const master = deviceCrypto.generateVaultMasterKey();
  const key = await deviceCrypto.deriveQuoteKey(master, GEN);
  const legacyKey = await cryptoApi.deriveEncryptionKey('pre-envelope-shared-key');
  const quotes = await Promise.all(Array.from({ length: count }, async (_, index) => {
    const id = `${String(index + 1).padStart(8, '0')}-1111-4111-8111-111111111111`;
    const visible = { id, quote_date: '2026-09-22', created_at: '2026-09-22T12:00:00.000Z', user_id: USER, vault_generation: GEN, author: 'ENCRYPTED', context: 'ENCRYPTED' };
    return quoteCrypto.encryptQuoteRecord(fields(index), visible, key);
  }));
  return { key, legacyKey, quotes };
}

test('dry run converts and verifies every quote without writing', async () => {
  const { key, quotes } = await vault(3);
  const calls = [];
  const runner = load((name, args) => { calls.push(name); if (name === 'sync_quotes') return ok({ generation: GEN, revision: 9, results: [], quotes }); throw new Error(`unexpected ${name}`); });
  const result = await runner.revertToLegacy({ sourceGeneration: GEN, sourceKey: key, passphrase: 'a long enough passphrase', deviceId: null, token: null, dryRun: true });
  assert.equal(result.quoteCount, 3);
  assert.equal(result.generation, null);
  assert.deepEqual([...calls], ['sync_quotes']);
});

test('reverts every field to v1 text readable with the new passphrase', async () => {
  const { key, quotes } = await vault(53);
  const batches = []; const stagedRows = []; let commitArgs;
  const runner = load((name, args) => {
    if (name === 'sync_quotes') return ok({ generation: GEN, revision: 9, results: [], quotes });
    if (name === 'begin_legacy_reversion') { assert.equal(args.p_source_revision, 9); return ok({ reversion_id: REVERSION, target_generation: TARGET, expected_quote_count: 53 }); }
    if (name === 'stage_legacy_reversion') { batches.push(args.p_rows.length); stagedRows.push(...args.p_rows); return ok({ reversion_id: REVERSION, staged_quote_count: stagedRows.length }); }
    if (name === 'commit_legacy_reversion') { commitArgs = args; return ok({ generation: TARGET, revision: 10, envelope_status: 'legacy', quote_count: 53 }); }
    throw new Error(`unexpected ${name}`);
  });
  const result = await runner.revertToLegacy({ sourceGeneration: GEN, sourceKey: key, passphrase: 'a long enough passphrase', deviceId: null, token: null });
  assert.equal(result.quoteCount, 53);
  assert.equal(result.generation, TARGET);
  assert.equal(JSON.stringify(batches), JSON.stringify([50, 3]));
  const newKey = await cryptoApi.unlockWithVerifier('a long enough passphrase', commitArgs.p_kdf, commitArgs.p_verifier);
  for (const [index, row] of stagedRows.entries()) {
    const bundle = JSON.parse(row.text.slice('$$E2E$$'.length));
    assert.equal(Object.hasOwn(bundle, 'version'), false);
    assert.equal(await cryptoApi.decryptData(bundle, newKey), JSON.stringify(fields(index)));
  }
});

test('aborts before any write when a quote cannot be decrypted', async () => {
  const { key, quotes } = await vault(2);
  const damaged = [quotes[0], { ...quotes[1], text: quotes[0].text }];
  const calls = [];
  const runner = load((name) => { calls.push(name); if (name === 'sync_quotes') return ok({ generation: GEN, revision: 9, results: [], quotes: damaged }); throw new Error(`unexpected ${name}`); });
  await assert.rejects(runner.revertToLegacy({ sourceGeneration: GEN, sourceKey: key, passphrase: 'a long enough passphrase', deviceId: null, token: null }), /00000002-1111-4111-8111-111111111111/);
  assert.deepEqual([...calls], ['sync_quotes']);
});

test('aborts without writing when the revision changes during staging', async () => {
  const { key, quotes } = await vault(2);
  const calls = [];
  const runner = load((name) => {
    calls.push(name);
    if (name === 'sync_quotes') return ok({ generation: GEN, revision: 9, results: [], quotes });
    if (name === 'begin_legacy_reversion') return ok({ reversion_id: REVERSION, target_generation: TARGET, expected_quote_count: 2 });
    if (name === 'stage_legacy_reversion') return { data: null, error: { code: '40001', message: 'Vault changed; reload and start again' } };
    throw new Error(`unexpected ${name}`);
  });
  await assert.rejects(runner.revertToLegacy({ sourceGeneration: GEN, sourceKey: key, passphrase: 'a long enough passphrase', deviceId: null, token: null }), /Vault changed/);
  assert.equal(calls.includes('commit_legacy_reversion'), false);
});

test('refuses a short passphrase before reading the vault', async () => {
  const { key } = await vault(1);
  const runner = load(() => { throw new Error('no RPC expected'); });
  await assert.rejects(runner.revertToLegacy({ sourceGeneration: GEN, sourceKey: key, passphrase: 'short', deviceId: null, token: null }), /at least 12/);
});

test('dry run refuses a quote the shared-key client cannot display', async () => {
  const master = deviceCrypto.generateVaultMasterKey();
  const key = await deviceCrypto.deriveQuoteKey(master, GEN);
  const id = '00000001-1111-4111-8111-111111111111';
  const visible = { id, quote_date: '2026-09-22', created_at: '2026-09-22T12:00:00.000Z', user_id: USER, vault_generation: GEN, author: 'ENCRYPTED', context: 'ENCRYPTED' };
  const quote = await quoteCrypto.encryptQuoteRecord({ text: 'only text' }, visible, key);
  const runner = load((name) => { if (name === 'sync_quotes') return ok({ generation: GEN, revision: 9, results: [], quotes: [quote] }); throw new Error(`unexpected ${name}`); });
  await assert.rejects(runner.revertToLegacy({ sourceGeneration: GEN, sourceKey: key, passphrase: 'a long enough passphrase', deviceId: null, token: null, dryRun: true }), /00000001-1111-4111-8111-111111111111 has no text or author/);
});

test('dry run refuses a quote whose context is not a string', async () => {
  const master = deviceCrypto.generateVaultMasterKey();
  const key = await deviceCrypto.deriveQuoteKey(master, GEN);
  const id = '00000002-1111-4111-8111-111111111111';
  const visible = { id, quote_date: '2026-09-22', created_at: '2026-09-22T12:00:00.000Z', user_id: USER, vault_generation: GEN, author: 'ENCRYPTED', context: 'ENCRYPTED' };
  const quote = await quoteCrypto.encryptQuoteRecord({ text: 'has a bad context', author: 'Ada', context: 42 }, visible, key);
  const runner = load((name) => { if (name === 'sync_quotes') return ok({ generation: GEN, revision: 9, results: [], quotes: [quote] }); throw new Error(`unexpected ${name}`); });
  await assert.rejects(runner.revertToLegacy({ sourceGeneration: GEN, sourceKey: key, passphrase: 'a long enough passphrase', deviceId: null, token: null, dryRun: true }), /00000002-1111-4111-8111-111111111111 has no text or author/);
});
