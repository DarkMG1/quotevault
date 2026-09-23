import assert from 'node:assert/strict';
import test from 'node:test';
import { webcrypto } from 'node:crypto';
import { loadModule } from './load-module.mjs';

const cryptoApi = loadModule('src/lib/crypto.ts', {}, { crypto: webcrypto, TextEncoder, TextDecoder, btoa, atob });
const deviceCrypto = loadModule('src/lib/device-crypto.ts', { './crypto': cryptoApi }, { crypto: webcrypto, TextEncoder, TextDecoder, btoa, atob });
const quoteCrypto = loadModule('src/lib/quote-crypto.ts', {
  './crypto': cryptoApi,
  './device-crypto': deviceCrypto,
}, { crypto: webcrypto, TextEncoder, TextDecoder, btoa, atob });

const SOURCE_GENERATION = '11111111-1111-4111-8111-111111111111';
const TARGET_GENERATION = '22222222-2222-4222-8222-222222222222';
const ACTOR = '33333333-3333-4333-8333-333333333333';
const DEVICE = '44444444-4444-4444-8444-444444444444';

function loadMigration(rpc) {
  return loadModule('src/lib/vault-migration.ts', {
    './crypto': cryptoApi,
    './device-crypto': deviceCrypto,
    './quote-crypto': quoteCrypto,
    './supabase': { supabase: { rpc } },
  }, { crypto: webcrypto, TextEncoder, TextDecoder, btoa, atob, navigator: { onLine: true } });
}

async function fixture(key, index) {
  const id = `${String(index + 1).padStart(8, '0')}-1111-4111-8111-111111111111`;
  return quoteCrypto.encryptQuoteRecord({
    text: index === 0 ? 'first line\nsecond line' : `Private quote ${index}`,
    author: index % 2 ? 'Ada & Grace' : 'Ada',
    context: index === 0 ? 'A multiline dialogue with context.' : `Imported context ${index}`,
    source_sender: 'Original sender',
    import_source_id: `${String(index + 1).padStart(64, '0')}`,
  }, {
    id,
    quote_date: '2026-09-22',
    created_at: `2026-09-22T12:00:${String(index % 60).padStart(2, '0')}.000Z`,
    user_id: ACTOR,
    vault_generation: SOURCE_GENERATION,
    author: 'ENCRYPTED',
    context: 'ENCRYPTED',
  }, key);
}

function response(data) {
  return { data, error: null };
}

test('stages encrypted quote batches and verifies every private field before finalizing', async () => {
  const sourceKey = await cryptoApi.deriveEncryptionKey('migration-source-key');
  const targetMasterKey = deviceCrypto.generateVaultMasterKey();
  const sourceQuotes = await Promise.all(Array.from({ length: 53 }, (_, index) => fixture(sourceKey, index)));
  const calls = [];
  let targetRows = [];
  const rpc = async (name, args) => {
    calls.push({ name, args });
    if (name === 'get_pending_envelope_migration') return response(null);
    if (name === 'prepare_envelope_migration') return response({ migration_id: DEVICE, status: 'staging', expected_quote_count: sourceQuotes.length, reset: false });
    if (name === 'refresh_envelope_migration_source') return response({ migration_id: DEVICE, status: 'staging', source_generation: SOURCE_GENERATION, source_revision: 7, expected_quote_count: sourceQuotes.length, reset: false });
    if (name === 'stage_envelope_wrappers') return response({ migration_id: DEVICE, status: 'staging' });
    if (name === 'stage_envelope_quotes') { targetRows.push(...args.p_rows); return response({ migration_id: DEVICE, status: targetRows.length === sourceQuotes.length ? 'ready' : 'staging', staged_quote_count: targetRows.length }); }
    if (name === 'activate_envelope_migration') return response({ migration_id: DEVICE, status: 'activated', generation: TARGET_GENERATION });
    if (name === 'get_envelope_migration_snapshot') return response({ migration_id: DEVICE, generation: TARGET_GENERATION, revision: 8, quotes: targetRows });
    if (name === 'finalize_envelope_migration') return response({ migration_id: DEVICE, status: 'finalized', generation: TARGET_GENERATION });
    throw new Error(`unexpected RPC ${name}`);
  };
  const migration = loadMigration(rpc);
  const input = {
    sourceGeneration: SOURCE_GENERATION,
    sourceRevision: 7,
    sourceKey,
    sourceQuotes,
    targetGeneration: TARGET_GENERATION,
    targetMasterKey,
    deviceId: DEVICE,
    token: 'transient-device-token',
    actorId: ACTOR,
    encryptedExportConfirmed: true,
  };
  const staged = await migration.runEnvelopeMigration(input);
  assert.equal(staged.status, 'ready');
  assert.equal(staged.stagedQuoteCount, 53);
  const result = await migration.activateEnvelopeMigration(input);
  assert.equal(result.status, 'finalized');
  assert.equal(result.verifiedQuoteCount, 53);
  assert.deepEqual(calls.filter(call => call.name === 'stage_envelope_quotes').map(call => call.args.p_rows.length), [50, 3]);
  assert.ok(calls.every(call => !JSON.stringify(call.args).includes('Private quote')));
  const targetKey = await deviceCrypto.deriveQuoteKey(targetMasterKey, TARGET_GENERATION);
  const decrypted = await Promise.all(targetRows.map(row => quoteCrypto.decryptQuoteRecord(row, targetKey)));
  assert.equal(decrypted[0].text, 'first line\nsecond line');
  assert.equal(decrypted[0].author, 'Ada');
  assert.equal(decrypted[0].context, 'A multiline dialogue with context.');
  assert.equal(decrypted[0].source_sender, 'Original sender');
  assert.equal(decrypted[0].import_source_id, '1'.padStart(64, '0'));
  assert.equal(decrypted[1].author, 'Ada & Grace');
});

test('keeps resumable migration rows and rolls back when post-activation verification fails', async () => {
  const sourceKey = await cryptoApi.deriveEncryptionKey('migration-source-key');
  const targetMasterKey = deviceCrypto.generateVaultMasterKey();
  const sourceQuotes = [await fixture(sourceKey, 0), await fixture(sourceKey, 1), await fixture(sourceKey, 2)];
  const calls = [];
  let staged = [];
  let activatedStatus = false;
  const rpc = async (name, args) => {
    calls.push({ name, args });
    if (name === 'get_pending_envelope_migration') return activatedStatus ? response({ migration_id: DEVICE, status: 'activated', source_generation: SOURCE_GENERATION, target_generation: TARGET_GENERATION, source_revision: 7, expected_quote_count: sourceQuotes.length, staged_quote_count: staged.length }) : response(null);
    if (name === 'prepare_envelope_migration') return response({ migration_id: DEVICE, status: 'staging', expected_quote_count: sourceQuotes.length, reset: false });
    if (name === 'refresh_envelope_migration_source') return response({ migration_id: DEVICE, status: 'staging', source_generation: SOURCE_GENERATION, source_revision: 7, expected_quote_count: sourceQuotes.length, reset: false });
    if (name === 'stage_envelope_wrappers') return response({ migration_id: DEVICE, status: 'staging' });
    if (name === 'stage_envelope_quotes') { staged.push(...args.p_rows); return response({ migration_id: DEVICE, status: staged.length === sourceQuotes.length ? 'ready' : 'staging', staged_quote_count: staged.length }); }
    if (name === 'activate_envelope_migration') return response({ migration_id: DEVICE, status: 'activated', generation: TARGET_GENERATION });
    if (name === 'get_envelope_migration_snapshot') return response({ migration_id: DEVICE, generation: TARGET_GENERATION, revision: 8, quotes: staged.map((row, index) => index === 0 ? { ...row, quote_date: '2026-09-21' } : row) });
    if (name === 'rollback_envelope_migration') return response({ migration_id: DEVICE, status: 'rolled_back', generation: SOURCE_GENERATION });
    throw new Error(`unexpected RPC ${name}`);
  };
  const migration = loadMigration(rpc);
  const input = {
    sourceGeneration: SOURCE_GENERATION,
    sourceRevision: 7,
    sourceKey,
    sourceQuotes,
    targetGeneration: TARGET_GENERATION,
    targetMasterKey,
    migrationId: DEVICE,
    deviceId: DEVICE,
    token: 'transient-device-token',
    actorId: ACTOR,
    encryptedExportConfirmed: true,
  };
  const stagedResult = await migration.runEnvelopeMigration(input);
  assert.equal(stagedResult.status, 'ready');
  activatedStatus = true;
  await assert.rejects(migration.activateEnvelopeMigration(input), /verification failed/);
  assert.equal(calls.filter(call => call.name === 'activate_envelope_migration').length, 0);
  assert.equal(calls.at(-1).name, 'rollback_envelope_migration');
});

test('creates an encrypted export without placing quote plaintext in the file', async () => {
  const key = await cryptoApi.deriveEncryptionKey('export-key');
  const migration = loadMigration(async () => response({}));
  const exportText = await migration.createEncryptedMigrationExport({
    generation: SOURCE_GENERATION,
    revision: 7,
    quotes: [{ id: 'q', text: 'private export words' }],
    key,
  });
  assert.equal(typeof exportText, 'string');
  assert.equal(exportText.includes('private export words'), false);
  const parsed = JSON.parse(exportText);
  assert.equal(parsed.version, 1);
  assert.equal(typeof parsed.iv, 'string');
  assert.equal(typeof parsed.data, 'string');
});

test('prepares an empty vault without staging an empty quote batch', async () => {
  const sourceKey = await cryptoApi.deriveEncryptionKey('empty-migration-source');
  const targetMasterKey = deviceCrypto.generateVaultMasterKey();
  const calls = [];
  const rpc = async (name, args) => {
    calls.push({ name, args });
    if (name === 'get_pending_envelope_migration') return response(null);
    if (name === 'prepare_envelope_migration') return response({ migration_id: DEVICE, status: 'prepared', staged_quote_count: 0 });
    if (name === 'refresh_envelope_migration_source') return response({ migration_id: DEVICE, status: 'staging', source_generation: SOURCE_GENERATION, source_revision: 4, expected_quote_count: 0, reset: false });
    if (name === 'stage_envelope_wrappers') return response({ migration_id: DEVICE, status: 'ready', staged_quote_count: 0 });
    throw new Error(`unexpected RPC ${name}`);
  };
  const migration = loadMigration(rpc);
  const prepared = await migration.prepareEnvelopeMigration({ sourceGeneration: SOURCE_GENERATION, sourceRevision: 4, sourceKey, sourceQuotes: [], targetGeneration: TARGET_GENERATION, targetMasterKey, actorId: ACTOR, encryptedExportConfirmed: true });
  assert.equal(prepared.quoteCount, 0);
  assert.equal(calls.find(call => call.name === 'prepare_envelope_migration').args.p_device_id, null);
  const staged = await migration.runEnvelopeMigration({ sourceGeneration: SOURCE_GENERATION, sourceRevision: 4, sourceKey, sourceQuotes: [], targetGeneration: TARGET_GENERATION, targetMasterKey, migrationId: DEVICE, deviceId: DEVICE, token: 'transient-device-token', actorId: ACTOR, encryptedExportConfirmed: true });
  assert.equal(staged.status, 'ready');
  assert.equal(calls.filter(call => call.name === 'stage_envelope_quotes').length, 0);
});

test('refreshes a changed source before staging and waits for new device reports', async () => {
  const sourceKey = await cryptoApi.deriveEncryptionKey('changed-migration-source');
  const targetMasterKey = deviceCrypto.generateVaultMasterKey();
  const sourceQuotes = [await fixture(sourceKey, 0)];
  const calls = [];
  const rpc = async (name, args) => {
    calls.push({ name, args });
    if (name === 'get_pending_envelope_migration') return response({ migration_id: DEVICE, status: 'ready', source_generation: SOURCE_GENERATION, target_generation: TARGET_GENERATION, source_revision: 6, expected_quote_count: 0, staged_quote_count: 0 });
    if (name === 'refresh_envelope_migration_source') return response({ migration_id: DEVICE, status: 'staging', source_generation: SOURCE_GENERATION, source_revision: 7, expected_quote_count: 1, reset: true });
    throw new Error(`unexpected RPC ${name}`);
  };
  const migration = loadMigration(rpc);
  const result = await migration.runEnvelopeMigration({ sourceGeneration: SOURCE_GENERATION, sourceRevision: 7, sourceQuotes, sourceKey, targetGeneration: TARGET_GENERATION, targetMasterKey, migrationId: DEVICE, deviceId: DEVICE, token: 'transient-device-token', actorId: ACTOR, encryptedExportConfirmed: true });
  assert.equal(result.migrationId, DEVICE);
  assert.equal(result.status, 'staging');
  assert.equal(result.targetGeneration, TARGET_GENERATION);
  assert.equal(result.stagedQuoteCount, 0);
  assert.equal(calls.some(call => call.name === 'stage_envelope_wrappers' || call.name === 'stage_envelope_quotes'), false);
});

test('wraps the target key only for public keys attested under the source key', async () => {
  const sourceKey = await cryptoApi.deriveEncryptionKey('attested-migration-source');
  const targetMasterKey = deviceCrypto.generateVaultMasterKey();
  const keyPair = () => webcrypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
  const [trusted, injected, swapped] = await Promise.all([keyPair(), keyPair(), keyPair()]);
  const jwk = pair => webcrypto.subtle.exportKey('jwk', pair.publicKey);
  const ids = ['55555555-5555-4555-8555-555555555555', '66666666-6666-4666-8666-666666666666', '77777777-7777-4777-8777-777777777777'];
  const calls = [];
  const rpc = async (name, args) => {
    calls.push({ name, args });
    if (name === 'get_pending_envelope_migration') return response(null);
    if (name === 'refresh_envelope_migration_source') return response({ migration_id: DEVICE, status: 'staging', source_generation: SOURCE_GENERATION, source_revision: 4, expected_quote_count: 0, reset: false });
    if (name === 'stage_envelope_wrappers') return response({ migration_id: DEVICE, status: 'ready', staged_quote_count: 0 });
    if (name === 'attest_vault_keys') return response(null);
    throw new Error(`unexpected RPC ${name}`);
  };
  const migration = loadMigration(rpc);
  const trustedFingerprint = await deviceCrypto.fingerprintPublicJwk(await jwk(trusted));
  const deviceWrappers = [
    { id: ids[0], publicJwk: await jwk(trusted), attestation: await migration.createKeyAttestation(sourceKey, 'device', ids[0], SOURCE_GENERATION, trustedFingerprint) },
    { id: ids[1], publicJwk: await jwk(injected) },
    { id: ids[2], publicJwk: await jwk(swapped), attestation: await migration.createKeyAttestation(sourceKey, 'device', ids[2], SOURCE_GENERATION, trustedFingerprint) },
  ];
  await migration.runEnvelopeMigration({ sourceGeneration: SOURCE_GENERATION, sourceRevision: 4, sourceKey, sourceQuotes: [], targetGeneration: TARGET_GENERATION, targetMasterKey, migrationId: DEVICE, deviceId: DEVICE, token: 'transient-device-token', actorId: ACTOR, encryptedExportConfirmed: true, deviceWrappers });
  const staged = calls.find(call => call.name === 'stage_envelope_wrappers').args.p_devices;
  assert.equal(JSON.stringify(staged.map(item => item.device_id)), JSON.stringify([ids[0]]), 'unattested or swapped public keys never receive the target key');
  const attested = calls.find(call => call.name === 'attest_vault_keys').args;
  assert.equal(attested.p_generation, TARGET_GENERATION);
  const targetKey = await deviceCrypto.deriveQuoteKey(targetMasterKey, TARGET_GENERATION);
  assert.equal(await migration.verifyKeyAttestation(attested.p_devices[0].attestation, targetKey, 'device', ids[0], TARGET_GENERATION, trustedFingerprint), true, 'staging re-attests the key for the next rotation');
});
