import test from 'node:test';
import assert from 'node:assert/strict';
import { loadModule } from './load-module.mjs';

const state = { envelope_status: 'legacy', generation: '11111111-1111-4111-8111-111111111111', prepared_generation: null, legacy_generation: null,
  kdf: { salt: 'AAAAAAAAAAAAAAAAAAAAAA==', iterations: 600000 },
  verifier: { iv: 'AAAAAAAAAAAAAAAA', data: 'AAAAAAAAAAAAAAAAAAAAAA==' } };
function setup() {
  const stored = new Map();
  const navigator = { onLine: true };
  let calls = 0;
  const network = { result: { data: state, error: null } };
  const exports = loadModule('src/lib/vault.ts', {
    './supabase': { supabase: { rpc: async name => {
      assert.equal(name, 'get_vault_bootstrap_state'); calls++; return network.result;
    } } },
  }, { navigator, atob, localStorage: { getItem: key => stored.get(key), setItem: (key, value) => stored.set(key, value), removeItem: key => stored.delete(key) } });
  return { ...exports, navigator, network, calls: () => calls, stored };
}

test('cached vault settings unlock offline without a server request and remain account-scoped', async () => {
  const app = setup();
  await app.loadVaultState('alice');
  app.navigator.onLine = false;
  assert.equal((await app.loadVaultState('alice')).generation, state.generation);
  assert.equal(app.calls(), 1);
  await assert.rejects(app.loadVaultState('bob'), /Connect once/);
});

test('an authorization denial cannot fall back to cached access', async () => {
  const app = setup();
  await app.loadVaultState('alice');
  app.network.result = { data: null, error: { code: '42501', message: 'Access denied' } };
  await assert.rejects(app.loadVaultState('alice'), /Access denied/);
  assert.equal(app.readCachedVaultState('alice'), null, 'denied membership removes offline preparation');
});

test('a transport failure permits previously prepared offline access', async () => {
  const app = setup();
  await app.loadVaultState('alice');
  app.network.result = { data: null, error: { code: '', message: 'Failed to fetch' } };
  assert.equal((await app.loadVaultState('alice')).generation, state.generation);
});

test('invalid server settings never replace the valid offline cache', async () => {
  const app = setup();
  await app.loadVaultState('alice');
  app.network.result = { data: { ...state, kdf: { ...state.kdf, iterations: 999999999 } }, error: null };
  await assert.rejects(app.loadVaultState('alice'), /Invalid/);
  app.network.result = { data: { ...state, kdf: { ...state.kdf, salt: 'invalid!' } }, error: null };
  await assert.rejects(app.loadVaultState('alice'), /Invalid/);
  app.navigator.onLine = false;
  assert.equal((await app.loadVaultState('alice')).kdf.iterations, 600000);
});

test('local-only settings never wait for an online session refresh', async () => {
  const app = setup();
  await app.loadVaultState('alice');
  app.network.result = { data: null, error: { code: '42501', message: 'Must not be requested' } };
  assert.equal((await app.loadVaultState('alice', true)).generation, state.generation);
  assert.equal(app.calls(), 1);
});

test('server state requires an explicit envelope status and rejects legacy verifier material after cutover', () => {
  const app = setup();
  const { envelope_status, prepared_generation, ...preMigration } = state;
  assert.throws(() => app.parseVaultState(preMigration), /Invalid/);
  assert.throws(() => app.parseVaultState({ ...state, envelope_status: 'active' }), /Invalid/);
  const active = app.parseVaultState({ envelope_status: 'active', generation: state.generation, prepared_generation: null });
  assert.equal(active.envelope_status, 'active');
});

test('only cached pre-migration legacy settings are normalized for offline compatibility', () => {
  const app = setup();
  const { envelope_status, prepared_generation, ...preMigration } = state;
  app.stored.set('quotevault:settings:alice', JSON.stringify(preMigration));
  assert.equal(app.readCachedVaultState('alice')?.envelope_status, 'legacy');
  app.stored.set('quotevault:settings:bob', JSON.stringify({ ...state, envelope_status: 'active' }));
  assert.equal(app.readCachedVaultState('bob'), null);
});

test('legacy vault mutation responses normalize only the known pre-union shape', () => {
  const app = setup();
  const { envelope_status, prepared_generation, ...mutation } = state;
  const initialized = app.parseLegacyVaultMutation(mutation);
  assert.equal(initialized.envelope_status, 'legacy');
  assert.equal(initialized.prepared_generation, null);
  assert.throws(() => app.parseLegacyVaultMutation({ ...mutation, envelope_status: 'legacy' }), /Invalid/);
  assert.throws(() => app.parseLegacyVaultMutation({ ...mutation, prepared_generation: null }), /Invalid/);
});
