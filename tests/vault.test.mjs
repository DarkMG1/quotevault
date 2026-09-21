import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import ts from 'typescript';

const state = { generation: '11111111-1111-4111-8111-111111111111', legacy_generation: null,
  kdf: { salt: 'AAAAAAAAAAAAAAAAAAAAAA==', iterations: 600000 },
  verifier: { iv: 'AAAAAAAAAAAAAAAA', data: 'AAAAAAAAAAAAAAAAAAAAAA==' } };
function setup() {
  const stored = new Map();
  const navigator = { onLine: true };
  let calls = 0;
  const network = { result: { data: state, error: null } };
  const exports = {};
  runInNewContext(ts.transpileModule(readFileSync(new URL('../src/lib/vault.ts', import.meta.url), 'utf8'),
    { compilerOptions: { module: ts.ModuleKind.CommonJS } }).outputText, {
    exports, navigator, atob, localStorage: { getItem: key => stored.get(key), setItem: (key, value) => stored.set(key, value) },
    require: () => ({ supabase: { rpc: async name => {
      assert.equal(name, 'get_vault_state'); calls++; return network.result;
    } } }),
  });
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
