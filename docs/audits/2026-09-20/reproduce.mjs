// Audit reproductions: assertions describe observed bugs, not desired behavior.
// Run from any directory: node docs/audits/2026-09-20/reproduce.mjs
// Uses the actual source with in-memory DB/network substitutes; no real requests.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { createRequire } from 'node:module';
import { webcrypto } from 'node:crypto';
import ts from 'typescript';

const root = new URL('../../../', import.meta.url);
const require = createRequire(import.meta.url);
function load(path, dependencies = {}, globals = {}) {
  const source = readFileSync(new URL(path, root), 'utf8');
  const { outputText } = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, target: ts.ScriptTarget.ES2022 },
    fileName: path,
  });
  const exports = {};
  runInNewContext(outputText, {
    exports, require: name => {
      if (name in dependencies) return dependencies[name];
      if (name === 'react/jsx-runtime') return require(name);
      throw new Error(`Unexpected import: ${name}`);
    },
    console: { error() {} }, crypto: webcrypto, TextEncoder, TextDecoder, btoa, atob, setTimeout,
    ...globals,
  }, { filename: path });
  return exports;
}

function table() {
  const rows = new Map();
  return {
    rows,
    async put(row) { rows.set(row.id, structuredClone(row)); },
    async update(id, changes) { if (rows.has(id)) Object.assign(rows.get(id), changes); },
    async delete(id) { rows.delete(id); },
    async clear() { rows.clear(); },
    async bulkPut(data) { for (const row of data) await this.put(row); },
    orderBy(field) {
      return { toArray: async () => structuredClone([...rows.values()].sort((a, b) => a[field].localeCompare(b[field]))) };
    },
  };
}

const quote = (id = 'q1') => ({ id, text: '$$E2E$${"iv":"example","data":"ciphertext"}', author: 'ENCRYPTED',
  context: 'ENCRYPTED', user_id: 'user-a', created_at: '2026-09-20T12:00:00Z', sync_status: 'pending' });
function setup() {
  const db = { quotes: table(), syncQueue: table() };
  const remote = new Map();
  const navigator = { onLine: true };
  const transport = {
    async insert(rows) {
      if (remote.has(rows[0].id)) return { error: { code: '23505', message: 'duplicate key' } };
      remote.set(rows[0].id, structuredClone(rows[0]));
      return { error: null };
    },
    async remove(id) { remote.delete(id); return { error: null }; },
  };
  const supabase = { from: () => ({
    insert: rows => transport.insert(rows),
    delete: () => ({ eq: (_, id) => transport.remove(id) }),
    select: () => ({ order: async () => ({ data: [...remote.values()], error: null }) }),
  }) };
  const sync = load('src/lib/sync.ts', { './db': { db }, './supabase': { supabase } }, {
    navigator, window: { addEventListener() {} }, document: { addEventListener() {} },
  });
  const { useQuotes } = load('src/hooks/useQuotes.tsx', {
    react: { useEffect() {} }, 'dexie-react-hooks': { useLiveQuery() {} },
    '../lib/db': { db }, '../lib/supabase': { supabase }, '../lib/sync': sync,
  }, { navigator });
  return { db, remote, navigator, transport, sync, hooks: useQuotes() };
}

const checks = [];
async function check(name, fn) { await fn(); checks.push(name); console.log(`REPRODUCED: ${name}`); }
function forms(node) {
  if (!node || typeof node !== 'object') return [];
  return [ ...(node.type === 'form' ? [node] : []), ...[node.props?.children].flat(Infinity).flatMap(forms) ];
}

await check('S1: deleting a displayed quote persists its plaintext in syncQueue', async () => {
  const { db, navigator, hooks } = setup();
  navigator.onLine = false;
  await db.quotes.put(quote());
  // This is the decrypted object passed by Feed.confirmDelete.
  await hooks.deleteQuote({ ...quote(), text: 'private quote', author: 'Alice', context: 'private context' });
  assert.equal(db.quotes.rows.size, 0);
  assert.equal(db.syncQueue.rows.get('q1').payload.text, 'private quote');
  assert.equal(db.syncQueue.rows.get('q1').payload.context, 'private context');
});

await check('D1: successful remote insert with a lost response blocks all later queued work', async () => {
  const { db, remote, transport, sync } = setup();
  const insert = transport.insert;
  let loseResponse = true;
  transport.insert = async rows => {
    const result = await insert(rows);
    if (loseResponse) { loseResponse = false; return { error: { message: 'response lost' } }; }
    return result;
  };
  await sync.addToSyncQueue('INSERT', quote());
  await sync.processSyncQueue();
  await sync.addToSyncQueue('INSERT', { ...quote('q2'), created_at: '2026-09-20T13:00:00Z' });
  await sync.processSyncQueue();
  assert.equal(remote.has('q1'), true);
  assert.equal(remote.has('q2'), false);
  assert.equal(db.syncQueue.rows.size, 2);
});

await check('D2: completion of an in-flight INSERT erases a newer DELETE', async () => {
  const { db, remote, navigator, transport, sync, hooks } = setup();
  const started = Promise.withResolvers();
  const release = Promise.withResolvers();
  const insert = transport.insert;
  transport.insert = async rows => { started.resolve(); await release.promise; return insert(rows); };
  await db.quotes.put(quote());
  await sync.addToSyncQueue('INSERT', quote());
  const processing = sync.processSyncQueue();
  await started.promise;
  navigator.onLine = false;
  await hooks.deleteQuote(quote());
  assert.equal(db.syncQueue.rows.get('q1').action, 'DELETE');
  release.resolve();
  await processing;
  assert.equal(db.syncQueue.rows.size, 0);
  assert.equal(remote.has('q1'), true);
  assert.equal(db.quotes.rows.size, 0);
});

await check('D3: refresh retains a quote deleted remotely while this client was absent', async () => {
  const { db, hooks } = setup();
  await db.quotes.put({ ...quote(), sync_status: 'synced' });
  await hooks.refresh(); // Remote is empty.
  assert.equal(db.quotes.rows.has('q1'), true);
});

await check('D3: refresh resurrects a local pending deletion', async () => {
  const { db, remote, navigator, hooks } = setup();
  remote.set('q1', quote());
  navigator.onLine = false;
  await hooks.deleteQuote(quote());
  navigator.onLine = true;
  await hooks.refresh();
  assert.equal(db.syncQueue.rows.get('q1').action, 'DELETE');
  assert.equal(db.quotes.rows.get('q1').sync_status, 'synced');
});

for (const failDelete of [false, true]) {
  await check(failDelete ? 'D5: failed wipe leaves the server using the new verifier with old quotes'
    : 'D4: successful wipe leaves queued old-key quotes that upload again', async () => {
    const { db, remote, sync } = setup();
    await db.quotes.put(quote());
    await sync.addToSyncQueue('INSERT', quote());
    if (failDelete) remote.set('existing', quote('existing'));
    let verifier = 'old-verifier';
    const state = [[], '', false, false, '', 'new-vault-key', 'ERASE EVERYTHING', false, '', ''];
    let cursor = 0;
    const { AdminDashboard } = load('src/components/Admin.tsx', {
      react: { useEffect() {}, useState() { const i = cursor++; return [state[i], v => { state[i] = v; }]; } },
      '../hooks/useAuth': { useAuth: () => ({ user: { email: 'darkmgdevelopment@gmail.com' } }) },
      '../lib/crypto': { hashVaultKey: async () => 'new-verifier' }, '../lib/db': { db },
      '../lib/supabase': { supabase: { from: () => ({
        upsert: async row => { verifier = row.value; return { error: null }; },
        delete: () => ({ neq: async () => {
          if (failDelete) return { error: { message: 'delete failed' } };
          remote.clear(); return { error: null };
        } }),
      }) } },
      'lucide-react': Object.fromEntries(['ShieldAlert', 'Users', 'Plus', 'Trash2', 'Loader2', 'RefreshCw', 'AlertTriangle'].map(k => [k, 'i'])),
      'framer-motion': { motion: { li: 'li' }, AnimatePresence: 'div' },
    }, { setTimeout() {} });
    await forms(AdminDashboard()).at(-1).props.onSubmit({ preventDefault() {} });
    assert.equal(verifier, 'new-verifier');
    if (failDelete) {
      assert.equal(remote.has('existing'), true);
      assert.equal(state[8], 'delete failed');
    } else {
      assert.equal(db.quotes.rows.size, 0);
      assert.equal(db.syncQueue.rows.size, 1);
      await sync.processSyncQueue();
      assert.equal(remote.has('q1'), true);
    }
  });
}

await check('D6: a failed network save is already marked synced', async () => {
  const { db, transport, hooks, sync } = setup();
  transport.insert = async () => ({ error: { message: 'server unavailable' } });
  await hooks.addQuote('ciphertext', 'ENCRYPTED', undefined, '2026-09-20', 'user-a');
  await sync.processSyncQueue();
  assert.equal(db.syncQueue.rows.size, 1);
  assert.equal([...db.quotes.rows.values()][0].sync_status, 'synced');
});

await check('D7: local save survives an outbox failure with no queued upload', async () => {
  const { db, navigator, hooks } = setup();
  navigator.onLine = false;
  db.syncQueue.put = async () => { throw new Error('storage failure'); };
  await assert.rejects(hooks.addQuote('ciphertext', 'ENCRYPTED'), /storage failure/);
  assert.equal(db.quotes.rows.size, 1);
  assert.equal(db.syncQueue.rows.size, 0);
});

// Render just enough React structure to invoke the actual unlock form handler.
await check('O1: cached-session unlock fails when the settings request is offline', async () => {
  const state = [null, 'correct-vault-key', false, ''];
  let cursor = 0;
  const React = {
    createContext: () => ({}), useContext() {},
    useState(initial) { const i = cursor++; return [state[i] ?? initial, value => { state[i] = value; }]; },
  };
  const { CryptoProvider } = load('src/hooks/useCrypto.tsx', {
    react: React, '../lib/crypto': { deriveEncryptionKey() { throw new Error('Must not reach derivation'); }, hashVaultKey() {} },
    '../lib/supabase': { supabase: { from: () => ({ select: () => ({ eq: () => ({
      maybeSingle: async () => ({ data: null, error: { message: 'Failed to fetch' } }),
    }) }) }) } },
    './useAuth': { useAuth: () => ({ user: { id: 'user-a' } }) },
    'lucide-react': { Lock: 'i', KeyRound: 'i', Loader2: 'i' },
    'framer-motion': { motion: { div: 'div' }, AnimatePresence: 'div' },
  });
  await forms(CryptoProvider({ children: null }))[0].props.onSubmit({ preventDefault() {} });
  assert.equal(state[0], null);
  assert.equal(state[3], 'Failed to fetch');
});

const crypt = load('src/lib/crypto.ts');
await check('S2: the stored verifier allows a dictionary check without PBKDF2', async () => {
  const verifier = await crypt.hashVaultKey('1234');
  let recovered;
  for (const guess of ['password', '0000', '1234', 'letmein']) {
    if (await crypt.hashVaultKey(guess) === verifier) { recovered = guess; break; }
  }
  assert.equal(recovered, '1234');
});

const key = await crypt.deriveEncryptionKey('audit-only-test-key');
const payload = await crypt.encryptData('Unicode round trip: café 🔒', key);
assert.equal(await crypt.decryptData(payload, key), 'Unicode round trip: café 🔒');
const bytes = Buffer.from(payload.data, 'base64');
bytes[0] ^= 1;
await assert.rejects(crypt.decryptData({ ...payload, data: bytes.toString('base64') }, key));
console.log(`\n${checks.length} bug scenarios reproduced; AES-GCM round-trip and tamper rejection passed.`);
