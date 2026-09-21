import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { loadModule } from './load-module.mjs';

const load = (path, dependencies, globals) => loadModule(path, dependencies, {
  crypto: webcrypto, structuredClone, TextEncoder, console: { error() {} }, ...globals,
});

function table() {
  const rows = new Map();
  return {
    rows,
    async get(id) { return structuredClone(rows.get(id)); },
    async put(row) { rows.set(row.id ?? row.key, structuredClone(row)); },
    async delete(id) { rows.delete(id); },
    async update(id, changes) { if (rows.has(id)) Object.assign(rows.get(id), changes); },
    async bulkPut(items) { for (const item of items) await this.put(item); },
    async bulkDelete(ids) { for (const id of ids) rows.delete(id); },
    async clear() { rows.clear(); },
    async toArray() { return structuredClone([...rows.values()]); },
    orderBy(field) { return { toArray: async () => structuredClone([...rows.values()].sort((a, b) => String(a[field]).localeCompare(String(b[field])))) }; },
    where(field) { return { equals: value => ({ toArray: async () => structuredClone([...rows.values()].filter(row => row[field] === value)) }) }; },
  };
}

function setup(reply = args => ({ generation: 'g1', revision: 1, results: args.p_operations.map(op => ({ operation_id: op.operation_id, status: op.quote_id === 'bad' ? 'rejected' : 'ok', error: op.quote_id === 'bad' ? 'denied' : undefined })), quotes: null })) {
  const db = { quotes: table(), syncQueue: table(), metadata: table(), transaction: async (_mode, ...args) => args.at(-1)() };
  const rpcCalls = [];
  const navigator = { onLine: true };
  const supabase = { rpc: async (_name, args) => {
    rpcCalls.push(args);
    return { data: await reply(args), error: null };
  } };
  const sync = load('src/lib/sync.ts', { './db': { db }, './supabase': { supabase } }, { navigator, window: { addEventListener() {} }, document: { addEventListener() {} } });
  return { db, sync, rpcCalls, navigator };
}

const quote = (id, generation = 'g1') => ({ id, text: 'ciphertext', author: 'cipher-author', context: 'cipher-context', quote_date: '2026-09-20', created_at: '2026-09-20T00:00:00.000Z', user_id: 'u1', vault_generation: generation, sync_status: 'pending' });
async function enqueue(db, sync, action, value, actor = 'u1', generation = 'g1') {
  const operation = sync.createSyncOperation(action, value, actor, generation);
  await db.syncQueue.put(operation);
  return operation;
}
const settle = () => new Promise(resolve => setImmediate(resolve));

function runProvider(db, { userId = 'u1', generation = 'g1', legacyGeneration = null } = {}) {
  const states = [];
  const cleanups = [];
  let cursor = 0;
  const React = {
    createContext: value => ({ value }),
    useContext: context => context.value,
    useState: initial => { const index = cursor++; states[index] ??= initial; return [states[index], value => { states[index] = value; }]; },
    useRef: initial => ({ current: initial }),
    useEffect: effect => {
      const cleanup = effect();
      if (typeof cleanup === 'function') cleanups.push(cleanup);
    },
    useMemo: callback => callback(), useCallback: callback => callback,
  };
  const { QuotesProvider } = load('src/hooks/useQuotes.tsx', {
    react: React, 'react/jsx-runtime': { jsx: (type, props) => ({ type, props }) },
    'dexie-react-hooks': { useLiveQuery: (_query, _deps, fallback) => fallback },
    '../lib/db': { db }, '../lib/sync': { cancelSyncRequests() {}, createSyncOperation() {}, enqueueDeleteMutation() {}, processSyncQueue: async () => {} },
    '../lib/supabase': { supabase: { channel: () => ({ on() { return this; }, subscribe() { return { unsubscribe: async () => {} }; } }) } },
    './useAuth': { useAuth: () => ({ user: { id: userId }, canSync: true }) },
    './useCrypto': { useCrypto: () => ({ vaultGeneration: generation, legacyVaultGeneration: legacyGeneration, lockVault() {} }) },
  }, { window: { clearTimeout() {}, setTimeout() {}, addEventListener() {}, removeEventListener() {} }, document: { addEventListener() {}, removeEventListener() {}, visibilityState: 'visible' }, crypto: webcrypto });
  const render = () => {
    cursor = 0;
    return QuotesProvider({ children: null });
  };
  return { states, rendered: render(), render, cleanup: () => cleanups.splice(0).reverse().forEach(cleanup => cleanup()) };
}

await (async () => {
  const { db, sync, rpcCalls } = setup();
  await enqueue(db, sync, 'INSERT', quote('ok'));
  await enqueue(db, sync, 'DELETE', { ...quote('deleted'), text: 'plaintext', author: 'Alice', context: 'secret' });
  await enqueue(db, sync, 'INSERT', quote('bad'));
  await sync.processSyncQueue({ actorId: 'u1', generation: 'g1' });

  const sentDelete = rpcCalls[0].p_operations.find(op => op.action === 'DELETE');
  assert.deepEqual(Object.keys(sentDelete).sort(), ['action', 'actor_id', 'operation_id', 'quote_id', 'vault_generation']);
  assert.equal(db.syncQueue.rows.size, 1, 'a rejected operation persists without blocking acknowledged operations');
  assert.equal([...db.syncQueue.rows.values()][0].quote_id, 'bad');
  assert.equal([...db.syncQueue.rows.values()][0].error, 'denied');
})();

await (async () => {
  const { db, sync, rpcCalls } = setup();
  const large = 'a'.repeat(500 * 1024);
  await enqueue(db, sync, 'INSERT', { ...quote('large-one'), text: large });
  await enqueue(db, sync, 'INSERT', { ...quote('large-two'), text: large });
  await sync.processSyncQueue({ actorId: 'u1', generation: 'g1' });
  assert.deepEqual(rpcCalls.map(call => call.p_operations.length), [1, 1], 'large operations are split before the RPC size limit');
})();

await (async () => {
  const { db, sync, rpcCalls } = setup();
  await db.quotes.put({ ...quote('oversized'), text: 'a'.repeat(901 * 1024) });
  await enqueue(db, sync, 'INSERT', { ...quote('oversized'), text: 'a'.repeat(901 * 1024) });
  await enqueue(db, sync, 'INSERT', quote('after-oversized'));
  await sync.processSyncQueue({ actorId: 'u1', generation: 'g1' });
  assert.equal(rpcCalls.length, 1, 'an oversized legacy insert does not stall following operations');
  assert.equal(rpcCalls[0].p_operations[0].quote_id, 'after-oversized');
  assert.equal([...db.syncQueue.rows.values()].find(item => item.quote_id === 'oversized').status, 'rejected');
  assert.equal(db.quotes.rows.get('oversized').sync_status, 'rejected');
})();

await (async () => {
  const { db, sync } = setup(args => ({ generation: 'g1', revision: 1, results: args.p_operations.map(() => ({ operation_id: 'forged', status: 'ok' })), quotes: null }));
  await enqueue(db, sync, 'INSERT', quote('forged-target'));
  await assert.rejects(sync.processSyncQueue({ actorId: 'u1', generation: 'g1' }), /Invalid sync response/);
  assert.equal(db.syncQueue.rows.size, 1, 'an unrequested result cannot acknowledge a local operation');
})();

await (async () => {
  const { db, sync } = setup();
  await db.quotes.put(quote('cancelled'));
  await enqueue(db, sync, 'INSERT', quote('cancelled'));
  await sync.enqueueDeleteMutation({ ...quote('cancelled'), text: 'plaintext' }, { actorId: 'u1', generation: 'g1' });
  const pending = [...db.syncQueue.rows.values()];
  assert.equal(pending.length, 1, 'deleting a local insert leaves only the delete operation');
  assert.equal(pending[0].action, 'DELETE');
  assert.equal(pending[0].payload, undefined);
})();

await (async () => {
  let calls = 0;
  const { db, sync } = setup(args => ++calls === 1
    ? { generation: 'g1', revision: 1, results: args.p_operations.map(op => ({ operation_id: op.operation_id, status: 'rejected', error: 'not allowed' })), quotes: null }
    : { generation: 'g1', revision: 1, results: [], quotes: [quote('remote-delete')] });
  await db.quotes.put(quote('remote-delete'));
  await enqueue(db, sync, 'DELETE', { ...quote('remote-delete'), text: 'plaintext' });
  await db.quotes.delete('remote-delete');
  await sync.processSyncQueue({ actorId: 'u1', generation: 'g1' });
  assert.equal(db.quotes.rows.get('remote-delete').text, 'ciphertext', 'a rejected delete refreshes the authoritative remote quote');
})();

await (async () => {
  const { db, sync } = setup(() => null);
  await db.quotes.put(quote('safe'));
  await enqueue(db, sync, 'INSERT', quote('safe'));
  await assert.rejects(sync.processSyncQueue({ actorId: 'u1', generation: 'g1' }), /Invalid sync response/);
  assert.equal(db.quotes.rows.size, 1, 'a malformed response never clears local data');
  assert.equal(db.syncQueue.rows.size, 1, 'a malformed response never acknowledges queued work');
})();

await (async () => {
  const { db, sync, rpcCalls } = setup();
  for (let index = 0; index < 51; index++) await enqueue(db, sync, 'INSERT', quote(`batch-${index}`));
  await sync.processSyncQueue({ actorId: 'u1', generation: 'g1' });
  assert.deepEqual(rpcCalls.map(call => call.p_operations.length), [50, 1], 'the queue drains batches without sending more than 50 operations');
})();

await (async () => {
  const started = Promise.withResolvers();
  const release = Promise.withResolvers();
  const { db, sync, navigator } = setup(async args => {
    started.resolve();
    await release.promise;
    return { generation: 'g1', revision: 1, results: args.p_operations.map(op => ({ operation_id: op.operation_id, status: 'ok' })), quotes: null };
  });
  await enqueue(db, sync, 'INSERT', quote('same'));
  const processing = sync.processSyncQueue({ actorId: 'u1', generation: 'g1' });
  await started.promise;
  await enqueue(db, sync, 'DELETE', { ...quote('same'), text: 'plaintext' });
  navigator.onLine = false;
  release.resolve();
  await processing;
  const pending = [...db.syncQueue.rows.values()];
  assert.equal(pending.length, 1, 'an in-flight acknowledgement never removes a newer operation');
  assert.equal(pending[0].action, 'DELETE');
  assert.equal(pending[0].payload, undefined);
})();

await (async () => {
  const started = Promise.withResolvers();
  const release = Promise.withResolvers();
  let calls = 0;
  const { sync, rpcCalls } = setup(async args => {
    calls++;
    if (calls === 1) {
      started.resolve();
      await release.promise;
    }
    if (calls === 2) throw new Error('second identity failed');
    return { generation: args.p_generation, revision: 1, results: [], quotes: null };
  });
  const first = sync.processSyncQueue({ actorId: 'u1', generation: 'g1' });
  await started.promise;
  const second = sync.processSyncQueue({ actorId: 'u2', generation: 'g2' });
  let secondSettled = false;
  void second.then(() => { secondSettled = true; }, () => { secondSettled = true; });
  await settle();
  assert.equal(secondSettled, false, 'a new identity does not resolve from an older identity RPC');
  release.resolve();
  await first;
  await assert.rejects(second, /second identity failed/);
  assert.deepEqual(rpcCalls.map(call => call.p_generation), ['g1', 'g2'], 'a new identity runs its own queued RPC');
})();

await (async () => {
  const { db, sync } = setup();
  await db.quotes.put(quote('stale'));
  await enqueue(db, sync, 'INSERT', quote('stale'));
  await db.metadata.put({ id: 'sync-revision:u1:g1', value: 7 });
  await sync.clearLocalSyncState();
  assert.equal(db.quotes.rows.size, 0, 'vault reset removes stale cached ciphertext');
  assert.equal(db.syncQueue.rows.size, 0, 'vault reset removes stale pending writes');
  assert.equal(db.metadata.rows.size, 0, 'vault reset removes cached revisions');
})();

await (async () => {
  const db = { quotes: table(), syncQueue: table(), metadata: table(), transaction: async (_mode, ...args) => args.at(-1)() };
  await db.quotes.put({ ...quote('legacy'), vault_generation: undefined });
  runProvider(db, { legacyGeneration: 'g1' });
  await settle();
  await settle();
  assert.equal(db.quotes.rows.get('legacy').vault_generation, 'g1', 'valid legacy cache is preserved and stamped with its initial generation');
  assert.equal(db.metadata.rows.get('sync-active-identity').value, 'u1:g1');
})();

await (async () => {
  const db = { quotes: table(), syncQueue: table(), metadata: table(), transaction: async (_mode, ...args) => args.at(-1)() };
  await db.quotes.put(quote('foreign'));
  await db.metadata.put({ id: 'sync-active-identity', value: 'other:g1' });
  await db.metadata.put({ id: 'sync-revision:u1:g1', value: 8 });
  await enqueue(db, { createSyncOperation: (action, value, actor, generation) => ({ id: 'queued', operation_id: 'queued', action, quote_id: value.id, actor_id: actor, vault_generation: generation, payload: value, created_at: '2026-09-20T00:00:01.000Z', status: 'pending' }) }, 'INSERT', quote('queued'));
  runProvider(db);
  await settle();
  await settle();
  assert.deepEqual([...db.quotes.rows.keys()], ['queued'], 'an account switch restores only its queued local insert');
  assert.equal(db.metadata.rows.has('sync-revision:u1:g1'), false, 'an account switch invalidates the destination revision');
})();

await (async () => {
  const started = Promise.withResolvers();
  const release = Promise.withResolvers();
  const { db, sync } = setup(async args => {
    started.resolve();
    await release.promise;
    return { generation: 'g1', revision: 2, results: args.p_operations.map(op => ({ operation_id: op.operation_id, status: 'ok' })), quotes: [quote('remote')] };
  });
  await enqueue(db, sync, 'INSERT', quote('inflight'));
  const running = sync.processSyncQueue({ actorId: 'u1', generation: 'g1' });
  await started.promise;
  sync.cancelSyncRequests();
  release.resolve();
  await running;
  assert.equal(db.syncQueue.rows.has([...db.syncQueue.rows.keys()][0]), true, 'cancelling a stale request preserves its pending operation');
  assert.equal(db.quotes.rows.has('remote'), false, 'cancelling a stale request prevents its snapshot write');
})();

await (async () => {
  const { db, sync } = setup(args => ({ generation: 'g1', revision: 1, results: args.p_operations.map(op => ({ operation_id: op.operation_id, status: 'rejected', error: 'denied' })), quotes: [] }));
  await db.quotes.put(quote('rejected-insert'));
  await enqueue(db, sync, 'INSERT', quote('rejected-insert'));
  await sync.processSyncQueue({ actorId: 'u1', generation: 'g1' });
  assert.equal(db.quotes.rows.get('rejected-insert').sync_status, 'rejected', 'a rejected insert survives a complete empty snapshot for retry');
})();

await (async () => {
  const { db, sync, rpcCalls } = setup(args => ({ generation: 'g1', revision: 1, results: args.p_operations.map(op => ({ operation_id: op.operation_id, status: 'rejected', error: 'denied' })), quotes: null }));
  for (let index = 0; index < 51; index++) await enqueue(db, sync, 'INSERT', quote(`rejected-${index}`));
  await sync.processSyncQueue({ actorId: 'u1', generation: 'g1' });
  assert.deepEqual(rpcCalls.map(call => call.p_operations.length), [50, 1], 'rejected operations do not stop later batches');
})();

await (async () => {
  const entered = Promise.withResolvers();
  const release = Promise.withResolvers();
  let locked = false;
  const { db, sync } = setup(() => ({ generation: 'g2', revision: 1, results: [], quotes: [] }));
  await db.quotes.put(quote('new-session-cache'));
  db.transaction = async (_mode, ...args) => { entered.resolve(); await release.promise; return args.at(-1)(); };
  const running = sync.processSyncQueue({ actorId: 'u1', generation: 'g1', onGenerationMismatch: () => { locked = true; } });
  await entered.promise;
  sync.cancelSyncRequests();
  release.resolve();
  await running;
  assert.equal(db.quotes.rows.has('new-session-cache'), true, 'stale generation cleanup cannot clear a newer session');
  assert.equal(locked, false, 'stale generation cleanup cannot lock a newer session');
})();

await (async () => {
  const db = { quotes: table(), syncQueue: table(), metadata: table(), transaction: async (_mode, ...args) => args.at(-1)() };
  let attempts = 0;
  db.transaction = async (_mode, ...args) => {
    attempts++;
    if (attempts === 1) throw new Error('transient IndexedDB failure');
    return args.at(-1)();
  };
  const provider = runProvider(db);
  await settle();
  await provider.rendered.props.value.refresh();
  await settle();
  assert.equal(attempts, 2, 'Refresh retries a failed local initialization');
  assert.equal(provider.states[0], 'u1:g1', 'successful retry marks the current identity ready');
})();

await (async () => {
  const entered = Promise.withResolvers();
  const release = Promise.withResolvers();
  const db = { quotes: table(), syncQueue: table(), metadata: table(), transaction: async (_mode, ...args) => args.at(-1)() };
  db.transaction = async (_mode, ...args) => {
    entered.resolve();
    await release.promise;
    return args.at(-1)();
  };
  const provider = runProvider(db);
  await entered.promise;
  provider.cleanup();
  release.resolve();
  await settle();
  await settle();
  assert.equal(provider.states[0], null, 'an unmounted provider never becomes ready from a deferred initialization');
  assert.equal(db.metadata.rows.has('sync-active-identity'), false, 'a cancelled initialization cannot mutate shared identity metadata');
})();

await (async () => {
  const entered = Promise.withResolvers();
  const release = Promise.withResolvers();
  let calls = 0;
  const { sync } = setup(async () => {
    if (++calls === 1) { entered.resolve(); await release.promise; }
    return { generation: 'g1', revision: 1, results: [], quotes: null };
  });
  const context = { actorId: 'u1', generation: 'g1' };
  const first = sync.processSyncQueue(context);
  await entered.promise;
  const second = sync.processSyncQueue(context);
  assert.equal(first, second, 'same-identity callers share the active promise');
  release.resolve();
  await second;
  assert.equal(calls, 2, 'a refresh requested during a request gets a subsequent synchronization');
})();

console.log('sync queue regression tests passed');
