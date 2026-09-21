// Historical reproduction against a878167, not a test of the current implementation.
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { runInNewContext } from 'node:vm';
import { webcrypto } from 'node:crypto';
import ts from 'typescript';
import assert from 'node:assert/strict';

const root = new URL('../../../', import.meta.url);
const require = createRequire(import.meta.url);
const rows = new Map();
let transactions = 0;
let syncCalls = 0;
const table = {
  async get(id) { return rows.get(id); }, async put(row) { rows.set(row.id, row); },
  async delete(id) { rows.delete(id); }, async clear() { rows.clear(); },
  async bulkPut(values) { values.forEach(value => rows.set(value.id, value)); },
  async toArray() { return [...rows.values()]; }, orderBy() { return { reverse: () => ({ toArray: async () => [] }) }; },
};
const db = {
  quotes: table, syncQueue: { ...table, bulkDelete: async () => {} }, metadata: table,
  async transaction(_mode, ...args) { transactions++; if (transactions === 1) throw new Error('transient IndexedDB failure'); return args.at(-1)(); },
};
const source = execFileSync('git', ['show', 'a878167:src/hooks/useQuotes.tsx'], { cwd: root, encoding: 'utf8' });
const { outputText } = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, target: ts.ScriptTarget.ES2022 } });
const states = [];
let cursor = 0;
const React = {
  createContext: value => ({ value }), useContext: context => context.value,
  useState: initial => { const index = cursor++; states[index] ??= initial; return [states[index], value => { states[index] = value; }]; },
  useEffect: effect => { effect(); }, useMemo: callback => callback(), useCallback: callback => callback,
};
const exports = {};
runInNewContext(outputText, {
  exports, crypto: webcrypto, console, setTimeout, clearTimeout,
  window: { setTimeout, clearTimeout, addEventListener() {}, removeEventListener() {} },
  document: { visibilityState: 'visible', addEventListener() {}, removeEventListener() {} },
  require: name => ({
    react: React, 'react/jsx-runtime': { jsx: (type, props) => ({ type, props }) },
    'dexie-react-hooks': { useLiveQuery: (_query, _deps, fallback) => fallback },
    '../lib/db': { db },
    '../lib/sync': { cancelSyncRequests() {}, createSyncOperation() {}, enqueueDeleteMutation() {}, processSyncQueue: async () => { syncCalls++; } },
    '../lib/supabase': { supabase: { channel: () => ({ on() { return this; }, subscribe() { return { unsubscribe: async () => {} }; } }) } },
    './useAuth': { useAuth: () => ({ user: { id: 'u1' } }) },
    './useCrypto': { useCrypto: () => ({ vaultGeneration: 'g1', legacyVaultGeneration: null, lockVault() {} }) },
  }[name] ?? require(name)),
});
const rendered = exports.QuotesProvider({ children: null });
await new Promise(resolve => setImmediate(resolve));
await rendered.props.value.refresh();
await new Promise(resolve => setImmediate(resolve));
console.log(JSON.stringify({ transactions, syncCalls, initializedIdentity: states[0], syncError: states[1] }, null, 2));

assert.equal(transactions, 1);
assert.equal(syncCalls, 1);
assert.equal(states[0], null);
assert.equal(states[1], "");
