import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { loadModule } from './load-module.mjs';

const load = (path, dependencies, globals) => loadModule(path, dependencies, {
  console: { error() {} }, ...globals,
});

const ui = load('src/components/ui.ts', {
  react: { useEffect: () => {}, useRef: initial => ({ current: initial }) },
  '../lib/crypto': { decryptData: async () => JSON.stringify({ text: 'decoded', author: 'Ada', context: 'letter', source_sender: 'Grace', id: 'evil', user_id: 'evil', sync_status: 'synced', extra: 'ignored' }) },
});

const previousTimezone = process.env.TZ;
process.env.TZ = 'America/Detroit';
assert.equal(ui.localDateInputValue(new Date('2026-09-21T01:00:00Z')), '2026-09-20');
if (previousTimezone === undefined) delete process.env.TZ;
else process.env.TZ = previousTimezone;
assert.equal(ui.getErrorMessage(new Error('save failed'), 'fallback'), 'save failed');
assert.equal(ui.getErrorMessage({ message: 'delete failed' }, 'fallback'), 'delete failed');
assert.equal(ui.getErrorMessage({ message: 42 }, 'fallback'), 'fallback');
assert.equal(ui.isDecryptedPayload({ text: 'hello', author: 'Ada', context: 'note' }), true);
assert.equal(ui.isDecryptedPayload({ text: 'hello', author: 'Ada', source_sender: 'Grace' }), true);
assert.equal(ui.isDecryptedPayload({ text: 'hello', author: 'Ada', extra: 'must not be merged' }), true);
assert.equal(ui.isDecryptedPayload({ text: 'hello', author: 42 }), false);
assert.equal(ui.isDecryptedPayload({ text: 'hello', author: 'Ada', source_sender: 42 }), false);
const decrypted = await ui.decryptQuoteForDisplay({
  id: 'q1', text: '$$E2E$${"iv":"iv","data":"data"}', author: 'ENCRYPTED',
  created_at: '2026-09-20T12:00:00Z', user_id: 'user-a', vault_generation: 'g1', sync_status: 'pending',
}, {});
assert.deepEqual({ text: decrypted.text, author: decrypted.author, context: decrypted.context, source_sender: decrypted.source_sender }, {
  text: 'decoded', author: 'Ada', context: 'letter', source_sender: 'Grace',
});
assert.equal('extra' in decrypted, false);
assert.equal(decrypted.id, 'q1');
assert.equal(decrypted.user_id, 'user-a');
assert.equal(decrypted.vault_generation, 'g1');
assert.equal(decrypted.sync_status, 'pending');

const invalidPayloadUi = load('src/components/ui.ts', {
  react: { useEffect: () => {}, useRef: initial => ({ current: initial }) },
  '../lib/crypto': { decryptData: async () => JSON.stringify({ text: 'decoded', author: 'Ada', source_sender: 42 }) },
});
const failedDecrypt = await invalidPayloadUi.decryptQuoteForDisplay({
  id: 'q2', text: '$$E2E$${"iv":"iv","data":"data"}', author: 'ENCRYPTED', source_sender: 'spoofed',
  created_at: '2026-09-20T12:00:00Z', user_id: 'user-a', vault_generation: 'g1',
}, {});
assert.equal(failedDecrypt.text, '🔒 Encrypted Payload (Decryption Failed)');
assert.equal('source_sender' in failedDecrypt, false, 'failed decrypts must not expose top-level provenance');

const cryptoModule = load('src/lib/crypto.ts', {}, { crypto: webcrypto, TextEncoder, TextDecoder, btoa, atob, console });
const encryptedUi = load('src/components/ui.ts', {
  react: { useEffect: () => {}, useRef: initial => ({ current: initial }) },
  '../lib/crypto': { decryptData: cryptoModule.decryptData },
});
const encryptionKey = await cryptoModule.deriveEncryptionKey('test-only-password');
const encryptedBundle = await cryptoModule.encryptData(JSON.stringify({ text: 'decoded', author: 'Ada', source_sender: 'Grace' }), encryptionKey);
const roundTrip = await encryptedUi.decryptQuoteForDisplay({
  id: 'q3', text: `$$E2E$$${JSON.stringify(encryptedBundle)}`, author: 'ENCRYPTED', source_sender: 'spoofed',
  created_at: '2026-09-20T12:00:00Z', user_id: 'user-a', vault_generation: 'g1',
}, encryptionKey);
assert.equal(roundTrip.source_sender, 'Grace');
assert.equal(roundTrip.text, 'decoded');
assert.equal(roundTrip.author, 'Ada');
assert.equal(roundTrip.context, undefined, 'payloads without context remain valid');
assert.equal(JSON.stringify(encryptedBundle).includes('Grace'), false, 'source sender stays inside ciphertext');

const legacyBundle = await cryptoModule.encryptData(JSON.stringify({ text: 'legacy', author: 'Ada' }), encryptionKey);
const legacyRoundTrip = await encryptedUi.decryptQuoteForDisplay({
  id: 'q4', text: `$$E2E$$${JSON.stringify(legacyBundle)}`, author: 'ENCRYPTED', source_sender: 'spoofed',
  created_at: '2026-09-20T12:00:00Z', user_id: 'user-a', vault_generation: 'g1',
}, encryptionKey);
assert.equal(legacyRoundTrip.text, 'legacy');
assert.equal('source_sender' in legacyRoundTrip, false, 'legacy payloads must not inherit outer provenance');

const components = load('src/components/AddQuote.tsx', {
  react: {
    useState: initial => [initial, () => {}],
    useEffect: () => {},
    useRef: initial => ({ current: initial }),
  },
  'framer-motion': { AnimatePresence: 'div', motion: new Proxy({}, { get: (_, key) => key }) },
  'lucide-react': new Proxy({}, { get: (_, key) => key }),
  '../hooks/useQuotes': { useQuotes: () => ({ addQuote: async () => {} }) },
  '../hooks/useAuth': { useAuth: () => ({ user: {id: 'user-a', user_metadata: {first_name: 'Grace'}} }) },
  '../hooks/useCrypto': { useCrypto: () => ({ encryptionKey: {}, isLocked: false }) },
  '../lib/crypto': { encryptData: async () => ({}) },
  '../lib/profile-cache': { loadProfiles: async () => [] },
  '../lib/quote-edit': { saveQuoteEdit: async () => {} },
  '../lib/access': { isAdminUser: () => false },
  './ui': ui,
});
const addQuoteTree = components.AddQuote({ onClose: () => {} });
assert.equal(ui.isCiphertextWithinLimit({ data: 'x'.repeat(262144) }), true);
assert.equal(ui.isCiphertextWithinLimit({ data: 'x'.repeat(262145) }), false);
const childrenOf = node => [node?.props?.children].flat(Infinity).filter(Boolean);
const find = (node, predicate) => {
  if (!node || typeof node !== 'object') return null;
  if (predicate(node)) return node;
  return childrenOf(node).map(child => find(child, predicate)).find(Boolean) || null;
};
assert.equal(find(addQuoteTree, node => node.type === 'dialog')?.props?.role, 'dialog');
assert.equal(find(addQuoteTree, node => node.type === 'textarea')?.props?.id, 'quote-text');
assert.equal(find(addQuoteTree, node => node.type === 'label' && node.props.htmlFor === 'quote-text') !== null, true);
assert.equal(find(addQuoteTree, node => node.type === 'input' && node.props.id === 'quote-source-sender') !== null, false);

async function renderWithProfiles(edit) {
  const states = [];
  let stateCursor = 0;
  let effectCursor = 0;
  const effects = [];
  const profiles = [{ id: 'ada', first_name: 'Ada', last_name: 'Lovelace' }, { id: 'grace', first_name: 'Grace', last_name: 'Hopper' }];
  const profileComponents = load('src/components/AddQuote.tsx', {
    react: {
      useState: initial => {
        const index = stateCursor++;
        if (!(index in states)) states[index] = initial;
        return [states[index], value => { states[index] = typeof value === 'function' ? value(states[index]) : value; }];
      },
      useEffect: effect => { const index = effectCursor++; if (!effects[index]) { effects[index] = true; effect(); } },
      useRef: initial => ({ current: initial }),
    },
    'framer-motion': { AnimatePresence: 'div', motion: new Proxy({}, { get: (_, key) => key }) },
    'lucide-react': new Proxy({}, { get: (_, key) => key }),
    '../hooks/useQuotes': { useQuotes: () => ({ addQuote: async () => {} }) },
    '../hooks/useAuth': { useAuth: () => ({ user: { id: 'user-a' } }) },
    '../hooks/useCrypto': { useCrypto: () => ({ encryptionKey: {}, isLocked: false }) },
    '../lib/crypto': { encryptData: async () => ({}) },
    '../lib/profile-cache': { loadProfiles: async () => profiles },
    '../lib/quote-edit': { saveQuoteEdit: async () => {} },
    '../lib/access': { isAdminUser: () => false },
    './ui': ui,
  });
  const render = () => { stateCursor = 0; effectCursor = 0; return profileComponents.AddQuote({ onClose: () => {}, edit }); };
  render();
  await Promise.resolve();
  await Promise.resolve();
  return { render, states };
}

const multiAuthor = await renderWithProfiles();
let multiAuthorTree = multiAuthor.render();
assert.equal(find(multiAuthorTree, node => node.type === 'legend')?.props?.children, 'Author');
assert.equal(find(multiAuthorTree, node => node.type === 'input' && node.props.type === 'checkbox' && node.props.checked === true && node.props.disabled === true) !== null, true);
find(multiAuthorTree, node => node.type === 'input' && node.props.type === 'checkbox' && node.props.checked === false).props.onChange({ target: { checked: true } });
multiAuthorTree = multiAuthor.render();
assert.equal(multiAuthor.states[1], 'Ada Lovelace & Grace Hopper');

const importedAuthor = await renderWithProfiles({ display: { text: '', author: 'Mystery & Outside Speaker', context: '' }, stored: { quote_date: '' } });
let importedTree = importedAuthor.render();
find(importedTree, node => node.type === 'input' && node.props.type === 'checkbox' && node.props.checked === false).props.onChange({ target: { checked: true } });
importedTree = importedAuthor.render();
assert.equal(importedAuthor.states[1], 'Mystery & Outside Speaker & Ada Lovelace');
find(importedTree, node => node.type === 'input' && node.props.type === 'checkbox' && node.props.checked === true).props.onChange({ target: { checked: false } });
assert.equal(importedAuthor.states[1], 'Mystery & Outside Speaker');

const encryptedInputs = [];
const submittedQuotes = [];
let addQuoteState = 0;
const submitComponents = load('src/components/AddQuote.tsx', {
  react: {
    useState: initial => [["quote", "Ada", "note"][addQuoteState++] ?? initial, () => {}],
    useEffect: () => {},
    useRef: initial => ({ current: initial }),
  },
  'framer-motion': { AnimatePresence: 'div', motion: new Proxy({}, { get: (_, key) => key }) },
  'lucide-react': new Proxy({}, { get: (_, key) => key }),
  '../hooks/useQuotes': { useQuotes: () => ({ addQuote: async (...quote) => { submittedQuotes.push(quote); } }) },
  '../hooks/useAuth': { useAuth: () => ({ user: {id: 'user-a', user_metadata: {first_name: 'Grace'}} }) },
  '../hooks/useCrypto': { useCrypto: () => ({ encryptionKey: {}, isLocked: false }) },
  '../lib/crypto': { encryptData: async plaintext => { encryptedInputs.push(plaintext); return { iv: 'iv', data: 'data' }; } },
  '../lib/profile-cache': { loadProfiles: async () => [] },
  '../lib/quote-edit': { saveQuoteEdit: async () => {} },
  '../lib/access': { isAdminUser: () => false },
  './ui': ui,
});
const submitTree = submitComponents.AddQuote({ onClose: () => {} });
await find(submitTree, node => node.type === 'form').props.onSubmit({ preventDefault() {} });
assert.deepEqual(encryptedInputs, ['{"text":"quote","author":"Ada","context":"note","source_sender":"Grace"}']);
assert.deepEqual(submittedQuotes, [['$$E2E$${"iv":"iv","data":"data"}', 'ENCRYPTED', 'ENCRYPTED', ui.localDateInputValue()]]);

const sessionDeferred = Promise.withResolvers();
let authEvent;
let authEffect;
let authCursor = 0;
let authContext;
const authStates = [];
const authReact = {
  createContext: initial => {
    authContext = { value: initial };
    authContext.Provider = ({ value }) => { authContext.value = value; return null; };
    return authContext;
  },
  useContext: context => context.value,
  useState: initial => {
    const index = authCursor++;
    if (!(index in authStates)) authStates[index] = typeof initial === 'function' ? initial() : initial;
    return [authStates[index], value => { authStates[index] = value; }];
  },
  useRef: initial => ({ current: initial }),
  useCallback: callback => callback,
  useEffect: effect => { authEffect = effect; },
};
const authModule = load('src/hooks/useAuth.tsx', {
  react: authReact,
  'react/jsx-runtime': { jsx: (type, props) => type(props) },
  '@supabase/supabase-js': { isAuthRetryableFetchError: () => false },
  '../lib/vault': { readCachedVaultState: () => null, clearCachedVaultState() {} },
  '../lib/supabase': {
    readCachedSessionUser: () => null, clearCachedSession() {}, isLocallySignedOut: () => false, setLocalSignedOut() {}, localSignOutKey: 'test-signout',
    supabase: {
      auth: {
        getSession: () => sessionDeferred.promise,
        onAuthStateChange: callback => { authEvent = callback; return { data: { subscription: { unsubscribe() {} } } }; },
      },
    },
  },
}, { navigator: { onLine: true }, document: { visibilityState: 'visible', addEventListener() {}, removeEventListener() {} }, window: { addEventListener() {}, removeEventListener() {}, clearTimeout() {} } });
const renderAuth = () => { authCursor = 0; authModule.AuthProvider({ children: null }); };
renderAuth();
const authCleanup = authEffect();
const newerUser = { id: 'new-user', email: 'new@example.invalid' };
authEvent('SIGNED_IN', { user: newerUser });
renderAuth();
sessionDeferred.resolve({ data: { session: { user: { id: 'old-user', email: 'old@example.invalid' } } }, error: null });
await sessionDeferred.promise;
await Promise.resolve();
renderAuth();
assert.equal(authContext.value.user, newerUser, 'a stale session result cannot overwrite a newer auth event');
assert.equal(authContext.value.loading, false, 'a newer auth event clears session loading');
authCleanup?.();

// A failed refresh must recover without needing a second browser online event.
let recoverEffect;
let recoverCalls = 0;
let retryTimer;
let retryDelay;
const recoveryListeners = {};
const recoveryNavigator = { onLine: true };
const recoveryDocument = { visibilityState: 'visible', addEventListener: (name, fn) => { recoveryListeners[name] = fn; }, removeEventListener() {} };
const recoveryWindow = {
  addEventListener: (name, fn) => { recoveryListeners[name] = fn; }, removeEventListener() {},
  setTimeout: (fn, delay) => { retryTimer = fn; retryDelay = delay; return 1; },
  clearTimeout: () => { retryTimer = undefined; },
};
const recoverModule = load('src/hooks/useAuth.tsx', {
  react: { ...authReact, useState: initial => [typeof initial === 'function' ? initial() : initial, () => {}], useEffect: effect => { recoverEffect = effect; } },
  'react/jsx-runtime': { jsx: (type, props) => type(props) },
  '@supabase/supabase-js': { isAuthRetryableFetchError: error => error?.name === 'AuthRetryableFetchError' },
  '../lib/vault': { readCachedVaultState: () => ({ verifier: {} }), clearCachedVaultState() {} },
  '../lib/supabase': {
    readCachedSessionUser: () => ({ id: 'cached-user' }), clearCachedSession() {}, isLocallySignedOut: () => false, setLocalSignedOut() {}, localSignOutKey: 'test-signout',
    supabase: { auth: {
      getSession: async () => {
        recoverCalls++;
        return { data: { session: null }, error: { name: 'AuthRetryableFetchError', message: 'Offline' } };
      },
      onAuthStateChange: () => ({ data: { subscription: { unsubscribe() {} } } }),
    } },
  },
}, { navigator: recoveryNavigator, document: recoveryDocument, window: recoveryWindow });
recoverModule.AuthProvider({ children: null });
const recoverCleanup = recoverEffect();
await new Promise(setImmediate);
assert.equal(typeof retryTimer, 'function', 'transient authentication failure schedules recovery');
assert.equal(retryDelay, 30000, 'SDK retries already back off; do not poll auth rapidly');
retryTimer();
await new Promise(setImmediate);
assert.equal(recoverCalls, 2);
recoveryDocument.visibilityState = 'hidden';
recoveryListeners.visibilitychange();
assert.equal(retryTimer, undefined, 'hidden apps must not spend requests on retry polling');
recoverCleanup();

const profileDeferred = Promise.withResolvers();
let profileCalls = 0;
const storage = new Map();
const profileModule = load('src/lib/profile-cache.ts', {
  './supabase': {
    supabase: {
      from: () => ({ select: () => ({ order: () => {
        profileCalls += 1;
        return profileCalls === 1 ? profileDeferred.promise : Promise.resolve({ data: [{ id: 'fresh', first_name: 'Fresh', last_name: 'Name' }], error: null });
      } }) }),
    },
  },
}, {
  navigator: { onLine: true },
  localStorage: { getItem: key => storage.get(key) ?? null, setItem: (key, value) => storage.set(key, value), removeItem: key => storage.delete(key) },
});
const staleProfiles = profileModule.loadProfiles('profile-user');
profileModule.clearProfileCache('profile-user');
profileDeferred.resolve({ data: [{ id: 'stale', first_name: 'Stale', last_name: 'Name' }], error: null });
await assert.rejects(staleProfiles, /superseded/);
assert.deepEqual(await profileModule.loadProfiles('profile-user'), [{ id: 'fresh', first_name: 'Fresh', last_name: 'Name' }], 'cache invalidation forces a fresh author request');
assert.equal(profileCalls, 2);

console.log('ui audit checks passed');
