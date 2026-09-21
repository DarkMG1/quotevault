import assert from 'node:assert/strict';
import { loadModule } from './load-module.mjs';

const load = (path, dependencies, globals) => loadModule(path, dependencies, {
  console: { error() {} }, ...globals,
});

const ui = load('src/components/ui.ts', {
  react: { useEffect: () => {}, useRef: initial => ({ current: initial }) },
  '../lib/crypto': { decryptData: async () => JSON.stringify({ text: 'decoded', author: 'Ada', context: 'letter', id: 'evil', user_id: 'evil', sync_status: 'synced', extra: 'ignored' }) },
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
assert.equal(ui.isDecryptedPayload({ text: 'hello', author: 'Ada', extra: 'must not be merged' }), true);
assert.equal(ui.isDecryptedPayload({ text: 'hello', author: 42 }), false);
const decrypted = await ui.decryptQuoteForDisplay({
  id: 'q1', text: '$$E2E$${"iv":"iv","data":"data"}', author: 'ENCRYPTED',
  created_at: '2026-09-20T12:00:00Z', user_id: 'user-a', vault_generation: 'g1', sync_status: 'pending',
}, {});
assert.deepEqual({ text: decrypted.text, author: decrypted.author, context: decrypted.context }, {
  text: 'decoded', author: 'Ada', context: 'letter',
});
assert.equal('extra' in decrypted, false);
assert.equal(decrypted.id, 'q1');
assert.equal(decrypted.user_id, 'user-a');
assert.equal(decrypted.vault_generation, 'g1');
assert.equal(decrypted.sync_status, 'pending');

const components = load('src/components/AddQuote.tsx', {
  react: {
    useState: initial => [initial, () => {}],
    useEffect: () => {},
    useRef: initial => ({ current: initial }),
  },
  'framer-motion': { AnimatePresence: 'div', motion: new Proxy({}, { get: (_, key) => key }) },
  'lucide-react': new Proxy({}, { get: (_, key) => key }),
  '../hooks/useQuotes': { useQuotes: () => ({ addQuote: async () => {} }) },
  '../hooks/useAuth': { useAuth: () => ({ user: null }) },
  '../hooks/useCrypto': { useCrypto: () => ({ encryptionKey: {}, isLocked: false }) },
  '../lib/crypto': { encryptData: async () => ({}) },
  '../lib/profile-cache': { loadProfiles: async () => [] },
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
    authStates[index] ??= initial;
    return [authStates[index], value => { authStates[index] = value; }];
  },
  useRef: initial => ({ current: initial }),
  useCallback: callback => callback,
  useEffect: effect => { authEffect = effect; },
};
const authModule = load('src/hooks/useAuth.tsx', {
  react: authReact,
  'react/jsx-runtime': { jsx: (type, props) => type(props) },
  '../lib/supabase': {
    supabase: {
      auth: {
        getSession: () => sessionDeferred.promise,
        onAuthStateChange: callback => { authEvent = callback; return { data: { subscription: { unsubscribe() {} } } }; },
      },
    },
  },
});
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
