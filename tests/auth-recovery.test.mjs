import assert from 'node:assert/strict';
import { loadModule } from './load-module.mjs';

let authEvent;
let authEffect;
let cursor = 0;
const states = [];
let refCursor = 0;
const refs = [];
let context;
const react = {
  createContext: initial => {
    context = { value: initial };
    context.Provider = ({ value }) => { context.value = value; return null; };
    return context;
  },
  useContext: value => value.value,
  useState: initial => {
    const index = cursor++;
    if (!(index in states)) states[index] = typeof initial === 'function' ? initial() : initial;
    return [states[index], value => { states[index] = typeof value === 'function' ? value(states[index]) : value; }];
  },
  useRef: initial => {
    const index = refCursor++;
    return refs[index] ??= { current: initial };
  },
  useCallback: callback => callback,
  useEffect: effect => { authEffect = effect; },
};
const localSignedOutCalls = [];
const historyCalls = [];
const updatePasswords = [];
const recoveryStorage = new Map();
const recoveryUser = { id: 'recovery-user', email: 'recover@example.invalid' };
const recoveryWindow = {
  location: { hash: '#access_token=test&type=recovery&refresh_token=test', pathname: '/quotevault', search: '?recovery=1' },
  history: { replaceState: (...args) => { historyCalls.push(args); const url = new URL(args[2], 'http://test'); recoveryWindow.location.hash = url.hash; recoveryWindow.location.search = url.search; } },
  sessionStorage: { getItem: key => recoveryStorage.get(key) ?? null, setItem: (key, value) => recoveryStorage.set(key, value), removeItem: key => recoveryStorage.delete(key) },
  clearTimeout() {}, setTimeout() { return 1; }, addEventListener() {}, removeEventListener() {},
};
const auth = loadModule('src/hooks/useAuth.tsx', {
  react,
  'react/jsx-runtime': { jsx: (type, props) => type(props) },
  '@supabase/supabase-js': { isAuthRetryableFetchError: () => false },
  '../lib/vault': { readCachedVaultState: () => null, clearCachedVaultState() {} },
  '../lib/supabase': {
    isLocallySignedOut: () => true,
    setLocalSignedOut: value => { localSignedOutCalls.push(value); },
    clearCachedSession() {}, localSignOutKey: 'signed-out', readCachedSessionUser: () => null,
    supabase: { auth: {
      getSession: async () => ({ data: { session: null }, error: null }),
      updateUser: async ({ password }) => { updatePasswords.push(password); authEvent('USER_UPDATED', { user: recoveryUser, expires_at: Date.now() / 1000 + 60 }); return { error: null }; },
      onAuthStateChange: callback => { authEvent = callback; return { data: { subscription: { unsubscribe() {} } } }; },
    } },
  },
}, {
  URLSearchParams,
  navigator: { onLine: true },
  document: { title: 'QuoteVault', visibilityState: 'visible', addEventListener() {}, removeEventListener() {} },
  window: recoveryWindow,
});
const render = () => { cursor = 0; refCursor = 0; auth.AuthProvider({ children: null }); };
render();
const cleanup = authEffect();
authEvent('PASSWORD_RECOVERY', { user: recoveryUser, expires_at: Date.now() / 1000 + 60 });
render();
assert.equal(context.value.isPasswordRecovery, true, 'recovery sessions stay out of protected routes');
assert.equal(context.value.canSync, false, 'recovery sessions do not unlock vault sync');
assert.equal(context.value.user, recoveryUser);
assert.equal(recoveryStorage.get('quotevault-password-recovery-user'), recoveryUser.id, 'only the recovery event persists the verified user');
assert.equal(localSignedOutCalls.every(value => value === false), true, 'recovery overrides a local signed-out marker');
assert.equal(historyCalls.at(-1)?.[2], '/quotevault?recovery=1', 'recovery tokens are removed while recovery intent remains');
await context.value.completePasswordRecovery('new-account-password');
assert.deepEqual(updatePasswords, ['new-account-password']);
assert.equal(recoveryStorage.size, 0, 'a completed recovery cannot be reused');
cleanup?.();
