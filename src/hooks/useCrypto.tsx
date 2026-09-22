import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
import type { FormEvent, ReactNode } from 'react';
import { createVaultConfig, unlockWithVerifier } from '../lib/crypto';
import { cacheVaultState, isLegacyVaultState, loadVaultState, parseLegacyVaultMutation, readCachedVaultState } from '../lib/vault';
import type { VaultState } from '../lib/vault';
import { supabase } from '../lib/supabase';
import { Lock, Loader2 } from 'lucide-react';
import { useAuth } from './useAuth';
import { isAdminUser } from '../lib/access';

interface CryptoContextType {
    encryptionKey: CryptoKey | null;
    isLocked: boolean;
    vaultGeneration: string | null;
    legacyVaultGeneration: string | null;
    lockVault: () => void;
}
const CryptoContext = createContext<CryptoContextType>({
    encryptionKey: null, isLocked: true, vaultGeneration: null, legacyVaultGeneration: null, lockVault: () => {},
});

export const CryptoProvider = ({ children }: { children: ReactNode }) => {
    const { user, canSync, signOut } = useAuth();
    const [encryptionKey, setEncryptionKey] = useState<CryptoKey | null>(null);
    const [state, setState] = useState<VaultState | null>(() => user ? readCachedVaultState(user.id) : null);
    const currentState = useRef(state);
    const [password, setPassword] = useState('');
    const [busy, setBusy] = useState(!state);
    const [error, setError] = useState('');
    const request = useRef(0);
    const unlockRequest = useRef(0);
    const keyGeneration = useRef<string | null>(null);
    const userId = user?.id;

    const refreshSettings = useCallback(async () => {
        if (!userId) return;
        const version = ++request.current;
        try {
            const next = await loadVaultState(userId, !canSync);
            if (request.current === version) {
                if (currentState.current?.generation !== next.generation) {
                    unlockRequest.current++;
                    setBusy(false);
                }
                currentState.current = next;
                if (keyGeneration.current && keyGeneration.current !== next.generation) {
                    keyGeneration.current = null;
                    setEncryptionKey(null);
                }
                setState(next);
            }
        } catch (cause) {
            if (request.current === version) {
                unlockRequest.current++;
                keyGeneration.current = null;
                currentState.current = null;
                setEncryptionKey(null);
                setState(null);
                setError(cause instanceof Error ? cause.message : 'Could not load vault settings.');
            }
        } finally {
            if (request.current === version) setBusy(false);
        }
    }, [canSync, userId]);
    useEffect(() => {
        const lifecycle = request;
        const unlockLifecycle = unlockRequest;
        // Settings arrive asynchronously; the request counter also cancels stale results.
        // eslint-disable-next-line react-hooks/set-state-in-effect
        void refreshSettings();
        return () => { lifecycle.current++; unlockLifecycle.current++; };
    }, [refreshSettings]);

    const lockVault = useCallback(() => {
        unlockRequest.current++;
        currentState.current = null;
        keyGeneration.current = null;
        setEncryptionKey(null);
        setPassword('');
        setState(null);
        setBusy(true);
        setError('');
        void refreshSettings();
    }, [refreshSettings]);

    const handleUnlock = async (event: FormEvent) => {
        event.preventDefault();
        if (!state || !isLegacyVaultState(state) || !user || busy || !password) return;
        const version = ++unlockRequest.current;
        setBusy(true);
        setError('');
        try {
            let key: CryptoKey;
            let generation = state.generation;
            if (state.verifier) {
                key = await unlockWithVerifier(password, state.kdf, state.verifier);
            } else {
                if (!canSync) throw new Error('Connect to initialize the vault.');
                if (!isAdminUser(user)) throw new Error('The administrator must initialize the vault first.');
                const config = await createVaultConfig(password);
                const { data, error: initError } = await supabase.rpc('initialize_vault', {
                    p_expected_generation: state.generation, p_kdf: config.kdf, p_verifier: config.verifier,
                });
                if (initError) throw new Error(initError.message);
                const initialized = parseLegacyVaultMutation(data);
                if (!isLegacyVaultState(initialized)) throw new Error('Device vault setup is required.');
                if (unlockRequest.current !== version) return;
                cacheVaultState(user.id, initialized);
                currentState.current = initialized;
                setState(initialized);
                key = config.key;
                generation = initialized.generation;
            }
            if (unlockRequest.current === version) {
                keyGeneration.current = generation;
                setEncryptionKey(key);
                setPassword('');
            }
        } catch (cause) {
            if (unlockRequest.current === version) setError(cause instanceof Error ? cause.message : 'Could not unlock the vault.');
        } finally {
            if (unlockRequest.current === version) setBusy(false);
        }
    };

    if (!user) return children;
    if (!encryptionKey) {
        const legacyState = isLegacyVaultState(state) ? state : null;
        const initializing = legacyState && !legacyState.verifier;
        return <main className="min-h-[100dvh] flex items-center justify-center bg-background p-4">
            <section className="w-full max-w-sm bg-surface p-8 rounded-3xl border border-slate-700 text-center">
                <Lock className="w-10 h-10 mx-auto text-primary-400 mb-6" aria-hidden="true" />
                <h1 className="text-2xl font-bold mb-3">{initializing ? 'Initialize Group Vault' : 'Vault Locked'}</h1>
                <p className="text-sm text-slate-400 mb-6">{initializing
                    ? 'An administrator must choose a shared passphrase of at least 12 characters.'
                    : "Enter your group's shared vault key. It stays on this device and unlocks cached quotes offline."}</p>
                {error && <p role="alert" className="mb-4 text-red-400 text-sm">{error}</p>}
                <form onSubmit={handleUnlock} className="space-y-4">
                    <label htmlFor="vault-key" className="block text-sm text-slate-300">Group Vault Key</label>
                    <input id="vault-key" type="password" required autoComplete={initializing ? 'new-password' : 'off'}
                        minLength={initializing ? 12 : undefined} value={password} onChange={event => setPassword(event.target.value)}
                        className="w-full bg-slate-900 border border-slate-700 rounded-xl p-3 text-white" />
                    <button type="submit" disabled={busy || !legacyState || !password}
                        className="w-full bg-primary-600 disabled:opacity-50 py-3 rounded-xl flex justify-center">
                        {busy ? <><Loader2 className="w-5 h-5 animate-spin" aria-hidden="true" /><span className="sr-only">Loading</span></>
                            : initializing ? 'Initialize Vault' : 'Unlock Vault'}
                    </button>
                </form>
                {error && <button type="button" disabled={busy} onClick={() => { setBusy(true); setError(''); void refreshSettings(); }} className="mt-4 text-primary-400">Retry connection</button>}
                <button type="button" disabled={busy} className="block mx-auto mt-6 text-sm text-slate-400 disabled:opacity-50" onClick={async () => {
                    try {
                        await signOut();
                    } catch (cause) {
                        setError(cause instanceof Error ? cause.message : 'Unable to sign out.');
                    }
                }}>Sign out</button>
                <p className="text-xs text-slate-500 mt-6">Keep the shared key safe. Lost encryption keys cannot be recovered.</p>
            </section>
        </main>;
    }
    return <CryptoContext.Provider value={{ encryptionKey, isLocked: false,
        vaultGeneration: state?.generation ?? null, legacyVaultGeneration: isLegacyVaultState(state) ? state.legacy_generation : null, lockVault }}>
        {children}
    </CryptoContext.Provider>;
};

export const useCrypto = () => useContext(CryptoContext);
