import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
import { clearCachedSession, isLocallySignedOut, localSignOutKey, readCachedSessionUser, setLocalSignedOut, supabase } from '../lib/supabase';
import { clearCachedVaultState, readCachedVaultState } from '../lib/vault';
import { isAuthRetryableFetchError, type User } from '@supabase/supabase-js';

interface AuthContextValue {
    user: User | null;
    loading: boolean;
    canSync: boolean;
    signingOut: boolean;
    error: string;
    isPasswordRecovery: boolean;
    recoveryError: string;
    retry: () => Promise<void>;
    signOut: () => Promise<void>;
    completePasswordRecovery: (password: string) => Promise<void>;
    cancelPasswordRecovery: () => void;
}

const AuthContext = createContext<AuthContextValue>({
    user: null,
    loading: true,
    canSync: false,
    signingOut: false,
    error: '',
    isPasswordRecovery: false,
    recoveryError: '',
    retry: async () => {},
    signOut: async () => undefined,
    completePasswordRecovery: async () => {},
    cancelPasswordRecovery: () => {},
});

function recoveryHashState(): 'recovery' | 'error' | null {
    if (typeof window === 'undefined' || !window.location) return null;
    const params = new URLSearchParams(window.location.hash.slice(1));
    if (params.get('type') === 'recovery') return 'recovery';
    return params.has('error') ? 'error' : null;
}

function hasRecoveryIntent() {
    return typeof window !== 'undefined' && !!window.location && new URLSearchParams(window.location.search).get('recovery') === '1';
}

const recoveryUserKey = 'quotevault-password-recovery-user';
function recoveryUserId() {
    try { return typeof window === 'undefined' ? null : window.sessionStorage?.getItem(recoveryUserKey); }
    catch { return null; }
}
function rememberRecoveryUser(userId: string) {
    try {
        window.sessionStorage?.setItem(recoveryUserKey, userId);
        return recoveryUserId() === userId;
    } catch { return false; }
}
function forgetRecoveryUser() {
    try { window.sessionStorage?.removeItem(recoveryUserKey); }
    catch { /* Storage access must not interrupt ordinary authentication. */ }
}

function clearRecoveryHash() {
    if (typeof window === 'undefined' || !window.history || !window.location || !recoveryHashState()) return;
    window.history.replaceState(null, document.title, `${window.location.pathname}${window.location.search}`);
}

function clearRecoveryIntent() {
    if (typeof window === 'undefined' || !window.history || !window.location || !hasRecoveryIntent()) return;
    const query = new URLSearchParams(window.location.search);
    query.delete('recovery');
    const search = query.toString();
    window.history.replaceState(null, document.title, `${window.location.pathname}${search ? `?${search}` : ''}`);
}

export const AuthProvider = ({ children }: { children: React.ReactNode }) => {
    const [user, setUser] = useState<User | null>(() => {
        const cached = readCachedSessionUser();
        return cached && readCachedVaultState(cached.id)?.verifier ? cached : null;
    });
    const localUser = useRef(user);
    const [loading, setLoading] = useState(!user || hasRecoveryIntent());
    const [canSync, setCanSync] = useState(false);
    const [signingOut, setSigningOut] = useState(false);
    const [error, setError] = useState('');
    const [isPasswordRecovery, setIsPasswordRecovery] = useState(false);
    const [recoveryError, setRecoveryError] = useState(() => recoveryHashState() === 'error' ? 'This password reset link is invalid or expired. Request a new one.' : '');
    const mounted = useRef(false);
    const requestEpoch = useRef(0);
    const accessEpoch = useRef(0);
    const retryTimer = useRef<number | undefined>(undefined);
    const signOutRequest = useRef<Promise<void> | null>(null);

    const clearLocalAccess = useCallback(() => {
        requestEpoch.current++;
        accessEpoch.current++;
        window.clearTimeout(retryTimer.current);
        if (localUser.current) clearCachedVaultState(localUser.current.id);
        localUser.current = null;
        setUser(null);
        setCanSync(false);
        setIsPasswordRecovery(false);
        forgetRecoveryUser();
        setLoading(false);
    }, []);

    const loadSession = useCallback(async function restoreSession() {
        const epoch = ++requestEpoch.current;
        window.clearTimeout(retryTimer.current);
        const recoveryIntent = hasRecoveryIntent();
        setLoading(!localUser.current || recoveryIntent);
        setError('');
        const recoveryHash = recoveryHashState();
        if (recoveryHash === 'error') {
            setIsPasswordRecovery(false);
            forgetRecoveryUser();
            setRecoveryError('This password reset link is invalid or expired. Request a new one.');
            clearRecoveryHash();
            clearLocalAccess();
            return;
        }
        if (recoveryHash === 'recovery') forgetRecoveryUser();
        const verifiedRecoveryUser = recoveryUserId();
        if (isLocallySignedOut() && !(recoveryIntent && verifiedRecoveryUser)) { clearLocalAccess(); return; }
        if (recoveryIntent && verifiedRecoveryUser) setLocalSignedOut(false);
        if (!navigator.onLine) {
            setCanSync(false);
            setLoading(false);
            return;
        }
        try {
            const { data: { session }, error: sessionError } = await supabase.auth.getSession();
            if (!mounted.current || epoch !== requestEpoch.current || signOutRequest.current) return;
            if (isLocallySignedOut() && !(recoveryIntent && verifiedRecoveryUser)) { clearLocalAccess(); return; }
            if (sessionError) throw sessionError;
            if (!session) {
                clearLocalAccess();
                if (recoveryIntent) setRecoveryError('This password reset link is invalid or expired. Request a new one.');
                return;
            }
            if (localUser.current?.id && localUser.current.id !== session.user.id) accessEpoch.current++;
            localUser.current = session.user;
            setUser(session.user);
            if (recoveryIntent && verifiedRecoveryUser === session.user.id) {
                setCanSync(false);
                setIsPasswordRecovery(true);
                setRecoveryError('');
                clearRecoveryHash();
            } else {
                if (recoveryIntent) forgetRecoveryUser();
                setIsPasswordRecovery(false);
                setCanSync(true);
            }
        } catch (sessionError: unknown) {
            if (!mounted.current || epoch !== requestEpoch.current) return;
            setCanSync(false);
            if (!isAuthRetryableFetchError(sessionError)) {
                clearLocalAccess();
                if (recoveryIntent) setRecoveryError('This password reset link is invalid or expired. Request a new one.');
            }
            else if (navigator.onLine && document.visibilityState === 'visible') {
                // The SDK already retries a refresh. Retry later, not on every render.
                retryTimer.current = window.setTimeout(() => {
                    if (mounted.current && epoch === requestEpoch.current && !signOutRequest.current) void restoreSession();
                }, 30000);
            }
            setError(sessionError instanceof Error ? sessionError.message : 'Unable to restore your session. Retry the connection.');
        } finally {
            if (mounted.current && epoch === requestEpoch.current) setLoading(false);
        }
    }, [clearLocalAccess]);

    const reportError = useCallback((message: string) => {
        if (!mounted.current) return;
        setError(message);
        setLoading(false);
    }, []);

    const signOut = useCallback(() => {
        if (signOutRequest.current) return signOutRequest.current;
        // Lock immediately, even when the SDK is waiting on an offline refresh.
        clearLocalAccess();
        clearRecoveryIntent();
        setRecoveryError('');
        try { setLocalSignedOut(true); } catch { clearCachedSession(); }
        setSigningOut(true);
        if (!navigator.onLine) clearCachedSession();
        const request = (async () => {
            try {
                const { error: signOutError } = await supabase.auth.signOut();
                if (signOutError) throw signOutError;
            } catch (signOutError: unknown) {
                const detail = signOutError instanceof Error ? signOutError.message : 'The server did not confirm sign-out.';
                const message = `Unable to confirm sign-out. Please sign in again if needed: ${detail}`;
                reportError(message);
                throw new Error(message);
            } finally {
                // A refresh already in flight must not restore a signed-out device.
                if (isLocallySignedOut()) clearCachedSession();
            }
        })();
        const settled = request.finally(() => {
            if (signOutRequest.current === settled) signOutRequest.current = null;
            if (mounted.current) setSigningOut(false);
        });
        signOutRequest.current = settled;
        return settled;
    }, [clearLocalAccess, reportError]);

    const completePasswordRecovery = useCallback(async (password: string) => {
        const epoch = accessEpoch.current;
        const userId = localUser.current?.id;
        if (!isPasswordRecovery || !userId || recoveryUserId() !== userId) throw new Error('This password reset link is invalid or expired. Request a new one.');
        const { error: updateError } = await supabase.auth.updateUser({ password });
        if (updateError) throw updateError;
        if (!mounted.current || epoch !== accessEpoch.current || localUser.current?.id !== userId) {
            throw new Error('This password reset link is invalid or expired. Request a new one.');
        }
        clearRecoveryIntent();
        forgetRecoveryUser();
        setIsPasswordRecovery(false);
        setRecoveryError('');
        await loadSession();
    }, [isPasswordRecovery, loadSession]);

    const cancelPasswordRecovery = useCallback(() => {
        clearRecoveryIntent();
        forgetRecoveryUser();
        clearLocalAccess();
        setLocalSignedOut(true);
        clearCachedSession();
        setRecoveryError('');
    }, [clearLocalAccess]);

    useEffect(() => {
        mounted.current = true;
        const epochRef = requestEpoch;
        const accessEpochRef = accessEpoch;
        // Session restoration is the external subscription this effect starts.
        void loadSession();

        // Listen for changes on auth state (logged in, signed out, etc.)
        const { data: { subscription } } = supabase.auth.onAuthStateChange((event, session) => {
            if (!mounted.current || signOutRequest.current) return;
            if (event === 'PASSWORD_RECOVERY') {
                requestEpoch.current++;
                window.clearTimeout(retryTimer.current);
                setLocalSignedOut(false);
                clearRecoveryHash();
                if (!session) {
                    clearLocalAccess();
                    setRecoveryError('This password reset link is invalid or expired. Request a new one.');
                    return;
                }
                if (!rememberRecoveryUser(session.user.id)) {
                    clearLocalAccess();
                    setRecoveryError('This password reset link is invalid or expired. Request a new one.');
                    return;
                }
                if (localUser.current?.id && localUser.current.id !== session.user.id) accessEpoch.current++;
                localUser.current = session.user;
                setUser(session.user);
                setCanSync(false);
                setIsPasswordRecovery(true);
                setRecoveryError('');
                setLoading(false);
                setError('');
                return;
            }
            const recoveryIntent = hasRecoveryIntent();
            const recoveryHash = recoveryHashState();
            if (recoveryHash === 'error') {
                clearLocalAccess();
                setRecoveryError('This password reset link is invalid or expired. Request a new one.');
                clearRecoveryHash();
                return;
            }
            if (recoveryHash === 'recovery') forgetRecoveryUser();
            const verifiedRecoveryUser = recoveryUserId();
            if (isLocallySignedOut() && !(recoveryIntent && verifiedRecoveryUser)) return;
            // INITIAL_SESSION can be null solely because an offline refresh failed.
            if (event === 'INITIAL_SESSION' && !session && localUser.current) return;
            requestEpoch.current++;
            window.clearTimeout(retryTimer.current);
            if (!session) {
                clearLocalAccess();
                if (recoveryIntent) setRecoveryError('This password reset link is invalid or expired. Request a new one.');
                return;
            }
            if (localUser.current?.id && localUser.current.id !== session.user.id) accessEpoch.current++;
            localUser.current = session.user;
            setUser(session.user);
            if (recoveryIntent && verifiedRecoveryUser === session.user.id) {
                setCanSync(false);
                setIsPasswordRecovery(true);
                setRecoveryError('');
                clearRecoveryHash();
            } else {
                if (recoveryIntent) forgetRecoveryUser();
                setIsPasswordRecovery(false);
                setCanSync(navigator.onLine && !!session.expires_at && session.expires_at * 1000 > Date.now());
            }
            setLoading(false);
            setError('');
        });

        const online = () => { void loadSession(); };
        const offline = () => { requestEpoch.current++; window.clearTimeout(retryTimer.current); setCanSync(false); setLoading(false); };
        const visible = () => {
            if (document.visibilityState === 'visible') void loadSession();
            else window.clearTimeout(retryTimer.current);
        };
        const storage = (event: StorageEvent) => {
            if (event.key !== localSignOutKey) return;
            if (isLocallySignedOut()) clearLocalAccess();
            else if (!signOutRequest.current) void loadSession();
        };
        document.addEventListener('visibilitychange', visible);
        window.addEventListener('storage', storage);
        window.addEventListener('online', online);
        window.addEventListener('offline', offline);
        return () => {
            window.clearTimeout(retryTimer.current);
            document.removeEventListener('visibilitychange', visible);
            window.removeEventListener('storage', storage);
            window.removeEventListener('online', online);
            window.removeEventListener('offline', offline);
            mounted.current = false;
            epochRef.current++;
            accessEpochRef.current++;
            subscription.unsubscribe();
        };
    }, [clearLocalAccess, loadSession]);

    return (
        <AuthContext.Provider value={{ user, loading, canSync, signingOut, error, isPasswordRecovery, recoveryError, retry: loadSession, signOut, completePasswordRecovery, cancelPasswordRecovery }}>
            {children}
        </AuthContext.Provider>
    );
};

export const useAuth = () => {
    return useContext(AuthContext);
};
