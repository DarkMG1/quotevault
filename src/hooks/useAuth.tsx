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
    retry: () => void;
    signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue>({
    user: null,
    loading: true,
    canSync: false,
    signingOut: false,
    error: '',
    retry: () => undefined,
    signOut: async () => undefined,
});

export const AuthProvider = ({ children }: { children: React.ReactNode }) => {
    const [user, setUser] = useState<User | null>(() => {
        const cached = readCachedSessionUser();
        return cached && readCachedVaultState(cached.id)?.verifier ? cached : null;
    });
    const localUser = useRef(user);
    const [loading, setLoading] = useState(!user);
    const [canSync, setCanSync] = useState(false);
    const [signingOut, setSigningOut] = useState(false);
    const [error, setError] = useState('');
    const mounted = useRef(false);
    const requestEpoch = useRef(0);
    const signOutRequest = useRef<Promise<void> | null>(null);

    const clearLocalAccess = useCallback(() => {
        requestEpoch.current++;
        if (localUser.current) clearCachedVaultState(localUser.current.id);
        localUser.current = null;
        setUser(null);
        setCanSync(false);
        setLoading(false);
    }, []);

    const loadSession = useCallback(async () => {
        const epoch = ++requestEpoch.current;
        setLoading(!localUser.current);
        setError('');
        if (isLocallySignedOut()) { clearLocalAccess(); return; }
        if (!navigator.onLine) {
            setCanSync(false);
            setLoading(false);
            return;
        }
        try {
            const { data: { session }, error: sessionError } = await supabase.auth.getSession();
            if (!mounted.current || epoch !== requestEpoch.current || signOutRequest.current) return;
            if (isLocallySignedOut()) { clearLocalAccess(); return; }
            if (sessionError) throw sessionError;
            if (!session) { clearLocalAccess(); return; }
            localUser.current = session.user;
            setUser(session.user);
            setCanSync(true);
        } catch (sessionError: unknown) {
            if (!mounted.current || epoch !== requestEpoch.current) return;
            setCanSync(false);
            if (!isAuthRetryableFetchError(sessionError)) clearLocalAccess();
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

    useEffect(() => {
        mounted.current = true;
        const epochRef = requestEpoch;
        // Session restoration is the external subscription this effect starts.
        void loadSession();

        // Listen for changes on auth state (logged in, signed out, etc.)
        const { data: { subscription } } = supabase.auth.onAuthStateChange((event, session) => {
            if (!mounted.current || signOutRequest.current || isLocallySignedOut()) return;
            // INITIAL_SESSION can be null solely because an offline refresh failed.
            if (event === 'INITIAL_SESSION' && !session && localUser.current) return;
            requestEpoch.current++;
            if (!session) { clearLocalAccess(); return; }
            localUser.current = session.user;
            setUser(session.user);
            setCanSync(navigator.onLine && !!session.expires_at && session.expires_at * 1000 > Date.now());
            setLoading(false);
            setError('');
        });

        const online = () => { void loadSession(); };
        const offline = () => { requestEpoch.current++; setCanSync(false); setLoading(false); };
        const storage = (event: StorageEvent) => {
            if (event.key !== localSignOutKey) return;
            if (isLocallySignedOut()) clearLocalAccess();
            else if (!signOutRequest.current) void loadSession();
        };
        window.addEventListener('storage', storage);
        window.addEventListener('online', online);
        window.addEventListener('offline', offline);
        return () => {
            window.removeEventListener('storage', storage);
            window.removeEventListener('online', online);
            window.removeEventListener('offline', offline);
            mounted.current = false;
            epochRef.current++;
            subscription.unsubscribe();
        };
    }, [clearLocalAccess, loadSession]);

    return (
        <AuthContext.Provider value={{ user, loading, canSync, signingOut, error, retry: loadSession, signOut }}>
            {children}
        </AuthContext.Provider>
    );
};

export const useAuth = () => {
    return useContext(AuthContext);
};
