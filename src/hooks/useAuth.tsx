import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
import { supabase } from '../lib/supabase';
import type { User } from '@supabase/supabase-js';

interface AuthContextValue {
    user: User | null;
    loading: boolean;
    error: string;
    retry: () => void;
    signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue>({
    user: null,
    loading: true,
    error: '',
    retry: () => undefined,
    signOut: async () => undefined,
});

export const AuthProvider = ({ children }: { children: React.ReactNode }) => {
    const [user, setUser] = useState<User | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const mounted = useRef(false);
    const requestEpoch = useRef(0);
    const signOutRequest = useRef<Promise<void> | null>(null);

    const loadSession = useCallback(async () => {
        const epoch = ++requestEpoch.current;
        setLoading(true);
        setError('');
        try {
            const { data: { session }, error: sessionError } = await supabase.auth.getSession();
            if (sessionError) throw sessionError;
            if (!mounted.current || epoch !== requestEpoch.current) return;
            setUser(session?.user ?? null);
        } catch (sessionError: unknown) {
            if (!mounted.current || epoch !== requestEpoch.current) return;
            setUser(null);
            setError(sessionError instanceof Error ? sessionError.message : 'Unable to restore your session. Retry the connection.');
        } finally {
            if (mounted.current && epoch === requestEpoch.current) setLoading(false);
        }
    }, []);

    const reportError = useCallback((message: string) => {
        if (!mounted.current) return;
        setError(message);
        setLoading(false);
    }, []);

    const signOut = useCallback(() => {
        if (signOutRequest.current) return signOutRequest.current;
        const request = (async () => {
            try {
                const { error: signOutError } = await supabase.auth.signOut();
                if (signOutError) throw signOutError;
            } catch (signOutError: unknown) {
                const detail = signOutError instanceof Error ? signOutError.message : 'The server did not confirm sign-out.';
                const message = `Unable to confirm sign-out. Please sign in again if needed: ${detail}`;
                reportError(message);
                throw new Error(message);
            }
        })();
        const settled = request.finally(() => {
            if (signOutRequest.current === settled) signOutRequest.current = null;
        });
        signOutRequest.current = settled;
        return settled;
    }, [reportError]);

    useEffect(() => {
        mounted.current = true;
        const epochRef = requestEpoch;
        // Session restoration is the external subscription this effect starts.
        // eslint-disable-next-line react-hooks/set-state-in-effect
        void loadSession();

        // Listen for changes on auth state (logged in, signed out, etc.)
        const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
            if (!mounted.current) return;
            requestEpoch.current++;
            setUser(session?.user ?? null);
            setLoading(false);
            setError('');
        });

        return () => {
            mounted.current = false;
            epochRef.current++;
            subscription.unsubscribe();
        };
    }, [loadSession]);

    return (
        <AuthContext.Provider value={{ user, loading, error, retry: loadSession, signOut }}>
            {children}
        </AuthContext.Provider>
    );
};

export const useAuth = () => {
    return useContext(AuthContext);
};
