import React, { createContext, useContext, useState } from 'react';
import type { ReactNode } from 'react';
import { deriveEncryptionKey, hashVaultKey } from '../lib/crypto';
import { supabase } from '../lib/supabase';
import { Lock, KeyRound, Loader2 } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { useAuth } from './useAuth';

interface CryptoContextType {
    encryptionKey: CryptoKey | null;
    isLocked: boolean;
    lockVault: () => void;
}

const CryptoContext = createContext<CryptoContextType>({
    encryptionKey: null,
    isLocked: true,
    lockVault: () => { },
});

export const CryptoProvider = ({ children }: { children: ReactNode }) => {
    const { user } = useAuth();
    const [encryptionKey, setEncryptionKey] = useState<CryptoKey | null>(null);
    const [passwordInput, setPasswordInput] = useState('');
    const [isDeriving, setIsDeriving] = useState(false);
    const [errorMsg, setErrorMsg] = useState('');

    const handleUnlock = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!passwordInput.trim()) return;

        setIsDeriving(true);
        setErrorMsg('');

        try {
            // Give UI time to paint loading state before blocking thread with crypto
            await new Promise(resolve => setTimeout(resolve, 50));

            // 1. Check if the server has a verification hash stored
            const { data: setting, error: fetchErr } = await supabase
                .from('app_settings')
                .select('value')
                .eq('key', 'vault_key_hash')
                .maybeSingle();

            if (fetchErr && fetchErr.code !== 'PGRST116' && fetchErr.code !== '42P01') {
                // Ignore missing table error (42P01) or no rows (PGRST116) gracefully
                throw fetchErr;
            }

            // 2. If a hash exists, verify the password BEFORE deriving the key
            if (setting?.value) {
                const computedHash = await hashVaultKey(passwordInput);
                if (computedHash !== setting.value) {
                    throw new Error("Incorrect Group Vault Key.");
                }
            }

            const key = await deriveEncryptionKey(passwordInput);
            setEncryptionKey(key);
            setPasswordInput('');
        } catch (err: any) {
            console.error("Failed to unlock vault", err);
            setErrorMsg(err.message || 'Failed to initialize encryption key.');
        } finally {
            setIsDeriving(false);
        }
    };

    const lockVault = () => {
        setEncryptionKey(null);
    };

    // If there is no authenticated user, the base Auth flow will handle it. We just pass through.
    if (!user) {
        return <>{children}</>;
    }

    // If an authenticated user exists but the vault is locked:
    if (!encryptionKey) {
        return (
            <div className="min-h-[100dvh] w-full flex items-center justify-center relative bg-background p-4 sm:p-8">
                {/* Visual Lock Overlay elements */}
                <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[60%] h-[60%] rounded-full bg-primary-600/10 blur-[150px] pointer-events-none" />

                <motion.div
                    initial={{ opacity: 0, scale: 0.95, y: 10 }}
                    animate={{ opacity: 1, scale: 1, y: 0 }}
                    className="w-full max-w-sm bg-surface/90 backdrop-blur-xl p-8 rounded-3xl shadow-2xl shadow-primary-900/10 border border-slate-700/50 relative z-10 text-center"
                >
                    <div className="w-16 h-16 mx-auto bg-slate-800/80 rounded-2xl flex items-center justify-center mb-6 shadow-inner overflow-hidden relative">
                        <div className="absolute inset-0 bg-gradient-to-br from-primary-500/20 to-purple-500/20" />
                        <Lock className="w-8 h-8 text-primary-400 relative z-10" />
                    </div>

                    <h2 className="text-2xl font-bold text-white mb-2">Vault Locked</h2>
                    <p className="text-slate-400 text-sm mb-8">
                        Enter your group's shared Master Vault Key to decrypt your friends' quotes. This key is never sent to the server.
                    </p>

                    <AnimatePresence>
                        {errorMsg && (
                            <motion.div
                                initial={{ opacity: 0, height: 0 }}
                                animate={{ opacity: 1, height: 'auto' }}
                                exit={{ opacity: 0, height: 0 }}
                                className="mb-6 overflow-hidden"
                            >
                                <div className="p-3 bg-red-500/10 border border-red-500/20 text-red-400 rounded-xl text-sm">
                                    {errorMsg}
                                </div>
                            </motion.div>
                        )}
                    </AnimatePresence>

                    <form onSubmit={handleUnlock} className="space-y-4">
                        <div className="relative group">
                            <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                                <KeyRound className="w-5 h-5 text-slate-500 group-focus-within:text-primary-400 transition-colors" />
                            </div>
                            <input
                                type="password"
                                required
                                value={passwordInput}
                                onChange={(e) => setPasswordInput(e.target.value)}
                                placeholder="Master Vault Key"
                                className="w-full bg-slate-900/50 border border-slate-700/50 rounded-xl py-3 pl-12 pr-4 text-white placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-primary-500/50 transition-all text-center tracking-widest"
                            />
                        </div>

                        <button
                            type="submit"
                            disabled={isDeriving || !passwordInput}
                            className="w-full bg-primary-600 hover:bg-primary-500 disabled:opacity-50 text-white font-medium py-3 rounded-xl transition-all flex items-center justify-center space-x-2"
                        >
                            {isDeriving ? (
                                <Loader2 className="w-5 h-5 animate-spin" />
                            ) : (
                                <span>Unlock Group Vault</span>
                            )}
                        </button>
                    </form>
                    <p className="text-xs text-slate-500 mt-6 max-w-[250px] mx-auto">
                        If this shared key is ever lost, all encrypted quotes cannot be recovered.
                    </p>
                </motion.div>
            </div>
        );
    }

    return (
        <CryptoContext.Provider value={{ encryptionKey, isLocked: !encryptionKey, lockVault }}>
            {children}
        </CryptoContext.Provider>
    );
};

export const useCrypto = () => useContext(CryptoContext);
