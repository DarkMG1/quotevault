import React, { useState } from 'react';
import { supabase } from '../lib/supabase';
import { Loader2, Mail, Lock, Quote } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

export const AuthUI = () => {
    const [loading, setLoading] = useState(false);
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [firstName, setFirstName] = useState('');
    const [lastName, setLastName] = useState('');
    const [isSignUp, setIsSignUp] = useState(false);
    const [errorMsg, setErrorMsg] = useState('');

    const handleAuth = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setErrorMsg('');

        try {
            if (isSignUp) {
                // 1. Check if the email exists in the allowlist
                const { data: allowlistEntry, error: allowlistError } = await supabase
                    .from('allowlist')
                    .select('email')
                    .eq('email', email.trim().toLowerCase())
                    .single();

                if (allowlistError || !allowlistEntry) {
                    throw new Error('Access Denied: Your email is not on the approved early-access list.');
                }

                // 2. If valid, proceed with sign up
                const { error } = await supabase.auth.signUp({
                    email: email.trim(),
                    password,
                    options: {
                        data: {
                            first_name: firstName.trim(),
                            last_name: lastName.trim()
                        }
                    }
                });

                if (error) throw error;

                // 3. Inform user to verify email
                setLoading(false);
                setIsSignUp(false);
                setErrorMsg('Success! Please check your email inbox to verify your account before logging in.');
                return; // Early return to prevent clearing success message
            } else {
                const { error } = await supabase.auth.signInWithPassword({
                    email: email.trim(),
                    password
                });
                if (error) throw error;
            }
        } catch (err: any) {
            setErrorMsg(err.message || 'An error occurred during authentication');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-[100dvh] w-full flex items-center justify-center relative overflow-hidden bg-background p-4 sm:p-8">
            {/* Ambient Background Glows */}
            <div className="absolute top-[-20%] left-[-10%] w-[50%] h-[50%] rounded-[100%] bg-primary-600/20 blur-[120px] pointer-events-none" />
            <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[60%] rounded-[100%] bg-purple-600/10 blur-[120px] pointer-events-none" />

            <motion.div
                initial={{ opacity: 0, scale: 0.95, y: 10 }}
                animate={{ opacity: 1, scale: 1, y: 0 }}
                transition={{ duration: 0.4, ease: "easeOut" }}
                className="w-full max-w-[420px] bg-surface/80 backdrop-blur-xl p-8 sm:p-10 rounded-3xl shadow-2xl shadow-primary-900/20 border border-white/[0.08] relative z-10"
            >
                <div className="flex flex-col items-center mb-10 text-center">
                    <div className="w-16 h-16 bg-gradient-to-br from-primary-500 to-purple-500 rounded-2xl flex items-center justify-center mb-6 shadow-lg shadow-primary-500/30">
                        <Quote className="w-8 h-8 text-white" />
                    </div>
                    <h1 className="text-3xl font-bold tracking-tight text-white mb-2">
                        {isSignUp ? 'Create an Account' : 'Welcome to QuoteVault'}
                    </h1>
                    <p className="text-slate-400 text-sm">
                        {isSignUp ? 'Sign up to start capturing your favorite moments.' : 'Enter your credentials to access your quotes.'}
                    </p>
                </div>

                <AnimatePresence mode="wait">
                    {errorMsg && (
                        <motion.div
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: 'auto' }}
                            exit={{ opacity: 0, height: 0 }}
                            className="mb-6 overflow-hidden"
                        >
                            <div className={`p-4 border rounded-xl text-sm text-center ${errorMsg.startsWith('Success') ? 'bg-green-500/10 border-green-500/20 text-green-400' : 'bg-red-500/10 border-red-500/20 text-red-400'}`}>
                                {errorMsg}
                            </div>
                        </motion.div>
                    )}
                </AnimatePresence>

                <form onSubmit={handleAuth} className="space-y-5">
                    <div className="space-y-4">
                        <AnimatePresence>
                            {isSignUp && (
                                <motion.div
                                    initial={{ opacity: 0, height: 0 }}
                                    animate={{ opacity: 1, height: 'auto' }}
                                    exit={{ opacity: 0, height: 0 }}
                                    className="grid grid-cols-2 gap-4 overflow-hidden"
                                >
                                    <input
                                        type="text"
                                        required
                                        value={firstName}
                                        onChange={(e) => setFirstName(e.target.value)}
                                        placeholder="First Name"
                                        className="w-full bg-slate-900/50 border border-slate-700/50 rounded-xl py-3.5 px-4 text-white placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-primary-500/50 transition-all font-medium"
                                    />
                                    <input
                                        type="text"
                                        required
                                        value={lastName}
                                        onChange={(e) => setLastName(e.target.value)}
                                        placeholder="Last Name"
                                        className="w-full bg-slate-900/50 border border-slate-700/50 rounded-xl py-3.5 px-4 text-white placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-primary-500/50 transition-all font-medium"
                                    />
                                </motion.div>
                            )}
                        </AnimatePresence>

                        <div className="relative group">
                            <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                                <Mail className="w-5 h-5 text-slate-400 group-focus-within:text-primary-400 transition-colors" />
                            </div>
                            <input
                                type="email"
                                required
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                                placeholder="Email address"
                                className="w-full bg-slate-900/50 border border-slate-700/50 rounded-xl py-3.5 pl-12 pr-4 text-white placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-primary-500/50 focus:border-primary-500/50 transition-all font-medium"
                            />
                        </div>

                        <div className="relative group">
                            <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                                <Lock className="w-5 h-5 text-slate-400 group-focus-within:text-primary-400 transition-colors" />
                            </div>
                            <input
                                type="password"
                                required
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                placeholder="Password"
                                className="w-full bg-slate-900/50 border border-slate-700/50 rounded-xl py-3.5 pl-12 pr-4 text-white placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-primary-500/50 focus:border-primary-500/50 transition-all font-medium"
                            />
                        </div>
                    </div>

                    <button
                        type="submit"
                        disabled={loading}
                        className="w-full bg-gradient-to-r from-primary-600 to-primary-500 hover:from-primary-500 hover:to-primary-400 text-white font-semibold py-3.5 rounded-xl shadow-lg shadow-primary-500/25 transition-all flex items-center justify-center space-x-2 disabled:opacity-50 disabled:cursor-not-allowed hover:-translate-y-0.5"
                    >
                        {loading ? (
                            <Loader2 className="w-5 h-5 animate-spin" />
                        ) : (
                            <span>{isSignUp ? 'Sign Up' : 'Sign In'}</span>
                        )}
                    </button>
                </form>

                <div className="mt-8 text-center">
                    <button
                        onClick={() => {
                            setIsSignUp(!isSignUp);
                            setErrorMsg('');
                        }}
                        className="text-slate-400 hover:text-white text-sm font-medium transition-colors"
                    >
                        {isSignUp ? (
                            <>Already have an account? <span className="text-primary-400">Sign in</span></>
                        ) : (
                            <>Don't have an account? <span className="text-primary-400">Sign up</span></>
                        )}
                    </button>
                </div>
            </motion.div>
        </div>
    );
};

