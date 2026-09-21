import React, { useState } from 'react';
import { setLocalSignedOut, supabase } from '../lib/supabase';
import { Loader2, Mail, Lock, Quote } from 'lucide-react';
import { getErrorMessage } from './ui';
import { useAuth } from '../hooks/useAuth';

export const AuthUI = () => {
    const { retry, signingOut, isPasswordRecovery, recoveryError, completePasswordRecovery, cancelPasswordRecovery } = useAuth();
    const [loading, setLoading] = useState(false);
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [firstName, setFirstName] = useState('');
    const [lastName, setLastName] = useState('');
    const [isSignUp, setIsSignUp] = useState(false);
    const [isForgotPassword, setIsForgotPassword] = useState(false);
    const [confirmPassword, setConfirmPassword] = useState('');
    const [errorMsg, setErrorMsg] = useState('');

    const handleAuth = async (e: React.FormEvent) => {
        e.preventDefault();
        if (loading || signingOut) return;
        setLoading(true);
        setErrorMsg('');

        try {
            if (isSignUp) {
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
                setLocalSignedOut(false);
                retry();
            }
        } catch (error: unknown) {
            setErrorMsg(getErrorMessage(error, 'An error occurred during authentication'));
        } finally {
            setLoading(false);
        }
    };

    const handlePasswordResetRequest = async (e: React.FormEvent) => {
        e.preventDefault();
        if (loading || signingOut) return;
        setLoading(true);
        setErrorMsg('');
        try {
            const { error } = await supabase.auth.resetPasswordForEmail(email.trim(), { redirectTo: `${window.location.origin}/?recovery=1` });
            if (error) throw error;
            setErrorMsg('If an account matches that email, a reset link has been sent.');
        } catch {
            setErrorMsg('We could not process that request. Please try again shortly.');
        } finally {
            setLoading(false);
        }
    };

    const handlePasswordRecovery = async (e: React.FormEvent) => {
        e.preventDefault();
        if (loading || signingOut) return;
        if (password.length < 12) {
            setErrorMsg('Use a password with at least 12 characters.');
            return;
        }
        if (password !== confirmPassword) {
            setErrorMsg('Passwords do not match.');
            return;
        }
        setLoading(true);
        setErrorMsg('');
        try {
            await completePasswordRecovery(password);
            setErrorMsg('Password updated. You can now access your vault.');
        } catch {
            setErrorMsg('This password reset link is invalid or expired. Request a new one.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-[100dvh] w-full flex items-center justify-center relative overflow-hidden bg-background p-4 sm:p-8">
            {/* Ambient Background Glows */}
            <div className="absolute top-[-20%] left-[-10%] w-[50%] h-[50%] rounded-[100%] bg-primary-600/20 blur-[120px] pointer-events-none" />
            <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[60%] rounded-[100%] bg-purple-600/10 blur-[120px] pointer-events-none" />

            <div className="w-full max-w-[420px] bg-surface/80 backdrop-blur-xl p-8 sm:p-10 rounded-3xl shadow-2xl shadow-primary-900/20 border border-white/[0.08] relative z-10">
                <div className="flex flex-col items-center mb-10 text-center">
                    <div className="w-16 h-16 bg-gradient-to-br from-primary-500 to-purple-500 rounded-2xl flex items-center justify-center mb-6 shadow-lg shadow-primary-500/30">
                        <Quote className="w-8 h-8 text-white" />
                    </div>
                    <h1 className="text-3xl font-bold tracking-tight text-white mb-2">
                        {isPasswordRecovery ? 'Reset account password' : isForgotPassword ? 'Reset your password' : isSignUp ? 'Create an Account' : 'Welcome to QuoteVault'}
                    </h1>
                    <p className="text-slate-400 text-sm">
                        {isPasswordRecovery ? 'Choose a new account password. This does not change your vault passphrase.' : isForgotPassword ? 'Enter your email and we will send a reset link if an account matches it.' : isSignUp ? 'Sign up to start capturing your favorite moments.' : 'Enter your credentials to access your quotes.'}
                    </p>
                </div>

                {(errorMsg || recoveryError) && <div className="mb-6" role={errorMsg.startsWith('Success') || errorMsg.startsWith('If an account') || errorMsg.startsWith('Password updated') ? 'status' : 'alert'} aria-live="polite">
                    <div className={`p-4 border rounded-xl text-sm text-center ${errorMsg.startsWith('Success') || errorMsg.startsWith('If an account') || errorMsg.startsWith('Password updated') ? 'bg-green-500/10 border-green-500/20 text-green-400' : 'bg-red-500/10 border-red-500/20 text-red-400'}`}>
                        {errorMsg || recoveryError}
                    </div>
                </div>}

                {isPasswordRecovery ? <form onSubmit={handlePasswordRecovery} className="space-y-5">
                    <div className="space-y-4">
                        <label htmlFor="recovery-password" className="sr-only">New account password</label>
                        <input id="recovery-password" type="password" required minLength={12} value={password} onChange={(e) => setPassword(e.target.value)} placeholder="New account password" className="w-full bg-slate-900/50 border border-slate-700/50 rounded-xl py-3.5 px-4 text-white placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-primary-500/50 transition-all font-medium" />
                        <label htmlFor="recovery-password-confirm" className="sr-only">Confirm new account password</label>
                        <input id="recovery-password-confirm" type="password" required minLength={12} value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} placeholder="Confirm new account password" className="w-full bg-slate-900/50 border border-slate-700/50 rounded-xl py-3.5 px-4 text-white placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-primary-500/50 transition-all font-medium" />
                    </div>
                    <button type="submit" disabled={loading} aria-busy={loading} className="w-full bg-gradient-to-r from-primary-600 to-primary-500 hover:from-primary-500 hover:to-primary-400 text-white font-semibold py-3.5 rounded-xl shadow-lg shadow-primary-500/25 transition-all disabled:opacity-50">
                        {loading ? 'Updating password…' : 'Update account password'}
                    </button>
                </form> : (isForgotPassword || recoveryError) ? <form onSubmit={handlePasswordResetRequest} className="space-y-5">
                    <div className="relative group">
                        <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none"><Mail className="w-5 h-5 text-slate-400 group-focus-within:text-primary-400 transition-colors" /></div>
                        <label htmlFor="reset-email" className="sr-only">Email address</label>
                        <input id="reset-email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email address" className="w-full bg-slate-900/50 border border-slate-700/50 rounded-xl py-3.5 pl-12 pr-4 text-white placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-primary-500/50 transition-all font-medium" />
                    </div>
                    <button type="submit" disabled={loading || signingOut} aria-busy={loading} className="w-full bg-gradient-to-r from-primary-600 to-primary-500 hover:from-primary-500 hover:to-primary-400 text-white font-semibold py-3.5 rounded-xl shadow-lg shadow-primary-500/25 transition-all disabled:opacity-50">
                        {loading ? 'Sending reset link…' : 'Send reset link'}
                    </button>
                </form> : <form onSubmit={handleAuth} className="space-y-5">
                    <div className="space-y-4">
                        {isSignUp && (
                                <div className="grid grid-cols-2 gap-4">
                                    <label htmlFor="first-name" className="sr-only">First name</label>
                                    <input
                                        id="first-name"
                                        type="text"
                                        required
                                        value={firstName}
                                        onChange={(e) => setFirstName(e.target.value)}
                                        placeholder="First Name"
                                        className="w-full bg-slate-900/50 border border-slate-700/50 rounded-xl py-3.5 px-4 text-white placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-primary-500/50 transition-all font-medium"
                                    />
                                    <label htmlFor="last-name" className="sr-only">Last name</label>
                                    <input
                                        id="last-name"
                                        type="text"
                                        required
                                        value={lastName}
                                        onChange={(e) => setLastName(e.target.value)}
                                        placeholder="Last Name"
                                        className="w-full bg-slate-900/50 border border-slate-700/50 rounded-xl py-3.5 px-4 text-white placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-primary-500/50 transition-all font-medium"
                                    />
                                </div>
                            )}

                        <div className="relative group">
                            <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                                <Mail className="w-5 h-5 text-slate-400 group-focus-within:text-primary-400 transition-colors" />
                            </div>
                            <label htmlFor="auth-email" className="sr-only">Email address</label>
                            <input
                                id="auth-email"
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
                            <label htmlFor="auth-password" className="sr-only">Password</label>
                            <input
                                id="auth-password"
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
                        disabled={loading || signingOut}
                        aria-busy={loading}
                        className="w-full bg-gradient-to-r from-primary-600 to-primary-500 hover:from-primary-500 hover:to-primary-400 text-white font-semibold py-3.5 rounded-xl shadow-lg shadow-primary-500/25 transition-all flex items-center justify-center space-x-2 disabled:opacity-50 disabled:cursor-not-allowed hover:-translate-y-0.5"
                    >
                        {loading ? (
                            <><Loader2 aria-hidden="true" className="w-5 h-5 animate-spin" /><span>{isSignUp ? 'Signing up…' : 'Signing in…'}</span></>
                        ) : (
                            <span>{isSignUp ? 'Sign Up' : 'Sign In'}</span>
                        )}
                    </button>
                </form>}

                {isPasswordRecovery && <button type="button" disabled={loading} onClick={cancelPasswordRecovery} className="mt-6 block mx-auto text-sm text-slate-400 hover:text-white">Cancel password reset</button>}
                {!isPasswordRecovery && <div className="mt-8 text-center space-y-3">
                    {!isSignUp && <button type="button" onClick={() => { if (isForgotPassword || recoveryError) { cancelPasswordRecovery(); setIsForgotPassword(false); } else setIsForgotPassword(true); setErrorMsg(''); }} className="block mx-auto text-slate-400 hover:text-white text-sm font-medium transition-colors">
                        {isForgotPassword || recoveryError ? 'Back to sign in' : 'Forgot password?'}
                    </button>}
                    {!isForgotPassword && !recoveryError && <div>
                    <button
                        type="button"
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
                    </div>}
                </div>}
            </div>
        </div>
    );
};
