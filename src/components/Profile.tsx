import React, { useState, useEffect } from 'react';
import { supabase } from '../lib/supabase';
import { useAuth } from '../hooks/useAuth';
import { UserCircle, Shield, Loader2, Save, KeyRound } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

export const Profile = () => {
    const { user } = useAuth();

    // Personal Info State
    const [firstName, setFirstName] = useState('');
    const [lastName, setLastName] = useState('');
    const [isSavingInfo, setIsSavingInfo] = useState(false);
    const [infoMessage, setInfoMessage] = useState({ text: '', type: '' });

    // Password State
    const [currentPassword, setCurrentPassword] = useState('');
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [isUpdatingPassword, setIsUpdatingPassword] = useState(false);
    const [passwordMessage, setPasswordMessage] = useState({ text: '', type: '' });

    // Initialize state with existing metadata
    useEffect(() => {
        if (user) {
            setFirstName(user.user_metadata?.first_name || '');
            setLastName(user.user_metadata?.last_name || '');
        }
    }, [user]);

    const handleUpdateInfo = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsSavingInfo(true);
        setInfoMessage({ text: '', type: '' });

        try {
            const { error } = await supabase.auth.updateUser({
                data: {
                    first_name: firstName.trim(),
                    last_name: lastName.trim()
                }
            });

            if (error) throw error;
            setInfoMessage({ text: 'Profile information updated successfully!', type: 'success' });
        } catch (err: any) {
            setInfoMessage({ text: err.message || 'Failed to update profile info', type: 'error' });
        } finally {
            setIsSavingInfo(false);
        }
    };

    const handleUpdatePassword = async (e: React.FormEvent) => {
        e.preventDefault();

        if (!currentPassword) {
            setPasswordMessage({ text: 'Please enter your current password.', type: 'error' });
            return;
        }

        if (newPassword !== confirmPassword) {
            setPasswordMessage({ text: 'New passwords do not match.', type: 'error' });
            return;
        }

        if (newPassword.length < 6) {
            setPasswordMessage({ text: 'Password must be at least 6 characters.', type: 'error' });
            return;
        }

        setIsUpdatingPassword(true);
        setPasswordMessage({ text: '', type: '' });

        try {
            // First, re-authenticate to verify the current password is correct
            const { error: signInError } = await supabase.auth.signInWithPassword({
                email: user?.email as string,
                password: currentPassword
            });

            if (signInError) {
                // Return a user-friendly error safely
                if (signInError.message.includes('Invalid login')) {
                    throw new Error('Current password is incorrect.');
                }
                throw signInError;
            }

            // Once confirmed, proceed to update the password securely
            const { error: updateError } = await supabase.auth.updateUser({ password: newPassword });
            if (updateError) throw updateError;

            setPasswordMessage({ text: 'Password successfully updated!', type: 'success' });
            setCurrentPassword('');
            setNewPassword('');
            setConfirmPassword('');
        } catch (err: any) {
            setPasswordMessage({ text: err.message || 'Failed to update password', type: 'error' });
        } finally {
            setIsUpdatingPassword(false);
        }
    };

    return (
        <div className="px-4 py-8 space-y-8 pb-32">

            <div className="flex items-center space-x-4 mb-4">
                <div className="w-14 h-14 bg-gradient-to-br from-primary-500 to-purple-600 rounded-2xl flex items-center justify-center shadow-lg shadow-primary-500/20">
                    <UserCircle className="w-8 h-8 text-white" />
                </div>
                <div>
                    <h2 className="text-2xl font-bold text-white tracking-tight">Your Profile</h2>
                    <p className="text-slate-400 text-sm">Manage your account settings and credentials</p>
                </div>
            </div>

            {/* Personal Information Card */}
            <motion.div
                initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
                className="bg-surface/80 backdrop-blur-xl border border-slate-700/50 rounded-3xl p-6 sm:p-8"
            >
                <div className="flex items-center space-x-2 mb-6">
                    <UserCircle className="w-5 h-5 text-primary-400" />
                    <h3 className="text-lg font-semibold text-white">Personal Information</h3>
                </div>

                <AnimatePresence>
                    {infoMessage.text && (
                        <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}>
                            <div className={`mb-6 p-4 rounded-xl text-sm border ${infoMessage.type === 'success' ? 'bg-green-500/10 border-green-500/20 text-green-400' : 'bg-red-500/10 border-red-500/20 text-red-400'}`}>
                                {infoMessage.text}
                            </div>
                        </motion.div>
                    )}
                </AnimatePresence>

                <form onSubmit={handleUpdateInfo} className="space-y-4">
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div className="space-y-1.5">
                            <label className="text-sm font-medium text-slate-400 pl-1">First Name</label>
                            <input
                                type="text"
                                value={firstName}
                                onChange={(e) => setFirstName(e.target.value)}
                                placeholder="Your first name"
                                className="w-full bg-slate-900/50 border border-slate-700/50 rounded-xl py-3 px-4 text-white focus:outline-none focus:ring-2 focus:ring-primary-500/40 transition-all placeholder:text-slate-600"
                            />
                        </div>
                        <div className="space-y-1.5">
                            <label className="text-sm font-medium text-slate-400 pl-1">Last Name</label>
                            <input
                                type="text"
                                value={lastName}
                                onChange={(e) => setLastName(e.target.value)}
                                placeholder="Your last name"
                                className="w-full bg-slate-900/50 border border-slate-700/50 rounded-xl py-3 px-4 text-white focus:outline-none focus:ring-2 focus:ring-primary-500/40 transition-all placeholder:text-slate-600"
                            />
                        </div>
                    </div>

                    <div className="space-y-1.5 pt-2">
                        <label className="text-sm font-medium text-slate-400 pl-1">Email Address</label>
                        <input
                            type="email"
                            disabled
                            value={user?.email || ''}
                            className="w-full bg-slate-900/30 border border-slate-800 rounded-xl py-3 px-4 text-slate-500 cursor-not-allowed"
                        />
                        <p className="text-xs text-slate-500 pl-1">Your email address cannot be changed.</p>
                    </div>

                    <div className="pt-4 flex justify-end">
                        <button
                            type="submit"
                            disabled={isSavingInfo}
                            className="bg-primary-600 hover:bg-primary-500 disabled:opacity-50 text-white font-medium py-2.5 px-6 rounded-xl transition-all flex items-center space-x-2"
                        >
                            {isSavingInfo ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
                            <span>Save Profile</span>
                        </button>
                    </div>
                </form>
            </motion.div>

            {/* Security Card */}
            <motion.div
                initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}
                className="bg-surface/80 backdrop-blur-xl border border-slate-700/50 rounded-3xl p-6 sm:p-8"
            >
                <div className="flex items-center space-x-2 mb-6">
                    <Shield className="w-5 h-5 text-primary-400" />
                    <h3 className="text-lg font-semibold text-white">Security</h3>
                </div>

                <AnimatePresence>
                    {passwordMessage.text && (
                        <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}>
                            <div className={`mb-6 p-4 rounded-xl text-sm border ${passwordMessage.type === 'success' ? 'bg-green-500/10 border-green-500/20 text-green-400' : 'bg-red-500/10 border-red-500/20 text-red-400'}`}>
                                {passwordMessage.text}
                            </div>
                        </motion.div>
                    )}
                </AnimatePresence>

                <form onSubmit={handleUpdatePassword} className="space-y-4">
                    <p className="text-sm text-slate-400 mb-6 leading-relaxed">
                        Update your personal login password. This is exactly what you use to sign in to your individual account and is completely separate from the Shared Group Vault key.
                    </p>

                    <div className="space-y-1.5">
                        <label className="text-sm font-medium text-slate-400 pl-1">Current Password</label>
                        <div className="relative">
                            <KeyRound className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                            <input
                                type="password"
                                required
                                value={currentPassword}
                                onChange={(e) => setCurrentPassword(e.target.value)}
                                placeholder="Your current login password"
                                className="w-full bg-slate-900/50 border border-slate-700/50 rounded-xl py-3 pl-11 pr-4 text-white focus:outline-none focus:ring-2 focus:ring-primary-500/40 transition-all"
                            />
                        </div>
                    </div>

                    <div className="space-y-1.5 pt-4 border-t border-slate-700/50">
                        <label className="text-sm font-medium text-slate-400 pl-1">New Password</label>
                        <div className="relative">
                            <KeyRound className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                            <input
                                type="password"
                                required
                                value={newPassword}
                                onChange={(e) => setNewPassword(e.target.value)}
                                placeholder="At least 6 characters"
                                className="w-full bg-slate-900/50 border border-slate-700/50 rounded-xl py-3 pl-11 pr-4 text-white focus:outline-none focus:ring-2 focus:ring-primary-500/40 transition-all"
                            />
                        </div>
                    </div>

                    <div className="space-y-1.5">
                        <label className="text-sm font-medium text-slate-400 pl-1">Confirm New Password</label>
                        <div className="relative">
                            <KeyRound className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                            <input
                                type="password"
                                required
                                value={confirmPassword}
                                onChange={(e) => setConfirmPassword(e.target.value)}
                                placeholder="Type your new password again"
                                className="w-full bg-slate-900/50 border border-slate-700/50 rounded-xl py-3 pl-11 pr-4 text-white focus:outline-none focus:ring-2 focus:ring-primary-500/40 transition-all"
                            />
                        </div>
                    </div>

                    <div className="pt-4 flex justify-end">
                        <button
                            type="submit"
                            disabled={isUpdatingPassword || !newPassword || !confirmPassword}
                            className="bg-primary-600 hover:bg-primary-500 disabled:opacity-50 text-white font-medium py-2.5 px-6 rounded-xl transition-all flex items-center space-x-2"
                        >
                            {isUpdatingPassword ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
                            <span>Update Password</span>
                        </button>
                    </div>
                </form>
            </motion.div>
        </div>
    );
};
