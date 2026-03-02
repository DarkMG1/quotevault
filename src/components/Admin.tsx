import React, { useEffect, useState } from 'react';
import { supabase } from '../lib/supabase';
import { useAuth } from '../hooks/useAuth';
import { hashVaultKey } from '../lib/crypto';
import { ShieldAlert, Users, Plus, Trash2, Loader2, RefreshCw, AlertTriangle } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

export const AdminDashboard = () => {
    const { user } = useAuth();
    const [allowlist, setAllowlist] = useState<{ id: string, email: string }[]>([]);
    const [newEmail, setNewEmail] = useState('');
    const [loading, setLoading] = useState(true);
    const [isAdding, setIsAdding] = useState(false);
    const [errorMsg, setErrorMsg] = useState('');

    // Danger Zone State
    const [vaultKey, setVaultKey] = useState('');
    const [vaultConfirm, setVaultConfirm] = useState('');
    const [isWiping, setIsWiping] = useState(false);
    const [wipeErrorMsg, setWipeErrorMsg] = useState('');
    const [wipeSuccessMsg, setWipeSuccessMsg] = useState('');

    const fetchAllowlist = async () => {
        setLoading(true);
        const { data, error } = await supabase.from('allowlist').select('*').order('email');
        if (error) {
            console.error(error);
            setErrorMsg('Failed to fetch allowlist. Make sure the table exists.');
        } else {
            setAllowlist(data || []);
            setErrorMsg('');
        }
        setLoading(false);
    };

    useEffect(() => {
        fetchAllowlist();
    }, []);

    const handleAddEmail = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!newEmail.trim()) return;
        setIsAdding(true);
        setErrorMsg('');

        try {
            const { error } = await supabase.from('allowlist').insert([{ email: newEmail.trim().toLowerCase() }]);
            if (error) throw error;
            setNewEmail('');
            await fetchAllowlist();
        } catch (err: any) {
            setErrorMsg(err.message || 'Failed to add email');
        } finally {
            setIsAdding(false);
        }
    };

    const handleRemoveEmail = async (id: string) => {
        try {
            const { error } = await supabase.from('allowlist').delete().eq('id', id);
            if (error) throw error;
            setAllowlist(prev => prev.filter(item => item.id !== id));
        } catch (err: any) {
            setErrorMsg(err.message || 'Failed to remove email');
        }
    };

    const handleWipeAndChangeKey = async (e: React.FormEvent) => {
        e.preventDefault();
        if (vaultConfirm !== 'ERASE EVERYTHING') {
            setWipeErrorMsg('You must type exactly "ERASE EVERYTHING" to confirm.');
            return;
        }
        if (!vaultKey || vaultKey.length < 4) {
            setWipeErrorMsg('New Vault Key must be at least 4 characters.');
            return;
        }

        setIsWiping(true);
        setWipeErrorMsg('');
        setWipeSuccessMsg('');

        try {
            const hash = await hashVaultKey(vaultKey);

            // 1. Update the app_settings
            const { error: settingsError } = await supabase
                .from('app_settings')
                .upsert({ key: 'vault_key_hash', value: hash });

            if (settingsError) throw settingsError;

            // 2. Delete all quotes in Supabase 
            // Ensures deleting all since id will never equal this dummy uuid
            const { error: deleteError } = await supabase
                .from('quotes')
                .delete()
                .neq('id', '00000000-0000-0000-0000-000000000000');

            if (deleteError) throw deleteError;

            // 3. Delete local quotes
            const { db } = await import('../lib/db');
            await db.quotes.clear();

            setVaultKey('');
            setVaultConfirm('');
            setWipeSuccessMsg('Vault Key changed. Databases wiped. Reloading...');

            // Force reload to kick user to the unlock screen
            setTimeout(() => window.location.reload(), 2500);
        } catch (err: any) {
            setWipeErrorMsg(err.message || 'Failed to change Vault Key');
        } finally {
            setIsWiping(false);
        }
    };

    // Strict access control check
    if (user?.email !== 'darkmgdevelopment@gmail.com') {
        return (
            <div className="flex flex-col items-center justify-center min-h-[50vh] text-center p-6 space-y-4">
                <ShieldAlert className="w-16 h-16 text-red-500" />
                <h2 className="text-2xl font-bold text-white">Access Denied</h2>
                <p className="text-slate-400">You do not have administrative privileges to view this page.</p>
            </div>
        );
    }

    return (
        <div className="px-4 py-6 space-y-6">
            <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                    <div className="p-3 bg-primary-500/10 rounded-xl">
                        <Users className="w-6 h-6 text-primary-400" />
                    </div>
                    <div>
                        <h2 className="text-2xl font-bold text-white">Access Control</h2>
                        <p className="text-sm text-slate-400">Manage allowed sign-up emails</p>
                    </div>
                </div>
                <button
                    onClick={fetchAllowlist}
                    className="p-3 bg-slate-800/50 border border-slate-700/50 rounded-xl text-slate-300 hover:text-white transition-colors"
                >
                    <RefreshCw className={`w-5 h-5 ${loading ? 'animate-spin' : ''}`} />
                </button>
            </div>

            {errorMsg && (
                <div className="p-4 bg-red-500/10 border border-red-500/20 text-red-400 rounded-xl text-sm">
                    {errorMsg}
                </div>
            )}

            {/* Add Form */}
            <form onSubmit={handleAddEmail} className="bg-surface p-5 rounded-2xl border border-slate-700/50 flex space-x-3">
                <input
                    type="email"
                    required
                    value={newEmail}
                    onChange={(e) => setNewEmail(e.target.value)}
                    placeholder="friend@example.com"
                    className="flex-1 bg-slate-900/50 border border-slate-700/50 rounded-xl py-3 px-4 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-primary-500 transition-all"
                />
                <button
                    type="submit"
                    disabled={isAdding}
                    className="bg-primary-600 hover:bg-primary-500 disabled:opacity-50 px-6 rounded-xl flex items-center justify-center text-white font-medium transition-colors"
                >
                    {isAdding ? <Loader2 className="w-5 h-5 animate-spin" /> : <Plus className="w-5 h-5" />}
                </button>
            </form>

            {/* Allowlist Grid */}
            <div className="bg-surface rounded-2xl border border-slate-700/50 overflow-hidden">
                <div className="p-4 bg-slate-800/50 border-b border-slate-700/50 font-medium text-slate-300">
                    Allowed Emails ({allowlist.length})
                </div>
                {loading ? (
                    <div className="p-10 flex justify-center">
                        <Loader2 className="w-8 h-8 animate-spin text-primary-500" />
                    </div>
                ) : (
                    <ul className="divide-y divide-slate-700/50">
                        <AnimatePresence>
                            {allowlist.map((item) => (
                                <motion.li
                                    key={item.id}
                                    initial={{ opacity: 0, height: 0 }}
                                    animate={{ opacity: 1, height: 'auto' }}
                                    exit={{ opacity: 0, height: 0 }}
                                    className="p-4 flex items-center justify-between hover:bg-slate-800/30 transition-colors"
                                >
                                    <span className="text-slate-200">{item.email}</span>
                                    <button
                                        onClick={() => handleRemoveEmail(item.id)}
                                        className="p-2 text-slate-500 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-colors"
                                    >
                                        <Trash2 className="w-4 h-4" />
                                    </button>
                                </motion.li>
                            ))}
                            {allowlist.length === 0 && (
                                <li className="p-8 text-center text-slate-500">
                                    No emails on the allowlist yet. Everyone will be blocked from signing up.
                                </li>
                            )}
                        </AnimatePresence>
                    </ul>
                )}
            </div>

            {/* Danger Zone */}
            <div className="mt-12 bg-red-950/20 border border-red-900/50 rounded-2xl p-6 space-y-4">
                <div className="flex items-center space-x-3 mb-2">
                    <div className="p-3 bg-red-500/10 rounded-xl">
                        <AlertTriangle className="w-6 h-6 text-red-400" />
                    </div>
                    <div>
                        <h2 className="text-xl font-bold text-red-400">Danger Zone: Vault Key Rotation</h2>
                        <p className="text-sm text-red-300/70">Wipe all existing quotes and change the group's key</p>
                    </div>
                </div>

                {wipeErrorMsg && (
                    <div className="p-4 bg-red-500/20 border border-red-500/30 text-red-300 rounded-xl text-sm">
                        {wipeErrorMsg}
                    </div>
                )}
                {wipeSuccessMsg && (
                    <div className="p-4 bg-green-500/20 border border-green-500/30 text-green-300 rounded-xl text-sm">
                        {wipeSuccessMsg}
                    </div>
                )}

                <form onSubmit={handleWipeAndChangeKey} className="space-y-4 mt-4">
                    <p className="text-sm text-slate-300 leading-relaxed mb-4">
                        <strong className="text-white">WARNING:</strong> Changing the Group Vault Key will
                        <span className="text-red-400 font-bold"> PERMANENTLY ERASE </span>
                        all quotes for all users in the database. This action cannot be undone. Everyone will be forced to use the new key hereafter.
                    </p>

                    <div>
                        <label className="block text-xs text-slate-400 mb-1 uppercase tracking-wider font-semibold">New Group Vault Key</label>
                        <input
                            type="text"
                            required
                            value={vaultKey}
                            onChange={(e) => setVaultKey(e.target.value)}
                            placeholder="Enter the new secure passcode"
                            className="w-full bg-slate-900/50 border border-slate-700/50 rounded-xl py-3 px-4 text-white focus:outline-none focus:ring-2 focus:ring-red-500/50 transition-all font-mono"
                        />
                    </div>

                    <div>
                        <label className="block text-xs text-slate-400 mb-1 uppercase tracking-wider font-semibold">Confirm Action</label>
                        <input
                            type="text"
                            required
                            value={vaultConfirm}
                            onChange={(e) => setVaultConfirm(e.target.value)}
                            placeholder='Type "ERASE EVERYTHING" to confirm'
                            className="w-full bg-slate-900/50 border border-red-900/50 rounded-xl py-3 px-4 text-white placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-red-500/50 transition-all"
                        />
                    </div>

                    <button
                        type="submit"
                        disabled={isWiping || vaultConfirm !== 'ERASE EVERYTHING'}
                        className="w-full bg-red-600 hover:bg-red-500 disabled:opacity-50 disabled:bg-slate-800 disabled:text-slate-500 text-white font-medium py-3 rounded-xl transition-all flex items-center justify-center space-x-2 mt-4"
                    >
                        {isWiping ? (
                            <Loader2 className="w-5 h-5 animate-spin" />
                        ) : (
                            <span>Wipe Database & Change Key</span>
                        )}
                    </button>
                </form>
            </div>
        </div>
    );
};
