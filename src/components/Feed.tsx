import { useState, useEffect } from 'react';
import { Search, CloudOff, Cloud, RefreshCw } from 'lucide-react';
import { useQuotes } from '../hooks/useQuotes';
import { useCrypto } from '../hooks/useCrypto';
import { decryptData } from '../lib/crypto';
import { motion, AnimatePresence } from 'framer-motion';
import type { Quote } from '../types';

export const Feed = () => {
    const { quotes, refresh } = useQuotes();
    const { encryptionKey } = useCrypto();
    const [search, setSearch] = useState('');
    const [isRefreshing, setIsRefreshing] = useState(false);
    const [decryptedQuotes, setDecryptedQuotes] = useState<Quote[] | null>(null);

    useEffect(() => {
        if (!quotes) return;

        const performDecryption = async () => {
            const mapped = await Promise.all(
                quotes.map(async (q) => {
                    if (q.text.startsWith('$$E2E$$')) {
                        try {
                            if (!encryptionKey) throw new Error("No key");
                            const bundle = JSON.parse(q.text.replace('$$E2E$$', ''));
                            const plaintextJSON = await decryptData(bundle, encryptionKey);
                            const override = JSON.parse(plaintextJSON);
                            return { ...q, ...override };
                        } catch (e) {
                            return { ...q, text: '🔒 Encrypted Payload (Decryption Failed)', author: 'Unknown' };
                        }
                    }
                    return q; // Plaintext fallback
                })
            );
            setDecryptedQuotes(mapped);
        };

        performDecryption();
    }, [quotes, encryptionKey]);

    const displayQuotes = decryptedQuotes || [];

    const filteredQuotes = displayQuotes.filter(q =>
        q.text.toLowerCase().includes(search.toLowerCase()) ||
        q.author.toLowerCase().includes(search.toLowerCase())
    ) || [];

    const handleRefresh = async () => {
        setIsRefreshing(true);
        await refresh();
        setTimeout(() => setIsRefreshing(false), 500);
    };

    return (
        <div className="px-4 py-6 space-y-6">
            {/* Search Header */}
            <div className="flex items-center space-x-3">
                <div className="relative flex-1">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" />
                    <input
                        type="text"
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        placeholder="Search quotes or authors..."
                        className="w-full bg-slate-800/50 border border-slate-700/50 rounded-xl py-3 pl-10 pr-4 focus:outline-none focus:ring-2 focus:ring-primary-500 transition-all text-white placeholder-slate-400"
                    />
                </div>
                <button
                    onClick={handleRefresh}
                    disabled={isRefreshing}
                    className="p-3 bg-slate-800/50 border border-slate-700/50 rounded-xl text-slate-300 hover:text-white transition-colors"
                >
                    <RefreshCw className={`w-5 h-5 ${isRefreshing ? 'animate-spin text-primary-400' : ''}`} />
                </button>
            </div>

            {/* Quote List */}
            <div className="space-y-4 pb-20">
                <AnimatePresence>
                    {filteredQuotes.map((quote) => (
                        <motion.div
                            key={quote.id}
                            initial={{ opacity: 0, y: 10 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, scale: 0.95 }}
                            className="bg-slate-800/40 backdrop-blur-sm border border-slate-700/50 p-5 rounded-2xl relative overflow-hidden group"
                        >
                            <div className="absolute top-4 right-4 text-xs">
                                {quote.sync_status === 'pending' ? (
                                    <span title="Pending Sync"><CloudOff className="w-4 h-4 text-orange-400" /></span>
                                ) : (
                                    <span title="Synced"><Cloud className="w-4 h-4 text-emerald-400/50 opacity-0 group-hover:opacity-100 transition-opacity" /></span>
                                )}
                            </div>
                            <blockquote className="text-lg md:text-xl font-medium text-slate-200 mb-4 leading-relaxed pr-8">
                                "{quote.text}"
                            </blockquote>
                            <div className="flex items-center justify-between text-sm">
                                <div className="font-semibold text-primary-400">
                                    — {quote.author}
                                </div>
                                <div className="text-slate-500">
                                    {new Date(quote.quote_date || quote.created_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' })}
                                </div>
                            </div>
                            {quote.context && (
                                <div className="mt-3 pt-3 border-t border-slate-700/30 text-sm text-slate-400 italic">
                                    Context: {quote.context}
                                </div>
                            )}
                        </motion.div>
                    ))}
                </AnimatePresence>

                {filteredQuotes.length === 0 && displayQuotes.length > 0 && (
                    <div className="text-center py-12 text-slate-500">
                        No quotes found matching "{search}"
                    </div>
                )}

                {(!displayQuotes || displayQuotes.length === 0) && (
                    <div className="text-center py-20 px-6">
                        <div className="w-16 h-16 bg-slate-800 rounded-full flex items-center justify-center mx-auto mb-4 border border-slate-700">
                            <span className="text-2xl">✍️</span>
                        </div>
                        <h3 className="text-xl font-medium text-white mb-2">No Quotes Yet</h3>
                        <p className="text-slate-400">Be the first to capture a memorable quote!</p>
                    </div>
                )}
            </div>
        </div>
    );
};
