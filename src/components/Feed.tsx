import { useState, useEffect } from 'react';
import { Search, CloudOff, Cloud, RefreshCw, Trash2 } from 'lucide-react';
import { useQuotes } from '../hooks/useQuotes';
import { useCrypto } from '../hooks/useCrypto';
import { decryptData } from '../lib/crypto';
import { motion, AnimatePresence } from 'framer-motion';
import type { Quote } from '../types';

export const Feed = () => {
    const { quotes, refresh, deleteQuote } = useQuotes();
    const { encryptionKey } = useCrypto();
    const [search, setSearch] = useState('');
    const [isRefreshing, setIsRefreshing] = useState(false);
    const [decryptedQuotes, setDecryptedQuotes] = useState<Quote[] | null>(null);
    const [quoteToDelete, setQuoteToDelete] = useState<Quote | null>(null);

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

    const confirmDelete = async () => {
        if (!quoteToDelete) return;
        await deleteQuote(quoteToDelete);
        setQuoteToDelete(null);
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
            <div className="space-y-4 pb-20 overflow-x-hidden">
                <AnimatePresence>
                    {filteredQuotes.map((quote) => (
                        <div key={quote.id} className="relative rounded-2xl">
                            {/* Delete Background that shows behind the swiping card */}
                            <div className="absolute inset-0 bg-red-500/80 rounded-2xl flex items-center justify-end px-8 z-0">
                                <Trash2 className="w-6 h-6 text-white" />
                            </div>

                            <motion.div
                                drag="x"
                                dragConstraints={{ left: 0, right: 0 }}
                                dragElastic={{ left: 0.5, right: 0 }} // Only allow pulling left
                                onDragEnd={(_e, info) => {
                                    const swipeThreshold = -100; // Swipe left by 100px to trigger
                                    if (info.offset.x < swipeThreshold) {
                                        setQuoteToDelete(quote);
                                    }
                                }}
                                initial={{ opacity: 0, y: 10 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, scale: 0.95 }}
                                className="bg-slate-800/40 backdrop-blur-sm border border-slate-700/50 p-5 rounded-2xl relative z-10 group bg-surface touch-pan-y"
                            >
                                <div className="absolute top-4 right-4 text-xs">
                                    {quote.sync_status === 'pending' ? (
                                        <span title="Pending Sync"><CloudOff className="w-4 h-4 text-orange-400" /></span>
                                    ) : (
                                        <span title="Synced"><Cloud className="w-4 h-4 text-emerald-400/50 opacity-0 group-hover:opacity-100 transition-opacity" /></span>
                                    )}
                                </div>
                                <blockquote className="text-lg md:text-xl font-medium text-slate-200 mb-4 leading-relaxed pr-8 select-text">
                                    "{quote.text}"
                                </blockquote>
                                <div className="flex items-center justify-between text-sm">
                                    <div className="font-semibold text-primary-400">
                                        — {quote.author}
                                    </div>
                                    <div className="text-slate-500 select-none">
                                        {new Date(quote.quote_date || quote.created_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' })}
                                    </div>
                                </div>
                                {quote.context && (
                                    <div className="mt-3 pt-3 border-t border-slate-700/30 text-sm text-slate-400 italic select-text">
                                        Context: {quote.context}
                                    </div>
                                )}
                            </motion.div>
                        </div>
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

            {/* Delete Confirmation Modal */}
            <AnimatePresence>
                {quoteToDelete && (
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4"
                    >
                        <motion.div
                            initial={{ scale: 0.95, y: 20 }}
                            animate={{ scale: 1, y: 0 }}
                            exit={{ scale: 0.95, y: 20 }}
                            className="bg-slate-800 border border-slate-700 p-6 rounded-2xl shadow-xl max-w-sm w-full"
                        >
                            <h3 className="text-lg font-semibold text-white mb-2 flex items-center gap-2">
                                <Trash2 className="w-5 h-5 text-red-400" />
                                Delete Quote
                            </h3>
                            <p className="text-slate-300 mb-6 text-sm">
                                Are you sure you want to completely delete this quote? This action cannot be undone.
                            </p>
                            <div className="flex gap-3 justify-end">
                                <button
                                    onClick={() => setQuoteToDelete(null)}
                                    className="px-4 py-2 text-sm font-medium text-slate-300 hover:text-white transition-colors"
                                >
                                    Cancel
                                </button>
                                <button
                                    onClick={confirmDelete}
                                    className="px-4 py-2 bg-red-500/10 hover:bg-red-500/20 text-red-500 text-sm font-medium rounded-lg border border-red-500/20 transition-colors"
                                >
                                    Delete Forever
                                </button>
                            </div>
                        </motion.div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
};
