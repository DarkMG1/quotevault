import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Save, Quote as QuoteIcon } from 'lucide-react';
import { useQuotes } from '../hooks/useQuotes';
import { useAuth } from '../hooks/useAuth';
import { useCrypto } from '../hooks/useCrypto';
import { encryptData } from '../lib/crypto';
import { supabase } from '../lib/supabase';

interface AddQuoteProps {
    isOpen: boolean;
    onClose: () => void;
}

export const AddQuote = ({ isOpen, onClose }: AddQuoteProps) => {
    const [text, setText] = useState('');
    const [author, setAuthor] = useState('');
    const [context, setContext] = useState('');
    const [quoteDate, setQuoteDate] = useState(new Date().toISOString().split('T')[0]);
    const [isSubmitting, setIsSubmitting] = useState(false);
    const { addQuote } = useQuotes();
    const { user } = useAuth();
    const { encryptionKey, isLocked } = useCrypto();
    const [profiles, setProfiles] = React.useState<{ first_name: string }[]>([]);

    React.useEffect(() => {
        const fetchProfiles = async () => {
            const { data, error } = await supabase
                .from('profiles')
                .select('first_name')
                .order('first_name');
            if (data && !error) {
                setProfiles(data);
                // Auto-select first author if none selected yet
                if (data.length > 0 && !author) {
                    setAuthor(data[0].first_name);
                }
            }
        };
        fetchProfiles();
    }, [author]);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!text.trim() || !author.trim()) return;

        setIsSubmitting(true);
        try {
            if (isLocked || !encryptionKey) {
                throw new Error("Cannot save: Vault is locked.");
            }

            // Create JSON payload of sensitive fields
            const payloadToEncrypt = JSON.stringify({
                text: text.trim(),
                author: author.trim(),
                context: context.trim()
            });

            const encryptedBundle = await encryptData(payloadToEncrypt, encryptionKey);

            // We pass the Base64 ciphertext straight into the 'text' field to minimize db schema changes.
            // A special prefix $$E2E$$ helps the UI identify an encrypted string later.
            const serializedCiphertext = `$$E2E$$${JSON.stringify(encryptedBundle)}`;

            // Instead of passing plaintext, we pass the ciphertext bundle into text, and empty author/context
            await addQuote(serializedCiphertext, 'ENCRYPTED', 'ENCRYPTED', quoteDate, user?.id);
            setText('');
            setAuthor('');
            setContext('');
            onClose();
        } catch (err) {
            console.error('Failed to add quote', err);
        } finally {
            setIsSubmitting(false);
        }
    };

    return (
        <AnimatePresence>
            {isOpen && (
                <>
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        onClick={onClose}
                        className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 p-4 flex items-center justify-center sm:p-6"
                    />
                    <motion.div
                        initial={{ opacity: 0, scale: 0.95, y: 20 }}
                        animate={{ opacity: 1, scale: 1, y: 0 }}
                        exit={{ opacity: 0, scale: 0.95, y: 20 }}
                        className="fixed inset-x-4 inset-y-12 sm:inset-0 sm:m-auto z-50 sm:w-[90%] sm:max-w-lg sm:h-fit max-h-[85vh] bg-surface border border-slate-700/50 rounded-3xl shadow-2xl overflow-hidden flex flex-col"
                    >
                        <div className="flex items-center justify-between p-6 border-b border-white/5">
                            <div className="flex items-center space-x-2">
                                <QuoteIcon className="w-5 h-5 text-primary-400" />
                                <h2 className="text-xl font-semibold text-white">Add Quote</h2>
                            </div>
                            <button
                                onClick={onClose}
                                className="p-2 -mr-2 text-slate-400 hover:text-white transition-colors rounded-full hover:bg-white/5"
                            >
                                <X className="w-5 h-5" />
                            </button>
                        </div>

                        <form onSubmit={handleSubmit} className="p-6 space-y-5 overflow-y-auto overscroll-contain flex-1 sm:flex-none">
                            <div>
                                <label className="block text-sm font-medium text-slate-300 mb-1">Quote</label>
                                <textarea
                                    required
                                    value={text}
                                    onChange={(e) => setText(e.target.value)}
                                    placeholder="&quot;The only limit to our realization of tomorrow...&quot;"
                                    rows={4}
                                    className="w-full bg-slate-800/50 border border-slate-700 rounded-xl py-3 px-4 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-primary-500 transition-all resize-none"
                                />
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-slate-300 mb-1">Author</label>
                                <select
                                    required
                                    value={author}
                                    onChange={(e) => setAuthor(e.target.value)}
                                    className="w-full bg-slate-800/50 border border-slate-700 rounded-xl py-3 px-4 text-white focus:outline-none focus:ring-2 focus:ring-primary-500 transition-all appearance-none"
                                >
                                    <option value="" disabled>Select an Author</option>
                                    {profiles.map((p, i) => (
                                        <option key={i} value={p.first_name}>{p.first_name}</option>
                                    ))}
                                </select>
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-slate-300 mb-1">Context <span className="text-slate-500 font-normal">(Optional)</span></label>
                                <input
                                    type="text"
                                    value={context}
                                    onChange={(e) => setContext(e.target.value)}
                                    placeholder="In a letter to a friend, 1945"
                                    className="w-full bg-slate-800/50 border border-slate-700 rounded-xl py-3 px-4 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-primary-500 transition-all"
                                />
                            </div>

                            <div className="max-w-full overflow-hidden">
                                <label className="block text-sm font-medium text-slate-300 mb-1">Date Said <span className="text-slate-500 font-normal">(Optional)</span></label>
                                <input
                                    type="date"
                                    value={quoteDate}
                                    onChange={(e) => setQuoteDate(e.target.value)}
                                    className="w-full max-w-full bg-slate-800/50 border border-slate-700 rounded-xl py-3 px-4 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-primary-500 transition-all [color-scheme:dark]"
                                />
                            </div>

                            <div className="pt-4 mt-auto">
                                <button
                                    type="submit"
                                    disabled={isSubmitting}
                                    className="w-full bg-primary-600 hover:bg-primary-500 disabled:opacity-50 text-white font-medium py-3.5 rounded-xl transition-colors flex items-center justify-center space-x-2"
                                >
                                    <Save className="w-5 h-5" />
                                    <span>{isSubmitting ? 'Saving...' : 'Save Quote'}</span>
                                </button>
                            </div>
                        </form>
                    </motion.div>
                </>
            )}
        </AnimatePresence>
    );
};
