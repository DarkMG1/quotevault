import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Save, Quote as QuoteIcon } from 'lucide-react';
import { useQuotes } from '../hooks/useQuotes';
import { useAuth } from '../hooks/useAuth';

interface AddQuoteProps {
    isOpen: boolean;
    onClose: () => void;
}

export const AddQuote = ({ isOpen, onClose }: AddQuoteProps) => {
    const [text, setText] = useState('');
    const [author, setAuthor] = useState('');
    const [context, setContext] = useState('');
    const [isSubmitting, setIsSubmitting] = useState(false);
    const { addQuote } = useQuotes();
    const { user } = useAuth();

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!text.trim() || !author.trim()) return;

        setIsSubmitting(true);
        try {
            await addQuote(text, author, context, user?.id);
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
                        className="fixed inset-x-4 bottom-4 top-20 sm:top-auto sm:inset-auto sm:w-full z-50 max-w-lg mx-auto bg-surface border border-slate-700/50 rounded-3xl shadow-2xl overflow-hidden flex flex-col"
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

                        <form onSubmit={handleSubmit} className="p-6 space-y-5 flex-1 overflow-y-auto">
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
                                <input
                                    type="text"
                                    required
                                    value={author}
                                    onChange={(e) => setAuthor(e.target.value)}
                                    placeholder="Franklin D. Roosevelt"
                                    className="w-full bg-slate-800/50 border border-slate-700 rounded-xl py-3 px-4 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-primary-500 transition-all"
                                />
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
