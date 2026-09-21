import { useEffect, useRef, useState } from 'react';
import { Search, CloudOff, Cloud, RefreshCw, Trash2, X } from 'lucide-react';
import { useQuotes } from '../hooks/useQuotes';
import { useAuth } from '../hooks/useAuth';
import { useCrypto } from '../hooks/useCrypto';
import { isAdminUser } from '../lib/access';
import { motion, AnimatePresence } from 'framer-motion';
import type { Quote } from '../types';
import { decryptQuoteForDisplay, getErrorMessage, useModalDialog } from './ui';

export const Feed = () => {
    const { quotes, loading, isSyncing, initialFetchPending, pendingCount, lastSyncedAt, refresh, deleteQuote, syncError, syncErrors, retrySyncOperation } = useQuotes();
    const { user } = useAuth();
    const { encryptionKey } = useCrypto();
    const [search, setSearch] = useState('');
    const [decryptedQuotes, setDecryptedQuotes] = useState<Quote[] | null>(null);
    const [quoteToDelete, setQuoteToDelete] = useState<Quote | null>(null);
    const [deleteError, setDeleteError] = useState('');
    const [isDeleting, setIsDeleting] = useState(false);
    const [syncRetryError, setSyncRetryError] = useState('');
    const deleteDialogRef = useRef<HTMLDialogElement>(null);
    const cancelDeleteRef = useRef<HTMLButtonElement>(null);
    const decryptionRequest = useRef(0);
    const isAdmin = isAdminUser(user);

    useModalDialog(deleteDialogRef, Boolean(quoteToDelete), () => setQuoteToDelete(null), cancelDeleteRef);

    useEffect(() => {
        const requestId = ++decryptionRequest.current;
        let active = true;
        if (!quotes) {
            return () => { active = false; };
        }

        Promise.all(quotes.map((quote) => decryptQuoteForDisplay(quote, encryptionKey)))
            .then((mapped) => {
                if (active && requestId === decryptionRequest.current) setDecryptedQuotes(mapped);
            });
        return () => { active = false; };
    }, [quotes, encryptionKey]);

    const displayQuotes = decryptedQuotes || [];
    const waitingForInitialSync = initialFetchPending && quotes?.length === 0 && typeof navigator !== 'undefined' && navigator.onLine;
    const isLoadingFeed = loading || waitingForInitialSync || (quotes !== undefined && decryptedQuotes === null);
    const searchTerm = search.toLowerCase();
    const filteredQuotes = displayQuotes.filter((quote) =>
        quote.text.toLowerCase().includes(searchTerm) || quote.author.toLowerCase().includes(searchTerm)
    );

    const confirmDelete = async () => {
        if (!quoteToDelete || isDeleting) return;
        setIsDeleting(true);
        setDeleteError('');
        try {
            await deleteQuote(quoteToDelete);
            setQuoteToDelete(null);
        } catch (error: unknown) {
            setDeleteError(getErrorMessage(error, 'Unable to delete quote. Please try again.'));
        } finally {
            setIsDeleting(false);
        }
    };

    const handleRetrySync = async (operationId: string) => {
        setSyncRetryError('');
        try {
            await retrySyncOperation(operationId);
        } catch (error: unknown) {
            setSyncRetryError(getErrorMessage(error, 'Unable to retry synchronization. Please try again.'));
        }
    };

    return (
        <div className="px-4 py-6 space-y-6">
            <div className="flex items-center space-x-3">
                <div className="relative flex-1">
                    <Search aria-hidden="true" className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" />
                    <label htmlFor="quote-search" className="sr-only">Search quotes or authors</label>
                    <input id="quote-search" type="text" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search quotes or authors..." className="w-full bg-slate-800/50 border border-slate-700/50 rounded-xl py-3 pl-10 pr-4 focus:outline-none focus:ring-2 focus:ring-primary-500 transition-all text-white placeholder-slate-400" />
                </div>
                <button onClick={() => void refresh()} disabled={isSyncing} aria-busy={isSyncing} aria-label="Sync now" className="p-3 inline-flex items-center gap-2 bg-slate-800/50 border border-slate-700/50 rounded-xl text-slate-300 hover:text-white disabled:opacity-50 transition-colors">
                    <RefreshCw aria-hidden="true" className={`w-5 h-5 ${isSyncing ? 'animate-spin text-primary-400' : ''}`} />
                    <span className="text-sm">{isSyncing ? 'Syncing…' : 'Sync now'}</span>
                </button>
            </div>

            {syncRetryError && <p role="alert" className="rounded-xl border border-red-500/20 bg-red-500/10 p-3 text-sm text-red-300">{syncRetryError}</p>}
            {(initialFetchPending || pendingCount > 0 || lastSyncedAt) && <p role="status" aria-live="polite" className="text-xs text-slate-500">
                {pendingCount > 0 ? `${pendingCount} change${pendingCount === 1 ? '' : 's'} waiting to sync.` : initialFetchPending ? 'Syncing quotes…' : `Last synced ${new Date(lastSyncedAt as string).toLocaleTimeString()}.`}
            </p>}
            {syncError && <p role="alert" className="rounded-xl border border-orange-500/20 bg-orange-500/10 p-3 text-sm text-orange-200">{syncError}</p>}
            {syncErrors && syncErrors.length > 0 && <div className="space-y-2" role="status">
                {syncErrors.map((error) => <div key={error.operation_id} className="flex items-center justify-between gap-3 rounded-xl border border-red-500/20 bg-red-500/10 p-3 text-sm text-red-300">
                    <span>{error.status === 'blocked' ? (error.error || 'This older quote must be re-added after unlocking the current vault.') : (error.error || 'This quote could not be synchronized.')}</span>
                    {error.status !== 'blocked' && <button type="button" onClick={() => void handleRetrySync(error.operation_id)} className="shrink-0 font-medium text-red-200 underline">Retry</button>}
                </div>)}
            </div>}

            <div className="space-y-4 pb-20 overflow-x-hidden">
                <AnimatePresence>
                    {filteredQuotes.map((quote) => {
                        const canDelete = quote.user_id === user?.id || isAdmin;
                        return <div key={quote.id} className="relative rounded-2xl">
                            {canDelete && <div className="absolute inset-0 bg-red-500/80 rounded-2xl flex items-center justify-end px-8 z-0"><Trash2 aria-hidden="true" className="w-6 h-6 text-white" /></div>}
                            <motion.div
                                drag={canDelete ? 'x' : false}
                                dragConstraints={{ left: 0, right: 0 }}
                                dragElastic={{ left: 0.5, right: 0 }}
                                onDragEnd={(_e, info) => {
                                    if (canDelete && info.offset.x < -100) {
                                        setDeleteError('');
                                        setQuoteToDelete(quote);
                                    }
                                }}
                                initial={{ opacity: 0, y: 10 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, scale: 0.95 }}
                                className="bg-slate-800/40 backdrop-blur-sm border border-slate-700/50 p-5 rounded-2xl relative z-10 group bg-surface touch-pan-y"
                            >
                                <div className="absolute top-4 right-4 text-xs">
                                    {quote.sync_status === 'pending' || quote.sync_status === 'rejected' ? <span title={quote.sync_status === 'rejected' ? 'Sync rejected' : 'Pending Sync'}><CloudOff aria-hidden="true" className={`w-4 h-4 ${quote.sync_status === 'rejected' ? 'text-red-400' : 'text-orange-400'}`} /></span> : <span title="Synced"><Cloud aria-hidden="true" className="w-4 h-4 text-emerald-400/50 opacity-0 group-hover:opacity-100 transition-opacity" /></span>}
                                </div>
                                <blockquote className="text-lg md:text-xl font-medium text-slate-200 mb-4 leading-relaxed pr-8 select-text whitespace-pre-wrap">"{quote.text}"</blockquote>
                                <div className="flex items-center justify-between text-sm">
                                    <div className="font-semibold text-primary-400">— {quote.author}</div>
                                    <div className="text-slate-500 select-none">{new Date(quote.quote_date || quote.created_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' })}</div>
                                </div>
                                {quote.context && <div className="mt-3 pt-3 border-t border-slate-700/30 text-sm text-slate-400 italic select-text">Context: {quote.context}</div>}
                                {canDelete && <button type="button" onClick={() => { setDeleteError(''); setQuoteToDelete(quote); }} aria-label={`Delete quote by ${quote.author}`} className="mt-4 inline-flex items-center gap-2 rounded-lg border border-red-500/20 px-3 py-2 text-sm font-medium text-red-400 hover:bg-red-500/10">
                                    <Trash2 aria-hidden="true" className="h-4 w-4" /> Delete
                                </button>}
                            </motion.div>
                        </div>;
                    })}
                </AnimatePresence>

                {filteredQuotes.length === 0 && displayQuotes.length > 0 && <div className="text-center py-12 text-slate-500">No quotes found matching "{search}"</div>}
                {isLoadingFeed && displayQuotes.length === 0 && <div role="status" aria-live="polite" className="text-center py-20 px-6 text-slate-400"><RefreshCw aria-hidden="true" className="w-8 h-8 animate-spin text-primary-400 mx-auto mb-4" /><p>Loading quotes…</p></div>}
                {!isLoadingFeed && displayQuotes.length === 0 && <div className="text-center py-20 px-6"><div className="w-16 h-16 bg-slate-800 rounded-full flex items-center justify-center mx-auto mb-4 border border-slate-700"><span className="text-2xl">✍️</span></div><h3 className="text-xl font-medium text-white mb-2">No Quotes Yet</h3><p className="text-slate-400">Be the first to capture a memorable quote!</p></div>}
            </div>

            <dialog ref={deleteDialogRef} role="dialog" aria-labelledby="delete-quote-title" className="z-50 bg-slate-800 border border-slate-700 p-6 rounded-2xl shadow-xl max-w-sm w-[calc(100%-2rem)] text-white [&::backdrop]:bg-black/60 [&::backdrop]:backdrop-blur-sm">
                <div className="flex items-center justify-between gap-3">
                    <h3 id="delete-quote-title" className="text-lg font-semibold flex items-center gap-2"><Trash2 aria-hidden="true" className="w-5 h-5 text-red-400" />Delete Quote</h3>
                    <button type="button" onClick={() => setQuoteToDelete(null)} aria-label="Close delete quote dialog" className="rounded-full p-1 text-slate-400 hover:text-white"><X aria-hidden="true" className="h-5 w-5" /></button>
                </div>
                <p className="text-slate-300 mt-2 mb-6 text-sm">Are you sure you want to completely delete this quote? This action cannot be undone.</p>
                {deleteError && <p role="alert" className="mb-4 rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-sm text-red-300">{deleteError}</p>}
                <div className="flex gap-3 justify-end">
                    <button ref={cancelDeleteRef} type="button" onClick={() => setQuoteToDelete(null)} className="px-4 py-2 text-sm font-medium text-slate-300 hover:text-white transition-colors">Cancel</button>
                    <button type="button" onClick={confirmDelete} disabled={isDeleting} aria-busy={isDeleting} className="px-4 py-2 bg-red-500/10 hover:bg-red-500/20 disabled:opacity-50 text-red-500 text-sm font-medium rounded-lg border border-red-500/20 transition-colors">{isDeleting ? 'Deleting…' : 'Delete Forever'}</button>
                </div>
            </dialog>
        </div>
    );
};
