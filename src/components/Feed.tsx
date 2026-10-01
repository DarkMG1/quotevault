import { ImportQuotes } from './ImportQuotes';
import { AddQuote } from './AddQuote';
import { MatchAuthors } from './MatchAuthors';
import { useEffect, useMemo, useRef, useState } from 'react';
import { Search, CloudOff, Cloud, RefreshCw, Trash2, Pencil, X, SlidersHorizontal, ArrowDownWideNarrow, ArrowUpNarrowWide } from 'lucide-react';
import { useQuotes } from '../hooks/useQuotes';
import { useAuth } from '../hooks/useAuth';
import { useCrypto } from '../hooks/useCrypto';
import { isAdminUser } from '../lib/access';
import { motion, AnimatePresence } from 'framer-motion';
import type { Quote } from '../types';
import { getErrorMessage, useModalDialog } from './ui';
import { decryptForFeed, type DecryptCache } from './feed-decrypt';
import { NO_FILTERS, authorParticipants, filterQuotes, type QuoteFilters } from '../lib/quote-search';

const formatDay = (day: string) => new Date(`${day}T00:00:00Z`).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' });

export const Feed = () => {
    const { quotes, loading, isSyncing, initialFetchPending, pendingCount, lastSyncedAt, refresh, deleteQuote, syncError, syncErrors, retrySyncOperation } = useQuotes();
    const { user } = useAuth();
    const { encryptionKey } = useCrypto();
    const [importOpen, setImportOpen] = useState(false);
    const [matchingAuthors, setMatchingAuthors] = useState(false);
    const [filters, setFilters] = useState<QuoteFilters>(NO_FILTERS);
    const [filtersOpen, setFiltersOpen] = useState(false);
    const [decryptedQuotes, setDecryptedQuotes] = useState<Quote[] | null>(null);
    const [quoteToDelete, setQuoteToDelete] = useState<Quote | null>(null);
    const [quoteToEdit, setQuoteToEdit] = useState<{ stored: Quote; display: Quote } | null>(null);
    const [deleteError, setDeleteError] = useState('');
    const [isDeleting, setIsDeleting] = useState(false);
    const [syncRetryError, setSyncRetryError] = useState('');
    const deleteDialogRef = useRef<HTMLDialogElement>(null);
    const cancelDeleteRef = useRef<HTMLButtonElement>(null);
    const decryptionRequest = useRef(0);
    const decryptCache = useRef<DecryptCache | undefined>(undefined);
    const isAdmin = isAdminUser(user);

    useModalDialog(deleteDialogRef, Boolean(quoteToDelete), () => setQuoteToDelete(null), cancelDeleteRef);

    useEffect(() => {
        const requestId = ++decryptionRequest.current;
        let active = true;
        if (!quotes) {
            return () => { active = false; };
        }

        const { cache, decrypted } = decryptForFeed(quotes, encryptionKey, decryptCache.current);
        decryptCache.current = cache;
        decrypted
            .then((mapped) => {
                if (active && requestId === decryptionRequest.current) setDecryptedQuotes(mapped);
            });
        return () => { active = false; };
    }, [quotes, encryptionKey]);

    const displayQuotes = useMemo(() => decryptedQuotes ?? [], [decryptedQuotes]);
    const waitingForInitialSync = initialFetchPending && quotes?.length === 0 && typeof navigator !== 'undefined' && navigator.onLine;
    const isLoadingFeed = loading || waitingForInitialSync || (quotes !== undefined && decryptedQuotes === null);
    const filteredQuotes = useMemo(() => filterQuotes(displayQuotes, filters), [displayQuotes, filters]);
    const authors = useMemo(() => authorParticipants(displayQuotes), [displayQuotes]);
    const updateFilters = (patch: Partial<QuoteFilters>) => setFilters(current => ({ ...current, ...patch }));
    const clearFilters = () => setFilters(current => ({ ...NO_FILTERS, order: current.order }));
    const panelFilterCount = [filters.author, filters.from || filters.to].filter(Boolean).length;
    const filtering = Boolean(filters.text.trim()) || panelFilterCount > 0;
    const reversedRange = Boolean(filters.from && filters.to && filters.from > filters.to);
    const dateChip = filters.from && filters.to ? `${formatDay(filters.from)} – ${formatDay(filters.to)}` : filters.from ? `From ${formatDay(filters.from)}` : filters.to ? `Until ${formatDay(filters.to)}` : '';
    const chips = [
        filters.text.trim() && { key: 'text', label: `“${filters.text.trim()}”`, clear: () => updateFilters({ text: '' }) },
        filters.author && { key: 'author', label: filters.author, clear: () => updateFilters({ author: '' }) },
        dateChip && { key: 'dates', label: dateChip, clear: () => updateFilters({ from: '', to: '' }) },
    ].filter((chip): chip is { key: string; label: string; clear: () => void } => Boolean(chip));

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
            {importOpen && <ImportQuotes onClose={() => setImportOpen(false)} />}
            {matchingAuthors && isAdmin && <MatchAuthors onClose={() => setMatchingAuthors(false)} />}
            {quoteToEdit && isAdmin && <AddQuote edit={quoteToEdit} onClose={() => setQuoteToEdit(null)} />}
            <button className="rounded-xl border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:text-white" onClick={() => setImportOpen(true)}>Import quotes</button>
            {isAdmin && <button className="ml-3 rounded-xl border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:text-white" onClick={() => setMatchingAuthors(true)}>Match imported authors</button>}
            <div className="space-y-3">
                <div className="flex w-full flex-wrap gap-2 sm:flex-nowrap">
                    <div className="relative w-full sm:flex-1">
                        <Search aria-hidden="true" className="pointer-events-none absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-400" />
                        <label htmlFor="quote-search" className="sr-only">Search quotes, authors or context</label>
                        <input id="quote-search" type="search" value={filters.text} onChange={event => updateFilters({ text: event.target.value })} placeholder="Search quotes, authors or context" className="w-full rounded-xl border border-slate-700/50 bg-slate-800/50 py-3 pl-10 pr-10 text-white placeholder-slate-400 transition-all focus:outline-none focus:ring-2 focus:ring-primary-500 [&::-webkit-search-cancel-button]:hidden" />
                        {filters.text && <button type="button" onClick={() => updateFilters({ text: '' })} aria-label="Clear search" className="absolute right-2 top-1/2 -translate-y-1/2 rounded-full p-1.5 text-slate-400 hover:text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary-500"><X aria-hidden="true" className="h-4 w-4" /></button>}
                    </div>
                    <button type="button" onClick={() => setFiltersOpen(open => !open)} aria-expanded={filtersOpen} aria-controls="quote-filters" className={`inline-flex flex-1 items-center justify-center gap-2 rounded-xl border px-3 py-3 text-sm transition-colors sm:flex-none ${panelFilterCount ? 'border-primary-500/50 bg-primary-500/10 text-primary-400' : 'border-slate-700/50 bg-slate-800/50 text-slate-300 hover:text-white'}`}>
                        <SlidersHorizontal aria-hidden="true" className="h-4 w-4" />Filters{panelFilterCount > 0 && <span className="rounded-full bg-primary-500 px-1.5 text-xs font-semibold text-white">{panelFilterCount}</span>}
                    </button>
                    <button type="button" onClick={() => updateFilters({ order: filters.order === 'newest' ? 'oldest' : 'newest' })} aria-label={`Sorted ${filters.order === 'newest' ? 'newest' : 'oldest'} first. Switch to ${filters.order === 'newest' ? 'oldest' : 'newest'} first`} className="inline-flex flex-1 items-center justify-center gap-2 rounded-xl border border-slate-700/50 bg-slate-800/50 px-3 py-3 text-sm text-slate-300 hover:text-white sm:flex-none">
                        {filters.order === 'newest' ? <ArrowDownWideNarrow aria-hidden="true" className="h-4 w-4" /> : <ArrowUpNarrowWide aria-hidden="true" className="h-4 w-4" />}<span className="whitespace-nowrap"><span className="sm:hidden">{filters.order === 'newest' ? 'Newest' : 'Oldest'}</span><span className="hidden sm:inline">{filters.order === 'newest' ? 'Newest first' : 'Oldest first'}</span></span>
                    </button>
                    <button onClick={() => void refresh()} disabled={isSyncing} aria-busy={isSyncing} aria-label="Sync now" className="inline-flex flex-1 items-center justify-center gap-2 rounded-xl border border-slate-700/50 bg-slate-800/50 p-3 text-slate-300 transition-colors hover:text-white disabled:opacity-50 sm:flex-none">
                        <RefreshCw aria-hidden="true" className={`h-5 w-5 ${isSyncing ? 'animate-spin text-primary-400' : ''}`} />
                        <span className="whitespace-nowrap text-sm">{isSyncing ? 'Syncing…' : <><span className="sm:hidden">Sync</span><span className="hidden sm:inline">Sync now</span></>}</span>
                    </button>
                </div>

                {filtersOpen && <div id="quote-filters" className="grid gap-3 rounded-xl border border-slate-700/50 bg-slate-800/30 p-3 sm:grid-cols-[2fr_1fr_1fr]">
                    <div><label htmlFor="filter-author" className="block text-sm text-slate-300">Author</label>
                        <select id="filter-author" value={filters.author} onChange={event => updateFilters({ author: event.target.value })} className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-800 p-2 text-white">
                            <option value="">Any author</option>
                            {filters.author && !authors.includes(filters.author) && <option value={filters.author}>{filters.author}</option>}
                            {authors.map(author => <option key={author} value={author}>{author}</option>)}
                        </select></div>
                    <div><label htmlFor="filter-from" className="block text-sm text-slate-300">From</label><input id="filter-from" type="date" value={filters.from} max={filters.to || undefined} onChange={event => updateFilters({ from: event.target.value })} className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-800 p-2 text-white [color-scheme:dark]" /></div>
                    <div><label htmlFor="filter-to" className="block text-sm text-slate-300">To</label><input id="filter-to" type="date" value={filters.to} min={filters.from || undefined} onChange={event => updateFilters({ to: event.target.value })} className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-800 p-2 text-white [color-scheme:dark]" /></div>
                    {reversedRange && <p role="alert" className="text-sm text-amber-300 sm:col-span-3">The From date is after the To date, so no quotes can match.</p>}
                </div>}

                {chips.length > 0 && <div className="flex flex-wrap items-center gap-2" aria-label="Active filters">
                    {chips.map(chip => <span key={chip.key} className="inline-flex items-center gap-1 rounded-full border border-primary-500/30 bg-primary-500/10 py-1 pl-3 pr-1 text-sm text-slate-100">
                        {chip.label}
                        <button type="button" onClick={chip.clear} aria-label={`Remove filter ${chip.label}`} className="rounded-full p-1 text-primary-400 hover:bg-primary-500/20 hover:text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary-500"><X aria-hidden="true" className="h-3.5 w-3.5" /></button>
                    </span>)}
                    <button type="button" onClick={clearFilters} className="text-sm text-slate-400 underline-offset-2 hover:text-white hover:underline">Clear all</button>
                    <span role="status" aria-live="polite" className="ml-auto text-sm text-slate-500">Showing {filteredQuotes.length} of {displayQuotes.length}</span>
                </div>}
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
                        return <motion.div key={quote.id} exit={{ opacity: 0 }} transition={{ duration: 0.15 }} className="relative rounded-2xl">
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
                                {quote.source_sender && <div className="mt-3 text-sm text-slate-400 select-text">Originally shared by {quote.source_sender}</div>}
                                {isAdmin && <button type="button" disabled={quote.sync_status === 'pending' || quote.sync_status === 'rejected'} onClick={() => {
                                    const stored = quotes?.find(item => item.id === quote.id);
                                    if (stored) setQuoteToEdit({ stored, display: quote });
                                }} aria-label={`Edit quote by ${quote.author}`} className="mt-4 mr-3 inline-flex items-center gap-2 rounded-lg border border-slate-600 px-3 py-2 text-sm font-medium text-slate-300 hover:bg-slate-700/50 disabled:opacity-50">
                                    <Pencil aria-hidden="true" className="h-4 w-4" /> Edit
                                </button>}
                                {canDelete && <button type="button" onClick={() => { setDeleteError(''); setQuoteToDelete(quote); }} aria-label={`Delete quote by ${quote.author}`} className="mt-4 inline-flex items-center gap-2 rounded-lg border border-red-500/20 px-3 py-2 text-sm font-medium text-red-400 hover:bg-red-500/10">
                                    <Trash2 aria-hidden="true" className="h-4 w-4" /> Delete
                                </button>}
                            </motion.div>
                        </motion.div>;
                    })}
                </AnimatePresence>

                {filteredQuotes.length === 0 && displayQuotes.length > 0 && filtering && <div className="py-12 text-center text-slate-400"><p>No quotes match these filters.</p><button type="button" onClick={clearFilters} className="mt-3 text-primary-400 hover:text-white">Clear all filters</button></div>}
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
