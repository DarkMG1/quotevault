import { ImportQuotes } from './ImportQuotes';
import { AddQuote } from './AddQuote';
import { MatchAuthors } from './MatchAuthors';
import { useEffect, useMemo, useRef, useState } from 'react';
import { RefreshCw, Trash2, X } from 'lucide-react';
import { useQuotes } from '../hooks/useQuotes';
import { useAuth } from '../hooks/useAuth';
import { useCrypto } from '../hooks/useCrypto';
import { isAdminUser } from '../lib/access';
import type { Quote } from '../types';
import { getErrorMessage, useModalDialog } from './ui';
import { decryptForFeed, type DecryptCache } from './feed-decrypt';
import { NO_FILTERS, authorParticipants, filterQuotes, type QuoteFilters } from '../lib/quote-search';
import { FilterBar } from './FilterBar';
import { QuoteCard } from './QuoteCard';

export const Feed = () => {
    const { quotes, loading, isSyncing, initialFetchPending, pendingCount, lastSyncedAt, refresh, deleteQuote, syncError, syncErrors, retrySyncOperation } = useQuotes();
    const { user } = useAuth();
    const { encryptionKey } = useCrypto();
    const [importOpen, setImportOpen] = useState(false);
    const [matchingAuthors, setMatchingAuthors] = useState(false);
    const [filters, setFilters] = useState<QuoteFilters>(NO_FILTERS);
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
    // Cards that drop out of the list stay rendered, in place, while they fade out.
    const [rendered, setRendered] = useState(() => ({ source: filteredQuotes, cards: filteredQuotes.map(quote => ({ quote, leaving: false })) }));
    if (rendered.source !== filteredQuotes) {
        const ids = new Set(filteredQuotes.map(quote => quote.id));
        const cards = filteredQuotes.map(quote => ({ quote, leaving: false }));
        rendered.cards.forEach((card, index) => {
            if (!ids.has(card.quote.id)) cards.splice(index, 0, { quote: card.quote, leaving: true });
        });
        setRendered({ source: filteredQuotes, cards });
    }
    const { cards } = rendered;
    const authors = useMemo(() => authorParticipants(displayQuotes), [displayQuotes]);
    const clearFilters = () => setFilters(current => ({ ...NO_FILTERS, order: current.order }));
    const filtering = Boolean(filters.text.trim() || filters.author || filters.from || filters.to);

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
            <FilterBar filters={filters} setFilters={setFilters} onClear={clearFilters} authors={authors}
                shown={filteredQuotes.length} total={displayQuotes.length}>
                <button
                    onClick={() => void refresh()}
                    disabled={isSyncing}
                    aria-busy={isSyncing}
                    aria-label="Sync now"
                    className="inline-flex flex-1 items-center justify-center gap-2 rounded-xl border border-slate-700/50 bg-slate-800/50 p-3 text-slate-300 transition-colors hover:text-white disabled:opacity-50 sm:flex-none"
                >
                    <RefreshCw aria-hidden="true" className={`h-5 w-5 ${isSyncing ? 'animate-spin text-primary-400' : ''}`} />
                    <span className="whitespace-nowrap text-sm">
                        {isSyncing ? 'Syncing…' : <><span className="sm:hidden">Sync</span><span className="hidden sm:inline">Sync now</span></>}
                    </span>
                </button>
            </FilterBar>

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
                {cards.map(({ quote, leaving }) => {
                    return <QuoteCard
                        key={quote.id}
                        quote={quote}
                        canEdit={isAdmin}
                        canDelete={quote.user_id === user?.id || isAdmin}
                        leaving={leaving}
                        onLeft={() => setRendered(current => ({
                            ...current, cards: current.cards.filter(card => !(card.leaving && card.quote.id === quote.id)),
                        }))}
                        onEdit={() => {
                            const stored = quotes?.find(item => item.id === quote.id);
                            if (stored) setQuoteToEdit({ stored, display: quote });
                        }}
                        onDelete={() => {
                            setDeleteError('');
                            setQuoteToDelete(quote);
                        }}
                    />;
                })}

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
