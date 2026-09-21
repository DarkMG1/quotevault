import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { useLiveQuery } from 'dexie-react-hooks';
import { db } from '../lib/db';
import { cancelSyncRequests, createSyncOperation, enqueueDeleteMutation, processSyncQueue, type SyncContext } from '../lib/sync';
import { supabase } from '../lib/supabase';
import { useAuth } from './useAuth';
import { useCrypto } from './useCrypto';
import type { Quote, SyncQueueItem } from '../types';

interface QuotesContextValue {
    quotes: Quote[] | undefined;
    addQuote: (text: string, author: string, context?: string, quoteDate?: string, userId?: string) => Promise<void>;
    deleteQuote: (quote: Quote) => Promise<void>;
    refresh: () => Promise<void>;
    syncError: string;
    syncErrors: SyncQueueItem[] | undefined;
    retrySyncOperation: (operationId: string) => Promise<void>;
}

const QuotesContext = createContext<QuotesContextValue | null>(null);
const activeIdentityKey = 'sync-active-identity';

export const QuotesProvider = ({ children }: { children: React.ReactNode }) => {
    const { user } = useAuth();
    const { vaultGeneration, legacyVaultGeneration, lockVault } = useCrypto();
    const [initializedIdentity, setInitializedIdentity] = useState<string | null>(null);
    const [syncError, setSyncError] = useState('');
    const actorId = user?.id;
    const generation = vaultGeneration;
    const context = useMemo<SyncContext | null>(() => actorId && generation ? {
        actorId, generation, legacyGeneration: legacyVaultGeneration, onGenerationMismatch: lockVault
    } : null, [actorId, generation, legacyVaultGeneration, lockVault]);
    const identity = context && `${context.actorId}:${context.generation}`;
    const ready = initializedIdentity === identity;
    const quotes = useLiveQuery<Quote[], Quote[]>(
        () => ready ? db.quotes.orderBy('created_at').reverse().toArray() : Promise.resolve<Quote[]>([]),
        [ready], [] as Quote[]
    );
    const syncErrors = useLiveQuery(
        () => db.syncQueue.toArray().then(items => items.filter(item =>
            (item.status === 'blocked' && (!item.actor_id || item.actor_id === actorId))
                || (item.actor_id === actorId && (!item.vault_generation || item.vault_generation === generation) && item.status === 'rejected')
        )),
        [actorId, generation], []
    );

    const refresh = useCallback(async () => {
        if (!context) return;
        try {
            await processSyncQueue(context);
            setSyncError('');
        } catch (error) {
            setSyncError(error instanceof Error ? error.message : 'Unable to synchronize. Changes remain on this device.');
        }
    }, [context]);

    useEffect(() => {
        let active = true;
        if (!context) return;
        const currentIdentity = `${context.actorId}:${context.generation}`;
        void (async () => {
            try {
                await db.transaction('rw', db.quotes, db.syncQueue, db.metadata, async () => {
                    const abort = () => { if (!active) throw new Error('Quote initialization cancelled.'); };
                    abort();
                    const previous = (await db.metadata.get(activeIdentityKey))?.value;
                    abort();
                    const preserveLegacyCache = previous === undefined && legacyVaultGeneration === context.generation;
                    if (previous !== currentIdentity) {
                        if (preserveLegacyCache) {
                            const legacyQuotes = await db.quotes.toArray();
                            abort();
                            await db.quotes.bulkPut(legacyQuotes.map(quote => ({ ...quote, vault_generation: context.generation })));
                        } else {
                            const queued = await db.syncQueue.toArray();
                            abort();
                            const deleted = new Set(queued.filter(item => item.action === 'DELETE' && item.actor_id === context.actorId && item.vault_generation === context.generation).map(item => item.quote_id));
                            const local = queued.filter(item => item.action === 'INSERT' && item.actor_id === context.actorId && item.vault_generation === context.generation && item.payload && !deleted.has(item.quote_id))
                                .map(item => ({ ...item.payload!, sync_status: item.status === 'rejected' ? 'rejected' as const : 'pending' as const }));
                            await db.quotes.clear();
                            abort();
                            await db.quotes.bulkPut(local);
                            await db.metadata.delete(`sync-revision:${context.actorId}:${context.generation}`);
                        }
                    }
                    abort();
                    await db.metadata.put({ id: activeIdentityKey, value: currentIdentity });
                });
                if (active) setInitializedIdentity(currentIdentity);
            } catch (error) {
                if (active) setSyncError(error instanceof Error ? error.message : 'Unable to initialize local quote storage.');
            }
        })();
        return () => { active = false; cancelSyncRequests(); };
    }, [context, legacyVaultGeneration]);

    useEffect(() => {
        if (!context || !ready) return;
        let timer: number | undefined;
        const schedule = () => {
            window.clearTimeout(timer);
            timer = window.setTimeout(() => { void refresh(); }, 150);
        };
        const online = () => schedule();
        const visible = () => { if (document.visibilityState === 'visible') schedule(); };
        const channel = supabase.channel(`quote-sync:${context.actorId}:${context.generation}`)
            .on('postgres_changes', { event: '*', schema: 'public', table: 'quotes' }, schedule)
            .subscribe();
        window.addEventListener('online', online);
        document.addEventListener('visibilitychange', visible);
        schedule();
        return () => {
            window.clearTimeout(timer);
            window.removeEventListener('online', online);
            document.removeEventListener('visibilitychange', visible);
            void channel.unsubscribe();
        };
    }, [context, ready, refresh]);

    const addQuote = useCallback(async (text: string, author: string, quoteContext?: string, quoteDate?: string, userId?: string) => {
        if (!context || !ready) throw new Error('Wait for the vault to finish loading before saving a quote.');
        const quote: Quote = {
            id: crypto.randomUUID(), text, author, context: quoteContext, quote_date: quoteDate || null,
            created_at: new Date().toISOString(), user_id: userId || context.actorId,
            vault_generation: context.generation, sync_status: 'pending'
        };
        const operation = createSyncOperation('INSERT', quote, context.actorId, context.generation);
        await db.transaction('rw', db.quotes, db.syncQueue, async () => {
            await db.quotes.put(quote);
            await db.syncQueue.put(operation);
        });
        void refresh();
    }, [context, ready, refresh]);

    const deleteQuote = useCallback(async (quote: Quote) => {
        if (!context || !ready) throw new Error('Wait for the vault to finish loading before deleting a quote.');
        if (quote.vault_generation !== context.generation) throw new Error('This quote belongs to an older vault generation. Refresh before deleting it.');
        await enqueueDeleteMutation(quote, context);
        void refresh();
    }, [context, ready, refresh]);

    const retrySyncOperation = useCallback(async (operationId: string) => {
        if (!context) return;
        const item = await db.syncQueue.get(operationId);
        if (!item || item.status !== 'rejected' || item.actor_id !== context.actorId || item.vault_generation !== context.generation) return;
        const replacementId = crypto.randomUUID();
        const replacement = { ...item, id: replacementId, operation_id: replacementId, status: 'pending' as const, error: undefined,
            payload: item.payload && { ...item.payload, sync_status: 'pending' as const } };
        await db.transaction('rw', db.quotes, db.syncQueue, async () => {
            await db.syncQueue.delete(operationId);
            await db.syncQueue.put(replacement);
            if (replacement.action === 'INSERT') await db.quotes.update(replacement.quote_id, { sync_status: 'pending' });
        });
        await refresh();
    }, [context, refresh]);

    const value = useMemo(() => ({ quotes, addQuote, deleteQuote, refresh, syncError, syncErrors, retrySyncOperation }),
        [quotes, addQuote, deleteQuote, refresh, syncError, syncErrors, retrySyncOperation]);
    return <QuotesContext.Provider value={value}>{children}</QuotesContext.Provider>;
};

export const useQuotes = () => {
    const context = useContext(QuotesContext);
    if (!context) throw new Error('useQuotes must be used inside QuotesProvider.');
    return context;
};
