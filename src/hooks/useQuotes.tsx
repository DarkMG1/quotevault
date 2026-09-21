import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { useLiveQuery } from 'dexie-react-hooks';
import { db } from '../lib/db';
import { cancelSyncRequests, createSyncOperation, enqueueDeleteMutation, processSyncQueue, type SyncContext } from '../lib/sync';
import { supabase } from '../lib/supabase';
import { useAuth } from './useAuth';
import { useCrypto } from './useCrypto';
import type { Quote, SyncQueueItem } from '../types';

interface QuotesContextValue {
    quotes: Quote[] | undefined;
    loading: boolean;
    initialFetchPending: boolean;
    pendingCount: number;
    lastSyncedAt: string | null;
    addQuote: (text: string, author: string, context?: string, quoteDate?: string) => Promise<void>;
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
    const [lastSync, setLastSync] = useState<{ identity: string; at: string } | null>(null);
    const [syncError, setSyncError] = useState('');
    const initializedIdentityRef = useRef<string | null>(null);
    const lifecycle = useRef(0);
    const actorId = user?.id;
    const generation = vaultGeneration;
    const context = useMemo<SyncContext | null>(() => actorId && generation ? {
        actorId, generation, legacyGeneration: legacyVaultGeneration, onGenerationMismatch: lockVault
    } : null, [actorId, generation, legacyVaultGeneration, lockVault]);
    const identity = context && `${context.actorId}:${context.generation}`;
    const ready = initializedIdentity === identity;
    const loading = !ready;
    const initialFetchPending = ready && lastSync?.identity !== identity;
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
    const pendingCount = useLiveQuery(
        () => db.syncQueue.toArray().then(items => items.filter(item =>
            item.actor_id === actorId && item.vault_generation === generation && item.status !== 'rejected' && item.status !== 'blocked'
        ).length),
        [actorId, generation], 0
    );

    const initialize = useCallback(async (currentContext: SyncContext, legacyGeneration: string | null, isActive: () => boolean) => {
        const currentIdentity = `${currentContext.actorId}:${currentContext.generation}`;
        if (initializedIdentityRef.current === currentIdentity) return true;
        try {
            await db.transaction('rw', db.quotes, db.syncQueue, db.metadata, async () => {
                const abort = () => { if (!isActive()) throw new Error('Quote initialization cancelled.'); };
                abort();
                const previous = (await db.metadata.get(activeIdentityKey))?.value;
                abort();
                const preserveLegacyCache = previous === undefined && legacyGeneration === currentContext.generation;
                if (previous !== currentIdentity) {
                    if (preserveLegacyCache) {
                        const legacyQuotes = await db.quotes.toArray();
                        abort();
                        await db.quotes.bulkPut(legacyQuotes.map(quote => ({ ...quote, vault_generation: currentContext.generation })));
                        abort();
                    } else {
                        const queued = await db.syncQueue.toArray();
                        abort();
                        const deleted = new Set(queued.filter(item => item.action === 'DELETE' && item.actor_id === currentContext.actorId && item.vault_generation === currentContext.generation).map(item => item.quote_id));
                        const local = queued.filter(item => item.action === 'INSERT' && item.actor_id === currentContext.actorId && item.vault_generation === currentContext.generation && item.payload && !deleted.has(item.quote_id))
                            .map(item => ({ ...item.payload!, sync_status: item.status === 'rejected' ? 'rejected' as const : 'pending' as const }));
                        await db.quotes.clear();
                        abort();
                        await db.quotes.bulkPut(local);
                        abort();
                        await db.metadata.delete(`sync-revision:${currentContext.actorId}:${currentContext.generation}`);
                        abort();
                    }
                }
                abort();
                await db.metadata.put({ id: activeIdentityKey, value: currentIdentity });
                abort();
            });
            if (isActive()) {
                initializedIdentityRef.current = currentIdentity;
                setInitializedIdentity(currentIdentity);
                setSyncError('');
            }
            return true;
        } catch (error) {
            if (isActive()) setSyncError(error instanceof Error ? error.message : 'Unable to initialize local quote storage.');
            return false;
        }
    }, []);

    const refresh = useCallback(async () => {
        if (!context) return;
        const token = lifecycle.current;
        const active = () => lifecycle.current === token;
        if (!await initialize(context, legacyVaultGeneration, active) || !active()) return;
        try {
            const performed = await processSyncQueue(context);
            if (!active()) return;
            setSyncError('');
            if (performed) {
                const currentIdentity = `${context.actorId}:${context.generation}`;
                setLastSync({ identity: currentIdentity, at: new Date().toISOString() });
            }
        } catch (error) {
            if (active()) setSyncError(error instanceof Error ? error.message : 'Unable to synchronize. Changes remain on this device.');
        }
    }, [context, initialize, legacyVaultGeneration]);

    useEffect(() => {
        let active = true;
        if (!context) return;
        const currentLifecycle = lifecycle;
        const token = ++currentLifecycle.current;
        void Promise.resolve().then(() => initialize(context, legacyVaultGeneration, () => active && currentLifecycle.current === token));
        return () => {
            active = false;
            if (currentLifecycle.current === token) currentLifecycle.current++;
            cancelSyncRequests();
        };
    }, [context, initialize, legacyVaultGeneration]);

    useEffect(() => {
        if (!context || !ready) return;
        let timer: number | undefined;
        const schedule = () => {
            window.clearTimeout(timer);
            timer = window.setTimeout(() => { void refresh(); }, 150);
        };
        const online = () => schedule();
        const visible = () => { if (document.visibilityState === 'visible') schedule(); };
        const channel = supabase.channel('quotevault-sync', { config: { private: true } })
            .on('postgres_changes', { event: '*', schema: 'public', table: 'quotes' }, schedule)
            .on('broadcast', { event: 'vault-generation' }, schedule)
            .subscribe(status => { if (status === 'SUBSCRIBED') schedule(); });
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

    const addQuote = useCallback(async (text: string, author: string, quoteContext?: string, quoteDate?: string) => {
        if (!context || !ready) throw new Error('Wait for the vault to finish loading before saving a quote.');
        const quote: Quote = {
            id: crypto.randomUUID(), text, author, context: quoteContext, quote_date: quoteDate || null,
            created_at: new Date().toISOString(), user_id: context.actorId,
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

    const lastSyncedAt = lastSync?.identity === identity ? lastSync.at : null;
    const value = useMemo(() => ({ quotes, loading, initialFetchPending, pendingCount, lastSyncedAt, addQuote, deleteQuote, refresh, syncError, syncErrors, retrySyncOperation }),
        [quotes, loading, initialFetchPending, pendingCount, lastSyncedAt, addQuote, deleteQuote, refresh, syncError, syncErrors, retrySyncOperation]);
    return <QuotesContext.Provider value={value}>{children}</QuotesContext.Provider>;
};

export const useQuotes = () => {
    const context = useContext(QuotesContext);
    if (!context) throw new Error('useQuotes must be used inside QuotesProvider.');
    return context;
};
