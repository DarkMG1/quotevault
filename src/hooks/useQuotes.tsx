import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { useLiveQuery } from 'dexie-react-hooks';
import { db } from '../lib/db';
import { cancelSyncRequests, createSyncOperation, enqueueDeleteMutation, isTransientSyncFailure, processSyncQueue, type SyncContext } from '../lib/sync';
import { supabase } from '../lib/supabase';
import { useAuth } from './useAuth';
import { useCrypto } from './useCrypto';
import { encryptQuoteRecord } from '../lib/quote-crypto';
import { isCiphertextWithinLimit } from '../components/ui';
import type { Quote, SyncQueueItem } from '../types';

interface QuotesContextValue {
    quotes: Quote[] | undefined;
    loading: boolean;
    initialFetchPending: boolean;
    pendingCount: number;
    lastSyncedAt: string | null;
    isSyncing: boolean;
    addQuote: (privateFields: { text: string; author: string; context?: string; source_sender?: string; import_source_id?: string }, quoteDate?: string) => Promise<void>;
    deleteQuote: (quote: Quote) => Promise<void>;
    refresh: () => Promise<void>;
    syncError: string;
    syncErrors: SyncQueueItem[] | undefined;
    retrySyncOperation: (operationId: string) => Promise<void>;
}

const QuotesContext = createContext<QuotesContextValue | null>(null);
const activeIdentityKey = 'sync-active-identity';

export const QuotesProvider = ({ children }: { children: React.ReactNode }) => {
    const { user, canSync, retry: retrySession } = useAuth();
    const { encryptionKey, vaultGeneration, legacyVaultGeneration, lockVault, getDeviceAuthorization, renewDeviceLease, deviceId } = useCrypto();
    const [initializedIdentity, setInitializedIdentity] = useState<string | null>(null);
    const [lastSync, setLastSync] = useState<{ identity: string; at: string } | null>(null);
    const [syncError, setSyncError] = useState('');
    const [isSyncing, setIsSyncing] = useState(false);
    const initializedIdentityRef = useRef<string | null>(null);
    const lifecycle = useRef(0);
    const retry = useRef<{ attempts: number; timer: number | undefined }>({ attempts: 0, timer: undefined });
    const actorId = user?.id;
    const generation = vaultGeneration;
    const context = useMemo<SyncContext | null>(() => actorId && generation ? {
        actorId, generation, legacyGeneration: legacyVaultGeneration, onGenerationMismatch: lockVault,
        getDeviceAuthorization: deviceId ? getDeviceAuthorization : undefined,
        renewLease: deviceId ? renewDeviceLease : undefined,
    } : null, [actorId, generation, legacyVaultGeneration, lockVault, getDeviceAuthorization, renewDeviceLease, deviceId]);
    const identity = context && `${context.actorId}:${context.generation}`;
    const ready = initializedIdentity === identity;
    const loading = !ready;
    const initialFetchPending = canSync && ready && lastSync?.identity !== identity;
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

    const refresh = useCallback(async function synchronize() {
        if (!context) return;
        const token = lifecycle.current;
        const active = () => lifecycle.current === token;
        window.clearTimeout(retry.current.timer);
        retry.current.timer = undefined;
        setIsSyncing(true);
        try {
            if (!await initialize(context, legacyVaultGeneration, active) || !active()) return;
            if (!navigator.onLine) {
                setSyncError('Offline. Changes are saved on this device and will sync when you reconnect.');
                return;
            }
            if (!canSync) {
                setSyncError('Restoring your session. Changes remain on this device until synchronization succeeds.');
                void retrySession();
                return;
            }
            const performed = await processSyncQueue(context);
            if (!active()) return;
            setSyncError('');
            retry.current.attempts = 0;
            if (performed) {
                const currentIdentity = `${context.actorId}:${context.generation}`;
                setLastSync({ identity: currentIdentity, at: new Date().toISOString() });
            }
        } catch (error) {
            if (!active()) return;
            setSyncError(error instanceof Error ? error.message : 'Unable to synchronize. Changes remain on this device.');
            if (isTransientSyncFailure(error) && typeof navigator !== 'undefined' && navigator.onLine && document.visibilityState === 'visible') {
                window.clearTimeout(retry.current.timer);
                const delay = Math.min(1000 * 2 ** retry.current.attempts++, 30_000);
                retry.current.timer = window.setTimeout(() => {
                    retry.current.timer = undefined;
                    if (active() && navigator.onLine && document.visibilityState === 'visible') void synchronize();
                }, delay);
            }
        } finally {
            if (active()) setIsSyncing(false);
        }
    }, [canSync, context, initialize, legacyVaultGeneration, retrySession]);

    useEffect(() => {
        let active = true;
        if (!context) return;
        const currentLifecycle = lifecycle;
        const currentRetry = retry.current;
        const token = ++currentLifecycle.current;
        void Promise.resolve().then(() => {
            if (!active || currentLifecycle.current !== token) return;
            setIsSyncing(false);
            return initialize(context, legacyVaultGeneration, () => active && currentLifecycle.current === token);
        });
        return () => {
            active = false;
            if (currentLifecycle.current === token) currentLifecycle.current++;
            window.clearTimeout(currentRetry.timer);
            currentRetry.timer = undefined;
            currentRetry.attempts = 0;
            cancelSyncRequests();
        };
    }, [canSync, context, initialize, legacyVaultGeneration]);

    useEffect(() => {
        if (!context || !ready || !canSync) return;
        let timer: number | undefined;
        const schedule = () => {
            window.clearTimeout(timer);
            if (!navigator.onLine || document.visibilityState !== 'visible') return;
            timer = window.setTimeout(() => { void refresh(); }, 150);
        };
        const online = () => schedule();
        const visible = () => { if (document.visibilityState === 'visible') schedule(); };
        const channel = supabase.channel('quotevault-sync', { config: { private: true } })
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
    }, [canSync, context, ready, refresh]);

    const addQuote = useCallback(async (privateFields: { text: string; author: string; context?: string; source_sender?: string; import_source_id?: string }, quoteDate?: string) => {
        if (!context || !ready || !encryptionKey) throw new Error('Wait for the vault to finish loading before saving a quote.');
        const encrypted = await encryptQuoteRecord(privateFields, {
            id: crypto.randomUUID(), quote_date: quoteDate || null, created_at: new Date().toISOString(),
            user_id: context.actorId, vault_generation: context.generation
        }, encryptionKey);
        if (!isCiphertextWithinLimit(JSON.parse(String(encrypted.text).slice(7)))) {
            throw new Error('This quote is too large to save. Shorten the quote or context and try again.');
        }
        const quote = { ...encrypted, author: 'ENCRYPTED', context: 'ENCRYPTED', sync_status: 'pending' } as unknown as Quote;
        const operation = createSyncOperation('INSERT', quote, context.actorId, context.generation);
        await db.transaction('rw', db.quotes, db.syncQueue, async () => {
            await db.quotes.put(quote);
            await db.syncQueue.put(operation);
        });
        void refresh();
    }, [context, encryptionKey, ready, refresh]);

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
    const value = useMemo(() => ({ quotes, loading, initialFetchPending, pendingCount, lastSyncedAt, isSyncing, addQuote, deleteQuote, refresh, syncError, syncErrors, retrySyncOperation }),
        [quotes, loading, initialFetchPending, pendingCount, lastSyncedAt, isSyncing, addQuote, deleteQuote, refresh, syncError, syncErrors, retrySyncOperation]);
    return <QuotesContext.Provider value={value}>{children}</QuotesContext.Provider>;
};

export const useQuotes = () => {
    const context = useContext(QuotesContext);
    if (!context) throw new Error('useQuotes must be used inside QuotesProvider.');
    return context;
};
