import { db } from './db';
import { supabase } from './supabase';
import type { Quote, SyncQueueItem } from '../types';

export interface SyncContext {
    actorId: string;
    generation: string;
    legacyGeneration?: string | null;
    getDeviceAuthorization?: () => Promise<{ deviceId: string; token: string }>;
    renewLease?: () => Promise<void>;
    onGenerationMismatch?: () => void;
}

const revisionKey = (actorId: string, generation: string) => `sync-revision:${actorId}:${generation}`;
// The RPC rejects a JSON operation list over 1 MiB. Leave room for the RPC's
// JSON encoding and reject legacy entries that cannot fit a conservative batch.
const MAX_SYNC_BATCH_BYTES = 900 * 1024;
const MAX_SYNC_OPERATIONS = 50;
const SYNC_REQUEST_TIMEOUT_MS = 15_000;
let inFlight: Promise<boolean> | null = null;
let syncEpoch = 0;
let activeIdentity = '';
let inFlightIdentity = '';
let inFlightEpoch = 0;
const queuedRuns = new Map<string, Promise<boolean>>();
let queueEpoch = 0;
let syncRequest = 0;
let lastOperationTime = 0;
let activeAbortController: AbortController | null = null;

export function isTransientSyncFailure(error: unknown) {
    if (!error || typeof error !== 'object') return false;
    const value = error as { status?: unknown; code?: unknown; message?: unknown; name?: unknown };
    const status = value.status;
    if (status === 401 || status === 403 || value.code === '42501') return false;
    if (typeof status === 'number' && (status === 408 || status === 429 || status >= 500)) return true;
    if (value.name === 'AbortError') return true;
    const code = typeof value.code === 'string' ? value.code : '';
    if (/^(08|53)/.test(code)) return true; // PostgreSQL connection or temporary resource failure.
    const message = typeof value.message === 'string' ? value.message.toLowerCase() : '';
    return /failed to fetch|networkerror|network request failed|fetch failed|timed out|timeout|temporarily unavailable|service unavailable/.test(message);
}

function activate(context: SyncContext) {
    const identity = `${context.actorId}:${context.generation}`;
    if (activeIdentity !== identity) {
        activeIdentity = identity;
        syncEpoch++;
    }
    return syncEpoch;
}

/** Clears the unlocked vault's visible cache and prevents an older request from restoring it. */
export async function clearLocalSyncState() {
    syncEpoch++;
    queueEpoch++;
    queuedRuns.clear();
    activeAbortController?.abort();
    activeAbortController = null;
    await db.transaction('rw', db.quotes, db.syncQueue, db.metadata, async () => {
        await db.quotes.clear();
        await db.syncQueue.clear();
        await db.metadata.clear();
    });
}

/** Stops an obsolete request from applying its response without deleting pending data. */
export function cancelSyncRequests() {
    syncEpoch++;
    queueEpoch++;
    queuedRuns.clear();
    activeAbortController?.abort();
    activeAbortController = null;
}

export function createSyncOperation(action: 'INSERT' | 'DELETE', quote: Quote, actorId: string, generation: string): SyncQueueItem {
    const operation_id = crypto.randomUUID();
    lastOperationTime = Math.max(Date.now(), lastOperationTime + 1);
    return {
        id: operation_id,
        operation_id,
        action,
        quote_id: quote.id,
        actor_id: actorId,
        vault_generation: generation,
        payload: action === 'INSERT' ? { ...quote, vault_generation: generation, sync_status: 'pending' } : undefined,
        created_at: new Date(lastOperationTime).toISOString(),
        status: 'pending'
    };
}

export async function enqueueDeleteMutation(quote: Quote, context: SyncContext) {
    const operation = createSyncOperation('DELETE', quote, context.actorId, context.generation);
    await db.transaction('rw', db.quotes, db.syncQueue, async () => {
        await db.quotes.delete(quote.id);
        const superseded = (await db.syncQueue.toArray()).filter(item =>
            item.quote_id === quote.id && (
                item.action === 'INSERT' && item.actor_id === context.actorId && item.vault_generation === context.generation ||
                item.action === 'DELETE' && item.status === 'blocked' && !item.actor_id
            )
        );
        await db.syncQueue.bulkDelete(superseded.map(item => item.id));
        await db.syncQueue.put(operation);
    });
    return operation;
}

async function adoptLegacyOperations({ actorId, generation, legacyGeneration }: SyncContext) {
    const queue = await db.syncQueue.toArray();
    for (const item of queue) {
        if (item.action !== 'INSERT' || item.vault_generation || item.actor_id !== actorId) continue;
        if (legacyGeneration === generation && item.payload) {
            await db.syncQueue.update(item.id, {
                vault_generation: generation,
                payload: { ...item.payload, vault_generation: generation },
                status: 'pending',
                error: undefined
            });
        } else {
            await db.syncQueue.update(item.id, {
                status: 'blocked',
                error: 'Quote was created before this vault generation; re-add it after unlocking.'
            });
        }
    }
}

async function mergeSnapshot(snapshot: Quote[], context: SyncContext) {
    // Called inside the response transaction so a new local delete cannot be overwritten.
    const queued = (await db.syncQueue.toArray()).filter(item =>
        item.actor_id === context.actorId && item.vault_generation === context.generation
            && (item.action === 'INSERT' || (item.status !== 'rejected' && item.status !== 'blocked'))
    );
    const pendingByQuote = new Map(queued.map(item => [item.quote_id, item]));
    const remoteById = new Map(snapshot.map(quote => [quote.id, { ...quote, sync_status: 'synced' as const }]));

    const local = await db.quotes.toArray();
    for (const quote of local) {
        if (!remoteById.has(quote.id) && !pendingByQuote.has(quote.id)) await db.quotes.delete(quote.id);
    }
    for (const quote of remoteById.values()) {
        if (!pendingByQuote.has(quote.id)) await db.quotes.put(quote);
    }
}

async function rejectStaleGeneration(context: SyncContext, epoch: number) {
    await db.transaction('rw', db.quotes, db.syncQueue, async () => {
        if (epoch !== syncEpoch) return;
        await db.quotes.clear();
        const stale = (await db.syncQueue.toArray()).filter(item => item.vault_generation === context.generation);
        await db.syncQueue.bulkDelete(stale.map(item => item.id));
    });
    if (epoch === syncEpoch) context.onGenerationMismatch?.();
}

function validQuote(value: unknown, generation: string): value is Quote {
    if (!value || typeof value !== 'object') return false;
    const quote = value as Record<string, unknown>;
    return ['id', 'text', 'author', 'created_at', 'user_id'].every(key => typeof quote[key] === 'string')
        && quote.vault_generation === generation
        && (quote.context === undefined || quote.context === null || typeof quote.context === 'string')
        && (quote.quote_date === undefined || quote.quote_date === null || typeof quote.quote_date === 'string');
}

function validResponse(data: unknown, sentIds: Set<string>): data is { generation: string; revision: number; results: Array<{ operation_id: string; status: 'ok' | 'rejected'; error?: string }>; quotes: Quote[] | null } {
    if (!data || typeof data !== 'object') return false;
    const response = data as Record<string, unknown>;
    const generation = response.generation;
    const revision = response.revision;
    const results = response.results;
    const quotes = response.quotes;
    if (typeof generation !== 'string' || typeof revision !== 'number' || !Number.isSafeInteger(revision) || revision < 0 || !Array.isArray(results)) return false;
    const resultIds = new Set<string>();
    if (results.length !== sentIds.size || !results.every(result => {
        if (!result || typeof result !== 'object') return false;
        const item = result as Record<string, unknown>;
        if (typeof item.operation_id !== 'string' || !sentIds.has(item.operation_id) || resultIds.has(item.operation_id)) return false;
        resultIds.add(item.operation_id);
        return (item.status === 'ok' || item.status === 'rejected') && (item.error === undefined || typeof item.error === 'string');
    })) return false;
    return quotes === null || (Array.isArray(quotes) && quotes.every(quote => validQuote(quote, generation)));
}

function operationFor(item: SyncQueueItem) {
    return {
        operation_id: item.operation_id,
        action: item.action,
        quote_id: item.quote_id,
        actor_id: item.actor_id!,
        vault_generation: item.vault_generation!,
        ...(item.action === 'INSERT' ? { payload: item.payload } : {})
    };
}

function encodedBytes(value: string) {
    return new TextEncoder().encode(value).byteLength;
}

async function rejectOversizedOperations(items: SyncQueueItem[]) {
    if (!items.length) return;
    await db.transaction('rw', db.quotes, db.syncQueue, async () => {
        for (const item of items) {
            const current = await db.syncQueue.get(item.id);
            if (!current || current.operation_id !== item.operation_id || current.status !== 'pending') continue;
            await db.syncQueue.update(item.id, {
                status: 'rejected',
                error: 'This saved quote is too large to synchronize. Shorten it and save it again.'
            });
            await db.quotes.update(item.quote_id, { sync_status: 'rejected' });
        }
    });
}

async function syncBatch(context: SyncContext, epoch: number): Promise<{ more: boolean; performed: boolean }> {
    if (!navigator.onLine) return { more: false, performed: false };
    await adoptLegacyOperations(context);
    const revision = (await db.metadata.get(revisionKey(context.actorId, context.generation)))?.value ?? null;
    const queue = (await db.syncQueue.orderBy('created_at').toArray())
        .filter(item => item.actor_id === context.actorId && item.vault_generation === context.generation && item.status !== 'rejected' && item.status !== 'blocked')
        .slice(0, MAX_SYNC_OPERATIONS);
    const operations = [] as ReturnType<typeof operationFor>[];
    const oversized: SyncQueueItem[] = [];
    let batchBytes = 2; // JSON array brackets
    for (const item of queue) {
        const operation = operationFor(item);
        const operationBytes = encodedBytes(JSON.stringify(operation));
        if (operationBytes + 2 > MAX_SYNC_BATCH_BYTES) {
            if (item.action === 'INSERT') oversized.push(item);
            continue;
        }
        const nextBytes = batchBytes + operationBytes + (operations.length ? 1 : 0);
        if (nextBytes > MAX_SYNC_BATCH_BYTES) break;
        operations.push(operation);
        batchBytes = nextBytes;
    }
    await rejectOversizedOperations(oversized);
    const controller = new AbortController();
    activeAbortController = controller;
    let timeout: number | undefined;
    const deadline = new Promise<never>((_resolve, reject) => {
        timeout = window.setTimeout(() => {
            controller.abort();
            reject(new Error('Sync timed out. Changes remain on this device; retrying automatically.'));
        }, SYNC_REQUEST_TIMEOUT_MS);
    });
    let data: unknown;
    let error: unknown;
    let status: number | undefined;
    const authorization = context.getDeviceAuthorization
        ? await context.getDeviceAuthorization()
        : { deviceId: null, token: null };
    try {
        // Auth restoration can stall before fetch sees the abort signal.
        ({ data, error, status } = await Promise.race([supabase.rpc('sync_quotes', {
            p_generation: context.generation,
            p_revision: revision,
            p_operations: operations,
            p_device_id: authorization.deviceId,
            p_device_token: authorization.token,
        }).abortSignal(controller.signal), deadline]));
    } finally {
        window.clearTimeout(timeout);
        if (activeAbortController === controller) activeAbortController = null;
    }
    if (error) throw Object.assign(new Error(error.message || 'Unable to synchronize. Changes remain on this device.'), error, { status });
    if (data === null) throw Object.assign(new Error('Device authorization was denied. Unlock this device and retry synchronization.'), { code: '42501', status: 403 });
    if (epoch !== syncEpoch) return { more: false, performed: true };
    const sentIds = new Set(operations.map(operation => operation.operation_id));
    if (!validResponse(data, sentIds)) throw new Error('Invalid sync response.');
    if (data.generation !== context.generation) {
        await rejectStaleGeneration(context, epoch);
        return { more: false, performed: true };
    }
    let rejectedDelete = false;
    await db.transaction('rw', db.quotes, db.syncQueue, db.metadata, async () => {
        if (epoch !== syncEpoch) return;
        for (const result of data.results) {
            const item = await db.syncQueue.get(result.operation_id);
            if (!item || item.operation_id !== result.operation_id) continue;
            if (result.status === 'ok') {
                await db.syncQueue.delete(result.operation_id);
                if (item.action === 'INSERT') {
                    const later = (await db.syncQueue.toArray()).some(next => next.quote_id === item.quote_id && next.id !== item.id);
                    if (!later) await db.quotes.update(item.quote_id, { sync_status: 'synced' });
                }
            } else {
                await db.syncQueue.update(item.id, { status: 'rejected', error: result.error || 'The server rejected this change.' });
                if (item.action === 'INSERT') await db.quotes.update(item.quote_id, { sync_status: 'rejected' });
                if (item.action === 'DELETE') rejectedDelete = true;
            }
        }
        if (epoch !== syncEpoch) return;
        if (data.quotes) await mergeSnapshot(data.quotes, context);
        if (epoch !== syncEpoch) return;
        if (rejectedDelete && !data.quotes) {
            // The local row was removed optimistically; force one complete snapshot to restore it.
            await db.metadata.delete(revisionKey(context.actorId, context.generation));
        } else {
            await db.metadata.put({ id: revisionKey(context.actorId, context.generation), value: data.revision });
        }
    });
    if (epoch !== syncEpoch) return { more: false, performed: true };
    if (context.renewLease) await context.renewLease();
    const remaining = (await db.syncQueue.toArray()).some(item =>
        item.actor_id === context.actorId && item.vault_generation === context.generation && item.status !== 'rejected' && item.status !== 'blocked'
    );
    return { more: remaining || (rejectedDelete && !data.quotes), performed: true };
}

async function sync(context: SyncContext, epoch: number) {
    let performed = false;
    while (epoch === syncEpoch) {
        const request = syncRequest;
        const result = await syncBatch(context, epoch);
        performed ||= result.performed;
        if (!result.more && request === syncRequest) return performed;
    }
    return performed;
}

async function withCrossTabLock(run: () => Promise<boolean>) {
    // ponytail: one shared vault uses one lock; partition locks if multiple vaults are added.
    const locks = typeof navigator !== 'undefined' && 'locks' in navigator ? (navigator as Navigator & { locks?: LockManager }).locks : undefined;
    return locks ? locks.request('quote-vault-sync', run) : run();
}

function startSync(context: SyncContext) {
    const epoch = activate(context);
    const identity = `${context.actorId}:${context.generation}`;
    const running = withCrossTabLock(() => sync(context, epoch));
    inFlight = running;
    inFlightIdentity = identity;
    inFlightEpoch = epoch;
    void running.then(
        () => { if (inFlight === running) inFlight = null; },
        () => { if (inFlight === running) inFlight = null; }
    );
    return running;
}

export function processSyncQueue(context: SyncContext) {
    syncRequest++;
    const identity = `${context.actorId}:${context.generation}`;
    const epoch = activate(context);
    if (inFlight && inFlightIdentity === identity && inFlightEpoch === epoch) return inFlight;
    const queued = queuedRuns.get(identity);
    if (queued) return queued;
    if (!inFlight) return startSync(context);

    const scheduledQueueEpoch = queueEpoch;
    const running = inFlight.catch(() => false).then(() =>
        scheduledQueueEpoch === queueEpoch ? startSync(context) : false
    );
    queuedRuns.set(identity, running);
    void running.then(
        () => { if (queuedRuns.get(identity) === running) queuedRuns.delete(identity); },
        () => { if (queuedRuns.get(identity) === running) queuedRuns.delete(identity); }
    );
    return running;
}
