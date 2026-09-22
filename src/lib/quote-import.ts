import { decryptData, encryptData } from './crypto';
import { decryptQuoteRecord, encryptQuoteRecord } from './quote-crypto';
import { db } from './db';
import { supabase } from './supabase';
import { processSyncQueue, type SyncContext } from './sync';
import { isCiphertextWithinLimit, isDecryptedPayload } from '../components/ui';
import type { Quote } from '../types';

export interface ImportRow {
    text: string;
    author: string;
    context: string;
    source_sender: string;
    import_source_id?: string;
    quote_date: string | null;
    selected: boolean;
}
export interface ExistingQuote { text: string; author: string; import_source_id?: string }
export interface ImportSnapshot { revision: number; quotes: ExistingQuote[] }
export interface ImportCheck { duplicate: boolean; similar: string | null }
interface ImportOperation {
    operation_id: string; action: 'INSERT'; quote_id: string; actor_id: string;
    vault_generation: string; payload: Quote;
}
export interface PendingImport { actorId: string; generation: string; revision: number; operations: ImportOperation[] }
const MAX_FILE_BYTES = 5 * 1024 * 1024;
const MAX_BATCH_BYTES = 800 * 1024; // Leave room for PostgreSQL JSON formatting within the 900 KiB server limit.
const pendingId = (context: SyncContext) => `quotevault-import:${context.actorId}:${context.generation}`;
const stringValue = (value: unknown, name: string, required = false): string => {
    if (value === undefined && !required) return '';
    if (typeof value !== 'string' || value.length > 100000 || (required && !value.trim())) throw new Error(`Invalid ${name} in import file.`);
    return value.trim();
};

function importDate(value: unknown, timestamp: unknown): string | null {
    if (value === undefined || value === null || value === '') {
        if (typeof timestamp !== 'string') return null;
        const match = /^([A-Z][a-z]{2}) (\d{1,2}), (\d{4})\s/.exec(timestamp);
        if (!match) return null;
        const month = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'].indexOf(match[1]) + 1;
        value = `${match[3]}-${String(month).padStart(2, '0')}-${match[2].padStart(2, '0')}`;
    }
    if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value) ||
        !Number.isFinite(Date.parse(`${value}T00:00:00Z`)) || new Date(`${value}T00:00:00Z`).toISOString().slice(0, 10) !== value) throw new Error('Invalid quote date.');
    return value;
}

export function parseImportFile(text: string): ImportRow[] {
    if (new TextEncoder().encode(text).length > MAX_FILE_BYTES) throw new Error('Import files must be at most 5 MiB.');
    const file: unknown = JSON.parse(text);
    if (!file || typeof file !== 'object') throw new Error('Choose a QuoteVault review JSON file.');
    const data = file as Record<string, unknown>;
    if (!['quotevault-reviewed-quotes', 'quotevault-review-draft'].includes(String(data.format)) || data.version !== 1 ||
        !Array.isArray(data.quotes) || !data.quotes.length || data.quotes.length > 500) throw new Error('Choose a QuoteVault review file containing 1–500 quotes.');
    return data.quotes.map((value: unknown) => {
        if (!value || typeof value !== 'object') throw new Error('Invalid quote entry.');
        const row = value as Record<string, unknown>;
        const source = row.source && typeof row.source === 'object' ? row.source as Record<string, unknown> : {};
        if (source.id !== undefined && (typeof source.id !== 'string' || !/^[a-f0-9]{64}$/.test(source.id))) throw new Error('Invalid message identity.');
        if (row.selected !== undefined && typeof row.selected !== 'boolean') throw new Error('Invalid selection.');
        return {
            text: stringValue(row.text, 'quote text', true), author: stringValue(row.author, 'person quoted', true),
            context: stringValue(row.context, 'context'), source_sender: stringValue(row.source_sender ?? source.sender, 'original sender', true),
            ...(source.id ? { import_source_id: source.id as string } : {}),
            quote_date: importDate(row.quote_date, source.timestamp),
            selected: data.format === 'quotevault-review-draft' ? row.selected === true : true,
        };
    });
}

export const normalizeQuote = (value: string) => value.normalize('NFKC').toLowerCase().replace(/[’‘]/g, "'")
    .replace(/[“”]/g, '"').replace(/[–—]/g, '-').replace(/\s+/g, ' ').trim();
const contentKey = (row: ExistingQuote) => JSON.stringify([normalizeQuote(row.text),
    [...new Set(normalizeQuote(row.author).split(/\s+&\s+/))].sort()]);

export function checkImports(rows: ImportRow[], existing: ExistingQuote[]): ImportCheck[] {
    const seen = [...existing];
    const content = new Set(seen.map(contentKey));
    const sources = new Set(seen.map(row => row.import_source_id).filter(Boolean));
    // ponytail: bounded 500-row review; tokenize/index if a vault grows beyond a few thousand quotes.
    return rows.map(row => {
        const key = contentKey(row);
        const duplicate = content.has(key) || !!row.import_source_id && sources.has(row.import_source_id);
        const text = normalizeQuote(row.text).replace(/[^\p{L}\p{N}\s]/gu, '');
        const words = new Set(text.split(/\s+/));
        const similar = duplicate ? null : seen.find(other => {
            const otherText = normalizeQuote(other.text).replace(/[^\p{L}\p{N}\s]/gu, '');
            if (text === otherText) return true;
            if (words.size < 5) return false;
            const otherWords = new Set(otherText.split(/\s+/));
            const overlap = [...words].filter(word => otherWords.has(word)).length;
            return overlap / Math.max(words.size, otherWords.size) >= 0.8;
        });
        content.add(key);
        if (row.import_source_id) sources.add(row.import_source_id);
        seen.push(row);
        return { duplicate, similar: similar ? `${similar.text} — ${similar.author}` : null };
    });
}

async function rpc(name: 'sync_quotes' | 'checked_import', args: Record<string, unknown>, authorization: { deviceId: string; token: string } | null) {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const timeout = new Promise<never>((_, reject) => {
        timer = setTimeout(() => { controller.abort(); reject(new Error('Import request timed out. Check the saved import status before starting another.')); }, 20000);
    });
    try {
        const { data, error } = await Promise.race([supabase.rpc(name, {
            ...args, p_device_id: authorization?.deviceId ?? null, p_device_token: authorization?.token ?? null,
        }).abortSignal(controller.signal), timeout]);
        if (error) throw Object.assign(new Error(error.message || 'Import request failed.'), { code: error.code });
        if (data === null) throw Object.assign(new Error('Device authorization was denied. Unlock this device and retry the import.'), { code: '42501' });
        return data;
    } finally { clearTimeout(timer!); }
}

export async function loadImportSnapshot(context: SyncContext, key: CryptoKey): Promise<ImportSnapshot> {
    if (!navigator.onLine) throw new Error('Connect before checking duplicates or importing.');
    if (!await processSyncQueue(context)) throw new Error('Wait for synchronization, then check again.');
    const queue = await db.syncQueue.toArray();
    if (queue.some(row => row.actor_id === context.actorId && row.vault_generation === context.generation)) throw new Error('Resolve pending or rejected sync changes before importing.');
    const authorization = context.getDeviceAuthorization ? await context.getDeviceAuthorization() : null;
    const data = await rpc('sync_quotes', { p_generation: context.generation, p_revision: null, p_operations: [] }, authorization);
    if (data?.generation !== context.generation || !Number.isSafeInteger(data.revision) || data.revision < 0 || !Array.isArray(data.quotes)) throw new Error('Could not verify the current vault snapshot.');
    const quotes = await Promise.all(data.quotes.map(async (row: Quote) => {
        if (row.vault_generation !== context.generation || typeof row.text !== 'string' || !row.text.startsWith('$$E2E$$')) throw new Error('An existing quote could not be checked safely.');
        const payload: unknown = await decryptQuoteRecord(row, key);
        if (!isDecryptedPayload(payload)) throw new Error('An existing encrypted quote is invalid.');
        const source = (payload as { import_source_id?: unknown }).import_source_id;
        if (source !== undefined && (typeof source !== 'string' || !/^[a-f0-9]{64}$/.test(source))) throw new Error('Invalid existing import identity.');
        return { text: payload.text, author: payload.author, ...(source ? { import_source_id: source as string } : {}) };
    }));
    return { revision: data.revision, quotes };
}

export async function readPendingImport(context: SyncContext, key: CryptoKey): Promise<PendingImport | null> {
    const saved = await db.metadata.get(pendingId(context));
    if (!saved) return null;
    const value = JSON.parse(await decryptData(JSON.parse(String(saved.value)), key)) as PendingImport;
    if (value.actorId !== context.actorId || value.generation !== context.generation || !Number.isSafeInteger(value.revision) ||
        !Array.isArray(value.operations) || value.operations.length < 1 || value.operations.length > 500 ||
        value.operations.some(op => op.action !== 'INSERT' || op.actor_id !== context.actorId || op.vault_generation !== context.generation)) throw new Error('Saved import does not match this account and vault.');
    return value;
}

export async function prepareImport(rows: ImportRow[], snapshot: ImportSnapshot, context: SyncContext, key: CryptoKey, active: () => boolean): Promise<PendingImport> {
    if (!active()) throw new Error('Vault access changed; unlock and review again.');
    if (rows.some(row => !row.text.trim() || !row.author.trim())) throw new Error('Every selected quote needs text and a person quoted.');
    if (!rows.length || rows.length > 500 || checkImports(rows, snapshot.quotes).some(check => check.duplicate)) throw new Error('Remove duplicate entries before importing.');
    const operations: ImportOperation[] = await Promise.all(rows.map(async row => {
        const id = crypto.randomUUID();
        const encrypted = await encryptQuoteRecord({ text: row.text, author: row.author, context: row.context,
            source_sender: row.source_sender, ...(row.import_source_id ? { import_source_id: row.import_source_id } : {}) }, {
            id, quote_date: row.quote_date, created_at: new Date().toISOString(), user_id: context.actorId,
            vault_generation: context.generation,
        }, key);
        if (!isCiphertextWithinLimit(JSON.parse(String(encrypted.text).slice(7)))) throw new Error('A quote is too large to import.');
        return { operation_id: crypto.randomUUID(), action: 'INSERT', quote_id: id, actor_id: context.actorId,
            vault_generation: context.generation, payload: { ...encrypted, author: 'ENCRYPTED', context: 'ENCRYPTED' } as Quote };
    }));
    if (new TextEncoder().encode(JSON.stringify(operations)).length > MAX_BATCH_BYTES) throw new Error('Import is too large for one atomic batch. Select fewer quotes.');
    if (!active()) throw new Error('Vault access changed; unlock and review again.');
    const pending = { actorId: context.actorId, generation: context.generation, revision: snapshot.revision, operations };
    const encrypted = await encryptData(JSON.stringify(pending), key);
    await db.transaction('rw', db.metadata, db.syncQueue, async () => {
        if (!active()) throw new Error('Vault access changed; unlock and review again.');
        if (await db.metadata.get(pendingId(context))) throw new Error('A saved import must be resolved first.');
        if ((await db.syncQueue.toArray()).some(op => op.actor_id === context.actorId && op.vault_generation === context.generation)) throw new Error('Sync your other changes before importing.');
        await db.metadata.put({ id: pendingId(context), value: JSON.stringify(encrypted) });
    });
    return pending;
}

export async function sendPendingImport(pending: PendingImport, context: SyncContext): Promise<number> {
    if (pending.actorId !== context.actorId || pending.generation !== context.generation) throw new Error('Saved import belongs to another vault session.');
    if (!navigator.onLine) throw new Error('Connect to check the saved import status.');
    try {
        const authorization = context.getDeviceAuthorization ? await context.getDeviceAuthorization() : null;
        const data = await rpc('checked_import', { p_generation: pending.generation, p_revision: pending.revision, p_operations: pending.operations }, authorization);
        const expected = new Set(pending.operations.map(op => op.operation_id));
        if (data?.generation !== pending.generation || !Array.isArray(data.results) || data.results.length !== expected.size ||
            !data.results.every((result: { operation_id: string; status: string }) => result.status === 'ok' && expected.delete(result.operation_id))) throw new Error('Import confirmation is incomplete. Check the saved import status.');
        await db.metadata.delete(pendingId(context));
        return pending.operations.length;
    } catch (error) {
        // These server errors guarantee the entire transaction was rejected, so it is safe to rebuild the review.
        if (error && typeof error === 'object' && 'code' in error && ['40001', '22023', '42501'].includes(String(error.code))) await db.metadata.delete(pendingId(context));
        throw error;
    }
}
