import { decryptQuoteRecord, encryptQuoteRecord } from './quote-crypto';
import { supabase } from './supabase';
import { isCiphertextWithinLimit, isDecryptedPayload } from '../components/ui';
import type { Quote } from '../types';
import { matchedAuthorContext } from './quote-authors';

export async function readQuotePayload(original: Quote, key: CryptoKey) {
    if (!original.text.startsWith('$$E2E$$') || original.sync_status === 'pending' || original.sync_status === 'rejected') {
        throw new Error('Sync this quote before editing.');
    }
    const payload: unknown = await decryptQuoteRecord(original, key);
    if (!isDecryptedPayload(payload)) throw new Error('This quote could not be decrypted safely.');
    return payload as typeof payload & { import_source_id?: string };
}

async function buildEdit(original: Quote, changes: { text?: string; author: string; context?: string }, quoteDate: string | null, key: CryptoKey) {
    const payload = await readQuotePayload(original, key);
    // Keep encrypted provenance and unedited fields exactly as stored.
    const updated = { ...payload, ...changes };
    if (!updated.text.trim() || !updated.author.trim()) throw new Error('Enter a quote and an author.');
    const encrypted = await encryptQuoteRecord(updated, { ...original, quote_date: quoteDate }, key);
    const text = encrypted.text as string;
    if (!text.startsWith('$$E2E$$')) throw new Error('This quote could not be encrypted safely.');
    if (!isCiphertextWithinLimit(JSON.parse(text.slice(7)))) throw new Error('This quote is too large to save.');
    return { quote_id: original.id, expected_text: original.text, text, quote_date: quoteDate };
}

async function editRequest(name: 'edit_quote' | 'edit_quotes', args: Record<string, unknown>, active: () => boolean,
    getDeviceAuthorization?: () => Promise<{ deviceId: string; token: string }>) {
    if (!active() || !navigator.onLine) throw new Error('Connect and unlock the vault before editing.');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 20000);
    try {
        const authorization = getDeviceAuthorization ? await getDeviceAuthorization() : null;
        const { data, error } = await supabase.rpc(name, {
            ...args, p_device_id: authorization?.deviceId ?? null, p_device_token: authorization?.token ?? null,
        }).abortSignal(controller.signal);
        if (error) {
            if (error.code === '40001') throw new Error('This quote or vault changed. Your draft is still here; copy it before closing, then sync and reopen.');
            throw new Error(error.message || 'Could not confirm the edit. Your draft is still here.');
        }
        if (data === null) throw new Error('Device authorization was denied. Unlock this device and retry the edit.');
        return data;
    } finally { clearTimeout(timer); }
}

export async function saveQuoteEdit(original: Quote, changes: { text: string; author: string; context: string; quoteDate: string }, key: CryptoKey, active: () => boolean,
    getDeviceAuthorization?: () => Promise<{ deviceId: string; token: string }>) {
    if (!navigator.onLine || !active()) throw new Error('Connect and unlock the vault before editing.');
    const edit = await buildEdit(original, { text: changes.text.trim(), author: changes.author.trim(), context: changes.context.trim() }, changes.quoteDate || null, key);
    await editRequest('edit_quote', { p_generation: original.vault_generation, p_quote_id: edit.quote_id,
        p_expected_text: edit.expected_text, p_text: edit.text, p_quote_date: edit.quote_date }, active, getDeviceAuthorization);
}

export async function saveAuthorMatches(rows: { quote: Quote; author: string }[], key: CryptoKey, active: () => boolean,
    getDeviceAuthorization?: () => Promise<{ deviceId: string; token: string }>) {
    if (!rows.length || rows.length > 500) throw new Error('Choose 1–500 author corrections.');
    const generation = rows[0].quote.vault_generation;
    if (rows.some(row => row.quote.vault_generation !== generation)) throw new Error('Vault changed; reopen author matching.');
    const edits = await Promise.all(rows.map(async row => {
        const payload = await readQuotePayload(row.quote, key);
        if (!payload.import_source_id) throw new Error('Author matching only changes imported quotes.');
        const author = row.author.trim();
        return buildEdit(row.quote, { author, ...(matchedAuthorContext(payload.author, author, payload.context) !== (payload.context || '')
            ? { context: matchedAuthorContext(payload.author, author, payload.context) } : {}) }, row.quote.quote_date || null, key);
    }));
    if (new TextEncoder().encode(JSON.stringify(edits)).length > 800 * 1024) throw new Error('Too many corrections for one batch. Apply fewer names at a time.');
    const result = await editRequest('edit_quotes', { p_generation: generation, p_edits: edits }, active, getDeviceAuthorization);
    if (result?.updated !== rows.length) throw new Error('Could not confirm all corrections. Close and sync before retrying.');
}
