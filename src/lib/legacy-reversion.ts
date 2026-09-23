import { createVaultConfig, decryptData } from './crypto';
import { decryptQuoteRecord, encryptLegacyQuoteText, QUOTE_CIPHERTEXT_SENTINEL } from './quote-crypto';
import { loadMigrationSourceSnapshot, MIGRATION_BATCH_SIZE } from './vault-migration';
import { supabase } from './supabase';

export interface LegacyReversionInput {
    sourceGeneration: string; sourceKey: CryptoKey; passphrase: string; deviceId: string | null; token: string | null;
    dryRun?: boolean; onProgress?: (done: number, total: number) => void;
}
export interface LegacyReversionResult { quoteCount: number; generation: string | null }

const VISIBLE = ['id', 'vault_generation', 'user_id', 'created_at', 'quote_date'];

async function call(name: string, args: Record<string, unknown>): Promise<Record<string, unknown>> {
    const { data, error } = await (supabase.rpc(name, args) as unknown as Promise<{ data: unknown; error: { code?: string; message?: string } | null }>);
    if (error) throw Object.assign(new Error(error.message || `${name} failed. Nothing was changed.`), { code: error.code });
    if (!data || typeof data !== 'object') throw new Error(`${name} returned no result. Nothing was changed.`);
    return data as Record<string, unknown>;
}

/** Re-encrypts every quote to pre-envelope v1 under a new shared passphrase; verifies all rows before any write. */
export async function revertToLegacy(input: LegacyReversionInput): Promise<LegacyReversionResult> {
    const config = await createVaultConfig(input.passphrase);
    const snapshot = await loadMigrationSourceSnapshot({ sourceGeneration: input.sourceGeneration, deviceId: input.deviceId, token: input.token });
    const rows: Array<{ quote_id: string; text: string }> = [];
    for (const quote of snapshot.quotes) {
        let fields: Record<string, unknown>;
        try { fields = { ...await decryptQuoteRecord(quote, input.sourceKey) }; } catch { throw new Error(`Quote ${quote.id} could not be decrypted. Nothing was changed.`); }
        for (const name of VISIBLE) delete fields[name];
        if (typeof fields.text !== 'string' || typeof fields.author !== 'string' ||
            fields.context !== undefined && typeof fields.context !== 'string' ||
            fields.source_sender !== undefined && typeof fields.source_sender !== 'string') throw new Error(`Quote ${quote.id} has no text or author for the shared-key client. Nothing was changed.`);
        const text = await encryptLegacyQuoteText(fields, config.key);
        if (await decryptData(JSON.parse(text.slice(QUOTE_CIPHERTEXT_SENTINEL.length)), config.key) !== JSON.stringify(fields)) throw new Error(`Quote ${quote.id} failed verification. Nothing was changed.`);
        rows.push({ quote_id: quote.id, text });
        input.onProgress?.(rows.length, snapshot.quotes.length);
    }
    if (input.dryRun) return { quoteCount: rows.length, generation: null };
    const auth = { p_device_id: input.deviceId, p_token: input.token };
    const begun = await call('begin_legacy_reversion', { p_source_generation: input.sourceGeneration, p_source_revision: snapshot.revision, ...auth });
    if (Number(begun.expected_quote_count) !== rows.length) throw new Error('The vault changed while it was being read. Nothing was changed; start again.');
    for (let start = 0; start < rows.length; start += MIGRATION_BATCH_SIZE) {
        await call('stage_legacy_reversion', { p_reversion_id: begun.reversion_id, p_rows: rows.slice(start, start + MIGRATION_BATCH_SIZE), ...auth });
    }
    const committed = await call('commit_legacy_reversion', { p_reversion_id: begun.reversion_id, p_kdf: config.kdf, p_verifier: config.verifier, ...auth });
    return { quoteCount: rows.length, generation: String(committed.generation) };
}
