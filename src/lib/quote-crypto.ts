import { decryptData } from './crypto';
import { decryptEnvelope, encryptEnvelope } from './device-crypto';
import type { Quote } from '../types';

export const QUOTE_CIPHERTEXT_SENTINEL = '$$E2E$$';

type QuoteMetadata = Pick<Quote, 'id' | 'vault_generation' | 'user_id' | 'created_at' | 'quote_date'>;
type QuoteFields = Record<string, unknown>;

const metadataOf = (quote: object): QuoteMetadata => {
    const fields = quote as QuoteFields;
    return {
        id: fields.id as string,
        vault_generation: fields.vault_generation as string,
        user_id: fields.user_id as string,
        created_at: fields.created_at as string,
        quote_date: fields.quote_date === undefined ? null : fields.quote_date as string | null,
    };
};

const aadOf = (metadata: QuoteMetadata): string => JSON.stringify([
    2, metadata.id, metadata.vault_generation, metadata.user_id, metadata.created_at, metadata.quote_date,
]);

const hasMetadata = (value: object): boolean => {
    const fields = value as QuoteFields;
    return typeof fields.id === 'string' && typeof fields.vault_generation === 'string' &&
    typeof fields.user_id === 'string' && typeof fields.created_at === 'string' &&
    (fields.quote_date === null || typeof fields.quote_date === 'string');
};

const sameMetadata = (left: QuoteMetadata, right: QuoteFields): boolean =>
    left.id === right.id && left.vault_generation === right.vault_generation &&
    left.user_id === right.user_id && left.created_at === right.created_at &&
    left.quote_date === (right.quote_date ?? null);

export async function encryptQuoteRecord(privateFields: QuoteFields, visibleFields: object & QuoteMetadata, key: CryptoKey): Promise<QuoteFields> {
    const metadata = metadataOf(visibleFields);
    if (!hasMetadata(metadata)) throw new Error('Invalid quote metadata.');
    const payload = { ...privateFields, ...metadata };
    const envelope = await encryptEnvelope(JSON.stringify(payload), key, aadOf(metadata));
    return { ...visibleFields, text: `${QUOTE_CIPHERTEXT_SENTINEL}${JSON.stringify(envelope)}` };
}

export async function decryptQuoteRecord(storedQuote: object, key: CryptoKey): Promise<QuoteFields> {
    const stored = storedQuote as QuoteFields;
    if (typeof stored.text !== 'string' || !stored.text.startsWith(QUOTE_CIPHERTEXT_SENTINEL)) {
        throw new Error('Quote is not encrypted.');
    }
    const bundle: unknown = JSON.parse(stored.text.slice(QUOTE_CIPHERTEXT_SENTINEL.length));
    const metadata = metadataOf(storedQuote);
    const validVisibleMetadata = hasMetadata(metadata);

    let payload: unknown;
    if (bundle && typeof bundle === 'object' && (bundle as { version?: unknown }).version === 2) {
        if (!validVisibleMetadata) throw new Error('Invalid quote metadata.');
        try {
            payload = JSON.parse(await decryptEnvelope(bundle as Parameters<typeof decryptEnvelope>[0], key, aadOf(metadata)));
        } catch {
            throw new Error('Quote authenticated metadata mismatch.');
        }
        if (!payload || typeof payload !== 'object' || !hasMetadata(payload as QuoteFields) || !sameMetadata(metadata, payload as QuoteFields)) {
            throw new Error('Quote authenticated metadata mismatch.');
        }
    } else {
        payload = JSON.parse(await decryptData(bundle as Parameters<typeof decryptData>[0], key));
    }
    if (!payload || typeof payload !== 'object') throw new Error('Invalid encrypted quote payload.');
    return { ...(payload as QuoteFields), ...(validVisibleMetadata ? metadata : {}) };
}
