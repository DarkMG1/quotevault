import { decryptData } from './crypto';
import { decryptEnvelope, encryptEnvelope } from './device-crypto';
import type { Quote } from '../types';

export const QUOTE_CIPHERTEXT_SENTINEL = '$$E2E$$';

type QuoteMetadata = Pick<Quote, 'id' | 'vault_generation' | 'user_id' | 'created_at' | 'quote_date'>;
type QuoteFields = Record<string, unknown>;

const canonicalTimestamp = (value: unknown): string => {
    if (typeof value !== 'string') throw new Error('Invalid quote metadata.');
    const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(?:Z|\+00:00)$/.exec(value);
    if (!match) throw new Error('Invalid quote metadata.');
    const year = Number(match[1]);
    const month = Number(match[2]);
    const day = Number(match[3]);
    const hour = Number(match[4]);
    const minute = Number(match[5]);
    const second = Number(match[6]);
    const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if (year === 0 || month < 1 || month > 12 || day < 1 || day > days[month - 1] || hour > 23 || minute > 59 || second > 59) {
        throw new Error('Invalid quote metadata.');
    }
    const fraction = (match[7] ?? '').replace(/0+$/, '');
    return `${match[1]}-${match[2]}-${match[3]}T${match[4]}:${match[5]}:${match[6]}${fraction ? `.${fraction}` : ''}Z`;
};

const metadataOf = (quote: object): QuoteMetadata => {
    const fields = quote as QuoteFields;
    return {
        id: fields.id as string,
        vault_generation: fields.vault_generation as string,
        user_id: fields.user_id as string,
        created_at: canonicalTimestamp(fields.created_at),
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

const sameMetadata = (left: QuoteMetadata, right: QuoteMetadata): boolean =>
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
    const isV2 = bundle && typeof bundle === 'object' && (bundle as { version?: unknown }).version === 2;
    const hasCompleteVisibleMetadata = ['id', 'vault_generation', 'user_id', 'created_at'].every(field => field in stored);
    const metadata = hasCompleteVisibleMetadata ? metadataOf(storedQuote) : undefined;
    const validVisibleMetadata = metadata !== undefined && hasMetadata(metadata);

    let payload: unknown;
    if (isV2) {
        if (!metadata || !validVisibleMetadata) throw new Error('Invalid quote metadata.');
        try {
            payload = JSON.parse(await decryptEnvelope(bundle as Parameters<typeof decryptEnvelope>[0], key, aadOf(metadata)));
        } catch {
            throw new Error('Quote authenticated metadata mismatch.');
        }
        let payloadMetadata: QuoteMetadata;
        try { payloadMetadata = metadataOf(payload as object); } catch { throw new Error('Quote authenticated metadata mismatch.'); }
        if (!payload || typeof payload !== 'object' || !hasMetadata(payload as QuoteFields) || !sameMetadata(metadata, payloadMetadata)) {
            throw new Error('Quote authenticated metadata mismatch.');
        }
    } else {
        payload = JSON.parse(await decryptData(bundle as Parameters<typeof decryptData>[0], key));
    }
    if (!payload || typeof payload !== 'object') throw new Error('Invalid encrypted quote payload.');
    const visible = validVisibleMetadata ? {
        id: (stored as QuoteFields).id, vault_generation: (stored as QuoteFields).vault_generation,
        user_id: (stored as QuoteFields).user_id, created_at: (stored as QuoteFields).created_at,
        quote_date: (stored as QuoteFields).quote_date ?? null,
    } : {};
    return { ...(payload as QuoteFields), ...visible };
}
