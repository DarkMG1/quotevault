import type { Quote } from '../types';
import { decryptQuoteForDisplay } from './ui';

type Decrypted = Promise<Partial<Quote>>;

/** In-memory only: plaintext must never be persisted. */
export interface DecryptCache {
    key: CryptoKey | null;
    entries: Map<string, Decrypted>;
}

/**
 * Decrypts the feed, reusing plaintext for rows whose id and ciphertext are unchanged under the same key.
 * The returned cache holds only the given rows.
 */
export function decryptForFeed(quotes: Quote[], key: CryptoKey | null, previous?: DecryptCache) {
    const reusable = previous?.key === key ? previous.entries : undefined;
    const entries = new Map<string, Decrypted>();
    const decrypted = Promise.all(quotes.map(quote => {
        const id = `${quote.id}\n${quote.text}`;
        // Only the ciphertext goes in, so the cached fields stay valid when other row fields (e.g. sync_status) change.
        const fields = reusable?.get(id) ?? decryptQuoteForDisplay({ text: quote.text } as Quote, key);
        entries.set(id, fields);
        return fields.then(plain => {
            const result = { ...quote };
            delete result.source_sender;
            return Object.assign(result, plain);
        });
    }));
    return { cache: { key, entries }, decrypted };
}
