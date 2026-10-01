import type { Quote } from '../types';

type FilterableQuote = Pick<Quote, 'id' | 'text' | 'author' | 'context' | 'quote_date' | 'created_at'>;

export type SortOrder = 'newest' | 'oldest';

/** One source of truth for the feed: empty strings mean "no filter". Dates are inclusive YYYY-MM-DD. */
export interface QuoteFilters {
    text: string;
    author: string;
    from: string;
    to: string;
    order: SortOrder;
}

export const NO_FILTERS: QuoteFilters = { text: '', author: '', from: '', to: '', order: 'newest' };

/** The day a quote was said, falling back to the day it was saved. */
export const quoteDay = (quote: Pick<Quote, 'quote_date' | 'created_at'>) => quote.quote_date || quote.created_at.slice(0, 10);

const participants = (author: string) => author.split(' & ').map(name => name.trim()).filter(Boolean);

export function filterQuotes<T extends FilterableQuote>(quotes: T[], filters: QuoteFilters): T[] {
    const text = filters.text.trim().toLowerCase();
    const author = filters.author.trim().toLowerCase();
    const direction = filters.order === 'oldest' ? 1 : -1;
    return quotes
        .filter(quote => {
            const day = quoteDay(quote);
            return (!text || [quote.text, quote.author, quote.context].some(value => value?.toLowerCase().includes(text)))
                && (!author || participants(quote.author).some(name => name.toLowerCase() === author))
                && (!filters.from || day >= filters.from)
                && (!filters.to || day <= filters.to);
        })
        .sort((a, b) => direction * (quoteDay(a).localeCompare(quoteDay(b))
            || Date.parse(a.created_at) - Date.parse(b.created_at)
            || a.id.localeCompare(b.id)));
}

export function authorParticipants(quotes: Pick<Quote, 'author'>[]) {
    return [...new Set(quotes.flatMap(quote => participants(quote.author)))].sort((a, b) => a.localeCompare(b));
}
