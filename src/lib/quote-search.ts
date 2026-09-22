import type { Quote } from '../types';

type SearchableQuote = Pick<Quote, 'text' | 'author' | 'context' | 'quote_date' | 'created_at'>;

export interface QuoteSearch {
    freeText: string;
    authors: string[];
    content: string[];
    context: string[];
    startDate?: string;
    endDate?: string;
    error?: string;
}

const dateValue = (value: string) => {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
    const date = new Date(`${value}T00:00:00Z`);
    return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === value;
};

function readTag(query: string, index: number) {
    const match = /^(authors|content|context|date-range):/i.exec(query.slice(index));
    if (!match) return;
    const key = match[1].toLowerCase();
    const valueStart = index + match[0].length;
    if (query[valueStart] === '"') {
        const close = query.indexOf('"', valueStart + 1);
        return close < 0 ? { key, value: '', end: query.length, invalid: true } : { key, value: query.slice(valueStart + 1, close), end: close + 1 };
    }
    const end = query.slice(valueStart).search(/\s/);
    const valueEnd = end < 0 ? query.length : valueStart + end;
    return { key, value: query.slice(valueStart, valueEnd), end: valueEnd };
}

export function parseQuoteSearch(query: string): QuoteSearch {
    const parsed: QuoteSearch = { freeText: '', authors: [], content: [], context: [] };
    let plain = '';
    let dateRangeSeen = false;
    for (let index = 0; index < query.length;) {
        const tag = (!index || /\s/.test(query[index - 1])) && readTag(query, index);
        if (!tag) { plain += query[index++]; continue; }
        const { key, value, end, invalid } = tag;
        if (!value.trim() || invalid) return { ...parsed, error: `Invalid ${key} filter.` };
        if (key === 'date-range') {
            const bounds = value.split('..');
            if (dateRangeSeen || bounds.length !== 2 || (!bounds[0] && !bounds[1]) || (bounds[0] && !dateValue(bounds[0])) || (bounds[1] && !dateValue(bounds[1])) || (bounds[0] && bounds[1] && bounds[0] > bounds[1])) return { ...parsed, error: 'Date range must use one valid YYYY-MM-DD range.' };
            dateRangeSeen = true;
            parsed.startDate = bounds[0] || undefined;
            parsed.endDate = bounds[1] || undefined;
        } else if (key === 'authors') parsed.authors.push(value);
        else if (key === 'content') parsed.content.push(value);
        else parsed.context.push(value);
        index = end;
    }
    parsed.freeText = plain.trim();
    return parsed;
}

export function searchQuotes<T extends SearchableQuote>(quotes: T[], query: string): { quotes: T[]; error?: string } {
    const search = parseQuoteSearch(query);
    if (search.error) return { quotes: [], error: search.error };
    const contains = (value: string | null | undefined, terms: string[]) => terms.every(term => value?.toLowerCase().includes(term.toLowerCase()));
    return { quotes: quotes.filter(quote => {
        const date = quote.quote_date || quote.created_at.slice(0, 10);
        return (!search.freeText || contains(quote.text, [search.freeText]) || contains(quote.author, [search.freeText])) &&
            contains(quote.author, search.authors) && contains(quote.text, search.content) && contains(quote.context, search.context) &&
            (!search.startDate || date >= search.startDate) && (!search.endDate || date <= search.endDate);
    }), error: undefined };
}

export function authorParticipants(quotes: SearchableQuote[]) {
    return [...new Set(quotes.flatMap(quote => quote.author.split(' & ').map(name => name.trim()).filter(Boolean)))].sort((a, b) => a.localeCompare(b));
}

export function replaceSearchTag(query: string, tag: 'authors' | 'date-range', value: string) {
    const next = value ? `${tag}:${/[\s"]/.test(value) ? `"${value.replaceAll('"', '')}"` : value}` : '';
    let replaced = false;
    let output = '';
    for (let index = 0; index < query.length;) {
        const found = (!index || /\s/.test(query[index - 1])) && readTag(query, index);
        if (!found) { output += query[index++]; continue; }
        if (found.key !== tag) { output += query.slice(index, found.end); index = found.end; continue; }
        if (!replaced) output += next;
        replaced = true;
        index = found.end;
    }
    return (replaced ? output : [output, next].filter(Boolean).join(' ')).trim();
}
