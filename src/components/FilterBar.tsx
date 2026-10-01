import { useState, type Dispatch, type ReactNode, type SetStateAction } from 'react';
import { Search, X, SlidersHorizontal, ArrowDownWideNarrow, ArrowUpNarrowWide } from 'lucide-react';
import type { QuoteFilters } from '../lib/quote-search';

const formatDay = (day: string) => new Date(`${day}T00:00:00Z`).toLocaleDateString(undefined, {
    month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC',
});

const toolButton = 'inline-flex flex-1 items-center justify-center gap-2 rounded-xl border px-3 py-3 text-sm sm:flex-none';
const dateInput = 'mt-1 w-full rounded-lg border border-slate-700 bg-slate-800 p-2 text-white [color-scheme:dark]';

interface FilterBarProps {
    filters: QuoteFilters;
    setFilters: Dispatch<SetStateAction<QuoteFilters>>;
    onClear: () => void;
    authors: string[];
    shown: number;
    total: number;
    /** Extra toolbar buttons, rendered after the sort toggle. */
    children: ReactNode;
}

export const FilterBar = ({ filters, setFilters, onClear, authors, shown, total, children }: FilterBarProps) => {
    const [open, setOpen] = useState(false);
    const update = (patch: Partial<QuoteFilters>) => setFilters(current => ({ ...current, ...patch }));
    const newest = filters.order === 'newest';
    const panelFilterCount = [filters.author, filters.from || filters.to].filter(Boolean).length;
    const reversedRange = Boolean(filters.from && filters.to && filters.from > filters.to);
    const dateChip = filters.from && filters.to ? `${formatDay(filters.from)} – ${formatDay(filters.to)}`
        : filters.from ? `From ${formatDay(filters.from)}`
            : filters.to ? `Until ${formatDay(filters.to)}`
                : '';
    const chips = [
        filters.text.trim() && { key: 'text', label: `“${filters.text.trim()}”`, clear: () => update({ text: '' }) },
        filters.author && { key: 'author', label: filters.author, clear: () => update({ author: '' }) },
        dateChip && { key: 'dates', label: dateChip, clear: () => update({ from: '', to: '' }) },
    ].filter((chip): chip is { key: string; label: string; clear: () => void } => Boolean(chip));

    return (
        <div className="space-y-3">
            <div className="flex w-full flex-wrap gap-2 sm:flex-nowrap">
                <div className="relative w-full sm:flex-1">
                    <Search aria-hidden="true" className="pointer-events-none absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-400" />
                    <label htmlFor="quote-search" className="sr-only">Search quotes, authors or context</label>
                    <input
                        id="quote-search"
                        type="search"
                        value={filters.text}
                        onChange={event => update({ text: event.target.value })}
                        placeholder="Search quotes, authors or context"
                        className="w-full rounded-xl border border-slate-700/50 bg-slate-800/50 py-3 pl-10 pr-10 text-white placeholder-slate-400 transition-all focus:outline-none focus:ring-2 focus:ring-primary-500 [&::-webkit-search-cancel-button]:hidden"
                    />
                    {filters.text && (
                        <button
                            type="button"
                            onClick={() => update({ text: '' })}
                            aria-label="Clear search"
                            className="absolute right-2 top-1/2 -translate-y-1/2 rounded-full p-1.5 text-slate-400 hover:text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary-500"
                        >
                            <X aria-hidden="true" className="h-4 w-4" />
                        </button>
                    )}
                </div>
                <button
                    type="button"
                    onClick={() => setOpen(value => !value)}
                    aria-expanded={open}
                    aria-controls="quote-filters"
                    className={`${toolButton} transition-colors ${panelFilterCount
                        ? 'border-primary-500/50 bg-primary-500/10 text-primary-400'
                        : 'border-slate-700/50 bg-slate-800/50 text-slate-300 hover:text-white'}`}
                >
                    <SlidersHorizontal aria-hidden="true" className="h-4 w-4" />
                    Filters
                    {panelFilterCount > 0 && <span className="rounded-full bg-primary-500 px-1.5 text-xs font-semibold text-white">{panelFilterCount}</span>}
                </button>
                <button
                    type="button"
                    onClick={() => update({ order: newest ? 'oldest' : 'newest' })}
                    aria-label={`Sorted ${newest ? 'newest' : 'oldest'} first. Switch to ${newest ? 'oldest' : 'newest'} first`}
                    className={`${toolButton} border-slate-700/50 bg-slate-800/50 text-slate-300 hover:text-white`}
                >
                    {newest
                        ? <ArrowDownWideNarrow aria-hidden="true" className="h-4 w-4" />
                        : <ArrowUpNarrowWide aria-hidden="true" className="h-4 w-4" />}
                    <span className="whitespace-nowrap">
                        <span className="sm:hidden">{newest ? 'Newest' : 'Oldest'}</span>
                        <span className="hidden sm:inline">{newest ? 'Newest first' : 'Oldest first'}</span>
                    </span>
                </button>
                {children}
            </div>

            {open && (
                <div id="quote-filters" className="grid gap-3 rounded-xl border border-slate-700/50 bg-slate-800/30 p-3 sm:grid-cols-[2fr_1fr_1fr]">
                    <div>
                        <label htmlFor="filter-author" className="block text-sm text-slate-300">Author</label>
                        <select
                            id="filter-author"
                            value={filters.author}
                            onChange={event => update({ author: event.target.value })}
                            className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-800 p-2 text-white"
                        >
                            <option value="">Any author</option>
                            {filters.author && !authors.includes(filters.author) && <option value={filters.author}>{filters.author}</option>}
                            {authors.map(author => <option key={author} value={author}>{author}</option>)}
                        </select>
                    </div>
                    <div>
                        <label htmlFor="filter-from" className="block text-sm text-slate-300">From</label>
                        <input id="filter-from" type="date" value={filters.from} max={filters.to || undefined}
                            onChange={event => update({ from: event.target.value })} className={dateInput} />
                    </div>
                    <div>
                        <label htmlFor="filter-to" className="block text-sm text-slate-300">To</label>
                        <input id="filter-to" type="date" value={filters.to} min={filters.from || undefined}
                            onChange={event => update({ to: event.target.value })} className={dateInput} />
                    </div>
                    {reversedRange && (
                        <p role="alert" className="text-sm text-amber-300 sm:col-span-3">
                            The From date is after the To date, so no quotes can match.
                        </p>
                    )}
                </div>
            )}

            {chips.length > 0 && (
                <div role="group" className="flex flex-wrap items-center gap-2" aria-label="Active filters">
                    {chips.map(chip => (
                        <span key={chip.key} className="inline-flex items-center gap-1 rounded-full border border-primary-500/30 bg-primary-500/10 py-1 pl-3 pr-1 text-sm text-slate-100">
                            {chip.label}
                            <button
                                type="button"
                                onClick={chip.clear}
                                aria-label={`Remove filter ${chip.label}`}
                                className="rounded-full p-1 text-primary-400 hover:bg-primary-500/20 hover:text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary-500"
                            >
                                <X aria-hidden="true" className="h-3.5 w-3.5" />
                            </button>
                        </span>
                    ))}
                    <button type="button" onClick={onClear} className="text-sm text-slate-400 underline-offset-2 hover:text-white hover:underline">
                        Clear all
                    </button>
                    <span role="status" aria-live="polite" className="ml-auto text-sm text-slate-500">Showing {shown} of {total}</span>
                </div>
            )}
        </div>
    );
};
