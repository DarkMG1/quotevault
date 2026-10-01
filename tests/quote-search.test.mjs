import assert from 'node:assert/strict';
import { loadModule } from './load-module.mjs';

const { NO_FILTERS, authorParticipants, filterQuotes } = loadModule('src/lib/quote-search.ts', {});
const quotes = [
  { id: 'a', text: 'Garden party planning', author: 'Ada Lovelace & Grace Hopper', context: 'Summer party', quote_date: '2026-06-15', created_at: '2026-06-16T01:00:00Z' },
  { id: 'b', text: 'Compiler notes', author: 'Grace Hopper', context: 'Work', quote_date: '2026-07-01', created_at: '2026-07-01T01:00:00Z' },
  { id: 'c', text: 'Earlier thought', author: 'Ada Lovelace', context: 'Notebook', quote_date: null, created_at: '2026-06-01T01:00:00Z' },
  { id: 'd', text: 'Adam speaks', author: 'Adam Smith', context: null, quote_date: '2026-06-15', created_at: '2026-06-15T09:00:00Z' },
];
const ids = (result) => JSON.stringify(Array.from(result, quote => quote.id));
const run = (patch) => ids(filterQuotes(quotes, { ...NO_FILTERS, ...patch }));

assert.equal(run({}), JSON.stringify(['b', 'a', 'd', 'c']), 'newest first by default, ties broken by creation time');
assert.equal(run({ order: 'oldest' }), JSON.stringify(['c', 'd', 'a', 'b']), 'oldest first when toggled');
assert.equal(run({ text: 'PARTY' }), JSON.stringify(['a']), 'search is case-insensitive');
assert.equal(run({ text: 'notebook' }), JSON.stringify(['c']), 'search covers context');
assert.equal(run({ text: 'grace' }), JSON.stringify(['b', 'a']), 'search covers authors');
assert.equal(run({ author: 'Ada Lovelace' }), JSON.stringify(['a', 'c']), 'author filter matches each participant of a multi-author quote');
assert.equal(run({ author: 'ada' }), JSON.stringify([]), 'author filter is an exact participant, not a substring of "Adam" or "Ada Lovelace"');
assert.equal(run({ from: '2026-06-15', to: '2026-06-15' }), JSON.stringify(['a', 'd']), 'date bounds are inclusive');
assert.equal(run({ to: '2026-06-01' }), JSON.stringify(['c']), 'the creation date stands in for a missing quote date');
assert.equal(run({ from: '2026-07-02' }), JSON.stringify([]));
assert.equal(run({ from: '2026-07-01', to: '2026-06-01' }), JSON.stringify([]), 'a reversed range matches nothing instead of erroring');
const filtered = { ...NO_FILTERS, text: 'party', author: 'Grace Hopper', from: '2026-06-01', to: '2026-06-30' };
assert.equal(ids(filterQuotes(quotes, { ...filtered, text: '', author: '', from: '', to: '' })), run({}), 'clearing every filter restores the full feed');
assert.equal(run({ text: '   ' }), run({}), 'whitespace-only search is no filter');
assert.equal(quotes.map(quote => quote.id).join(''), 'abcd', 'filtering never reorders the caller\'s array');
assert.deepEqual(Array.from(authorParticipants(quotes)), ['Ada Lovelace', 'Adam Smith', 'Grace Hopper']);
console.log('Quote filters search, filter by exact author and inclusive dates, and sort newest first by default.');
