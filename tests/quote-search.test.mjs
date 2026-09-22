import assert from 'node:assert/strict';
import { loadModule } from './load-module.mjs';

const { authorParticipants, parseQuoteSearch, replaceSearchTag, searchQuotes } = loadModule('src/lib/quote-search.ts', {});
const quotes = [
  { text: 'Garden party planning', author: 'Ada Lovelace & Grace Hopper', context: 'Summer party', quote_date: '2026-06-15', created_at: '2026-06-16T01:00:00Z' },
  { text: 'Compiler notes', author: 'Grace Hopper', context: 'Work', quote_date: '2026-07-01', created_at: '2026-07-01T01:00:00Z' },
  { text: 'Earlier thought', author: 'Ada Lovelace', context: 'Notebook', created_at: '2026-06-01T01:00:00Z' },
];

assert.deepEqual(searchQuotes(quotes, 'party').quotes, [quotes[0]]);
assert.deepEqual(searchQuotes(quotes, 'authors:"Grace Hopper" context:party date-range:2026-06-01..2026-06-30').quotes, [quotes[0]]);
assert.deepEqual(searchQuotes(quotes, 'authors:Ada').quotes, [quotes[0], quotes[2]], 'conversation participants are searchable individually');
assert.deepEqual(searchQuotes(quotes, 'date-range:..2026-06-01').quotes, [quotes[2]], 'created date supplies a missing quote date');
assert.equal(searchQuotes(quotes, 'date-range:2026-02-30..2026-03-01').error, 'Date range must use one valid YYYY-MM-DD range.');
assert.equal(searchQuotes(quotes, 'date-range:..').error, 'Date range must use one valid YYYY-MM-DD range.');
assert.equal(searchQuotes(quotes, 'date-range:2026-06-01..2026-06-30 date-range:2026-07-01..2026-07-31').error, 'Date range must use one valid YYYY-MM-DD range.');
assert.equal(parseQuoteSearch('authors:"Ada').error, 'Invalid authors filter.');
assert.equal(parseQuoteSearch('content:"said authors: hello"').error, undefined);
assert.equal(parseQuoteSearch('x-authors:Ada').freeText, 'x-authors:Ada');
assert.equal(replaceSearchTag('content:"said  authors: hello"', 'authors', 'Ada Lovelace'), 'content:"said  authors: hello" authors:"Ada Lovelace"');
assert.deepEqual(searchQuotes([{ ...quotes[0], text: 'speaker:Ada' }], 'speaker:Ada').quotes.length, 1, 'unknown tags remain literal text');
assert.deepEqual(Array.from(authorParticipants(quotes)), ['Ada Lovelace', 'Grace Hopper']);
console.log('Local quote search tags filter decrypted quotes without network access.');
