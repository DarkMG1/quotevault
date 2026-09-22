import assert from 'node:assert/strict';
import { loadModule } from './load-module.mjs';
const { matchAuthor, matchedAuthorContext } = loadModule('src/lib/quote-authors.ts', {});
const profiles = [{first_name: 'Avery', last_name: 'Stone'}, {first_name: 'Rowan', last_name: 'Lee'}];
assert.equal(matchAuthor('avery', profiles), 'Avery Stone');
assert.equal(matchAuthor('\u00a0@Rowan Lee', profiles), 'Rowan Lee');
assert.equal(matchAuthor('Avery, rowan', profiles), 'Avery Stone & Rowan Lee');
assert.equal(matchAuthor('Avery and Rowan', profiles), 'Avery Stone & Rowan Lee');
assert.equal(matchAuthor('unknown person', profiles), 'unknown person');
assert.equal(matchAuthor('Unknown speakers', profiles), 'Unknown speakers');
assert.equal(matchAuthor('Avery', [...profiles, {first_name: 'Avery', last_name: 'Miles'}]), 'Avery');
assert.equal(matchAuthor('Avery to Rowan', profiles), 'Avery Stone');
assert.equal(matchedAuthorContext('Avery to Rowan', 'Avery Stone', 'Keep this context.'), 'Keep this context.\nOriginal attribution: Avery to Rowan.');
assert.equal(matchedAuthorContext('Avery', 'Avery Stone', 'Keep this context.'), 'Keep this context.');
console.log('Profile author matching preserves unknown and ambiguous names.');

assert.equal(matchAuthor('Outside, Guest', profiles), 'Outside, Guest');
assert.equal(matchedAuthorContext('Avery to Rowan', 'Avery Stone', 'Original attribution: Avery to Rowan.'), 'Original attribution: Avery to Rowan.');
