import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { loadModule } from './load-module.mjs';

const api = loadModule('src/lib/recovery-phrase.ts', {}, { crypto: webcrypto, TextEncoder, TextDecoder });

test('the recovery word list is fixed, human-readable, and unique', () => {
  assert.equal(api.RECOVERY_WORDS.length, 256);
  assert.equal(new Set(api.RECOVERY_WORDS).size, 256);
  assert.ok(api.RECOVERY_WORDS.every(word => /^[a-z]+$/.test(word)));
});

test('phrase generation maps sixteen independent random bytes to sixteen words', () => {
  const original = webcrypto.getRandomValues;
  webcrypto.getRandomValues = value => {
    assert.equal(value.byteLength, 16);
    value.forEach((_, index) => { value[index] = index; });
    return value;
  };
  try {
    assert.deepEqual(api.generateRecoveryPhrase(), api.RECOVERY_WORDS.slice(0, 16));
  } finally {
    webcrypto.getRandomValues = original;
  }
});

test('confirmation positions are three distinct unbiased byte residues', () => {
  const positions = api.recoveryConfirmationPositions();
  assert.equal(positions.length, 3);
  assert.equal(new Set(positions).size, 3);
  assert.ok(positions.every(position => Number.isInteger(position) && position >= 0 && position < 16));
});

test('confirmation requires the requested words at exactly the requested positions', () => {
  const phrase = api.RECOVERY_WORDS.slice(0, 16);
  const positions = [1, 7, 12];
  assert.equal(api.confirmRecoveryPhrase(phrase, positions.map(position => phrase[position]), positions), true);
  assert.equal(api.confirmRecoveryPhrase(phrase, ['wrong', phrase[7], phrase[12]], positions), false);
  assert.equal(api.confirmRecoveryPhrase(phrase, phrase.slice(0, 2), positions), false);
});
