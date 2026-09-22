import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { loadModule } from './load-module.mjs';

const cryptoModule = loadModule('src/lib/crypto.ts', {}, { crypto: webcrypto, TextEncoder, TextDecoder, btoa, atob });
const deviceCrypto = loadModule('src/lib/device-crypto.ts', { './crypto': cryptoModule }, { crypto: webcrypto, TextEncoder, TextDecoder, btoa, atob });
const device = loadModule('src/lib/device.ts', {
  './db': { db: { deviceState: {} } },
  './supabase': { supabase: { rpc: async () => ({ data: null, error: null }) } },
  './crypto': cryptoModule,
  './device-crypto': deviceCrypto,
}, { crypto: webcrypto, TextEncoder, TextDecoder, btoa, atob });

test('enrollment code is a deterministic Crockford code bound to the fingerprint', async () => {
  const fingerprint = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  assert.equal(await device.formatEnrollmentCode(fingerprint), 'XKHA-TS07');
  assert.equal(await device.formatEnrollmentCode(fingerprint), await device.formatEnrollmentCode(fingerprint));
});

test('enrollment code rejects non-canonical fingerprints', async () => {
  await assert.rejects(device.formatEnrollmentCode('A'.repeat(42)));
  await assert.rejects(device.formatEnrollmentCode(`${'A'.repeat(43)}=`));
  await assert.rejects(device.formatEnrollmentCode('!'.repeat(43)));
});
