import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

test('client build guard accepts public configuration and rejects privileged or extra values', () => {
  const leaseKey = JSON.stringify({ kty: 'EC', crv: 'P-256', x: 'MCX_q9izENHf7RapICXq_vaA5qThNU284THSt3jzQtY', y: 'n5VOaBm-oCqL1jaepPAi7Q3bMoHo6M97nfhr-e0QcfA' });
  const check = values => spawnSync(process.execPath, ['scripts/check-client-env.mjs'], {
    cwd: new URL('../', import.meta.url),
    env: { ...process.env, VITE_SUPABASE_URL: 'https://example.supabase.co',
      VITE_SUPABASE_ANON_KEY: 'sb_publishable_test_only', VITE_DEVICE_LEASE_PUBLIC_JWK: leaseKey, ...values },
    encoding: 'utf8',
  }).status;
  assert.equal(check({}), 0);
  assert.notEqual(check({ VITE_SUPABASE_ANON_KEY: 'sb_secret_test_only' }), 0);
  const privilegedJwt = 'test.' + Buffer.from(JSON.stringify({ role: 'service_role' })).toString('base64url') + '.test';
  assert.notEqual(check({ VITE_SUPABASE_ANON_KEY: privilegedJwt }), 0);
  assert.notEqual(check({ VITE_PRIVATE_PASSWORD: 'test-only' }), 0);
  assert.notEqual(check({ VITE_SUPABASE_URL: 'http://example.supabase.co' }), 0);
  assert.notEqual(check({ VITE_DEVICE_LEASE_PUBLIC_JWK: '{}' }), 0);
  assert.notEqual(check({ VITE_DEVICE_LEASE_PUBLIC_JWK: '' }), 0);
});
