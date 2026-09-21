import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

test('client build guard accepts public configuration and rejects privileged or extra values', () => {
  const check = values => spawnSync(process.execPath, ['scripts/check-client-env.mjs'], {
    cwd: new URL('../', import.meta.url),
    env: { ...process.env, VITE_SUPABASE_URL: 'https://example.supabase.co',
      VITE_SUPABASE_ANON_KEY: 'sb_publishable_test_only', ...values },
    encoding: 'utf8',
  }).status;
  assert.equal(check({}), 0);
  assert.notEqual(check({ VITE_SUPABASE_ANON_KEY: 'sb_secret_test_only' }), 0);
  const privilegedJwt = 'test.' + Buffer.from(JSON.stringify({ role: 'service_role' })).toString('base64url') + '.test';
  assert.notEqual(check({ VITE_SUPABASE_ANON_KEY: privilegedJwt }), 0);
  assert.notEqual(check({ VITE_PRIVATE_PASSWORD: 'test-only' }), 0);
  assert.notEqual(check({ VITE_SUPABASE_URL: 'http://example.supabase.co' }), 0);
});
