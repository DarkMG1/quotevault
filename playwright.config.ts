import { defineConfig } from '@playwright/test';
import { createPrivateKey, createPublicKey, generateKeyPairSync } from 'node:crypto';

// Ephemeral signer shared by test workers; only its public half enters the build.
process.env.QV_TEST_LEASE_PRIVATE_JWK ??= JSON.stringify(generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ format: 'jwk' }));
const leasePublicKey = createPublicKey(createPrivateKey({ key: JSON.parse(process.env.QV_TEST_LEASE_PRIVATE_JWK), format: 'jwk' })).export({ format: 'jwk' });

export default defineConfig({
  testDir: './tests/browser',
  workers: 1,
  retries: 0,
  use: { baseURL: 'http://127.0.0.1:5180', viewport: { width: 390, height: 844 }, trace: 'retain-on-failure' },
  webServer: [
    { command: 'node tests/browser-server.mjs', url: 'http://127.0.0.1:54329/stats', reuseExistingServer: false },
    { command: 'npm run build -- --outDir dist-smoke.local && npm run preview -- --host 127.0.0.1 --port 5180 --outDir dist-smoke.local', url: 'http://127.0.0.1:5180', reuseExistingServer: false, timeout: 120000,
      env: { VITE_SUPABASE_URL: 'http://127.0.0.1:54329', VITE_SUPABASE_ANON_KEY: 'local-test-key', VITE_DEVICE_LEASE_PUBLIC_JWK: JSON.stringify(leasePublicKey) } },
  ],
});
