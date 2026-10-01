import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests/browser',
  workers: 1,
  retries: 0,
  use: { baseURL: 'http://127.0.0.1:5180', viewport: { width: 390, height: 844 }, trace: 'retain-on-failure' },
  webServer: [
    { command: 'node tests/browser-server.mjs', url: 'http://127.0.0.1:54329/stats', reuseExistingServer: false },
    { command: 'npm run build:smoke && npm run preview -- --host 127.0.0.1 --port 5180 --outDir dist-smoke.local', url: 'http://127.0.0.1:5180', reuseExistingServer: false, timeout: 120000 },
  ],
});
