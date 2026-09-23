import { test, expect, type Page } from '@playwright/test';
import { webcrypto } from 'node:crypto';
import { loadModule } from '../load-module.mjs';

const accountId = '22222222-2222-4222-8222-222222222222';
const generation = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const ADMIN_EMAIL = 'darkmgdevelopment@gmail.com';
const globals = { crypto: webcrypto, TextEncoder, TextDecoder, btoa, atob, Uint8Array };
const legacy = loadModule('src/lib/crypto.ts', {}, globals);
const crypt = loadModule('src/lib/device-crypto.ts', { './crypto': legacy }, globals);
const quotes = loadModule('src/lib/quote-crypto.ts', { './crypto': legacy, './device-crypto': crypt }, globals);

async function signIn(page: Page, email = 'browser-test@example.com') {
  await page.goto('/');
  await page.locator('input[type=email]').fill(email);
  await page.locator('input[type=password]').fill('local-test-password');
  await page.getByRole('button', { name: 'Sign In', exact: true }).click();
}

async function activeVault(page: Page) {
  await page.route('**/rest/v1/rpc/get_vault_bootstrap_state', route => route.fulfill({ json: { envelope_status: 'active', generation, prepared_generation: null } }));
}

test('a new device shows its approval code and can check approval after reload', async ({ page }) => {
  await activeVault(page);
  let request: Record<string, string>;
  await page.route('**/rest/v1/rpc/request_device', route => {
    request = route.request().postDataJSON();
    return route.fulfill({ json: { request_id: request.p_device_id, device_id: request.p_device_id,
      enrollment_fingerprint: request.p_enrollment_fingerprint, expires_at: new Date(Date.now() + 600000).toISOString() } });
  });
  await page.route('**/rest/v1/rpc/get_device_request', route => route.fulfill({ json: {
    request_id: request.p_device_id, owner_id: accountId, request_kind: 'first', label: request.p_label,
    public_jwk: request.p_public_jwk, public_key_fingerprint: request.p_public_key_fingerprint,
    authorization_token_digest: request.p_token_digest, enrollment_fingerprint: request.p_enrollment_fingerprint,
    protection_mode: request.p_protection_mode, protection: request.p_protection,
    expires_at: new Date(Date.now() + 600000).toISOString(),
  } }));
  await signIn(page);
  await page.getByRole('button', { name: 'Remember this device', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Device approval pending' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Open approval request' })).toBeVisible();
  await expect(page.getByRole('img', { name: 'Device approval QR code' })).toBeVisible();
  await page.reload();
  await expect(page.getByRole('button', { name: 'Check approval', exact: true })).toBeVisible();
});

async function rememberedDevice(page: Page, recoverySetupRequired = false, email = 'browser-test@example.com') {
  const deviceId = webcrypto.randomUUID();
  const pair = await crypt.generateWrappingKeyPair();
  const publicJwk = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
  const fingerprint = await crypt.fingerprintPublicJwk(publicJwk);
  const rawKey = webcrypto.getRandomValues(new Uint8Array(32));
  const key = await webcrypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt', 'decrypt']);
  const token = crypt.generateAuthorizationToken();
  const encryptedPrivateBundle = await crypt.encryptPrivateBundle({ version: 1,
    privateJwk: await webcrypto.subtle.exportKey('jwk', pair.privateKey), authorizationToken: token }, key,
  { accountId, recordId: deviceId, publicKeyFingerprint: fingerprint, protectionMode: 'remembered', version: 1 });
  const masterKey = webcrypto.getRandomValues(new Uint8Array(32));
  const wrappedKey = await crypt.wrapVaultKey({ version: 1, vaultId: 'quotevault', generation, targetFingerprint: fingerprint, masterKey }, pair.publicKey);
  const signingKey = await webcrypto.subtle.importKey('jwk', JSON.parse(process.env.QV_TEST_LEASE_PRIVATE_JWK!), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const claims = [1, deviceId, accountId, generation, Date.now(), Date.now() + 30 * 86400000, fingerprint];
  claims[5] = Number(claims[4]) + 30 * 86400000;
  const lease = { version: 1, claims, signature: Buffer.from(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, signingKey, new TextEncoder().encode(JSON.stringify(claims)))).toString('base64') };
  const quote = await quotes.encryptQuoteRecord({ text: 'Envelope browser secret', author: 'Demo Tester', context: 'Synthetic device test' },
    { id: webcrypto.randomUUID(), user_id: accountId, vault_generation: generation, created_at: new Date().toISOString(), quote_date: null, author: 'ENCRYPTED', context: 'ENCRYPTED' }, await crypt.deriveQuoteKey(masterKey, generation));
  const state = { accountId, deviceId, publicKeyFingerprint: fingerprint, protectionMode: 'remembered', protection: { version: 1, mode: 'remembered' }, encryptedPrivateBundle, wrapper: { generation, wrappedKey }, lease, recoverySetupRequired };
  await activeVault(page);
  await page.route('**/functions/v1/vault-security', route => route.fulfill({ json: lease }));
  await page.route('**/rest/v1/rpc/attest_vault_keys', route => route.fulfill({ json: null }));
  await page.route('**/rest/v1/rpc/sync_quotes', route => route.fulfill({ json: { generation, revision: 1, results: [], quotes: [quote] } }));
  await page.route('**/rest/v1/rpc/create_recovery_key', route => {
    const body = route.request().postDataJSON();
    return route.fulfill({ json: { recovery_key_id: body.p_recovery_key_id, generation } });
  });
  await signIn(page, email);
  await expect(page.getByRole('button', { name: 'Unlock remembered device' })).toBeVisible();
  await page.evaluate(async ({ state, rawKey }) => {
    const rememberedKey = await crypto.subtle.importKey('raw', new Uint8Array(rawKey), 'AES-GCM', false, ['encrypt', 'decrypt']);
    const database = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = indexedDB.open('QuoteVaultDB'); request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error);
    });
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction('deviceState', 'readwrite');
      transaction.objectStore('deviceState').put({ ...state, rememberedKey });
      transaction.oncomplete = () => resolve(); transaction.onerror = () => reject(transaction.error);
    });
    database.close();
  }, { state, rawKey: [...rawKey] });
  await page.reload();
  return { state, token };
}

test('a remembered device decrypts, locks, and unlocks offline after reload', async ({ page, context }) => {
  await rememberedDevice(page);
  await page.getByRole('button', { name: 'Unlock remembered device' }).click();
  await expect(page.locator('blockquote').filter({ hasText: 'Envelope browser secret' })).toBeVisible();
  await page.evaluate(() => navigator.serviceWorker.ready.then(() => true));
  await page.getByRole('button', { name: 'Lock vault', exact: true }).click();
  await expect(page.locator('blockquote').filter({ hasText: 'Envelope browser secret' })).toHaveCount(0);
  await context.setOffline(true);
  await page.reload();
  await page.getByRole('button', { name: 'Unlock remembered device' }).click();
  await expect(page.locator('blockquote').filter({ hasText: 'Envelope browser secret' })).toBeVisible();
});

test('a first approved device completes recovery setup before showing quotes', async ({ page }) => {
  await rememberedDevice(page, true);
  await page.getByRole('button', { name: 'Unlock remembered device' }).click();
  await expect(page.getByRole('heading', { name: 'Set up personal recovery' })).toBeVisible();
  await expect(page.locator('blockquote').filter({ hasText: 'Envelope browser secret' })).toHaveCount(0);
  const words = (await page.locator('p.font-mono').innerText()).split(' ');
  for (const label of await page.locator('label').all()) {
    const position = Number((await label.innerText()).match(/Word (\d+)/)![1]) - 1;
    await label.locator('input').fill(words[position]);
  }
  await page.getByRole('button', { name: 'Confirm recovery phrase' }).click();
  await expect(page.locator('blockquote').filter({ hasText: 'Envelope browser secret' })).toBeVisible();
  const storage = await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }));
  expect(storage).not.toContain(words.join(' '));
});


test('an idle approved device does not continuously synchronize and renew its lease', async ({ page }) => {
  await rememberedDevice(page);
  let syncs = 0;
  page.on('request', request => { if (request.url().endsWith('/rpc/sync_quotes')) syncs++; });
  await page.getByRole('button', { name: 'Unlock remembered device' }).click();
  await expect(page.locator('blockquote').filter({ hasText: 'Envelope browser secret' })).toBeVisible();
  // Observe a quiet interval: this is a rate assertion, not a wait for readiness.
  await page.waitForTimeout(1500);
  expect(syncs, 'idle sync requests in 1.5 seconds').toBeLessThanOrEqual(3);
});

test('an open offline device locks when its thirty-day lease expires', async ({ page, context }) => {
  const { state } = await rememberedDevice(page);
  await page.clock.install();
  await page.getByRole('button', { name: 'Unlock remembered device' }).click();
  await expect(page.locator('blockquote').filter({ hasText: 'Envelope browser secret' })).toBeVisible();
  await context.setOffline(true);
  await page.clock.setSystemTime(Number(state.lease.claims[5]) + 1);
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
  await expect(page.getByRole('heading', { name: 'Lease expired' })).toBeVisible();
  await expect(page.locator('blockquote')).toHaveCount(0);
});

test('the devices screen authenticates with this device when revoking another owned device', async ({ page }) => {
  const { state, token } = await rememberedDevice(page);
  const targetId = webcrypto.randomUUID();
  let revoked = false;
  await page.route('**/rest/v1/rpc/list_own_devices', route => route.fulfill({ json: [state.deviceId, targetId].map(id => ({
    id, label: id === targetId ? 'Second synthetic device' : 'Current synthetic device',
    status: id === targetId && revoked ? 'revoked' : 'active', protection_mode: 'remembered',
    created_at: new Date().toISOString(), last_sync_at: null, lease_expires_at: null, revoked_at: null,
  })) }));
  await page.route('**/rest/v1/rpc/revoke_own_device', async route => {
    const body = route.request().postDataJSON();
    expect(body).toEqual({ p_device_id: state.deviceId, p_token: token, p_target_device_id: targetId });
    revoked = true;
    await route.fulfill({ json: { device_id: targetId, status: 'revoked' } });
  });
  await page.getByRole('button', { name: 'Unlock remembered device' }).click();
  await page.getByRole('link', { name: 'Open profile' }).click();
  const target = page.getByRole('listitem').filter({ hasText: 'Second synthetic device' });
  await target.getByRole('button', { name: 'Revoke', exact: true }).click();
  await expect(target).toContainText('revoked');
  await expect(target.getByRole('button', { name: 'Revoke', exact: true })).toHaveCount(0);
  expect(revoked).toBe(true);
});

test('a reverted vault forgets the admin device instead of leaving it approved', async ({ page }) => {
  const { state } = await rememberedDevice(page, false, ADMIN_EMAIL);
  const targetGeneration = '88888888-8888-4888-8888-888888888888';
  let commitBody: Record<string, unknown> | undefined;
  let reverted = false;
  await page.route('**/rest/v1/rpc/list_members', route => route.fulfill({ json: [] }));
  await page.route('**/rest/v1/rpc/get_pending_envelope_migration', route => route.fulfill({ json: null }));
  await page.route('**/rest/v1/rpc/begin_legacy_reversion', route => route.fulfill({ json: {
    reversion_id: '77777777-7777-4777-8777-777777777777', target_generation: targetGeneration, expected_quote_count: 1 } }));
  await page.route('**/rest/v1/rpc/stage_legacy_reversion', route => route.fulfill({ json: {
    reversion_id: '77777777-7777-4777-8777-777777777777', staged_quote_count: 1 } }));
  await page.route('**/rest/v1/rpc/commit_legacy_reversion', route => {
    commitBody = route.request().postDataJSON();
    reverted = true;
    return route.fulfill({ json: { generation: targetGeneration, revision: 2, envelope_status: 'legacy', quote_count: 1 } });
  });
  await page.route('**/rest/v1/rpc/get_vault_bootstrap_state', route => reverted
    ? route.fulfill({ json: { envelope_status: 'legacy', generation: targetGeneration, prepared_generation: null,
        legacy_generation: targetGeneration, kdf: commitBody!.p_kdf, verifier: commitBody!.p_verifier } })
    : route.fulfill({ json: { envelope_status: 'active', generation, prepared_generation: null } }));
  await page.getByRole('button', { name: 'Unlock remembered device' }).click();
  await page.getByRole('link', { name: 'Open admin dashboard' }).click();
  await page.getByLabel('New shared passphrase').fill('a new shared passphrase');
  await page.getByLabel('Repeat passphrase').fill('a new shared passphrase');
  await page.getByLabel('Type RETURN TO SHARED KEY').fill('RETURN TO SHARED KEY');
  await page.getByRole('button', { name: 'Return to shared vault key', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Vault locked' })).toBeVisible();
  await page.locator('#vault-key').fill('a new shared passphrase');
  await page.getByRole('button', { name: 'Unlock Vault' }).click();
  await page.route('**/rest/v1/rpc/list_own_devices', route => route.fulfill({ json: [{
    id: state.deviceId, label: 'Current synthetic device', status: 'active', protection_mode: 'remembered',
    created_at: new Date().toISOString(), last_sync_at: null, lease_expires_at: null, revoked_at: null }] }));
  await page.getByRole('link', { name: 'Open profile' }).click();
  const target = page.getByRole('listitem').filter({ hasText: 'Current synthetic device' });
  await expect(target).toBeVisible();
  await expect(target).not.toContainText('(this device)');
});
