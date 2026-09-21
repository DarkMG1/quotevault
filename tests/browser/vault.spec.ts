import { test, expect, type Page } from '@playwright/test';

async function unlock(page: Page) {
  await page.getByLabel('Group Vault Key').fill('demo-vault-key');
  await page.getByRole('button', { name: 'Unlock Vault', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Add quote', exact: true })).toBeVisible();
}

async function localRows(page: Page, table: string) {
  return page.evaluate(async name => {
    const database = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = indexedDB.open('QuoteVaultDB');
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    try {
      return await new Promise<Record<string, unknown>[]>((resolve, reject) => {
        const request = database.transaction(name).objectStore(name).getAll();
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
    } finally { database.close(); }
  }, table);
}

async function addQuote(page: Page, text: string) {
  await page.getByRole('button', { name: 'Add quote', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Add Quote', exact: true });
  await dialog.getByLabel('Quote', { exact: true }).fill(text);
  await expect(dialog.getByLabel('Author', { exact: true })).not.toHaveValue('');
  await dialog.getByRole('button', { name: 'Save Quote', exact: true }).click();
  await expect(dialog).not.toBeVisible();
  await expect(page.locator('blockquote').filter({ hasText: text })).toBeVisible();
}

async function cacheAuthors(page: Page) {
  await page.getByRole('button', { name: 'Add quote', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Add Quote', exact: true });
  await expect(dialog.getByLabel('Author', { exact: true })).not.toHaveValue('');
  await dialog.getByRole('button', { name: 'Close add quote dialog' }).click();
  await expect(dialog).not.toBeVisible();
}


async function prepareDevice(page: Page) {
  await page.goto('/');
  await page.locator('input[type=email]').fill('browser-test@example.com');
  await page.locator('input[type=password]').fill('local-test-password');
  await page.getByRole('button', { name: 'Sign In', exact: true }).click();
  await unlock(page);
  await expect(page.locator('blockquote').filter({ hasText: 'A locally generated test quote.' })).toBeVisible();
  await cacheAuthors(page);
  await page.evaluate(() => navigator.serviceWorker.ready.then(() => true));
}

async function expireSession(page: Page) {
  await page.evaluate(() => {
    const key = Object.keys(localStorage).find(key => key.endsWith('-auth-token'))!;
    const session = JSON.parse(localStorage.getItem(key)!);
    session.expires_at = Math.floor(Date.now() / 1000) - 3600;
    localStorage.setItem(key, JSON.stringify(session));
  });
}

test('expired-session PWA reload preserves encrypted offline changes and deletion', async ({ page, context }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await prepareDevice(page);
  // A cold start must not depend on renewing an expired Supabase access token.
  await expireSession(page);
  await context.setOffline(true);
  await page.reload();
  await expect(page.getByLabel('Group Vault Key')).toBeVisible({ timeout: 3000 });
  await page.getByLabel('Group Vault Key').fill('wrong-vault-key');
  await page.getByRole('button', { name: 'Unlock Vault', exact: true }).click();
  await expect(page.getByRole('alert')).toBeVisible();
  await expect(page.locator('blockquote')).toHaveCount(0);
  await unlock(page);
  await addQuote(page, 'Browser-only secret quote');
  await expect.poll(() => localRows(page, 'syncQueue').then(rows => rows.length)).toBe(1);
  const cached = await localRows(page, 'quotes');
  expect(JSON.stringify(cached)).not.toContain('Browser-only secret quote');
  expect(cached.every(row => typeof row.text === 'string' && row.text.startsWith('$$E2E$$'))).toBe(true);
  expect(JSON.stringify(await localRows(page, 'syncQueue'))).not.toContain('Browser-only secret quote');
  const storage = await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }));
  expect(storage).not.toContain('demo-vault-key');
  expect(storage).not.toContain('Browser-only secret quote');

  await context.setOffline(false);
  await expect.poll(() => localRows(page, 'syncQueue').then(rows => rows.length)).toBe(0);
  const card = page.locator('blockquote').filter({ hasText: 'Browser-only secret quote' }).locator('..');
  const remove = card.getByRole('button', { name: /Delete quote by/ });
  await remove.click();
  await expect(page.getByRole('dialog', { name: 'Delete Quote', exact: true })).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(remove).toBeFocused();

  await context.setOffline(true);
  await remove.click();
  await page.getByRole('button', { name: 'Delete Forever', exact: true }).click();
  await expect(page.locator('blockquote').filter({ hasText: 'Browser-only secret quote' })).toHaveCount(0);
  const deletes = await localRows(page, 'syncQueue');
  expect(deletes).toHaveLength(1);
  expect(deletes[0].action).toBe('DELETE');
  expect(deletes[0].payload).toBeUndefined();
  await context.setOffline(false);
  await expect.poll(() => localRows(page, 'syncQueue').then(rows => rows.length)).toBe(0);
  await page.reload();
  await unlock(page);
  await expect(page.locator('blockquote').filter({ hasText: 'Browser-only secret quote' })).toHaveCount(0);
  expect(errors).toEqual([]);

  await page.route('**/auth/v1/logout*', route => route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ message: 'Test sign-out failure' }) }));
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText(/sign.out|failure/i);
  await expect(page.getByRole('button', { name: 'Sign In', exact: true })).toBeVisible();
  await page.unroute('**/auth/v1/logout*');
});


test('an unreachable auth server does not block local unlock; a rejected session locks it', async ({ page, context }) => {
  await prepareDevice(page);
  await expireSession(page);
  const release = Promise.withResolvers<void>();
  await page.route('**/auth/v1/token*', async route => {
    await release.promise;
    await route.fulfill({ status: 400, contentType: 'application/json', body: JSON.stringify({ code: 'refresh_token_not_found', message: 'Refresh token revoked' }) });
  });
  const remoteReads: string[] = [];
  page.on('request', request => { if (request.url().includes('/rest/v1/')) remoteReads.push(request.url()); });
  page.on('websocket', socket => remoteReads.push(socket.url()));
  await page.reload(); // navigator.onLine stays true while the auth request hangs.
  await expect(page.getByLabel('Group Vault Key')).toBeVisible({ timeout: 3000 });
  await unlock(page);
  await expect(page.locator('blockquote').filter({ hasText: 'A locally generated test quote.' })).toBeVisible();
  await cacheAuthors(page);
  expect(remoteReads).toEqual([]);
  release.resolve();
  await expect(page.getByRole('button', { name: 'Sign In', exact: true })).toBeVisible();
  await expect(page.locator('blockquote')).toHaveCount(0);
  await context.setOffline(true);
  await page.reload();
  await expect(page.getByRole('button', { name: 'Sign In', exact: true })).toBeVisible();
  await expect(page.getByLabel('Group Vault Key')).toHaveCount(0);
});

test('offline sign-out locks immediately and cannot revive cached access on reload', async ({ page, context }) => {
  await prepareDevice(page);
  await expireSession(page);
  await context.setOffline(true);
  await page.reload();
  await unlock(page);
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Sign In', exact: true })).toBeVisible({ timeout: 3000 });
  await page.reload();
  await expect(page.getByRole('button', { name: 'Sign In', exact: true })).toBeVisible();
  await expect(page.getByLabel('Group Vault Key')).toHaveCount(0);
  await expect(page.locator('blockquote')).toHaveCount(0);
});

test('a membership denial locks an already unlocked local vault and removes offline preparation', async ({ page, context }) => {
  await prepareDevice(page);
  const release = Promise.withResolvers<void>();
  await page.route('**/rest/v1/rpc/get_vault_state', async route => {
    await release.promise;
    await route.fulfill({ status: 403, contentType: 'application/json', body: JSON.stringify({ code: '42501', message: 'Vault membership denied' }) });
  });
  await page.reload();
  await unlock(page);
  release.resolve();
  await expect(page.getByRole('alert')).toContainText('Vault membership denied');
  await expect(page.getByRole('button', { name: 'Add quote', exact: true })).toHaveCount(0);
  await expect(page.locator('blockquote')).toHaveCount(0);
  await context.setOffline(true);
  await page.reload();
  await expect(page.getByRole('alert')).toContainText('Connect once');
  await page.getByLabel('Group Vault Key').fill('demo-vault-key');
  await expect(page.getByRole('button', { name: 'Unlock Vault', exact: true })).toBeDisabled();
});

test('a second tab cannot revive access during pending online sign-out', async ({ page, context }) => {
  await prepareDevice(page);
  const release = Promise.withResolvers<void>();
  await page.route('**/auth/v1/logout*', async route => {
    await release.promise;
    await route.fulfill({ status: 204 });
  });
  const second = await context.newPage();
  const finished = page.waitForResponse(response => response.url().includes('/auth/v1/logout'));
  try {
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Sign In', exact: true })).toBeVisible();
    await second.goto('/'); // Keep the original page and its logout request alive.
    await expect(second.getByRole('button', { name: 'Sign In', exact: true })).toBeVisible({ timeout: 3000 });
    await expect(second.getByLabel('Group Vault Key')).toHaveCount(0);
  } finally { release.resolve(); await finished; }
  await second.locator('input[type=email]').fill('browser-test@example.com');
  await second.locator('input[type=password]').fill('local-test-password');
  await second.getByRole('button', { name: 'Sign In', exact: true }).click();
  await unlock(second);
});
