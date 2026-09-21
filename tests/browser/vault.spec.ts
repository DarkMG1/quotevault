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

test('real IndexedDB and installed PWA preserve encrypted offline changes and deletion', async ({ page, context }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto('/');
  await page.locator('input[type=email]').fill('browser-test@example.com');
  await page.locator('input[type=password]').fill('local-test-password');
  await page.getByRole('button', { name: 'Sign In', exact: true }).click();
  await unlock(page);
  await expect(page.locator('blockquote').filter({ hasText: 'A locally generated test quote.' })).toBeVisible();
  await cacheAuthors(page);
  await page.evaluate(() => navigator.serviceWorker.ready.then(() => true));

  await context.setOffline(true);
  await page.reload();
  await unlock(page);
  await addQuote(page, 'Browser-only secret quote');
  await expect.poll(() => localRows(page, 'syncQueue').then(rows => rows.length)).toBe(1);
  const cached = await localRows(page, 'quotes');
  expect(JSON.stringify(cached)).not.toContain('Browser-only secret quote');
  expect(cached.every(row => typeof row.text === 'string' && row.text.startsWith('$$E2E$$'))).toBe(true);

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
