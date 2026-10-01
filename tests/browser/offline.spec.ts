import { test, expect, type Page } from '@playwright/test';

async function unlock(page: Page) {
  await page.getByLabel('Group Vault Key').fill('demo-vault-key');
  await page.getByRole('button', { name: 'Unlock Vault', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Add quote', exact: true })).toBeVisible();
}

test('lazy-loaded screens render offline from the service-worker precache', async ({ page, context }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto('/');
  await page.locator('input[type=email]').fill('browser-test@example.com');
  await page.locator('input[type=password]').fill('local-test-password');
  await page.getByRole('button', { name: 'Sign In', exact: true }).click();
  await unlock(page);
  await page.evaluate(() => navigator.serviceWorker.ready.then(() => true));

  // The offline reload drops every module loaded online, so the Auth chunk loaded by signing out must come from the precache.
  await context.setOffline(true);
  await page.reload();
  await unlock(page);

  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Sign In', exact: true })).toBeVisible({ timeout: 3000 });
  expect(errors).toEqual([]);
});

test.describe('without the service worker', () => {
  test.use({ serviceWorkers: 'block' });

  test('a screen chunk that fails to load leaves the feed reachable', async ({ page }) => {
    await page.route('**/assets/Profile-*.js', route => route.abort());
    await page.goto('/');
    await page.locator('input[type=email]').fill('browser-test@example.com');
    await page.locator('input[type=password]').fill('local-test-password');
    await page.getByRole('button', { name: 'Sign In', exact: true }).click();
    await unlock(page);

    await page.getByRole('link', { name: 'Open profile', exact: true }).click();
    await expect(page.getByRole('alert')).toContainText('This screen could not load.');
    await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeVisible();
    await page.getByRole('link', { name: 'Open profile', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Add quote', exact: true })).toBeVisible();
    await expect(page.getByRole('alert')).not.toBeVisible();
  });
});
