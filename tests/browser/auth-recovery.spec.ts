import { test, expect } from '@playwright/test';

test('password recovery is explicit, durable across reload, and stays outside the vault', async ({ page }) => {
  await page.goto('/');
  const vaultRequests: string[] = [];
  page.on('request', request => {
    const path = new URL(request.url()).pathname;
    if (path.startsWith('/rest/v1/') || path.startsWith('/functions/v1/')) vaultRequests.push(path);
  });
  await page.getByRole('button', { name: 'Forgot password?' }).click();
  await page.getByLabel('Email address').fill('nobody@example.invalid');
  await page.route('**/auth/v1/recover*', route => route.fulfill({ status: 200, contentType: 'application/json', body: '{}' }));
  await page.getByRole('button', { name: 'Send reset link' }).click();
  await expect(page.getByRole('status')).toContainText('If an account matches that email');
  expect(vaultRequests).toEqual([]);
  await page.unroute('**/auth/v1/recover*');

  await page.addInitScript(() => localStorage.setItem('sb-127-auth-token:signed-out', '1'));
  await page.goto('/?recovery=1#access_token=test&refresh_token=test&token_type=bearer&expires_in=3600&type=recovery');
  await expect(page.getByLabel('New account password', { exact: true })).toBeVisible();
  await expect(page.getByLabel('Group Vault Key')).toHaveCount(0);
  await expect(page.locator('#recovery-password')).toHaveAttribute('minlength', '12');
  expect(page.url()).toContain('?recovery=1');
  expect(page.url()).not.toContain('access_token');

  await page.reload();
  await expect(page.getByLabel('New account password', { exact: true })).toBeVisible();
  await page.getByLabel('New account password', { exact: true }).fill('long-enough-password');
  await page.getByLabel('Confirm new account password').fill('different-password');
  await page.getByRole('button', { name: 'Update account password' }).click();
  await expect(page.getByRole('alert')).toContainText('Passwords do not match');
  let updates = 0;
  await page.route('**/auth/v1/user', route => route.request().method() === 'PUT'
    ? route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ id: '22222222-2222-4222-8222-222222222222', email: 'browser-test@example.com' }) })
    : route.continue());
  page.on('request', request => { if (request.url().includes('/auth/v1/user') && request.method() === 'PUT') updates++; });
  await page.getByLabel('Confirm new account password').fill('long-enough-password');
  await page.getByRole('button', { name: 'Update account password' }).click();
  await expect(page.getByLabel('Group Vault Key')).toBeVisible();
  expect(page.url()).not.toContain('recovery=1');
  expect(updates).toBe(1);
  await page.unroute('**/auth/v1/user');
});

test('invalid recovery links offer a new reset request', async ({ page }) => {
  await page.goto('/?recovery=1#error=access_denied');
  await expect(page.getByRole('alert')).toContainText('invalid or expired');
  await expect(page.getByRole('button', { name: 'Send reset link' })).toBeVisible();
  await expect(page.getByLabel('New account password', { exact: true })).toHaveCount(0);
});

test('recovery intent alone does not reset an existing session', async ({ page }) => {
  await page.goto('/');
  await page.locator('input[type=email]').fill('browser-test@example.com');
  await page.locator('input[type=password]').fill('local-test-password');
  await page.getByRole('button', { name: 'Sign In', exact: true }).click();
  await expect(page.getByLabel('Group Vault Key')).toBeVisible();

  await page.goto('/?recovery=1');
  await expect(page.getByLabel('Group Vault Key')).toBeVisible();
  await expect(page.getByLabel('New account password', { exact: true })).toHaveCount(0);
});
