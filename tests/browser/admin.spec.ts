import { test, expect } from '@playwright/test';

test('a failed vault key rotation is announced as an alert', async ({ page }) => {
  await page.route('**/rpc/rotate_vault', route => route.fulfill({ status: 409, contentType: 'application/json', body: JSON.stringify({ code: '40001', message: 'Vault generation changed' }) }));
  await page.goto('/');
  await page.getByLabel('Email address').fill('darkmgdevelopment@gmail.com');
  await page.getByLabel('Password', { exact: true }).fill('local-test-password');
  await page.getByRole('button', { name: 'Sign In', exact: true }).click();
  await page.getByLabel('Group Vault Key').fill('demo-vault-key');
  await page.getByRole('button', { name: 'Unlock Vault', exact: true }).click();
  await page.getByRole('link', { name: 'Open admin dashboard' }).click();
  await page.getByLabel('New Group Vault Key').fill('a-rotated-vault-key');
  await page.getByLabel('Confirm Action').fill('ERASE EVERYTHING');
  await page.getByRole('button', { name: 'Wipe Database & Change Key' }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'Vault generation changed' })).toBeVisible();
});
