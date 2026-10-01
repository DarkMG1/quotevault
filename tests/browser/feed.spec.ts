import { test, expect, type Locator, type Page } from '@playwright/test';

async function dragCard(page: Page, card: Locator, dx: number, release = true) {
  const box = (await card.locator('blockquote').boundingBox())!;
  const x = box.x + box.width / 2;
  const y = box.y + box.height / 2;
  await page.mouse.move(x, y);
  await page.mouse.down();
  await page.mouse.move(x + dx, y, { steps: 10 });
  if (release) await page.mouse.up();
  return { x, y };
}

test('swiping a card left past the threshold asks to delete it, and the deleted card leaves the feed', async ({ page }) => {
  const text = 'A swipe-to-delete browser regression quote.';
  await page.goto('/');
  await page.locator('input[type=email]').fill('browser-test@example.com');
  await page.locator('input[type=password]').fill('local-test-password');
  await page.getByRole('button', { name: 'Sign In', exact: true }).click();
  await page.getByLabel('Group Vault Key').fill('demo-vault-key');
  await page.getByRole('button', { name: 'Unlock Vault', exact: true }).click();
  await page.getByRole('button', { name: 'Add quote', exact: true }).click();
  const add = page.getByRole('dialog', { name: 'Add Quote', exact: true });
  await add.getByLabel('Quote', { exact: true }).fill(text);
  await expect(add.getByRole('checkbox', { name: 'Demo Tester', exact: true })).toBeChecked();
  await add.getByRole('button', { name: 'Save Quote', exact: true }).click();
  await expect(add).not.toBeVisible();

  const card = page.locator('blockquote').filter({ hasText: text }).locator('..');
  const confirm = page.getByRole('dialog', { name: 'Delete Quote', exact: true });
  await expect(card).toBeVisible();
  await page.getByLabel('Search quotes, authors or context').fill('swipe-to-delete');
  await expect(page.getByRole('group', { name: 'Active filters' })).toContainText('Showing 1 of');
  await page.getByRole('button', { name: 'Clear all', exact: true }).click();

  // The red delete panel exists only mid-swipe, so scrolling never paints it under a card.
  const panel = card.locator('..').locator('.bg-red-500\\/80');
  await expect(panel).toHaveCount(0);
  const start = await dragCard(page, card, -120, false);
  await expect(card).toHaveCSS('transform', 'matrix(1, 0, 0, 1, -60, 0)');
  await expect(panel).toBeVisible();
  await page.mouse.move(start.x, start.y, { steps: 5 });
  await page.mouse.up();
  await expect(confirm).not.toBeVisible();

  await dragCard(page, card, -60);
  await dragCard(page, card, 250);
  await expect(confirm).not.toBeVisible();

  await dragCard(page, card, -250);
  await expect(confirm).toBeVisible();
  await confirm.getByRole('button', { name: 'Cancel', exact: true }).click();
  await expect(confirm).not.toBeVisible();
  await expect(card).toHaveCSS('transform', 'none');
  await expect(panel).toHaveCount(0);

  await dragCard(page, card, -250);
  await confirm.getByRole('button', { name: 'Delete Forever', exact: true }).click();
  await expect(page.locator('blockquote').filter({ hasText: text })).toHaveCount(0);
});
