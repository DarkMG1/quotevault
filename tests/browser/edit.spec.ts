import { test, expect, type Page } from '@playwright/test';

const imported = {
  id: '44444444-4444-4444-8444-444444444444',
  text: 'A synthetic imported quote reserved for edit regression.',
  author: 'Imported Synthetic Speaker',
  sourceSender: 'Original Imported Sender',
  sourceId: '9'.repeat(64),
};
const directed = {
  id: '55555555-5555-4555-8555-555555555555',
  text: 'A directed imported attribution remains traceable.',
  author: 'Demo to Outside Speaker',
  context: 'Directed attribution context',
  sourceSender: 'Directed Original Sender',
  sourceId: 'a'.repeat(64),
};
const compound = {
  id: '66666666-6666-4666-8666-666666666666',
  text: 'An unknown compound imported attribution stays intact.',
  author: 'Mystery & Outside Speaker',
  context: 'Unknown compound context',
  sourceSender: 'Compound Original Sender',
  sourceId: '8'.repeat(64),
};

async function enterVault(page: Page, email = 'darkmgdevelopment@gmail.com') {
  await page.goto('/');
  await page.getByLabel('Email address').fill(email);
  await page.getByLabel('Password', { exact: true }).fill('local-test-password');
  await page.getByRole('button', { name: 'Sign In', exact: true }).click();
  await page.getByLabel('Group Vault Key').fill('demo-vault-key');
  await page.getByRole('button', { name: 'Unlock Vault', exact: true }).click();
  await expect(page.locator('blockquote').filter({ hasText: /synthetic imported quote reserved for edit regression|edited imported quote remains private/i })).toBeVisible();
}

async function storedPayload(page: Page, quote = imported) {
  return page.evaluate(async quote => {
    const [state, row] = await Promise.all([
      fetch('http://127.0.0.1:54329/rest/v1/rpc/get_vault_state', { method: 'POST' }).then(response => response.json()),
      fetch(`http://127.0.0.1:54329/fixture/quotes/${quote.id}`).then(response => response.json()),
    ]);
    const payload = JSON.parse(row.text.slice('$$E2E$$'.length));
    const material = await crypto.subtle.importKey('raw', new TextEncoder().encode('demo-vault-key'), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: Uint8Array.from(atob(state.kdf.salt), char => char.charCodeAt(0)), iterations: state.kdf.iterations, hash: 'SHA-256' }, material, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const clear = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: Uint8Array.from(atob(payload.iv), char => char.charCodeAt(0)) }, key, Uint8Array.from(atob(payload.data), char => char.charCodeAt(0)));
    return { ciphertext: row.text, payload: JSON.parse(new TextDecoder().decode(clear)) };
  }, quote);
}

test('an administrator edits an imported quote without exposing or losing provenance', async ({ page }) => {
  await enterVault(page);
  let submitted = '';
  page.on('request', request => { if (request.url().endsWith('/rpc/edit_quote')) submitted = request.postData() || ''; });
  await page.getByRole('button', { name: `Edit quote by ${imported.author}` }).click();
  const dialog = page.getByRole('dialog', { name: 'Edit Quote', exact: true });
  await expect(dialog.getByLabel('Quote', { exact: true })).toHaveValue(imported.text);
  await expect(dialog.getByLabel('Author', { exact: true })).toHaveValue(imported.author);
  await expect(dialog.getByText(`Originally shared by ${imported.sourceSender}`, { exact: true })).toBeVisible();
  await expect(dialog.getByLabel('Originally shared by', { exact: false })).toHaveCount(0);
  await dialog.getByLabel('Quote', { exact: true }).fill('The edited imported quote remains private.');
  await dialog.getByLabel('Author', { exact: true }).fill('Edited Speaker');
  await dialog.getByLabel(/Context/).fill('Edited private context');
  await dialog.getByLabel(/Date Said/).fill('2026-09-21');
  await dialog.getByRole('button', { name: 'Save Changes', exact: true }).click();
  await expect(dialog).not.toBeVisible();
  await expect(page.locator('blockquote').filter({ hasText: 'The edited imported quote remains private.' })).toBeVisible();
  for (const secret of ['The edited imported quote remains private.', 'Edited Speaker', 'Edited private context', imported.sourceSender, imported.sourceId]) expect(submitted).not.toContain(secret);

  const stored = await storedPayload(page);
  expect(stored.ciphertext).toContain('$$E2E$$');
  expect(stored.payload).toMatchObject({ text: 'The edited imported quote remains private.', author: 'Edited Speaker', context: 'Edited private context', source_sender: imported.sourceSender, import_source_id: imported.sourceId });
  await page.reload();
  await page.getByLabel('Group Vault Key').fill('demo-vault-key');
  await page.getByRole('button', { name: 'Unlock Vault', exact: true }).click();
  await expect(page.locator('blockquote').filter({ hasText: 'The edited imported quote remains private.' })).toBeVisible();
});

test('a stale edit retains its draft and cannot be saved offline', async ({ page, context }) => {
  await enterVault(page);
  await page.getByRole('button', { name: /Edit quote by (Imported Synthetic Speaker|Edited Speaker)/ }).click();
  const dialog = page.getByRole('dialog', { name: 'Edit Quote', exact: true });
  await dialog.getByLabel('Quote', { exact: true }).fill('Draft retained after a stale edit.');
  await page.route('**/rpc/edit_quote', route => route.fulfill({ status: 409, contentType: 'application/json', body: JSON.stringify({ code: '40001', message: 'Quote changed; refresh and try again.' }) }));
  await dialog.getByRole('button', { name: 'Save Changes', exact: true }).click();
  await expect(dialog.getByRole('alert')).toContainText('draft is still here');
  await expect(dialog.getByLabel('Quote', { exact: true })).toHaveValue('Draft retained after a stale edit.');
  await page.unroute('**/rpc/edit_quote');
  await context.setOffline(true);
  await page.waitForFunction(() => !navigator.onLine);
  await expect(dialog.getByRole('button', { name: 'Save Changes', exact: true })).toBeDisabled();
});

test('matching imported authors preserves directed provenance and unknown compounds', async ({ page }) => {
  await enterVault(page);
  const before = await storedPayload(page);
  const directedBefore = await storedPayload(page, directed);
  const compoundBefore = await storedPayload(page, compound);
  const cardCount = await page.locator('blockquote').count();
  await page.getByRole('button', { name: 'Match imported authors', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Match imported authors', exact: true });
  const author = dialog.getByLabel(/Replace author (Imported Synthetic Speaker|Edited Speaker)/);
  await author.fill('Demo Tester');
  await expect(dialog.getByLabel(`Replace author ${directed.author}`, { exact: true })).toHaveValue('Demo Tester');
  await expect(dialog.getByLabel(`Replace author ${compound.author}`, { exact: true })).toHaveValue(compound.author);
  await expect(dialog.getByText('2 author corrections ready', { exact: true })).toBeVisible();
  await dialog.getByRole('button', { name: 'Save 2 author corrections', exact: true }).click();
  await expect(dialog).not.toBeVisible();
  await expect(page.locator('blockquote')).toHaveCount(cardCount);
  await expect(page.locator('blockquote').filter({ hasText: before.payload.text })).toBeVisible();
  expect(await storedPayload(page)).toMatchObject({ payload: { text: before.payload.text, author: 'Demo Tester', source_sender: imported.sourceSender, import_source_id: imported.sourceId } });
  expect(await storedPayload(page, directed)).toMatchObject({ payload: { text: directedBefore.payload.text, author: 'Demo Tester', context: `${directedBefore.payload.context}\nOriginal attribution: ${directed.author}.`, source_sender: directed.sourceSender, import_source_id: directed.sourceId } });
  expect(await storedPayload(page, compound)).toMatchObject({ payload: compoundBefore.payload });
});

test('a non-administrator cannot start an edit', async ({ page }) => {
  await enterVault(page, 'syntheticmember@example.invalid');
  await expect(page.getByRole('button', { name: /^Edit quote by / })).toHaveCount(0);
});
