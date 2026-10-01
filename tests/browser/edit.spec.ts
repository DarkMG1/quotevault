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

test('add and edit keep multiple selected authors, text, and the original sender', async ({ page }) => {
  const text = 'A browser regression quote with two authors.';
  await enterVault(page);
  await page.getByRole('button', { name: 'Add quote', exact: true }).click();
  const add = page.getByRole('dialog', { name: 'Add Quote', exact: true });
  await add.getByLabel('Quote', { exact: true }).fill(text);
  await add.getByLabel(/Context/).fill('Two author browser context');
  await add.getByLabel(/Date Said/).fill('2026-09-21');
  await expect(add.getByRole('checkbox', { name: 'Demo Tester', exact: true })).toBeChecked();
  await add.getByRole('checkbox', { name: 'Morgan Lee', exact: true }).check();
  await add.getByRole('button', { name: 'Save Quote', exact: true }).click();
  await expect(add).not.toBeVisible();
  await expect(page.locator('blockquote').filter({ hasText: text })).toBeVisible();
  const search = page.getByLabel('Search quotes, authors or context');
  const other = page.locator('blockquote').filter({ hasText: 'A locally generated test quote.' });
  const added = page.locator('blockquote').filter({ hasText: text });
  await search.fill('Morgan Lee');
  await expect(added).toBeVisible();
  await expect(other).toHaveCount(0);
  await search.fill('browser context');
  await expect(added).toBeVisible();
  await page.getByRole('button', { name: 'Remove filter “browser context”' }).click();
  await expect(search).toHaveValue('');
  await expect(other).toBeVisible();

  await page.getByRole('button', { name: 'Filters' }).click();
  const author = page.getByLabel('Author', { exact: true });
  expect(await author.locator('option').allTextContents()).toEqual(expect.arrayContaining(['Any author', 'Demo Tester', 'Morgan Lee']));
  await author.selectOption('Morgan Lee');
  await page.getByLabel('From', { exact: true }).fill('2026-09-21');
  await page.getByLabel('To', { exact: true }).fill('2026-09-21');
  await expect(added).toBeVisible();
  await expect(other).toHaveCount(0);
  await expect(page.getByRole('button', { name: /^Filters\s*2$/ })).toBeVisible();

  await page.getByRole('button', { name: 'Remove filter Morgan Lee' }).click();
  await expect(author).toHaveValue('');
  await page.getByRole('button', { name: /^Remove filter Sep 21, 2026 – Sep 21, 2026$/ }).click();
  await expect(page.getByLabel('From', { exact: true })).toHaveValue('');
  await expect(page.getByLabel('To', { exact: true })).toHaveValue('');
  await expect(other).toBeVisible();
  await expect(page.getByRole('button', { name: /^Filters$/ })).toBeVisible();

  await expect(page.locator('blockquote').first()).toContainText(text);
  await page.getByRole('button', { name: /Switch to oldest first/ }).click();
  await expect(page.locator('blockquote').last()).toContainText(text);
  await page.getByRole('button', { name: /Switch to newest first/ }).click();
  await expect(page.locator('blockquote').first()).toContainText(text);

  await page.getByLabel('From', { exact: true }).fill('2026-09-22');
  await page.getByLabel('To', { exact: true }).fill('2026-09-20');
  await expect(page.getByRole('alert')).toContainText('From date is after the To date');
  await expect(page.locator('blockquote')).toHaveCount(0);
  await page.getByRole('button', { name: 'Clear all', exact: true }).click();
  await expect(other).toBeVisible();
  await expect(added).toBeVisible();
  await page.reload();
  await page.getByLabel('Group Vault Key').fill('demo-vault-key');
  await page.getByRole('button', { name: 'Unlock Vault', exact: true }).click();

  await page.getByRole('button', { name: 'Edit quote by Demo Tester & Morgan Lee', exact: true }).click();
  const edit = page.getByRole('dialog', { name: 'Edit Quote', exact: true });
  await expect(edit.getByLabel('Quote', { exact: true })).toHaveValue(text);
  await expect(edit.getByLabel('Author', { exact: true })).toHaveValue('Demo Tester & Morgan Lee');
  await expect(edit.getByRole('checkbox', { name: 'Demo Tester', exact: true })).toBeChecked();
  await expect(edit.getByRole('checkbox', { name: 'Morgan Lee', exact: true })).toBeChecked();
  await edit.getByRole('checkbox', { name: 'Morgan Lee', exact: true }).uncheck();
  await expect(edit.getByLabel('Author', { exact: true })).toHaveValue('Demo Tester');
  await edit.getByRole('button', { name: 'Save Changes', exact: true }).click();
  await expect(edit).not.toBeVisible();
  await expect(page.locator('blockquote').filter({ hasText: text })).toBeVisible();
  await expect(page.locator('blockquote').filter({ hasText: text }).locator('..').getByText('Originally shared by Demo Tester', { exact: true })).toBeVisible();

  await page.locator('blockquote').filter({ hasText: text }).locator('..').getByRole('button', { name: 'Edit quote by Demo Tester', exact: true }).click();
  const reopened = page.getByRole('dialog', { name: 'Edit Quote', exact: true });
  await expect(reopened.getByLabel('Quote', { exact: true })).toHaveValue(text);
  await expect(reopened.getByRole('checkbox', { name: 'Morgan Lee', exact: true })).not.toBeChecked();
  await reopened.getByRole('checkbox', { name: 'Morgan Lee', exact: true }).check();
  await expect(reopened.getByLabel('Author', { exact: true })).toHaveValue('Demo Tester & Morgan Lee');
  await reopened.getByRole('button', { name: 'Save Changes', exact: true }).click();
  await expect(reopened).not.toBeVisible();
  await expect(page.locator('blockquote').filter({ hasText: text })).toBeVisible();
  await expect(page.locator('blockquote').filter({ hasText: text }).locator('..').getByText('Originally shared by Demo Tester', { exact: true })).toBeVisible();
});

test('a non-administrator cannot start an edit', async ({ page }) => {
  await enterVault(page, 'syntheticmember@example.invalid');
  await expect(page.getByRole('button', { name: /^Edit quote by / })).toHaveCount(0);
});

test('an edit interrupted by a session change says so instead of staying open silently', async ({ page }) => {
  await enterVault(page);
  let release!: () => void;
  const released = new Promise<void>(resolve => { release = resolve; });
  await page.route('**/rpc/edit_quote', async route => { await released; await route.continue(); });
  await page.getByRole('button', { name: `Edit quote by ${compound.author}`, exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Edit Quote', exact: true });
  await expect(dialog.getByLabel('Quote', { exact: true })).toHaveValue(compound.text);
  const sent = page.waitForRequest('**/rpc/edit_quote');
  await dialog.getByRole('button', { name: 'Save Changes', exact: true }).click();
  await sent;
  await page.evaluate(() => window.dispatchEvent(new Event('offline')));
  release();
  await expect(dialog.getByRole('alert')).toContainText('Your session changed while saving');
  await expect(dialog.getByLabel('Quote', { exact: true })).toHaveValue(compound.text);
});

test('matching authors with a quote from another vault generation shows an error', async ({ page }) => {
  await enterVault(page);
  await page.evaluate(id => new Promise<void>((resolve, reject) => {
    const open = indexedDB.open('QuoteVaultDB');
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const tx = open.result.transaction('quotes', 'readwrite');
      const store = tx.objectStore('quotes');
      const get = store.get(id);
      get.onsuccess = () => store.put({ ...get.result, vault_generation: '22222222-2222-4222-8222-222222222222' });
      tx.oncomplete = () => { open.result.close(); resolve(); };
      tx.onerror = () => reject(tx.error);
    };
  }), compound.id);
  await page.reload();
  await page.getByLabel('Group Vault Key').fill('demo-vault-key');
  await page.getByRole('button', { name: 'Unlock Vault', exact: true }).click();
  let edits = 0;
  page.on('request', request => { if (request.url().endsWith('/rpc/edit_quotes')) edits++; });
  await page.getByRole('button', { name: 'Match imported authors', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Match imported authors', exact: true });
  await dialog.getByLabel(`Replace author ${compound.author}`, { exact: true }).fill('Morgan Lee');
  await dialog.getByRole('button', { name: /^Save \d+ author corrections$/ }).click();
  await expect(dialog.getByRole('alert')).toContainText('The vault changed');
  expect(edits).toBe(0);
});
