import { test, expect, type Page } from '@playwright/test';

async function enterVault(page: Page) {
    await page.goto('/');
    await page.getByLabel('Email address').fill('browser-test@example.invalid');
    await page.getByLabel('Password', { exact: true }).fill('local-test-password');
    await page.getByRole('button', {name: 'Sign In', exact: true}).click();
    await unlock(page);
}
async function unlock(page: Page) {
    await page.getByLabel('Group Vault Key').fill('demo-vault-key');
    await page.getByRole('button', { name: 'Unlock Vault', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Import quotes', exact: true })).toBeVisible();
}
const row = (text: string, id: string) => ({ text, author: 'Synthetic Speaker', context: 'Synthetic private context', source_sender: 'Original Chat Sender', source: {id: id.repeat(64), timestamp: 'Sep 21, 2026  1:00:00 PM'} });
async function loadFile(page: Page, quotes: unknown[]) {
    await page.getByRole('button', { name: 'Import quotes', exact: true }).click();
    const dialog = page.getByRole('dialog', { name: 'Import quotes', exact: true });
    await dialog.getByLabel('Reviewed quotes or full draft').setInputFiles({ name: 'synthetic.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify({format: 'quotevault-reviewed-quotes', version: 1, quotes})) });
    await expect(dialog.getByRole('button', {name: 'Select new quotes'})).toBeVisible();
    return dialog;
}

test('import checks duplicates, encrypts provenance, and safely skips a repeated file', async ({ page }) => {
    await enterVault(page);
    const quotes = [row('A synthetic import with completely original words.', 'b'), row('A synthetic import with completely original words.', 'b'),
        {...row('A locally generated test quote.', 'c'), author: 'Demo Tester'}, row('Speaker A: “First line”\nSpeaker B: “Second line”', 'd')];
    let submitted = '';
    page.on('request', request => { if (request.url().endsWith('/rpc/checked_import')) submitted = request.postData() || ''; });
    const dialog = await loadFile(page, quotes);
    await expect(dialog.getByText('2 selected · 2 duplicates skipped', {exact: true})).toBeVisible();
    await dialog.getByRole('button', {name: 'Import 2 selected quotes'}).click();
    await expect(dialog.getByText(/^2 quotes imported and encrypted/)).toBeVisible();
    for (const secret of [quotes[0].text, quotes[0].context, quotes[0].source_sender, quotes[0].source.id]) expect(submitted).not.toContain(secret);
    await dialog.getByRole('button', {name: 'Close', exact: true}).click();
    await page.reload(); await unlock(page);
    await expect(page.locator('blockquote').filter({hasText: quotes[0].text})).toHaveCount(1);
    await expect(page.getByText('Originally shared by Original Chat Sender', {exact: true})).toHaveCount(2);
    const repeated = await loadFile(page, quotes);
    await expect(repeated.getByText('0 selected · 4 duplicates skipped', {exact: true})).toBeVisible();
    await expect(repeated.getByRole('button', {name: 'Import 0 selected quotes'})).toBeDisabled();
});

test('a lost import response survives reload and retries the identical encrypted batch', async ({ page }) => {
    await enterVault(page);
    const quote = row('Retry this uniquely identifiable synthetic entry safely.', 'e');
    const requests: string[] = [];
    await page.route('**/rpc/checked_import', async route => {
        requests.push(route.request().postData() || '');
        await route.fetch(); // Commit server-side, then lose the response.
        await route.abort('failed');
    });
    const dialog = await loadFile(page, [quote]);
    await dialog.getByRole('button', {name: 'Import 1 selected quotes'}).click();
    await expect(dialog.getByRole('button', {name: 'Check saved import'})).toBeEnabled();
    await page.unroute('**/rpc/checked_import');
    page.on('request', request => { if (request.url().endsWith('/rpc/checked_import')) requests.push(request.postData() || ''); });
    await page.reload(); await unlock(page);
    await page.getByRole('button', {name: 'Import quotes', exact: true}).click();
    const resumed = page.getByRole('dialog', {name: 'Import quotes', exact: true});
    await resumed.getByRole('button', {name: 'Check saved import'}).click();
    await expect(resumed.getByText(/^1 quotes imported and encrypted/)).toBeVisible();
    expect(requests).toHaveLength(2); expect(requests[1]).toBe(requests[0]);
    await resumed.getByRole('button', {name: 'Close', exact: true}).click();
    await expect(page.locator('blockquote').filter({hasText: quote.text})).toHaveCount(1);
});

test('revision conflicts reject an import without leaving an uncertain batch', async ({ page }) => {
    await enterVault(page);
    await page.route('**/rpc/checked_import', route => route.fulfill({ status: 409, contentType: 'application/json', body: JSON.stringify({code: '40001', message: 'Vault changed; refresh and review the import again'}) }));
    const dialog = await loadFile(page, [row('A rejected import must never appear in the feed.', 'f')]);
    await dialog.getByRole('button', {name: 'Import 1 selected quotes'}).click();
    await expect(dialog.getByRole('alert')).toContainText('Vault changed');
    await expect(dialog.getByRole('button', {name: 'Check saved import'})).toHaveCount(0);
    await dialog.getByRole('button', {name: 'Close', exact: true}).click();
    await expect(page.locator('blockquote').filter({hasText: 'A rejected import must never appear in the feed.'})).toHaveCount(0);
});
