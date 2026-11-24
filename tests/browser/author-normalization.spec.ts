import { test, expect } from '@playwright/test';

test('import normalizes names before encryption and duplicate checking', async ({ page }) => {
    await page.goto('/');
    await page.getByLabel('Email address').fill('browser-test@example.invalid');
    await page.getByLabel('Password', { exact: true }).fill('local-test-password');
    await page.getByRole('button', { name: 'Sign In', exact: true }).click();
    await page.getByLabel('Group Vault Key').fill('demo-vault-key');
    await page.getByRole('button', { name: 'Unlock Vault', exact: true }).click();
    await page.getByRole('button', { name: 'Import quotes', exact: true }).click();
    const dialog = page.getByRole('dialog', { name: 'Import quotes', exact: true });
    const quotes = [
        { text: 'Naming check for a guest lecturer.', author: 'pei zhang' },
        { text: 'Naming check for an aliased speaker.', author: '\u00a0@Abhinav Daram' },
        { text: 'Naming check for a conversation.', author: 'demo and @Abhinav Daram' },
        { text: 'Naming check for an outside commentator.', author: 'nbc commentator' },
    ].map((row, index) => ({ ...row, source_sender: 'Original Sender', source: {
        id: `0${index + 1}`.repeat(32), timestamp: 'Sep 18, 2026  1:00:00 PM',
    } }));
    await dialog.getByLabel('Reviewed quotes or full draft').setInputFiles({
        name: 'names.json', mimeType: 'application/json',
        buffer: Buffer.from(JSON.stringify({ format: 'quotevault-reviewed-quotes', version: 1, quotes })),
    });
    for (const [index, name] of ['Pei Zhang', 'Abhi Daram', 'Demo Tester & Abhi Daram', 'NBC Commentator'].entries()) {
        await expect(dialog.getByLabel(`Person quoted for quote ${index + 1}`)).toHaveValue(name);
    }
    await dialog.getByRole('button', { name: 'Import 4 selected quotes' }).click();
    await expect(dialog.getByText(/^4 quotes imported and encrypted/)).toBeVisible();
    await dialog.getByRole('button', { name: 'Close', exact: true }).click();
    await page.reload();
    await page.getByLabel('Group Vault Key').fill('demo-vault-key');
    await page.getByRole('button', { name: 'Unlock Vault', exact: true }).click();
    for (const name of ['Pei Zhang', 'Abhi Daram', 'Demo Tester & Abhi Daram', 'NBC Commentator']) {
        await expect(page.getByText(`— ${name}`, { exact: true })).toBeVisible();
    }
    await expect(page.getByText('Originally shared by Original Sender', { exact: true })).toHaveCount(4);
    await page.getByRole('button', { name: 'Import quotes', exact: true }).click();
    await dialog.getByLabel('Reviewed quotes or full draft').setInputFiles({
        name: 'repeat.json', mimeType: 'application/json',
        buffer: Buffer.from(JSON.stringify({ format: 'quotevault-reviewed-quotes', version: 1,
            quotes: [{ ...quotes[1], author: 'abhinav daram', source: { id: '0a'.repeat(32) } }] })),
    });
    await expect(dialog.getByText('0 selected · 1 duplicates skipped', { exact: true })).toBeVisible();
});
