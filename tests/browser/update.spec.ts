import { test, expect } from '@playwright/test';

test('an open app checks for a new version every hour', async ({ page }) => {
  await page.clock.install();
  await page.addInitScript(() => {
    (window as unknown as { updateChecks: number }).updateChecks = 0;
    const update = ServiceWorkerRegistration.prototype.update;
    ServiceWorkerRegistration.prototype.update = function () {
      (window as unknown as { updateChecks: number }).updateChecks++;
      return update.call(this);
    };
  });
  await page.goto('/');
  await page.evaluate(() => navigator.serviceWorker.ready.then(() => true));
  const checks = () => page.evaluate(() => (window as unknown as { updateChecks: number }).updateChecks);
  const before = await checks();
  await page.clock.runFor('01:00:00');
  await expect.poll(checks).toBeGreaterThan(before);
});
