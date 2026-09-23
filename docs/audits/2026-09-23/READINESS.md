# Local pre-deployment verification — September 23, 2026

**Original assessment (superseded):** three feature bugs blocked this working tree. The subsequent independent [recheck](RECHECK.md) verified all three fixes and a real built-in-browser passkey PRF round trip. No production data, deployments, signing secrets, or hosted configuration were changed.

Tested `codex/audit-fixes-2026-09-20` at `a4f2bba9319655f85ff05cb869d8a3e9938a513d`, including the pre-existing uncommitted audit fixes and migration `20260922140000_audit_fixes.sql`. This is a working-tree assessment, not verification of an immutable release commit.

## Confirmed bugs

### QV1 — High: new-device enrollment hides its approval details

- Location: `src/hooks/useCrypto.tsx:319`; display conditions in `src/components/VaultGate.tsx:58`.
- Reproduce: sign into an active envelope vault in a fresh browser, select **Remember this device**, and let `request_device` succeed.
- Expected: pending-approval screen, code, QR/link, and **Check approval**.
- Actual: the provider passes `pending: false` unconditionally. Its separate `pending` flag is restricted to `preparing`, so an active vault displays none of the approval information despite saving the request.
- Impact: the ordinary enrollment workflow cannot provide the information required by an approving device. The same provider branch serves passkey enrollment.
- Evidence: `tests/browser/device.spec.ts`, test **a new device shows its approval code and can check approval after reload**. Reproduced in consecutive runs.
- Fix direction: derive pending state from the actual outstanding enrollment in both active and preparing vaults, preserve legacy unlock during preparation, and verify reload and approval completion.

### QV2 — High: successful lease renewal causes an endless sync loop

- Location: `src/hooks/useCrypto.tsx:243-249`, `src/hooks/useQuotes.tsx:45-52` and `188-210`.
- Reproduce: unlock an approved remembered device in an active vault, then leave the page idle with successful sync and signed lease responses.
- Actual: 10 sync requests within a 1.5-second quiet interval in the focused run. Each renewal saves a new `deviceState` object, changing the renewal callback, the sync context, and the subscription effect. That effect schedules another sync after 150 ms, which renews again.
- Impact: sustained unnecessary database/Edge requests and realtime subscription churn on every unlocked online device. It also repeatedly resets synchronization lifecycle bookkeeping.
- Evidence: `tests/browser/device.spec.ts`, test **an idle approved device does not continuously synchronize and renew its lease**; no user action or realtime broadcast is needed.
- Fix direction: keep sync callbacks stable across lease metadata updates while preserving authorization/generation changes and cancellation checks.

### QV3 — High: users cannot revoke another one of their devices

- Location: `src/components/DeviceSecurity.tsx:16`, `src/lib/device.ts:133`, `supabase/migrations/20260922130000_envelope_rotation.sql:58-69`.
- Reproduce: give one member two active devices with different authorization tokens. From device A, click **Revoke** on device B.
- Actual request: B's ID plus A's token. The RPC authorizes that token against B, returns null, and leaves B active. The client rejects the null response. The UI only renders this action for other devices, so its intended path cannot work with independently generated tokens.
- Impact: a member cannot revoke a lost second device using this screen. Self-revocation through **Forget this device** is a different path.
- Evidence: reproduced against PostgreSQL 17 with the complete migration chain. `reproduce-device-revocation.sql` checks that A is authorized, then confirms the exact UI-shaped request leaves B active.
- Fix direction: authenticate the acting device separately from the revocation target, verify both belong to the member, preserve lock order and maintenance restrictions, and test cross-owner denial. Do not bypass token validation.

## Results and limits

- `npm test`: 70 Node tests passed, plus 24 Python import tests. Several Node entries also contain multiple direct assertions.
- `npm run test:edge`: Deno type checking and all four tests passed, including signature verification against the browser verifier.
- `npm run test:database`: passed on local PostgreSQL 17.11, with `PGHOST=127.0.0.1 PGPORT=55432 PGUSER=chiragbhat`. This includes all migrations, reapplication guards, authorization, recovery, migration staging/activation/rollback, retained-history rotation, and the existing audit regressions.
- Production-mode frontend compilation/build succeeds as part of the browser runner, using synthetic local URLs and a fresh test lease public key. The private test signer exists only in the Node test environment, never a `VITE_` variable.
- Lint and whitespace checks passed. A concurrent lint attempt raced Playwright removing its ignored test-results directory; rerunning lint sequentially avoids that tooling race.
- Initial existing-browser run: 19 passed, one failed. The unreachable-auth test observed bootstrap/sync/realtime traffic while expecting none. The same test passed on the focused rerun. Treat this as an unresolved intermittent test failure, not a confirmed auth vulnerability or a clean first run.
- Final complete browser run: **23 passed, 2 failed** (54.5 seconds). Both failures are QV1 and QV2. The original unreachable-auth check passed in this run.
- New focused tests: remembered-device decrypt/lock/offline reload, first-device recovery setup, and open-app lease expiry passed. Enrollment and idle-sync checks failed as described above.

Browser tests use Chromium, the actual built React app, IndexedDB, Web Crypto, and the service worker. Auth and RPC responses are local fixtures or intercepted test responses; database authorization is tested separately against PostgreSQL. Passing either layer does not prove a hosted Supabase end-to-end deployment.

Still unverified: physical iOS/Safari/Android/Firefox/Edge combinations; actual passkey PRF registration/restoration with authenticators; personal-recovery use and replacement through a real hosted Edge/Auth/database chain; browser-driven admin approval, migration activation/resume/rollback, removal plus rotation, and interrupted-write recovery against a full Supabase stack; production lease-key matching, realtime settings, pg_cron, backup restoration, hosted migration state, and CI for the final release commit. These cannot be called fully working on the evidence from this local run.

## Reproduce

```sh
npm test
npm run test:edge
npm run lint
PGHOST=127.0.0.1 PGPORT=55432 PGUSER=chiragbhat npm run test:database
npm run test:browser
# Focus on the new feature checks:
npm run test:browser -- tests/browser/device.spec.ts
```

To reproduce QV3, create an empty disposable local PostgreSQL database, apply `tests/database-fixture.sql`, apply every file in `supabase/migrations/` in timestamp order, then run `psql -X -v ON_ERROR_STOP=1 -d DATABASE -f docs/audits/2026-09-23/reproduce-device-revocation.sql`. The probe rolls back its fixture data. Never run fixture or audit SQL on production.

This verification added five browser checks, an ephemeral test lease signer in `playwright.config.ts`, this report, and the SQL reproduction. It did not change application or migration behavior or overwrite the audit fixes already present at the start. The two failing browser checks intentionally keep the feature defects visible in the normal test command.

## Resolution (same day)

- QV1: the gate shows the pending-approval screen whenever an outstanding request loads and the device has no wrapper, in active and preparing vaults (`src/hooks/useCrypto.tsx`). An expired request falls back to enrollment buttons.
- QV2: the lease-renewal and conversion callbacks read stored device state instead of `deviceState`, so a renewal no longer rebuilds the sync context.
- QV3: `revoke_own_device(p_device_id, p_token, p_target_device_id)` authorizes the acting device and revokes any device of the same member (`20260922140000_audit_fixes.sql`); regression in `tests/database-audit-fixes.sql`. The probe above now checks the fixed contract.
- The two failing checks in `tests/browser/device.spec.ts` pass, and fail again when their fix is reverted.
