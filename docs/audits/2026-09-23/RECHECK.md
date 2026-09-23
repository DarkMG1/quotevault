# Independent recheck after the three fixes

September 23, 2026. Reviewed the working tree on `codex/audit-fixes-2026-09-20`, based on `a4f2bba9319655f85ff05cb869d8a3e9938a513d`, including the uncommitted fixes. **QV1, QV2, and QV3 are resolved in the local checks below.** This supersedes the original report's assessment of those three bugs.

## Fix verification

| Finding | Reviewed change | Fresh evidence |
| --- | --- | --- |
| QV1: missing enrollment details | Pending state now reflects an outstanding unapproved request. | Enrollment screen, QR/link, and approval action after reload passed. |
| QV2: idle synchronization loop | Renewal and conversion callbacks no longer depend on the device-state object replaced during renewal. | Idle request-rate regression passed; remembered-device unlock, offline reload, and lease expiry also passed. |
| QV3: cannot revoke another owned device | UI sends the acting device ID/token separately from the target; SQL checks target ownership. | Full database suite passed, including separate device tokens, cross-owner denial, wrong-token denial, other-device revocation, and self-revocation. An added browser test verified the UI's exact RPC arguments and refreshed revoked status. |

## Checks run

- `npm test`: 70 Node tests and 24 Python tests passed.
- `npm run test:edge`: type checking and all four tests passed.
- `PGHOST=127.0.0.1 PGPORT=55432 PGUSER=chiragbhat npm run test:database`: passed on PostgreSQL 17.11.
- `npm run test:browser`: all 25 existing browser tests passed, including the formerly intermittent unreachable-auth check.
- After adding the revocation UI regression, `npm run test:browser -- tests/browser/device.spec.ts`: all six device tests passed. This was a focused rerun, not a second full 26-test run.
- The browser commands compile TypeScript and build the production-mode frontend with local test configuration before running.
- `npm run lint` and `git diff --check`: passed.

Browser API/RPC tests use synthetic local responses. SQL tests exercise the migrated database separately. They do not represent a hosted Supabase end-to-end deployment.

## Built-in browser and real passkey check

Opened the standalone diagnostic in the actual Codex in-app browser at `http://localhost:5186/`. No virtual authenticator, mocked credential API, or intercepted passkey response was used. The user completed registration and authentication through the browser's real credential prompts.

Observed results:

- Browser user agent reports Chrome 153 on macOS. This is the embedded browser, not a Safari test.
- Localhost was a secure context; Web Crypto, IndexedDB, Service Worker, and WebAuthn APIs were exposed.
- RSA-OAEP 3072-bit encryption/decryption round trip passed.
- A non-extractable AES-GCM key persisted through IndexedDB structured cloning and successfully encrypted/decrypted data.
- Client capabilities advertised `extension:prf: true` and `hybridTransport: true`.
- `isUserVerifyingPlatformAuthenticatorAvailable()` returned false; the capability map also reported `userVerifyingPlatformAuthenticator: false`. This does not rule out external or cross-device authenticators and does not verify Touch ID.
- After the user completed both prompts, the page displayed:

```json
{"assertionReturned":true,"prfBytes":32,"matchesRegistrationPrf":true}
```

This verifies a real passkey PRF round trip using a **phone / synced passkey**, as confirmed by the user, in the built-in browser. The phone OS and passkey provider were not specified. The diagnostic does not store or print credential IDs, private keys, or PRF bytes.

The test credential belongs to **localhost** and is named **QuoteVault local compatibility test**. It grants no QuoteVault access. The app's real RP ID remains `quotes.darkmg1.dev`; the localhost result verifies browser/authenticator primitives, not production-origin enrollment or restoration. No production credential was created or changed.

The reproducible diagnostic is `browser-compatibility.html` in this directory. Serve this directory on localhost and open that file to repeat; physical credential creation and verification must be completed by the user. A test passkey may remain in the selected provider until the user removes it.

## Remaining release limits

The three reported local bugs no longer block release. This is not a claim that the entire platform/browser matrix or production rollout is verified. Still outstanding: QuoteVault enrollment/restore at its real RP origin and a real hosted backend; physical Safari/iOS/Android/Firefox/Edge combinations; production signer/public-key matching, realtime settings, pg_cron, backup restoration, migration readback, and CI against the final release commit. Production deployment and envelope activation were not performed.
