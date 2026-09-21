# QuoteVault: code and infrastructure review

Reviewed September 21, 2026 against `a878167`. Production ran that revision at the start of the review. See FIXES.md for subsequent remediation status. Scope: all 20 application source files (2,172 lines), the 671-line SQL migration, tests, dependencies, build/PWA configuration, documentation, Git remote state, and a read-only VPS/HTTPS inspection. The lower-cost database, sync, and UI agents reviewed separate areas; their findings were checked and consolidated here. No application or production changes were made during this review.

The existing architecture fits this application: React → browser encryption and Dexie → Supabase RPC/PostgreSQL, with Nginx serving static assets. Keep that structure. Most useful work is release discipline, recovery behavior, and small UI cleanup. No new application server, cache service, queue service, or routing/state framework is warranted by the observed workload.

## Confirmed findings, in priority order

### I1 — P1: the production release's parent directory is world-writable

**Evidence:** `ssh vps 'namei -l /pages/quotevault/dist/index.html'` reports `/pages` as `drwxrwxrwx root root`, without the sticky bit. The release directory is `775 dark:dark`. No immutable flag was present. The host also serves other applications.

**Impact:** under these filesystem permissions, another unprivileged local process with access to this path can rename/replace a release directory without needing permission to edit its files. Replacing the served JavaScript could compromise vault passphrases when users next unlock. This is a local-compromise escalation path, not evidence that compromise occurred. No replacement/exploit was attempted.

**Smallest fix:** give the deployment user a dedicated writable release parent under a protected directory, with web workers having read/traverse access only. Alternatively, correct `/pages` ownership/group permissions after checking the other sites' deployment requirements. Do not run a blanket recursive chmod over this shared host. Verify deployment still works as `dark` and a service identity cannot replace releases.

### I2 — P2: the deployed fixes are absent from the origin branch

**Evidence:** `git ls-remote origin refs/heads/main refs/heads/codex/audit-fixes-2026-09-20` returned only `main` at `5798655`. Local and production HEAD are `a878167`; the audit branch is not published to origin.

**Impact:** a fresh clone or deployment from main would restore the old frontend against the new database contract. The fixes currently exist on the local machine and VPS, but are not represented in the normal remote release history.

**Smallest fix:** publish the reviewed branch, integrate it through the normal repository workflow, and record a release revision. Deploy explicit tested revisions rather than an unspecified working tree.

### R1 — P2: the administrator can lock themselves out of the application

**Evidence:** `src/components/Admin.tsx:63` permits removing any allowlist row. The SQL DELETE policy at `supabase/migrations/20260920000000_secure_vault.sql:627` checks only `qv_is_admin()`. That function does not require allowlist membership. By contrast, `get_vault_state()` at line 350 requires membership, and `src/hooks/useCrypto.tsx:106` prevents all application routes from mounting until the vault is unlocked.

**Reproduction:** remove the configured administrator's own allowlist entry, then reload online. The vault settings RPC denies membership, and the administrator cannot reach the Admin screen to restore the entry. This path was traced in code; it was not executed against production.

**Smallest fix:** protect the sole administrator's allowlist entry against deletion/renaming on the server and disable its Remove action in the UI. Direct authenticated admin/API authority remains available today; this is UI lockout, not loss of database privileges.

### R2 — P2: transient local-storage initialization failure has no working retry

**Evidence:** `src/hooks/useQuotes.tsx:63` catches initialization transaction failures without setting `initializedIdentity`. The query at line 35 continues returning `[]`; the subscription effect at line 97 never starts. Refresh at line 47 runs synchronization but does not retry initialization, and can clear the visible error despite the feed still being unready.

**Reproduction:** `node docs/audits/2026-09-21/reproduce-init.mjs`. A mocked transaction fails once, then the captured Refresh action runs. Output: `transactions: 1`, `syncCalls: 1`, `initializedIdentity: null`, `syncError: ""`. This isolates the provider control-flow failure; it is not a real browser/IndexedDB transaction test.

**Smallest fix:** reuse initialization from an explicit Retry action, or have Refresh retry initialization when unready. Keep failure visible until initialization actually succeeds.

### I3 — P2: missing assets return cached HTML, and cache policy does not distinguish releases

**Evidence:** `/etc/nginx/sites-available/quotes.conf:39` sends every missing path to `index.html`. An HTTPS GET of `/assets/audit-missing-file.js` returned **200, text/html, Cache-Control: max-age=14400**. Both `/sw.js` and the hashed main JavaScript also returned a four-hour cache lifetime. The root HTML had no explicit Cache-Control header.

**Impact:** clients requesting a removed asset receive a misleading success response and unusable HTML. Service-worker releases and immutable hashed assets need different cache behavior. The observed header is not proof that every browser delays service-worker updates four hours; browser update fetches and CDN behavior differ.

**Smallest fix:** return 404 for missing `/assets/` files, give content-hashed assets long-lived immutable caching, and make HTML/service-worker metadata revalidate with matching CDN rules. Retain compatible previous assets for the intended update window. The app uses hash navigation, so it does not need a general server-side SPA route fallback. Preserve security headers when adding Nginx location blocks. [Nginx header/caching documentation](https://nginx.org/en/docs/http/ngx_http_headers_module.html).

### U1 — P2: sign-out failures are silently ignored

**Evidence:** `src/components/Layout.tsx:11` awaits `supabase.auth.signOut()` and ignores its returned error. The locked-vault screen already handles this error at `src/hooks/useCrypto.tsx:128`.

**Impact/reproduction:** return a sign-out error while the user is in the unlocked application; clicking Sign out gives no failure explanation. The user can incorrectly believe the session ended.

**Smallest fix:** inspect the returned error, catch thrown failures, and display an accessible message. Preserve pending offline changes.

### U2 — P3: loading, empty, and failure states remain inconsistent

`src/hooks/useQuotes.tsx:35` supplies an empty array before initialization, and `src/components/Feed.tsx:138` renders “No Quotes Yet” before an initial fetch/decryption finishes. Track initial readiness/fetch state explicitly while still displaying cached quotes immediately. The author selector similarly has no loading feedback while `AddQuote.tsx:97` fetches profiles; render “Loading authors…” until it resolves.

Auth, profile, and admin feedback at `Auth.tsx:78`, `Profile.tsx:120`, and `Admin.tsx:138` lacks alert/live-region semantics. Add an alert for failures and polite status announcements for success. Use the existing error-message helper in Admin so Supabase error objects retain their useful messages. Disable a pending allowlist removal to avoid repeated requests.

### D1 — P3: accepted timestamps can be unusable by the browser

**Evidence:** the validator at `supabase/migrations/20260920000000_secure_vault.sql:333` casts `created_at` to PostgreSQL `timestamptz`; PostgreSQL accepts `infinity`. A read-only call against the local migrated test database confirmed `qv_valid_quote(...) = true` for this value. JavaScript renders `new Date('infinity').toLocaleDateString()` as `Invalid Date`.

**Impact:** a member using the RPC directly can create a quote that displays an invalid fallback date when `quote_date` is absent. The normal UI generates a finite ISO timestamp.

**Smallest fix:** enforce a finite, supported timestamp representation at the RPC boundary and retain explicit validation for the optional quote date.

## Additions worth making to the existing infrastructure

| Order | Addition | Minimum useful implementation |
| --- | --- | --- |
| 1 | Repeatable release workflow | One checked-in deployment script: exact revision, clean build, public configuration validation, asset hashes, compatible database migration, atomic cutover, HTTP smoke check, and retained rollback release. Record the Nginx site configuration in the repository with no keys. Keep sequential migrations immutable after release. |
| 2 | CI with database checks | Run `npm ci`, tests, lint, build, and the existing SQL scripts against a disposable PostgreSQL instance. Test Supabase-shaped default grants and migration reapplication. There is currently no tracked CI workflow; `npm test` only runs `.test.mjs` files. |
| 3 | Verified backup and restore procedure | Confirm this Supabase project's actual backup plan and retention, then restore into an isolated environment. Preserve schema, auth dependencies, encrypted data, vault derivation/verifier metadata, and frontend compatibility. The prior deployment snapshots are useful evidence but are not a demonstrated automated recovery system. Use existing managed backups where sufficient; add scheduled exports only for a concrete retention/recovery gap. [Supabase backup documentation](https://supabase.com/docs/guides/platform/backups). |
| 4 | Small health/space checks | Check HTML plus an actual referenced JS asset, and verify anonymous access remains denied. Alert on failures and disk pressure without logging quote contents, passphrases, or tokens. No QuoteVault monitor/backup timer was visible in the inspected timers, user cron, or repository; externally configured monitoring remains unverified. |

The shared host had less than 20% free disk space. Inspect disk use before adding release archives or backups. Unrelated services and root-only host configuration are outside this application remediation.

Nginx also contains copied upload settings (`client_max_body_size 800m`, `client_body_timeout 120s`, lines 17–19) despite serving a static app. Remove this unused policy when versioning the site config. The current CSP only restricts framing; a tested script/resource policy would provide additional protection, but must allow the actual Supabase HTTPS/WebSocket connections and preserve the PWA.

## Useful product additions

1. **Account password recovery.** Add “Forgot password?” and handle the recovery callback before the vault gate. Reuse Supabase's recovery flow; this resets the login password, never recovers the shared encryption key. [Supabase recovery API](https://supabase.com/docs/reference/javascript/auth-resetpasswordforemail).
2. **Lock vault and visible sync status.** Reuse the existing `lockVault()` method for a manual Lock button. Show pending operation count/last successful sync and a clear recovery path for rejected/blocked work. An idle timeout is optional and must not silently discard a draft.
3. **Portable export.** Start with an encrypted JSON export containing versioned ciphertext and the metadata needed to unlock it. If adding readable export, require an explicit user action and generate it locally after unlock; never upload plaintext to produce the file. Test restore before describing export as a backup.
4. **Small search improvements.** Include context and add local author/date filters. Search remains on decrypted browser data. A server-side search service would conflict with the current encryption design and is unnecessary at this scale.

## Conditional improvements and test boundaries

- **Empty-vault reset notification:** `rotate_vault` changes `vault_state`, but the frontend only subscribes to quote changes (`useQuotes.tsx:106`). Resetting an already empty vault emits no quote-row event. Another visible unlocked client can remain on the old generation until its next sync; an attempted save is rejected and stale local work is discarded. Server enforcement remains intact. Add an authorized generation-change signal if prompt cross-device reset notification is required; do not broadly expose vault-state tables or add constant polling.
- **Auth startup error path:** `useAuth.tsx:16` has no rejection handler for `getSession()`. A rejected promise would leave the app loading. The SDK's normal returned-error behavior is distinct; an actual SDK rejection was not reproduced here. A small guarded catch/finally is appropriate robustness work, not a proven production incident.
- **Test realism:** `tests/sync.test.mjs:47` calls the transaction callback directly; its fake does not roll back or model cross-tab IndexedDB behavior. `tests/ui.test.mjs:64` replaces React effects with no-ops. Keep the useful deterministic tests, but add a small automated browser flow covering real storage, offline create/delete/reconnect, session changes, and keyboard dialogs. Do not expand the handwritten React/IndexedDB imitation to approximate a browser.
- **Startup payload:** current main JS is 740.64 kB / 222.52 kB gzip. Lazy-load Admin/Profile with React's existing `lazy`/`Suspense` if startup profiling justifies it. Current PWA precaching would still fetch the emitted chunks, so splitting alone does not promise lower total install bytes. [React lazy documentation](https://react.dev/reference/react/lazy).
- **Request/receipt limits:** the server accepts 50 operations, with up to 10 MiB of encoded cipher data per quote and extra JSON fields. Add reasonable per-quote and total request byte bounds before expanding usage. Receipts intentionally preserve retry safety and currently have no expiry except reset. Do not prune them by age without a defined retry horizon; old inserts could otherwise replay after deletion.
- **Keep the simple sync design:** full snapshots on revision change and a singleton database lock are reasonable for the last verified small vault (18 quotes, six accounts in the earlier deployment record). Add incremental sync only after measured payload/latency growth. No current record counts or authenticated production flows were rechecked in this pass.
- **Author rename consistency:** profile edits do not invalidate the five-minute author cache. Invalidate the current account's cache after a successful rename if immediate visibility matters; keep the offline cache.

## Ponytail audit: ranked cleanup only

- `native:` Replace cosmetic Framer wrappers in Auth/Profile/Admin with plain elements and existing CSS. Keep Feed's motion code for its real swipe interaction. [`src/components/Auth.tsx:60`, `src/components/Profile.tsx:111`, `src/components/Admin.tsx:176`]
- `shrink:` Consolidate the repeated TypeScript-to-VM loading boilerplate into one test-local helper; keep assertions and dependency injection explicit. Do not build a general test framework. [`tests/crypto.test.mjs:8`, `tests/vault.test.mjs:15`, `tests/ui.test.mjs:10`, `tests/sync.test.mjs:11`]
- `yagni:` Remove AddQuote's always-true `isOpen` prop and its redundant post-save field resets: Layout conditionally mounts/unmounts the whole dialog. Keep the shared modal hook because Feed also uses it. [`src/components/Layout.tsx:66`, `src/components/AddQuote.tsx:10`, `src/components/AddQuote.tsx:127`]
- `yagni:` Remove `addQuote`'s optional creator override; its sole caller passes the same authenticated user already owned by QuotesProvider. Derive ownership once. Server checks must remain. [`src/hooks/useQuotes.tsx:120`, `src/components/AddQuote.tsx:126`]
- `shrink:` Define the repeated frontend admin comparison once, and reuse `getErrorMessage` in Admin. SQL remains the authority; no roles framework is needed. [`src/components/Layout.tsx:33`, `src/components/Feed.tsx:24`, `src/components/Admin.tsx:14`, `src/hooks/useCrypto.tsx:80`]
- `delete:` Remove the unimplemented background-sync commentary and unused Tailwind color aliases. They describe flexibility the application does not use. [`vite.config.ts:40`, `tailwind.config.js:18`]

Removing Framer Motion entirely would remove one direct dependency, but would also remove the existing swipe behavior unless it were reimplemented. That is an optional interaction change, not free cleanup. Retain Dexie, Supabase, the operation receipts, legacy migration support, and the actual encryption validation; these all do necessary work. Do not delete the historical audit reproducer merely because it describes repaired behavior—the README already labels it as historical evidence.

## Verification in this pass

| Check | Result |
| --- | --- |
| `npm test` | PASS: 11 runner entries; some entries contain multiple assertions. |
| `npm run lint` | PASS. |
| `npm run build` | PASS; existing large-chunk warning remains. |
| `npm audit --json` | PASS: zero reported vulnerabilities. |
| Initialization failure reproduction | Confirmed; script and output described under R2. |
| Infinite timestamp validator probe | Confirmed in local migrated PostgreSQL; server stopped afterward. |
| VPS, production HEAD, HTTPS and Git origin probes | Read-only; findings above reflect this pass. |
| Full SQL regression suites, live signed-in browser and real-device PWA | Not rerun in this pass; earlier deployment checks remain documented separately. No production token was reused. |

Suggested order: fix I1, preserve the release in origin, repair R1/R2/U1, then add CI/deployment and restore verification. Apply the small Ponytail cuts alongside those changes; add product features afterward.

net: approximately -60 lines, -0 direct dependencies possible while preserving current interactions. Estimate only; no cleanup applied.
