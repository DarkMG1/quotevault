# QuoteVault audit and architecture

Audited checkout: `5798655` on `main`, September 20, 2026. The initial working tree was clean. Application code and dependencies were not changed; this directory contains the report and reproduction evidence.

**Assessment:** the application is small and understandable, but the offline synchronization and vault-reset paths have data-integrity defects. Encryption also has two concrete weaknesses: deleted content is persisted as plaintext, and the stored key verifier provides a cheap password-guessing target. These should be addressed before relying on the app for sensitive or irreplaceable quotes.

## How the application works

| Area | Implementation and responsibility |
| --- | --- |
| App entry | `src/main.tsx` mounts React StrictMode and registers the generated PWA service worker. `src/App.tsx` wraps the app in authentication, gates it behind vault unlock, and selects Feed, Profile, or Admin from the URL hash. |
| Authentication | `useAuth.tsx` restores the Supabase session and subscribes to auth changes. `Auth.tsx` checks an email allowlist before calling sign-up and uses Supabase password login. Profile updates names and reauthenticates before changing the account password. |
| Vault key | `useCrypto.tsx` fetches the shared `app_settings.vault_key_hash`, checks SHA-256 of the entered secret, then derives a non-exportable AES-256-GCM key using PBKDF2-SHA256 with 100,000 iterations and a fixed salt. The key lives in React state. The Supabase account password and group vault key are separate secrets. Normal sign-out unmounts the crypto provider. |
| Quote creation | `AddQuote.tsx` fetches registered users' first names. It encrypts JSON containing text, author, and context, prefixes the encrypted bundle with `$$E2E$$`, and sends it to `useQuotes.addQuote`. UUID, creator ID, quote date, and creation timestamp remain unencrypted. |
| Local storage | `db.ts` creates one origin-wide Dexie database, `QuoteVaultDB`, with `quotes` and `syncQueue` tables. The quote ID is also the queue primary key, so each new action replaces any earlier queued action for that quote. |
| Synchronization | `useQuotes.tsx` first saves/deletes locally and then writes the queue. `sync.ts` processes queued INSERT/DELETE requests sequentially within each invocation. Processing is triggered on hook mount, mutations, the online event, and visibility changes. Concurrent invocations are possible. |
| Reading | `useQuotes.tsx` merges a remote SELECT into IndexedDB and listens for realtime inserts, updates, and deletes. Feed decrypts records in memory, searches text/author locally, displays status/date, and opens delete confirmation after a left swipe. |
| Administration | `Admin.tsx` manages the allowlist. Its destructive key change updates the verifier, deletes remote quotes, clears local quotes, and reloads. The visible admin gate is a hardcoded email comparison. |
| Offline/PWA | Vite PWA precaches the application shell. The queue processor runs in the page, not in a background-sync worker. Profiles and vault-verification settings have no application-managed offline cache. |

This is one shared group vault, not a multi-vault implementation: there is one settings key and no group/vault identifier in quotes. Expected remote tables are `quotes`, `profiles`, `allowlist`, and `app_settings`. No schema migrations, RLS policies, auth hooks, profile-population triggers, deployment configuration, CI workflow, or original test suite are checked in. The README remains the Vite template.

## Confirmed findings

P1 = high priority, affecting confidentiality or core data integrity. P2 = normal-priority functional/reliability/accessibility defect. “Reproduced” below means executed against the actual source with in-memory storage and network substitutes, unless otherwise stated; it does not mean an exploit or destructive operation was run against Supabase.

### S1 — P1: deleting an encrypted quote stores its plaintext on disk

**Location:** [Feed.tsx:58](../../../src/components/Feed.tsx#L58), [useQuotes.tsx:84](../../../src/hooks/useQuotes.tsx#L84), [sync.ts:9](../../../src/lib/sync.ts#L9).

Feed passes the decrypted display object to `deleteQuote`; the queue saves that entire object as its payload. Reproduce by deleting a quote offline and inspecting `syncQueue`: text, author, and context are readable without the vault key. They remain until successful synchronization, including across sign-out/reload. The error logger can also print the plaintext item after a failed sync.

**Minimum fix:** a deletion queue item needs only the quote ID and ownership/version metadata, never the decrypted contents. Clean up existing DELETE payloads as part of the fix. **Evidence:** reproduction S1.

### S2 — P1: the server-side vault verifier bypasses the expensive key derivation

**Location:** [crypto.ts:114](../../../src/lib/crypto.ts#L114), [useCrypto.tsx:40](../../../src/hooks/useCrypto.tsx#L40), [Admin.tsx:74](../../../src/components/Admin.tsx#L74).

The verifier is unsalted SHA-256 of the same secret used for encryption. Anyone obtaining that value can test candidate secrets with one SHA-256 each, bypassing PBKDF2's 100,000-iteration cost. The UI permits four-character keys. The local reproduction recovers a synthetic `1234` secret from a short dictionary using the actual `hashVaultKey` function. No real key was accessed or guessed.

**Minimum fix:** remove the fast verifier; validate a candidate derived key by decrypting an authenticated, known verification payload. Store a random per-vault salt and KDF/version metadata so derivation remains reproducible offline. Existing encrypted data requires a migration strategy when changing derivation. Fast hashes are unsuitable for password verification; see [OWASP guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html). **Evidence:** reproduction S2; access to the deployed verifier was not tested.

### D1 — P1: an acknowledged-late INSERT can block the entire queue indefinitely

**Location:** [sync.ts:26](../../../src/lib/sync.ts#L26), [sync.ts:56](../../../src/lib/sync.ts#L56).

Reproduce an INSERT that commits remotely but loses its response. Its queue entry remains. Every retry attempts another ordinary INSERT with the same UUID, receives a duplicate-key error, and breaks before processing later items. One ambiguous network failure can therefore stop all subsequent saves and deletes.

**Minimum fix:** make retries idempotent for a specific operation and verify any existing record before acknowledging it. Distinguish retriable failures from permanently rejected items so one bad record cannot block unrelated work. **Evidence:** reproduction D1.

### D2 — P1: finishing an old INSERT can discard a newer DELETE

**Location:** [sync.ts:7](../../../src/lib/sync.ts#L7), [sync.ts:17](../../../src/lib/sync.ts#L17), [sync.ts:51](../../../src/lib/sync.ts#L51).

The processor snapshots queue entries, waits for remote requests, then unconditionally deletes the queue entry by quote ID. Reproduce by starting a delayed INSERT, going offline, deleting that quote, then allowing the original INSERT response to arrive. The DELETE replaces the pending INSERT, but the old processor removes it as though it were the acknowledged INSERT. The server retains the quote and no deletion remains queued.

**Minimum fix:** acknowledge the exact queued operation/version that completed, atomically. Coordinate competing processors as well; a processing lock alone does not prevent a user mutation from replacing an in-flight entry. **Evidence:** reproduction D2.

### D4 — P1: key rotation leaves old-key uploads active

**Location:** [Admin.tsx:102](../../../src/components/Admin.tsx#L102), [useCrypto.tsx:23](../../../src/hooks/useCrypto.tsx#L23), [AddQuote.tsx:60](../../../src/components/AddQuote.tsx#L60).

The wipe clears `db.quotes` but never clears `db.syncQueue`. Reproduce with a pending INSERT, complete a successful wipe, and resume synchronization: the supposedly erased quote is uploaded again using the old encryption key. Separately, other already-unlocked clients keep their old key and can create more old-key quotes because no vault generation is checked. New-key clients cannot decrypt those records.

**Minimum fix:** coordinate reset with synchronization; clear the current client's outbox and invalidate stale operations using a server-enforced vault generation. Other clients must discard stale queued writes and relock when the generation changes. Clearing only one browser's queue is insufficient. **Evidence:** reproduction D4 for queued resurrection; active-client key retention confirmed by source inspection.

### D5 — P1: a partially failed rotation changes the verifier before the wipe succeeds

**Location:** [Admin.tsx:87](../../../src/components/Admin.tsx#L87).

The settings upsert and quote deletion are separate requests. Reproduce a successful settings update followed by a failed DELETE: the server keeps old-key ciphertext but advertises only the new verifier. The old secret is rejected on unlock, while the new secret cannot decrypt existing quotes. This is an inconsistent state, even though the UI reports the failure.

**Minimum fix:** perform the authorized remote reset and generation change in one database transaction; synchronize local cleanup only after the transaction succeeds. **Evidence:** reproduction D5.

### D3 — P2: refresh cannot reconcile deletions and can restore pending deletions

**Location:** [useQuotes.tsx:24](../../../src/hooks/useQuotes.tsx#L24), [useQuotes.tsx:42](../../../src/hooks/useQuotes.tsx#L42).

Refresh only calls `bulkPut`. A quote deleted remotely while this client was closed or disconnected remains locally even after an empty successful refresh. In the other direction, deleting locally while offline and refreshing before the DELETE is uploaded restores the remote row as “synced.” Realtime writes also do not consult pending deletion state.

**Minimum fix:** reconcile a complete remote snapshot or use deletion tombstones, while preserving pending local mutations. Refresh after reconnect/subscription recovery as well; current reconnect listeners only process outgoing work. Do not remove absent local rows from a potentially truncated remote page. **Evidence:** both D3 reproductions.

### D6 — P2: online saves claim “synced” before any server acknowledgement

**Location:** [useQuotes.tsx:66](../../../src/hooks/useQuotes.tsx#L66), [Feed.tsx:111](../../../src/components/Feed.tsx#L111).

Reproduce with `navigator.onLine === true` while Supabase rejects or cannot receive the INSERT. The quote remains queued but is already marked `synced`, so Feed does not warn that it exists only on this device. Browser connectivity is not a successful server write.

**Minimum fix:** initialize every new quote as pending and mark it synced only after verified acknowledgement. **Evidence:** reproduction D6.

### D7 — P2: local data and its queued operation are committed separately

**Location:** [useQuotes.tsx:70](../../../src/hooks/useQuotes.tsx#L70), [useQuotes.tsx:81](../../../src/hooks/useQuotes.tsx#L81).

Reproduce a successful local quote write followed by a failed queue write. The quote remains visible but has no upload operation. The equivalent interruption during deletion removes the local quote without scheduling the remote delete. A storage error or termination between the two commits leaves unrecoverable synchronization intent.

**Minimum fix:** one Dexie read/write transaction spanning `quotes` and `syncQueue` for each local mutation. **Evidence:** reproduction D7 injects the second-write failure.

### O1 — P2: reopening the PWA offline prevents vault access

**Location:** [useCrypto.tsx:40](../../../src/hooks/useCrypto.tsx#L40).

Even with a cached authenticated session and encrypted quotes, reopening resets the in-memory encryption key. Unlock then requires an uncached Supabase settings request. A network error exits before key derivation, so the correct key cannot unlock cached data. This defeats the advertised offline behavior after a reload.

**Minimum fix:** persist non-secret vault derivation/verification metadata and allow local authenticated decryption; reconcile the vault generation when online. **Evidence:** reproduction O1 executes the actual unlock handler with an offline response.

### O2 — P2: the PWA manifest references missing icons

**Location:** [vite.config.ts:18](../../../vite.config.ts#L18).

The generated manifest references `pwa-192x192.png` and `pwa-512x512.png`; neither exists in `public` or the production build. The configured favicon/apple-touch/masked assets are missing too. The app cannot supply its declared install icons. Browser-specific installation consequences were not tested.

**Minimum fix:** add the actual icon files and verify their deployed responses. **Evidence:** production manifest and filesystem inspection after a successful build.

### U1 — P2: the default quote date uses UTC instead of the user's calendar day

**Location:** [AddQuote.tsx:19](../../../src/components/AddQuote.tsx#L19).

`toISOString().split('T')[0]` sets September 21 when the local time is September 20 at 9 PM in Detroit. The input can therefore save a quote under tomorrow's date. Its state also survives modal closes, so an app left open across midnight retains the previous initialization date.

**Minimum fix:** derive the initial value from local date components when opening a fresh form. **Evidence:** executed with `TZ=America/Detroit` and a fixed September 20, 2026, 9 PM date.

### U2 — P2: failed creation has no visible error state

**Location:** [AddQuote.tsx:72](../../../src/components/AddQuote.tsx#L72).

When encryption or local storage rejects, the catch only logs to the console; the form silently stops showing “Saving…”. There is no explanation or recovery instruction. The D7 failure is one concrete route into this catch.

**Minimum fix:** display an inline save error and retain the draft. **Evidence:** source inspection and reproduced rejection from `addQuote`; visual browser behavior not exercised.

### U3 — P2: deleting quotes requires a dragging gesture

**Location:** [Feed.tsx:95](../../../src/components/Feed.tsx#L95).

The only control opening delete confirmation is `onDragEnd` on a non-focusable card. Keyboard and assistive-technology users have no equivalent delete action.

**Minimum fix:** add an accessible Delete button alongside the optional swipe gesture. **Evidence:** UI event/markup inspection.

### U4 — P2: dialogs lack keyboard focus management and dialog semantics

**Location:** [AddQuote.tsx:90](../../../src/components/AddQuote.tsx#L90), [Feed.tsx:164](../../../src/components/Feed.tsx#L164).

Both dialogs are ordinary divs without dialog naming, modal semantics, initial focus, focus containment/restoration, or Escape handling. Nothing prevents keyboard focus from reaching the obscured page behind them.

**Minimum fix:** use native modal `<dialog>` behavior with an accessible name, or implement equivalent behavior in the existing components. **Evidence:** source inspection; no screen-reader/device testing performed.

### U5 — P2: core icon controls are unnamed and visible labels are unassociated

**Location:** [Layout.tsx:26](../../../src/components/Layout.tsx#L26), [Layout.tsx:40](../../../src/components/Layout.tsx#L40), [Layout.tsx:55](../../../src/components/Layout.tsx#L55), [AddQuote.tsx:111](../../../src/components/AddQuote.tsx#L111).

Profile/admin navigation, sign-out, add, refresh, and close controls use icons without accessible text. Several visible form labels have no `htmlFor`/input `id` association. Auth fields rely on placeholders instead of persistent labels.

**Minimum fix:** name icon actions with `aria-label` and connect visible labels to their controls. **Evidence:** source inspection.

## Verification results and limits

| Check | Observed result |
| --- | --- |
| `npm run build` | PASS, exit 0. TypeScript and Vite production build complete. Main JS is 635.00 kB, 193.73 kB gzip. Warnings: large chunk, ineffective dynamic DB import, outdated Browserslist data. These warnings are not build failures. |
| `npm run lint` | FAIL, exit 1: 10 errors. Seven explicit `any` catches, one unused caught error, two Fast Refresh export-rule failures. This is a lint failure, not proof of ten runtime bugs. |
| `node docs/audits/2026-09-20/reproduce.mjs` | Eleven bug scenarios reproduced. AES-GCM Unicode round-trip and tampered-ciphertext rejection pass. Script exit 0 means the reported faulty behavior was observed; it is not a green regression suite. |
| Date initialization | Wrong calendar date reproduced with a fixed Detroit evening timestamp. |
| PWA assets | Both unique manifest icon paths absent from the generated output. |
| `npm audit --json` | 21 affected package entries: 13 high, 5 moderate, 3 low, 0 critical. Raw registry output is saved alongside this report. All entries report a fix available. |
| `npm audit --omit=dev --json` | One high package entry: `ws@8.19.0`, pulled through Supabase Realtime. This client uses native browser WebSocket, so a reachable browser exploit through that Node package was not established. |

The audit script transpiles current source using the already-installed TypeScript package and substitutes in-memory storage/network boundaries. It does not exercise Dexie in a browser, Supabase RLS, actual network timing, realtime delivery, service-worker installation, or physical-device behavior. No application tests existed before this audit. No live records, accounts, settings, or secrets were changed.

Dependency advisories are a separate maintenance finding, **B1 (P2)**. Installed Vite `7.3.1` falls within the upstream dev-server file-read advisory; that advisory requires a network-exposed dev server, which the checked-in configuration does not enable. See the [Vite advisory](https://github.com/vitejs/vite/security/advisories/GHSA-p9ff-h696-f583) and [ws advisory](https://github.com/websockets/ws/security/advisories/GHSA-96hv-2xvq-fx4p). Review compatible updates and rerun the build, lint, and behavioral checks; the dependency count does not represent 21 demonstrated application exploits.

## Backend and deployment questions still open

- **Authorization:** sign-up allowlisting and the admin-email check are implemented in browser code. They need independent enforcement through auth hooks and database privileges/RLS. The repository cannot establish whether that enforcement exists. Specifically verify anonymous sign-up, non-admin allowlist/settings writes, quote ownership/deletion rules, and profile reads. This is an unverified security boundary, not a confirmed deployed authorization bypass. See [Supabase's RLS guidance](https://supabase.com/docs/guides/database/postgres/row-level-security).
- **Account changes:** the local database/outbox is global to the origin and survives sign-out; queue processing does not check the current authenticated owner. An old user's pending writes can be attempted under the next session. Actual acceptance/rejection depends on deployed policies; rejection can trigger D1-style queue blocking. Decide explicitly how the shared-vault cache and per-user pending writes should behave across accounts.
- **Remote row limits:** quotes are fetched using one unpaginated SELECT. Older quotes disappear from a fresh device once the server's response cap is exceeded; the project-specific cap and current data count were not inspected. Supabase documents a default maximum of 1,000 rows and range pagination in its [select reference](https://supabase.com/docs/reference/javascript/v1/select). Any D3 reconciliation fix must fetch complete data before pruning local rows.
- **Profile provisioning:** sign-up/profile edit only update auth metadata, while Add Quote reads the separate `profiles` table. A trigger or equivalent synchronization must exist remotely. Without it, authors are missing/stale; there is no checked-in definition to validate. Profiles also are not persisted for offline form initialization.
- **Vault bootstrap:** no visible setting, or some missing-table errors, allows unlock without verifying the supplied key. Confirm that a verifier is provisioned and readable before use; otherwise users can create ciphertext under incompatible secrets.
- **Deployment:** HTTPS/security headers, deployed bundle, auth confirmation/redirect settings, service-worker upgrade behavior, and actual mobile layout/accessibility were not tested. Missing Supabase environment values silently fall back to a placeholder endpoint, so a successful build alone does not demonstrate a working deployment.

## Complexity audit

The code is already small. Correctness work is more valuable than a broad refactor.

- `delete:` remove unused `clsx` and `tailwind-merge` direct dependencies; there are no application imports. Replacement: nothing. [package.json:14](../../../package.json#L14)
- `delete:` remove unused `src/index2.css`, `src/index_test.css`, `src/assets/react.svg`, and empty `src/App.css`. Replacement: existing `src/index.css`. [main.tsx:3](../../../src/main.tsx#L3)
- `shrink:` stop mounting a data-subscribing AddQuote while closed. The hidden component and Feed each invoke `useQuotes`, duplicating live queries, pulls, and subscription/queue setup. Conditional mounting removes the hidden work; sharing one synchronization lifecycle prevents duplicate work while the modal is open too. [Layout.tsx:62](../../../src/components/Layout.tsx#L62)
- `yagni:` remove the advertised `UPDATE` queue action until it is implemented. There is no caller today, and the processor would mark such an item synced and delete it without performing a remote update. [sync.ts:5](../../../src/lib/sync.ts#L5)

net: approximately -6 source/manifest lines and -2 direct dependencies possible from the simple dead-file/dependency removals, excluding lockfile churn. The synchronization lifecycle change is a separate correctness/duplication cleanup, not a reason to introduce a new framework.

## Suggested repair order

1. Prevent plaintext DELETE payloads and migrate existing queue entries (S1).
2. Make local mutations transactional and remote operations retry-safe, with exact-operation acknowledgement (D7, D1, D2), then correct status reporting and reconciliation (D6, D3).
3. Verify backend privileges and implement atomic, generation-aware vault reset (D4, D5); replace the fast key verifier and enable local unlock (S2, O1).
4. Fix date handling, visible errors, accessible controls/dialogs, PWA assets, and dependency/lint failures.

No fixes were applied during this audit.
