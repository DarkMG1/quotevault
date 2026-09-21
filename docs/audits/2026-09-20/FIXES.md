# QuoteVault remediation

Branch: `codex/audit-fixes-2026-09-20`. Original audited revision: `5798655`.

## Changes

| Findings | Repair |
| --- | --- |
| S1 | DELETE operations contain metadata only; the Dexie upgrade removes legacy plaintext delete payloads. |
| S2 | Replace the raw SHA-256 verifier with authenticated ciphertext verified through PBKDF2. Preserve legacy ciphertext derivation; new vault configurations use random salt and 600,000 iterations. |
| D1–D2 | Independent operation IDs, server receipts, exact operation acknowledgements, rejected-operation isolation, and serialized sync prevent duplicate retries and lost later edits. |
| D3 | Complete revisioned snapshots reconcile remote removals while preserving pending local edits. |
| D4–D5 | An administrator-only SQL transaction resets quotes and encryption metadata together; generation checks reject obsolete clients. |
| D6–D7 | Local quotes start pending. Quote changes and queue writes commit in the same IndexedDB transaction; only server acknowledgement marks success. |
| O1 | Account-scoped encrypted verification metadata and author caches support prepared offline use. |
| O2 | Add real PWA, touch, mask, and favicon assets. |
| U1 | Fresh dialogs initialize dates from the local calendar. |
| U2 | Saving, deleting, author loading, and synchronization failures have visible recovery messages. |
| U3–U5 | Accessible Delete buttons, named native dialogs, keyboard focus restoration, and associated form labels. |
| B1 | Refresh compatible dependency versions; remove unused dependencies and starter files. |
| Backend gaps | Add server-side allowlisting, membership and owner/admin enforcement, restrictive RLS, profile provisioning, and complete snapshots without a SELECT row-cap truncation. |

## API usage

One shared provider replaces repeated hook subscriptions. A sync RPC handles up to 50 queued operations and the resulting snapshot in one transaction. A revision match returns no quote payload. Realtime/visibility events are debounced; author requests are deduplicated and cached per account for five minutes, with persistent offline fallback. These reduce requests and transferred data; no dollar savings have been measured.

## Release status

Production has not been changed. The VPS serves static files; the required database changes belong to Supabase project `umcprnfdaomntzhvmaoc`. Only the public application key was available during remediation. SQL management access is required to inspect the actual schema, save a database backup, apply the migration transactionally, and verify permissions before frontend deployment.

The original production checkout and modified production lockfile must be retained for rollback. Nginx already serves `/pages/quotevault/dist`; replacing that site's release directory does not require changing other VPS services.

## Validation

| Check | Result |
| --- | --- |
| `npm test` | PASS: crypto, offline metadata, UI, and sync regression checks. Sync checks include account changes, legacy cache migration, rejected operations, batch draining, stale responses, and in-flight deletion races. |
| `npm run lint` | PASS. |
| `npm run build` | PASS. Main JS 740.64 kB / 222.52 kB gzip. The existing large-chunk warning remains a performance observation, not a failed build. |
| `npm audit --json` | PASS: zero reported vulnerabilities; saved in `npm-audit-after.json`. |
| PostgreSQL 17.11 | PASS: migration commit, base SQL regression suite, security/atomic-reset suite, and legacy-data migration/reapplication checks in disposable local databases. |
| Browser / actual IndexedDB | PASS: encrypted creation and deletion, deletion after fresh unlock, native dialog Escape/focus restoration, and phone dialog layout at 390 × 844. |
| Built PWA with browser network disabled | PASS: cold reload, cached verifier unlock, decrypted cached quotes, cached authors, a pending local save, and successful synchronization after reconnecting. All browser data used a disposable local backend. |
| Release assets | PASS: production Supabase endpoint in the production bundle, no local test endpoint, service worker, manifest icon paths, and PNG dimensions. |

The historical `reproduce.mjs` is not the regression suite for this branch. The local database fixture models Supabase's schema and roles; hosted Auth, actual production RLS/data/triggers, live realtime delivery, and physical-device installation remain unverified until production SQL access is available. Local test servers and the disposable PostgreSQL server were stopped after validation; PostgreSQL 17 remains installed for reproducible tests.
