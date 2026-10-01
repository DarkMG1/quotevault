# QuoteVault — Handoff for the optimization and cleanup agent

You are taking over QuoteVault to **optimize, clean up, speed up, and fix bad code without changing what the app does**. This document is everything you need. Read it fully before touching anything. As of 2026-10-01, `main` is at `3d24e15` and production serves that exact build.

---

## 1. Your mission

Make the app faster, smaller, and easier to maintain, while every user-visible behavior, every security property, and every stored quote stays exactly as it is.

In scope:
- Bundle size and load time.
- Render performance.
- Redundant work in sync and decryption.
- Readability: the dense, very long lines in several components.
- Splitting oversized components.
- Dead code.
- Small correctness bugs you find along the way. Prove each with a failing test first.

Out of scope unless the operator asks:
- New features.
- Redesigns.
- Changing the encryption model.
- Changing the database schema.
- Anything in Section 2's "never" list.

---

## 2. Non-negotiables (read twice)

1. **Never reintroduce device-envelope encryption.** That means no passkeys, remembered devices, recovery phrases, device approval, leases, or an Edge Function. It was built, deployed, and then deliberately removed on 2026-10-01 at the operator's request. QuoteVault uses **one shared group vault key**. Don't propose otherwise.
2. **End-to-end encryption stays intact.**
   - Quotes are encrypted in the browser with a key derived from the shared passphrase. The server stores only `$$E2E$$`-prefixed ciphertext; `author`/`context` columns hold the literal `ENCRYPTED`.
   - No plaintext quote, passphrase, or derived key may reach the server, `localStorage`, `sessionStorage`, logs, URLs, analytics, or the service-worker cache.
   - The service worker caches static assets only.
   - The CSP in `ops/quotes.conf` stays strict (`script-src 'self'`, no third-party scripts).
3. **Zero quote loss.** Never write code that could delete, overwrite, or reorder stored ciphertext, or drop locally queued work. Production has **238 quotes** (as of 2026-10-01). Any change touching sync, the local store (Dexie), or the database needs a test proving data survives.
4. **Production is off-limits without explicit operator approval.** That covers the Supabase database, deploys to `vps`, migrations, and secrets.
   - Local work, local tests, and pushing to `main` are fine.
   - Deploying is fine only when the operator asks or confirms.
   - Read-only production probes are fine only when the operator runs them; you never hold the database password.
5. **Migrations are immutable history.**
   - Don't edit, rename, or delete anything in `supabase/migrations/`.
   - Any schema change needs a new file and operator approval, and is out of scope here.
   - `20260922020000`…`20261001000000` (envelope) and `20261002000000_remove_device_envelope.sql` (its removal) are applied in production. Never reapply one individually.
6. **Old service-worker caches exist in the wild.** Some members' browsers ran very old cached builds (pre-2026-09-20). Changes to Dexie schema versions, queue item shapes, or the `$$E2E$$` format must stay backward compatible with data those clients wrote.

---

## 3. What the app is

A private PWA where a small friend group saves memorable quotes. Members sign in (Supabase Auth, allowlisted emails only) and unlock the vault with the shared passphrase. They can read, add, edit (admin only), delete, import, and filter quotes, online or offline.

**Stack:** React 19, TypeScript, Vite 7, Tailwind 3, `vite-plugin-pwa` (workbox, `registerType: 'prompt'`, so the page never auto-reloads), Dexie 4 (IndexedDB) with `dexie-react-hooks`, `@supabase/supabase-js` 2, `framer-motion` (feed swipe-to-delete and exit animations), and `lucide-react` icons.

**Data flow:**
1. **Unlock.** `useCrypto` derives an AES-GCM key from the passphrase with PBKDF2, using the `vault_state.kdf` salt and iterations, and checks it against `vault_state.verifier`.
2. **Write.** Quotes are encrypted client-side (`src/lib/crypto.ts`, `src/components/AddQuote.tsx`, `src/lib/quote-import.ts`), then queued in Dexie `syncQueue`.
3. **Sync.** `src/lib/sync.ts` + `src/hooks/useQuotes.tsx` call RPC `sync_quotes(p_generation, p_revision, p_operations)`. The server is idempotent per `operation_id` (receipts), revision-based, and generation-checked. The local `quotes` table caches ciphertext.
4. **Display.** `Feed.tsx` decrypts for display (`decryptQuoteForDisplay` in `src/components/ui.ts`), then filters and sorts in memory (`src/lib/quote-search.ts`).
5. **Live updates.** Realtime `postgres_changes` on `quotes` plus a private broadcast channel `quotevault-sync` (`vault-generation` event). The schedule is debounced in `useQuotes`.

**Key files** (line counts as of handoff):

| File | Lines | Role |
|---|---|---|
| `src/lib/sync.ts` | 351 | Queue processing, batching (≤1 MiB requests), receipts, revisions, generation mismatch, Web Lock across tabs |
| `src/hooks/useAuth.tsx` | 342 | Sessions, offline-tolerant auth, sign-out across tabs, password recovery |
| `src/components/Admin.tsx` | 278 | Allowlist, vault initialize/rotate (rotate is destructive by design) |
| `src/components/Profile.tsx` | 251 | Profile names |
| `src/hooks/useQuotes.tsx` | 246 | Live query, sync scheduling, retries, add/delete/edit |
| `src/components/Auth.tsx` | 242 | Sign-in/up/reset |
| `src/components/Feed.tsx` | 214 | Feed, toolbar, filters, chips, delete dialog |
| `src/lib/quote-import.ts` | 182 | Reviewed encrypted imports with duplicate checks |
| `src/hooks/useCrypto.tsx` | 165 | Unlock gate, key lifetime |
| `src/lib/crypto.ts` | 126 | PBKDF2, AES-GCM, verifier |
| `src/lib/quote-search.ts` | 42 | `filterQuotes`, `authorParticipants`, `NO_FILTERS` (rebuilt 2026-10-01; keep its semantics) |
| `supabase/migrations/` | 21 files | Schema history (immutable) |
| `scripts/deploy.py` | | Atomic release deploys with health check and auto-rollback |
| `scripts/healthcheck.py` | | Public health check (`--revision SHA` pins the build) |
| `scripts/backup.sh`, `scripts/verify-restore.sh` | | `pg_dump` backup and isolated restore check |
| `ops/quotes.conf`, `ops/cache.conf` | | nginx site, CSP and cache headers |

`docs/operations.md` is the operations runbook. Read it, especially the "Removed device-envelope rollout" section.

---

## 4. Production facts

- **Site:** https://quotes.darkmg1.dev. nginx on host `vps` (`ssh vps`, user `dark`) serves `/home/dark/quotevault/current/dist`.
- **Releases:** `/home/dark/quotevault/releases/<full SHA>`. `current` points at `3d24e15…`, and `previous` is a rollback symlink. The deploy script maintains both.
  - Keep at least the current and one compatible previous release.
  - `a1bb840` and `cd3e697` are older shared-key releases kept for rollback.
  - `/pages/quotevault` no longer exists. It was a stale checkout; don't recreate it.
- **Deploy** (only when the operator asks or approves):
  ```sh
  python3 scripts/deploy.py <full 40-char SHA> --host vps --root /home/dark/quotevault \
    --site https://quotes.darkmg1.dev --env-file .env --database-verified
  ```
  It builds the exact git archive, runs tests, lint and build, uploads, switches `current` atomically, and runs the health check, restoring `previous` on failure.
  - Instant manual rollback: `ssh vps 'cd /home/dark/quotevault && ln -sfn releases/<SHA> current.next && mv -Tf current.next current'`.
- **Supabase project:** `umcprnfdaomntzhvmaoc` (PostgreSQL 17.6, us-east-1).
  - `.env` holds only `VITE_SUPABASE_URL` and `VITE_SUPABASE_ANON_KEY` (a `sb_publishable_` key). `scripts/check-client-env.mjs` rejects any other `VITE_` variable.
  - The CLI is installed and linked locally (`supabase/.temp` is git-ignored).
  - Direct database access needs the operator's password, through the session pooler `aws-1-us-east-1.pooler.supabase.com:5432`, user `postgres.umcprnfdaomntzhvmaoc`.
  - The operator sets it with `read -rs "SUPABASE_DB_PASSWORD?Database password: "; echo; export SUPABASE_DB_PASSWORD`.
  - It must be **exported**, or the CLI fails with a `cli_login_postgres` error.
  - The pooler **ignores `PGOPTIONS`**. Read-only probes must wrap their SQL in `begin transaction read only; … rollback;`.
- **Backups** live in `~/.local/share/quotevault/backups/` (mode 700/600). The latest verified one is `20261001T040818Z-before-envelope-removal/`: 224 quotes at that time.
- **CI:** `.github/workflows/ci.yml` runs on every push. It runs npm ci, test, lint, build, the database tests against a postgres:17 service, and Playwright (Chromium). It must stay green.
- **Git:** default branch `main`, remote `https://github.com/DarkMG1/quotevault.git`.
  - Commits are **SSH-signed**; the signing key is in `~/.ssh`.
  - The keychain's HTTPS token lacks `workflow` scope. Push with `git -c credential.helper= -c 'credential.helper=!gh auth git-credential' push origin main`.
  - **No attribution or Co-Authored-By trailers** in commit messages.

---

## 5. Local development and tests

```sh
npm ci
npm test                 # node --test tests/*.test.mjs + Python import tests
npx tsc -b --pretty false
npm run lint
npm run build            # runs check-client-env first
npm run test:browser     # Playwright, Chromium, local mock backend (tests/browser-server.mjs on :54329)
PGHOST=localhost PGPORT=55432 PGUSER=postgres npm run test:database   # needs a disposable local PG
git diff --check
```

- **Disposable PostgreSQL:** Homebrew PG 17.
  ```sh
  D=$TMPDIR/pg; initdb -D $D -U postgres -A trust && pg_ctl -D $D -o "-p 55432 -k '' -c listen_addresses=localhost" -l $D.log start
  ```
  - Use `-k ''`: long socket paths fail.
  - Don't use port 54329, which the Playwright mock backend uses.
  - `scripts/test-database.sh` refuses any `PGHOST` other than localhost, 127.0.0.1 or `/tmp`.
  - It replays the full migration chain, including the envelope migrations and their removal, then verifies the removal kept every shared-key row.
- **Sandbox gotchas** (if your harness sandboxes shell commands): Chromium (Playwright), PostgreSQL shared memory, `ssh`, git signing, and `gh` all need the sandbox disabled.
- **Shell gotchas:**
  - In zsh, never name a loop variable `path`: it is tied to `PATH` and silently breaks every command.
  - zsh doesn't word-split unquoted variables. Use bash or arrays for file lists.
- **Unit-test harness:** `tests/load-module.mjs` transpiles a TS module and injects dependencies, e.g. `loadModule('src/lib/x.ts', {'./dep': stub}, globals)`.
  - Modules run in a separate realm, so compare arrays with `JSON.stringify`, not `deepEqual`.
  - React hooks and components have **no unit harness**; cover them with Playwright.
- **Browser tests:** they use the mock backend (`tests/browser-server.mjs`), shared vault key `demo-vault-key`, and user `browser-test@example.com` / `local-test-password`. The admin is `darkmgdevelopment@gmail.com` (`src/lib/access.ts`).
- **Never run Playwright and lint at the same time:** both touch generated paths.

---

## 6. How the operator wants you to work

- **Terse communication.** No filler. Results first.
- **"Ponytail" minimalism:** the smallest change that fixes the root cause. Reuse what exists. No speculative abstractions. Deleting beats adding.
- **Research before editing:** read the file, and grep every caller before changing a function.
- **TDD for behavior changes:** write a failing test, see it fail for the right reason, then fix it. For a pure refactor, prove behavior is unchanged with the existing tests plus a characterization test where coverage is thin.
- **Verify before claiming done:** run the full sequence in Section 5 and report real output. If something fails, say so with the output.
- **Stop and report** if the same approach fails twice. Ask when a decision is genuinely the operator's (anything in Section 2, deploys, user-visible changes).
- **Commit in small, reviewable steps** on `main`, each green. Push when green. Deploy only with approval.
- **Errors must never be swallowed silently.** Several past bugs were errors written into state that wasn't rendered.

---

## 7. Current state and open items

- **Production:** shared-key schema, all 238 quotes verified. Release `3d24e15` is live with the rebuilt filters: one filter state, an exact-author picker, inclusive dates, removable chips, newest first by default with a toggle.
- **Akash's device (`akashsarada@gmail.com`):** it ran a pre-2026-09-20 cached build.
  - On 2026-10-01 it uploaded 14 queued quotes successfully (224 → 238).
  - 3 queued inserts were rejected as duplicates, and 1 old delete is blocked by design.
  - The old UI only offers **Retry** for those errors, which can never succeed. A small improvement in scope: let users **dismiss** a rejected or blocked queue item, with confirmation, but only when the item has no unsynced data at risk.
  - **Unverified:** whether those 14 quotes (written by the old app in March) display correctly or as "Decryption Failed". The operator was asked to check, and to run a read-only `kdf` check: does `vault_state.kdf.salt` still equal base64 of `QuoteVault-FixedSalt-2026` with 100000 iterations? Ask the operator before assuming. Don't let Akash clear site data until both are confirmed.
- **Some members may still have old cached service workers.** They need to close every tab once.

---

## 8. Optimization and cleanup backlog

Measured on 2026-10-01. Measure again before and after each item.

1. **Bundle size.** `vite build` emits one JS chunk of **790 KB (237 KB gzip)** and warns about it.
   - Lazy-load the rarely used screens (`Admin`, `ImportQuotes`, `MatchAuthors`, `AddQuote`, `Profile`, `Auth`) with `React.lazy`.
   - Check what `framer-motion` costs. It's only used for the feed's swipe-to-delete and exit fade, so a small pointer-event plus CSS implementation may replace it. The swipe-to-delete behavior and its confirm dialog must stay.
   - Confirm the service-worker precache still covers every lazy chunk, so offline still works. Add a Playwright offline check.
2. **Decryption churn.** `Feed.tsx:45` re-decrypts **every** quote whenever the quote list changes, including after each sync.
   - Cache decrypted results keyed by `id` + ciphertext `text`.
   - Clear the cache when the key changes or the vault locks.
   - Never persist it; plaintext stays in memory only.
3. **Render work.**
   - `filterQuotes`/`authorParticipants` in `Feed.tsx` run on every render; memoize them.
   - `useQuotes.tsx:48` sorts the live query by `created_at`, while the feed re-sorts by quote date anyway. Remove the redundant ordering if nothing else depends on it (check callers).
   - Consider whether each card needs a `motion.div` at 238+ quotes.
4. **Readability.** Very long single-line statements are concentrated in `Feed.tsx` (22 lines over 220 characters), `Auth.tsx` (14), `ImportQuotes.tsx` (9), `AddQuote.tsx` (9), `MatchAuthors.tsx` (5) and `Profile.tsx` (4).
   - Reformat them, and extract components where it clarifies things: e.g. `QuoteCard` and `FilterBar` from `Feed.tsx`.
   - No behavior change. The existing Playwright tests must pass unmodified, apart from selectors if structure changes.
5. **Sync engine review** (`src/lib/sync.ts`, `useQuotes.tsx`): look for redundant reads of the whole queue (`syncQueue.toArray()` in loops), repeated metadata reads, and timers that never get cancelled. Preserve:
   - idempotent receipts;
   - the epoch checks;
   - the cross-tab Web Lock;
   - batching under 1 MiB;
   - generation-mismatch handling, which keeps queued work as `blocked` and never deletes it.
6. **Dead code and dependencies.**
   - Check `src/lib/quote-authors.ts`, `src/components/ui.ts` and `src/types/index.ts` for unused exports.
   - Remove dependencies nothing imports.
   - Keep the `.gitignore` entry for `supabase/.temp/`.
7. **Accessibility pass on touched components:** visible focus, labels, `role="alert"` on errors, and live regions for status. Don't regress what exists.

**Definition of done for each item:**
- A measured before and after (bundle KB, render or decrypt counts, or timings).
- The full test sequence green.
- No user-visible behavior change unless the operator approved one.
- No new place where plaintext or keys could persist.

---

## 9. Context sources

- `docs/operations.md`: the operations runbook.
- `docs/audits/`: earlier audits of the shared-key app (2026-09-20/21).
- Git history: `git log --oneline` from `a1bb840` onward shows the envelope experiment and its removal (`c9326d2`).
- Persistent agent memory (if your harness shares it): `~/.claude/projects/-Users-chiragbhat-CLionProjects-QuoteVault/memory/`, which records the shared-key decision.
