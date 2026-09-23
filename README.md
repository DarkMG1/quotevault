# QuoteVault

A shared, encrypted quote collection at https://quotes.darkmg1.dev. React and Vite provide the installable frontend; Supabase provides authentication, PostgreSQL, and realtime notifications. Nginx serves the static bundle. Release, backup, and health-check procedures are in [operations.md](docs/operations.md).

## Development

Use Node 22 or newer. Copy `.env.example` to `.env` and fill in the project's public Supabase URL and anonymous key. Never put a database password or service-role key in a `VITE_` variable.

```sh
npm ci
npm run dev
npm test
npm run lint
npm run build
```

Database setup is in [database-prerequisites.md](docs/database-prerequisites.md). Apply all migrations in timestamp order before deploying the corresponding frontend. CI runs application, SQL, and real browser checks. Run `npm run test:database` against an explicitly selected disposable local PostgreSQL server and `npm run test:browser` for the installed-PWA offline flow.

## Data flow

1. An allowlisted, confirmed Supabase account signs in. The server enforces membership and administrator privileges.
2. Legacy vaults still use a shared passphrase until the staged device-envelope migration is explicitly activated. After activation, the browser unwraps a generation-specific vault master key using an approved device or recovery wrapper; private keys, phrases, and unwrapped vault keys remain local to the browser. Existing ciphertext is never re-encrypted by deployment alone.
3. Quote text, author, and context are encrypted. IDs, ownership, dates, and vault generation are metadata. Dexie commits the local quote and its queued operation together.
4. One `QuotesProvider` synchronizes batches of at most 50 operations and 900 KiB through `sync_quotes`. Operation receipts make retries safe. A revision token avoids downloading an unchanged snapshot; a changed snapshot contains the complete shared vault and is reconciled with pending edits.
5. The PWA caches the app shell and encrypted application data only. First use requires an online sign-in and device enrollment. Afterward, an approved device can unlock offline for the lease window, currently 30 days, and pending changes synchronize when the app reconnects. Clearing site data removes remembered-device material; a passkey, recovery phrase, or administrator-assisted enrollment is then required.

If an offline edit races the first migration away from the shared group key,
the app requests that previous key once and keeps it only in memory while it
re-encrypts the saved edit for the active device-envelope generation.

A reload can use the locally protected device bundle, but it still requires the device's passkey or remembered-device key. Local unlock does not authenticate server requests. Sign-out and observed session/membership denials lock the local vault and invalidate offline preparation. A disconnected device cannot learn of remote revocation or a vault reset until it reconnects.

Administrator vault reset is intentionally destructive: one database transaction changes the generation and verification metadata and removes all quotes. Old clients cannot write into the new generation. Deployment does not invoke this reset. The device-envelope migration and retained-history rotation use the staged, verified workflow in [operations.md](docs/operations.md), which preserves rollback data until the explicit finalize or purge step.

## Audit and checks

The original findings are in [AUDIT.md](docs/audits/2026-09-20/AUDIT.md). That report describes checkout `5798655`; its original reproduction script demonstrates the old failures, rather than testing the repaired code. Current regression checks are under `tests/`.

For a disposable browser smoke test, run `node tests/browser-server.mjs`, then in another terminal:

```sh
VITE_SUPABASE_URL=http://127.0.0.1:54329 VITE_SUPABASE_ANON_KEY=local-test-key npm run dev -- --host 127.0.0.1 --port 5179
```

The fake backend accepts a local test sign-in and uses vault passphrase `demo-vault-key`. It never contacts production. It exercises frontend behavior; `tests/database.sql` separately exercises the real database functions and permissions in a disposable database.
