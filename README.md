# QuoteVault

A shared, encrypted quote collection at https://quotes.darkmg1.dev. React and Vite provide the installable frontend; Supabase provides authentication, PostgreSQL, and realtime notifications. Nginx serves `/pages/quotevault/dist` on `ssh vps`.

## Development

Use Node 22 or newer. Copy `.env.example` to `.env` and fill in the project's public Supabase URL and anonymous key. Never put a database password or service-role key in a `VITE_` variable.

```sh
npm ci
npm run dev
npm test
npm run lint
npm run build
```

Database setup and SQL regression instructions are in [database-prerequisites.md](docs/database-prerequisites.md). The frontend requires that migration; deploy the database changes before the new bundle.

## Data flow

1. An allowlisted, confirmed Supabase account signs in. The server enforces membership and administrator privileges.
2. The shared vault passphrase derives an AES-GCM key in the browser. An authenticated ciphertext verifies it; the passphrase and derived key are never sent to Supabase. Existing ciphertext retains its legacy derivation until an explicit administrator reset.
3. Quote text, author, and context are encrypted. IDs, ownership, dates, and vault generation are metadata. Dexie commits the local quote and its queued operation together.
4. One `QuotesProvider` synchronizes batches of at most 50 operations through `sync_quotes`. Operation receipts make retries safe. A revision token avoids downloading an unchanged snapshot; a changed snapshot contains the complete shared vault and is reconciled with pending edits.
5. The PWA caches the app shell. Public key-derivation metadata, an encrypted verifier, encrypted quotes, and author names are cached for offline use. First use requires a connection and a valid cached account session. Pending changes synchronize while the app is open after connectivity returns.

Administrator vault reset is intentionally destructive: one database transaction changes the generation and verification metadata and removes all quotes. Old clients cannot write into the new generation. Deployment does not invoke this reset.

## Audit and checks

The original findings are in [AUDIT.md](docs/audits/2026-09-20/AUDIT.md). That report describes checkout `5798655`; its original reproduction script demonstrates the old failures, rather than testing the repaired code. Current regression checks are under `tests/`.

For a disposable browser smoke test, run `node tests/browser-server.mjs`, then in another terminal:

```sh
VITE_SUPABASE_URL=http://127.0.0.1:54329 VITE_SUPABASE_ANON_KEY=local-test-key npm run dev -- --host 127.0.0.1 --port 5179
```

The fake backend accepts a local test sign-in and uses vault passphrase `demo-vault-key`. It never contacts production. It exercises frontend behavior; `tests/database.sql` separately exercises the real database functions and permissions in a disposable database.
