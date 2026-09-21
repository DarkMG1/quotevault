# Operations

The application is static. Deploy only a reviewed, committed revision after its
database changes pass. Public Supabase URL/publishable keys belong in the local
`.env`; management tokens and PostgreSQL passwords belong in private operator
configuration outside this repository. `scripts/check-client-env.mjs` rejects
privileged keys and unexpected `VITE_` variables before building.

## Verification and database changes

Run `npm test`, `npm run lint`, `npm run build`, `npm run test:database`, and
`npm run test:browser`. SQL tests require an explicitly selected disposable
PostgreSQL instance through `PGHOST`, `PGPORT`, and `PGUSER`. The runner creates
and drops its own databases. The browser test builds a separate local PWA and
uses a loopback-only backend; it never uses production accounts or keys.

The deployed September 20 migration is immutable. Apply
`supabase/migrations/20260921000000_vault_hardening.sql` as the database owner
followed by `supabase/migrations/20260921010000_browser_timestamps.sql`,
after taking a backup and reviewing current grants/policies. It protects the
administrator allowlist entry, validates timestamps, limits new quote
ciphertext to 256 KiB base64 and sync requests to 1 MiB, and adds private reset
notifications. Existing ciphertext/verifier derivation and receipts remain.
The frontend splits requests below that total limit and keeps oversized legacy
pending work visibly rejected so it does not block other changes.

Enable private-only channels in Supabase Realtime settings when deploying the
private `quotevault-sync` channel. Verify its membership policy on
`realtime.messages`, anonymous denial, and inability for clients to publish a
reset signal. Public-channel clients from older releases may need to reload.
Do not reapply the old migration after the new one; that would replace newer
function bodies with their older definitions.

## Static release

The protected production root is `/home/dark/quotevault`, with immutable
revision directories under `releases/` and an atomic `current` symlink. Its
ancestors must not be group/world writable. Nginx serves `current/dist`.
`ops/quotes.conf` and `ops/cache.conf` contain the complete site/header policy;
the TLS certificate/key stay on the server. `ops/apply-nginx.sh` installs these
files with a retained configuration backup, validates, and reloads Nginx.

```sh
python3 scripts/deploy.py FULL_40_CHARACTER_COMMIT \
  --host vps --root /home/dark/quotevault \
  --site https://quotes.darkmg1.dev --env-file .env --database-verified
```

The script builds the exact Git archive, runs application checks, verifies
asset hashes on the server, retains the previous build's hashed assets, and
switches the symlink. It runs the HTTP/anonymous-access health check after
activation and restores the previous symlink if that check fails. Use
`--stage-only` to prepare a release without activation. The database flag
records an operator check; it does not pretend to validate a migration from
an anonymous HTTP connection.

The application-level rollback must remain compatible with the live schema.
Do not roll back to the pre-secure-sync frontend. Keep at least the current
and previous compatible releases; inspect disk use before pruning older
release directories. Match CDN caching to origin headers: HTML, service
worker, manifest and errors revalidate; successful hashed assets are immutable.

## Backups and restoration

Use PostgreSQL 17 tools and a private `PGSERVICEFILE`/`PGPASSFILE` (mode 600).
The backup identity must have enough read privileges for `public` and `auth`
including RLS-protected tables; a public API key is insufficient. This script
uses standard `pg_dump`, not a partial collection of REST responses.

```sh
PGSERVICE=quotevault bash scripts/backup.sh "$HOME/.local/share/quotevault/backups"
PGHOST=127.0.0.1 PGPORT=55432 PGUSER=postgres \
  bash scripts/verify-restore.sh /private/path/quotevault-backup.dump
```

`backup.sh` writes a custom archive and SHA-256 checksum outside the checkout.
`verify-restore.sh` creates a fresh local database, restores schema/data without
production ownership/grants, checks core tables, and drops only that temporary
database. Hosted recovery additionally requires Supabase roles, grant/RLS
validation, Auth settings, any external extension dependencies, and the tested
compatible application revision. Account passwords and verifier metadata in
backups are sensitive; never publish archives or test them on production.

Before enabling periodic backups, verify the actual project's managed backup
availability and a real restore. A missing PostgreSQL credential or incomplete
restore must be reported as an operational gap, not a successful backup setup.

## Health

```sh
python3 scripts/healthcheck.py --site https://quotes.darkmg1.dev \
  --env-file /private/path/public-client.env --disk-path /home/dark/quotevault
```

The check verifies the public key against the Auth settings endpoint, downloads
the page and its actual script, and checks anonymous table
access is denied without retrieving rows, and optionally fails below 10% free
disk space. Exit status is suitable for an existing monitor or cron. It prints
no quote content, tokens, or account data. Configure the notification destination
explicitly before promising external alerts.
Pass `--revision FULL_40_CHARACTER_COMMIT` to also verify the served manifest,
HTML, and script hashes against that release. Deployment always uses this check.
