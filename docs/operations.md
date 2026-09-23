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
function bodies with their older definitions. If an older migration was reapplied by
mistake, reapply `20260922140000_audit_fixes.sql`; it revokes the device-less RPC
overloads that older files recreate.

Staging a migration wraps the new vault key only for device and recovery keys
attested under the current key. Devices attest themselves when unlocked and
recovery keys when created, so a device that has not unlocked in the current
generation appears as `missing_device_wrapper` until it unlocks once.

### Device-envelope rollout

The device-envelope rollout is additive. Keep production in `legacy` or
`preparing` while deploying the compatible database and frontend. Do not call
`activate_envelope_migration` during deployment. Production activation is a
separate security-sensitive operation and requires explicit approval after
every member is enrolled and the encrypted backup has been verified.

From a clean, reviewed commit, link the intended Supabase project and inspect
the pending migration list before applying anything:

```sh
supabase link --project-ref umcprnfdaomntzhvmaoc
supabase migration list
supabase db push --linked
```

The migrations must be applied in timestamp order. The envelope additions are,
in order, `20260922000000_checked_import.sql`,
`20260922010000_admin_quote_edit.sql`, `20260922020000_envelope_foundation.sql`,
`20260922030000_envelope_recovery.sql`,
`20260922040000_recovery_device_transition.sql`,
`20260922050000_recovery_binding_metadata.sql`,
`20260922060000_device_bootstrap.sql`,
`20260922070000_bootstrap_contract_hardening.sql`,
`20260922080000_device_authorized_rpcs.sql`,
`20260922090000_device_authorized_rpc_fixes.sql`,
`20260922100000_device_recovery_requirement.sql`,
`20260922110000_bootstrap_state_rpc.sql`,
`20260922120000_envelope_migration.sql`,
`20260922130000_envelope_rotation.sql`, and
`20260922140000_audit_fixes.sql`. Never apply these files out of order
or by copying individual function bodies into the SQL editor. Read back
`vault_state.envelope_status` and confirm it is still `legacy` after the
migrations.

The production prerequisite is Supabase's native `pg_cron` extension. Enable
it before the migration that creates the purge schedule. If it is unavailable,
leave the schedule absent and run the service-only purge RPC from a controlled
operator job; do not grant the purge function to browser clients.

Deploy the signing function only after the database functions exist:

```sh
supabase functions deploy vault-security --project-ref umcprnfdaomntzhvmaoc
```

Set the private lease signing JWK through the Supabase secret store. Read it
from a password manager or an interactive terminal; never put it in `.env`, a
repository file, shell history, a deployment archive, or a `VITE_` variable:

```sh
read -r -s DEVICE_LEASE_PRIVATE_JWK
printf '\n'
supabase secrets set --project-ref umcprnfdaomntzhvmaoc \
  DEVICE_LEASE_PRIVATE_JWK="$DEVICE_LEASE_PRIVATE_JWK"
unset DEVICE_LEASE_PRIVATE_JWK
```

The public half is not secret, but it must match the private signing key. Put
only that public JWK in the build environment as
`VITE_DEVICE_LEASE_PUBLIC_JWK`, verify that it contains no private EC fields,
and run `scripts/check-client-env.mjs` before building. Keep the private and
public halves separate and record only the public-key fingerprint in the
release notes. If the lease key is rotated, generate a new P-256 keypair,
publish the matching public JWK with the next static build, set the new
private JWK in Supabase, and verify lease renewal before removing the old
secret. Do not rotate the signing key and activate a vault generation in the
same change window.

Deploy the static app with the staged release procedure below. Verify the
anonymous health check and confirm that an existing legacy device can still
sign in, unlock, read, edit, import, and synchronize. Enroll devices before
activation; enrollment creates a device wrapper but does not activate the new
generation.

For activation, use an unlocked approved administrator device:

1. Download the encrypted backup and store it outside the repository. Verify
   its checksum and that a restore can read the expected quote count.
2. Create or resume the migration, download the current encrypted source
   snapshot, stage every quote, and wait for every active device to report a
   recent empty queue. Refresh the snapshot if the source revision changes.
3. Review readiness, including member wrappers, recovery wrappers, device
   leases, quote count, and queue reports. Stop if any member or device is
   missing.
4. Obtain separate explicit approval immediately before calling
   `activate_envelope_migration`. Activation enters `maintenance` and retains
   rollback copies for seven days.
5. Verify the target generation, quote count, decryptability, device sync,
   edit/import authorization, offline unlock, and reconnect synchronization.
6. Call `finalize_envelope_migration` only after verification. This removes
   the active migration pointer and marks the generation `active`.

If verification fails while rollback is available, stop writes, call
`rollback_envelope_migration`, verify the restored source generation, and keep
the compatible frontend serving legacy behavior. If the process is interrupted
after `maintenance`, use an already authorized maintenance device or the
documented admin recovery path; do not delete rollback rows manually. After
the seven-day retention window, `purge_expired_vault_rollback` deletes the
rollback quote copies. Record the purge result and verify that the active
generation remains readable before pruning old static releases.

Removing a member always revokes the allowlist entry, devices, wrappers,
recovery records, pending requests, and sessions. Choose explicitly between
removing access and removing access plus retained-history rotation. The latter
uses the same prepare, stage, activate, verify, finalize, and purge workflow;
it must not call the destructive legacy `rotate_vault` operation. Offline
queued work from an active device is converted through its short-lived
conversion wrapper. A removed member's pending work is rejected and is never
copied into the new generation.

During the first shared-key cutover, a client that created offline work after
its empty-queue report asks for the previous group vault key once. The browser
uses it only in memory to re-encrypt that queued work, then removes the cached
public derivation metadata. The key and password are never stored or sent.

### Rollback to the shared vault key

The rollback works from `legacy` or `active` at any time. It never deletes a
quote: the pre-reversion ciphertext is retained in
`vault_legacy_reversion_rows` (`row_kind='source'`).

1. From `preparing`, first click **Cancel preparation** (abandon). From
   `maintenance`, use **rollback** (within 7 days) or finalize first.
2. Ask every member to open the app online and confirm **Sync now** shows no
   pending changes. Unsynced offline work is not uploaded by a reversion.
3. Record `scripts/quote-fingerprint.sql` output (count and `id_digest`).
4. On an unlocked administrator device: Admin → **Dry run (no changes)**.
   Stop if it reports any quote ID.
5. Enter a new shared passphrase (12+ characters), repeat it, type
   `RETURN TO SHARED KEY`, and click **Return to shared vault key**.
6. Rerun the fingerprint: `quote_count` and `id_digest` must equal step 3,
   `envelope_status` must be `legacy`.
7. Optional: restore the shared-key frontend. Switch it immediately after
   step 6, before anyone is given the new passphrase — while `current` is
   still the new frontend, it keeps writing v2 quotes in `legacy` mode,
   which release a1bb840 shows as "Decryption Failed". If the switch is
   wanted later and any time has passed since the reversion, rerun steps
   2-6 first (the reversion works from `legacy` too, and the same
   passphrase may be reused), then switch immediately:
   ```sh
   ssh vps 'cd /home/dark/quotevault && ln -sfn releases/a1bb8400bf2c6ad013f756ccb6ee7a70c8640eb1 current.next && mv -Tf current.next current'
   python3 scripts/healthcheck.py --site https://quotes.darkmg1.dev --env-file .env
   ```
   Rerun the fingerprint again: `v2_count` must be `0`. If it is not,
   point `current` back at the new-frontend release (same `ln -sfn … &&
   mv -Tf` command with that release directory), rerun steps 2-6, and
   switch again; the old frontend cannot rewrite v2 quotes itself. Only once the
   frontend decision above is complete does the operator give every
   member the new shared passphrase, out of band.

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
The Cloudflare cache rule `QuoteVault respect origin cache headers` matches only
`http.host eq "quotes.darkmg1.dev"`: eligible for caching, use origin Cache-Control
at the edge (bypass if absent), and respect origin browser TTL. Verify the public
headers after changing either Nginx or CDN rules; zone defaults can override them.

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

## Browser support and PWA boundary

The supported target is the current mainstream release of Safari on iPhone and
iPad, Chrome and Firefox on Android, and Safari, Chrome, Firefox, and Edge on
macOS, Windows, and Linux. Web Crypto, IndexedDB, Service Workers, WebAuthn,
and the platform's passkey PRF are feature-detected; PRF is an enhancement,
not the only recovery path. Exact OS/browser/authenticator combinations must be
tested before being marked supported. Any physical combination not tested in
the release record remains **unverified**.

The PWA service worker is asset-only: `vite-plugin-pwa` precaches the app shell
and static image/style/script assets, while encrypted quote data remains in
the browser's encrypted local store. It must never read vault keys, decrypt
quotes, or cache Supabase responses. Verify the generated service-worker
manifest contains only static build assets and that a cache inspection contains
no access token, private JWK, passphrase, device token, or plaintext quote.

The current Nginx CSP permits same-origin scripts/workers and the required
Supabase HTTPS/WebSocket endpoints only. Keep `script-src 'self'`,
`worker-src 'self'`, `object-src 'none'`, and `frame-ancestors 'none'`; do not
add third-party script origins for QR, passkey, or analytics behavior. Recheck
the public CSP and cache headers after every Nginx or Cloudflare change.
