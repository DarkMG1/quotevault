# QuoteVault database migration prerequisites

Run `supabase/migrations/20260920000000_secure_vault.sql` only as the project database owner after confirming the target project is `umcprnfdaomntzhvmaoc`. The file is transactional; do not split it into individual SQL-editor submissions.

The migration requires these existing columns:

```sql
select table_name, column_name, data_type
from information_schema.columns
where table_schema = 'public'
  and table_name in ('quotes', 'profiles', 'allowlist', 'app_settings')
order by table_name, ordinal_position;
```

`quotes` must contain `id uuid`, `text text`, `author text`, `context text`, `quote_date` (date or legacy text containing valid calendar dates), `created_at timestamptz`, and `user_id uuid`. The migration converts legacy text dates to `date`. `profiles` needs `id uuid`, `first_name text`, and `last_name text`; `allowlist` needs `id uuid`, `email text`, and `created_at timestamptz`; `app_settings` needs `key text` and `value text`.

Inspect existing auth triggers before deployment. The migration replaces its own `qv_*` triggers and the verified legacy `on_auth_user_created` / `on_auth_user_updated` hooks only when they target `public.handle_new_user()` / `public.handle_user_update()`. Unrelated provisioning hooks are preserved.

```sql
select trigger_name, event_manipulation, action_statement
from information_schema.triggers
where event_object_schema = 'auth' and event_object_table = 'users'
order by trigger_name;
```

It preserves every quote. If a valid legacy `$$E2E$$` quote exists, its encrypted bundle becomes the verifier and the exposed `vault_key_hash` row is removed. If none exists, the old hash remains inaccessible behind RLS until an administrator calls `initialize_vault`. That function permits pre-existing plaintext quotes because it only rejects encrypted ones; decide whether those rows must be removed or migrated before initialization.

Run [tests/database.sql](../tests/database.sql) only in a disposable Supabase project after the migration. It always rolls back, but several assertions deliberately expect the test vault to contain exactly one quote.

Device-envelope migration production prerequisite: install and enable Supabase's native `pg_cron` extension before applying `20260922120000_envelope_migration.sql`. The migration schedules the hourly `quotevault-purge-expired-vault-rollback` job idempotently. Disposable databases without `pg_cron` remain supported for tests; an operator must invoke the service-only purge RPC until production scheduling is available.

Local PostgreSQL 17 verification, using an empty disposable database:

```sh
createdb quotevault_test
psql -d quotevault_test -v ON_ERROR_STOP=1 -f tests/database-fixture.sql
psql -d quotevault_test -v ON_ERROR_STOP=1 -f supabase/migrations/20260920000000_secure_vault.sql
psql -d quotevault_test -v ON_ERROR_STOP=1 -f tests/database.sql
psql -d quotevault_test -v ON_ERROR_STOP=1 -f tests/database-security.sql
createdb quotevault_migration_check
psql -d quotevault_migration_check -v ON_ERROR_STOP=1 -f tests/database-migration.sql
```

The last script installs its own baseline and tests preservation of legacy ciphertext, plaintext, profile names, and derivation metadata, plus migration reapplication after a vault reset. The security script verifies owner checks, null validation, atomic rollback after a deliberately failed reset, generation changes, and receipt-backed replay after deletion. None of these fixture scripts belongs in production.

Before deployment, inspect live quote counts and null ownership/date fields, existing policies/functions, and auth provisioning triggers. Save the current database schema/data and frontend release. This migration changes the API contract: rolling back only to the old frontend is insufficient. Any rollback must preserve writes made since deployment and restore a compatible database contract.
