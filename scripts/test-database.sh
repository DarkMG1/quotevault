#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# PGHOST/PGPORT/PGUSER/PGPASSWORD select a disposable PostgreSQL server.
case "${PGHOST:-}" in localhost|127.0.0.1|/tmp) ;; *) echo 'Select a disposable local PostgreSQL server explicitly with PGHOST.' >&2; exit 1;; esac
test -z "${PGSERVICE:-}" || { echo 'Unset PGSERVICE before running local database tests.' >&2; exit 1; }
test_db="quotevault_test_${$}_${RANDOM}"
migration_db="quotevault_migration_${$}_${RANDOM}"
hardening_db="quotevault_hardening_${$}_${RANDOM}"
cleanup() {
  dropdb --if-exists "$test_db" >/dev/null
  dropdb --if-exists "$migration_db" >/dev/null
  dropdb --if-exists "$hardening_db" >/dev/null
}
trap cleanup EXIT
createdb "$test_db"
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f tests/database-fixture.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f supabase/migrations/20260920000000_secure_vault.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f tests/database.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f tests/database-security.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f supabase/migrations/20260921000000_vault_hardening.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f supabase/migrations/20260921010000_browser_timestamps.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f supabase/migrations/20260922000000_checked_import.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f tests/database-import.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f supabase/migrations/20260922010000_admin_quote_edit.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f tests/database-edit.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f supabase/migrations/20260922020000_envelope_foundation.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f tests/database-envelope.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f supabase/migrations/20260922030000_envelope_recovery.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f supabase/migrations/20260922040000_recovery_device_transition.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f supabase/migrations/20260922050000_recovery_binding_metadata.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f tests/database-envelope-recovery.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f supabase/migrations/20260922060000_device_bootstrap.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f supabase/migrations/20260922070000_bootstrap_contract_hardening.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f tests/database-bootstrap.sql
createdb "$migration_db"
psql -X -v ON_ERROR_STOP=1 -d "$migration_db" -f tests/database-migration.sql
createdb "$hardening_db"
psql -X -v ON_ERROR_STOP=1 -d "$hardening_db" -f tests/database-hardening.sql
