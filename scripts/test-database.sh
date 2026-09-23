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
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f supabase/migrations/20260922080000_device_authorized_rpcs.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f tests/database-envelope-auth.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f supabase/migrations/20260922090000_device_authorized_rpc_fixes.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f supabase/migrations/20260922100000_device_recovery_requirement.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f supabase/migrations/20260922110000_bootstrap_state_rpc.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f tests/database-envelope-auth-fixes.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f tests/database-bootstrap.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f supabase/migrations/20260922120000_envelope_migration.sql
# Reapplication is intentional: this verifies additive migration idempotence.
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f supabase/migrations/20260922120000_envelope_migration.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f tests/database-envelope-migration.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f supabase/migrations/20260922130000_envelope_rotation.sql
# Reapplication is intentional: this verifies additive rotation migration idempotence.
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f supabase/migrations/20260922130000_envelope_rotation.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f tests/database-envelope-rotation.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f supabase/migrations/20260922140000_audit_fixes.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f supabase/migrations/20260922140000_audit_fixes.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f tests/database-audit-fixes.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f tests/database-legacy-client.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f scripts/quote-fingerprint.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f supabase/migrations/20260923000000_legacy_reversion.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f supabase/migrations/20260923000000_legacy_reversion.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f tests/database-legacy-reversion.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -c "do \$\$ begin if has_function_privilege('anon','public.begin_legacy_reversion(uuid,bigint,uuid,text)','execute') or has_function_privilege('anon','public.stage_legacy_reversion(uuid,jsonb,uuid,text)','execute') or has_function_privilege('anon','public.commit_legacy_reversion(uuid,jsonb,jsonb,uuid,text)','execute') or has_function_privilege('authenticated','public.qv_reversion_authorized(public.vault_state,uuid,text)','execute') or has_function_privilege('authenticated','public.qv_legacy_v1_text(text)','execute') or has_table_privilege('authenticated','public.vault_legacy_reversions','select,insert,update,delete') or has_table_privilege('anon','public.vault_legacy_reversions','select,insert,update,delete') or has_table_privilege('authenticated','public.vault_legacy_reversion_rows','select,insert,update,delete') or has_table_privilege('anon','public.vault_legacy_reversion_rows','select,insert,update,delete') then raise exception 'legacy reversion privilege is too broad'; end if; end \$\$;"
# An older migration reapplied by mistake recreates device-less overloads; the latest migration closes them.
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f supabase/migrations/20260921000000_vault_hardening.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f supabase/migrations/20260922140000_audit_fixes.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -c "do \$\$ begin if exists(select 1 from pg_proc where oid in (to_regprocedure('public.sync_quotes(uuid,bigint,jsonb)'),to_regprocedure('public.checked_import(uuid,bigint,jsonb)'),to_regprocedure('public.edit_quote(uuid,uuid,text,text,date)'),to_regprocedure('public.edit_quotes(uuid,jsonb)')) and (has_function_privilege('authenticated',oid,'execute') or has_function_privilege('anon',oid,'execute'))) or to_regprocedure('public.sync_quotes(uuid,bigint,jsonb)') is null then raise exception 'legacy overload remains executable'; end if; end \$\$;"
createdb "$migration_db"
psql -X -v ON_ERROR_STOP=1 -d "$migration_db" -f tests/database-migration.sql
createdb "$hardening_db"
psql -X -v ON_ERROR_STOP=1 -d "$hardening_db" -f tests/database-hardening.sql
