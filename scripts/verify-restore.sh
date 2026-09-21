#!/usr/bin/env bash
set -euo pipefail
archive="${1:?Usage: verify-restore.sh /private/backup.dump}"
case "${PGHOST:-}" in localhost|127.0.0.1|/tmp) ;; *) echo 'Use a disposable local PostgreSQL instance (explicit PGHOST required).' >&2; exit 1;; esac
test -z "${PGSERVICE:-}" || { echo 'Unset PGSERVICE to avoid selecting a remote database.' >&2; exit 1; }
python3 - "$archive" <<'PY'
import hashlib, pathlib, sys
path = pathlib.Path(sys.argv[1])
expected = path.with_suffix('.sha256').read_text().split()[0]
if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
    raise SystemExit('Backup checksum mismatch; refusing restore.')
PY
target="quotevault_restore_${$}_${RANDOM}"
cleanup() { dropdb --if-exists "$target" >/dev/null; }
createdb "$target"
trap cleanup EXIT
psql -X -v ON_ERROR_STOP=1 --dbname="$target" -c 'drop schema public' >/dev/null
# Validate data/schema restoration independently of production ownership. Roles
# and grants must also be checked when restoring into a Supabase environment.
pg_restore --exit-on-error --no-owner --no-privileges --dbname="$target" "$archive"
psql -X -v ON_ERROR_STOP=1 --dbname="$target" <<'SQL'
select count(*) as restored_quotes from public.quotes;
select count(*) as restored_accounts from auth.users;
select count(*) as vault_configurations from public.vault_state;
SQL
echo 'Isolated data/schema restore succeeded; production role/configuration restoration is a separate check.'
