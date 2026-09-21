#!/usr/bin/env bash
set -euo pipefail
umask 077
# Use a private PGSERVICEFILE/PGPASSFILE or PG* environment. Never pass credentials
# as command-line arguments or place this archive under the checkout.
destination="${1:?Usage: backup.sh /private/backup/directory}"
test -n "${PGSERVICE:-${PGHOST:-}}" || { echo 'Select the database explicitly using PGSERVICE or PGHOST.' >&2; exit 1; }
repo="$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)"
destination="$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())' "$destination")"
case "$destination/" in "$repo/"*) echo 'Backups must be stored outside the repository.' >&2; exit 1;; esac
mkdir -p "$destination"
archive="$destination/quotevault-$(date -u +%Y%m%dT%H%M%SZ)-${$}.dump"
partial="$archive.partial"
trap 'rm -f "$partial"' EXIT
pg_dump --format=custom --schema=public --schema=auth --file="$partial"
pg_restore --list "$partial" >/dev/null
mv "$partial" "$archive"
python3 - "$archive" <<'PY'
import hashlib, pathlib, sys
path = pathlib.Path(sys.argv[1])
digest = hashlib.sha256(path.read_bytes()).hexdigest()
path.with_suffix('.sha256').write_text(digest + '  ' + path.name + '\n')
print('Database archive written and readable:', path)
PY
