#!/usr/bin/env bash
set -euo pipefail
test "$(id -u)" = 0 || { echo 'Run this reviewed script with sudo.' >&2; exit 1; }
source_dir="$(cd "$(dirname "$0")" && pwd)"
test -f /home/dark/quotevault/current/dist/index.html
backup_dir="/etc/nginx/quotevault-backups/$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 700 "$backup_dir"
cp -a /etc/nginx/sites-available/quotes.conf "$backup_dir/quotes.conf"
if test -f /etc/nginx/conf.d/quotevault-cache.conf; then
  cp -a /etc/nginx/conf.d/quotevault-cache.conf "$backup_dir/cache.conf"
fi
rollback() {
  cp -a "$backup_dir/quotes.conf" /etc/nginx/sites-available/quotes.conf
  if test -f "$backup_dir/cache.conf"; then
    cp -a "$backup_dir/cache.conf" /etc/nginx/conf.d/quotevault-cache.conf
  else
    rm -f /etc/nginx/conf.d/quotevault-cache.conf
  fi
}
trap rollback ERR
install -m 644 "$source_dir/cache.conf" /etc/nginx/conf.d/quotevault-cache.conf
install -m 644 "$source_dir/quotes.conf" /etc/nginx/sites-available/quotes.conf
nginx -t
systemctl reload nginx
trap - ERR
echo 'QuoteVault now serves the protected release path; previous Nginx configuration retained.'
