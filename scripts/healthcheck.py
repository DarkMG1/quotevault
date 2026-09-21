#!/usr/bin/env python3
"""Check the static release and anonymous-denial contract without logging data."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from urllib.parse import urljoin, urlparse


def get(url, key=None):
    with tempfile.TemporaryDirectory(prefix='quotevault-health-') as temp:
        body = Path(temp) / 'body'
        command = ['curl', '--silent', '--show-error', '--max-time', '20', '-o', str(body), '-w', '%{http_code}', url]
        if key:
            command += ['-H', 'apikey: ' + key]
        status = subprocess.check_output(command, text=True)
        return int(status), body.read_bytes()


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--site', required=True)
parser.add_argument('--env-file', type=Path, required=True, help='public Supabase client configuration only')
parser.add_argument('--disk-path', type=Path)
parser.add_argument('--revision', help='expected 40-character deployed release revision')
args = parser.parse_args()
try:
    if args.revision and not re.fullmatch(r'[a-f0-9]{40}', args.revision):
        raise ValueError('Expected a full lowercase Git revision')
    site_endpoint = urlparse(args.site)
    if site_endpoint.scheme != 'https' or not site_endpoint.hostname:
        raise ValueError('Expected an HTTPS site URL')
    values = dict(line.split('=', 1) for line in args.env_file.read_text().splitlines()
                  if line and not line.startswith('#') and '=' in line)
    supabase = values['VITE_SUPABASE_URL'].strip().strip('"\'')
    key = values['VITE_SUPABASE_ANON_KEY'].strip().strip('"\'')
    if not key.startswith('sb_publishable_'):
        import base64
        payload = key.split('.')[1]
        if json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4))).get('role') != 'anon':
            raise ValueError('Expected public anonymous configuration')
    endpoint = urlparse(supabase)
    if endpoint.scheme != 'https' or not endpoint.hostname.endswith('.supabase.co'):
        raise ValueError('Expected a Supabase HTTPS endpoint')
    status, _ = get(supabase + '/auth/v1/settings', key)
    if status != 200:
        raise RuntimeError('Supabase API did not accept the configured public key')
    status, html = get(args.site)
    if status != 200:
        raise RuntimeError('Site HTTP status is not 200')
    script = re.search(rb'<script[^>]*\bsrc="([^"]+)"', html)
    if not script:
        raise RuntimeError('No application script in HTML')
    asset = urljoin(args.site, script.group(1).decode())
    if urlparse(asset).netloc != urlparse(args.site).netloc:
        raise RuntimeError('Application script unexpectedly loads from another origin')
    status, body = get(asset)
    if status != 200 or body.lstrip().lower().startswith(b'<!doctype html'):
        raise RuntimeError('Application script is unavailable')
    if args.revision:
        status, manifest_body = get(urljoin(args.site, 'release.json'))
        if status != 200:
            raise RuntimeError('Deployed release manifest is unavailable')
        try:
            manifest = json.loads(manifest_body)
        except json.JSONDecodeError as error:
            raise RuntimeError('Deployed release manifest is invalid') from error
        if (not isinstance(manifest, dict) or manifest.get('revision') != args.revision
                or not isinstance(manifest.get('assets'), dict)):
            raise RuntimeError('Deployed release revision does not match the reviewed revision')
        asset_name = urlparse(asset).path.lstrip('/')
        if (manifest['assets'].get('index.html') != hashlib.sha256(html).hexdigest()
                or manifest['assets'].get(asset_name) != hashlib.sha256(body).hexdigest()):
            raise RuntimeError('Deployed HTML or application script does not match the reviewed release')
    for table in ['quotes', 'profiles', 'allowlist', 'app_settings']:
        status, _ = get(supabase + '/rest/v1/' + table + '?select=*&limit=0', key)
        if status not in (401, 403):
            raise RuntimeError('Anonymous table access is not denied: ' + table)
    if args.disk_path:
        usage = shutil.disk_usage(args.disk_path)
        if usage.free / usage.total < 0.1:
            raise RuntimeError('Disk free space is below 10%')
    print('QuoteVault healthy: HTML, application asset, Supabase public key, and anonymous access restrictions verified.')
except (OSError, ValueError, KeyError, IndexError, RuntimeError, subprocess.SubprocessError) as error:
    parser.exit(1, 'QuoteVault health check failed: ' + str(error) + '\n')
