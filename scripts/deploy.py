#!/usr/bin/env python3
"""Build an exact reviewed revision, verify its assets, and atomically activate it."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def public_client_env(path):
    values = {}
    for line in path.read_text().splitlines():
        if line and not line.startswith('#') and '=' in line:
            name, value = line.split('=', 1)
            if name in {'VITE_SUPABASE_URL', 'VITE_SUPABASE_ANON_KEY'}:
                values[name] = value
    if set(values) != {'VITE_SUPABASE_URL', 'VITE_SUPABASE_ANON_KEY'}:
        raise ValueError('env file must provide the two public Supabase client variables')
    return ''.join(f'{name}={values[name]}\n' for name in sorted(values))


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('revision', help='full 40-character reviewed Git commit')
parser.add_argument('--host', required=True)
parser.add_argument('--root', required=True, help='protected absolute release directory on host')
parser.add_argument('--env-file', type=Path, default=Path('.env'))
parser.add_argument('--site', required=True, help='HTTPS site for the post-deployment check')
parser.add_argument('--stage-only', action='store_true', help='stage without changing current')
parser.add_argument('--database-verified', action='store_true', help='operator verified the migration and its security checks')
args = parser.parse_args()
if not re.fullmatch(r'[a-f0-9]{40}', args.revision):
    parser.error('revision must be a full commit hash')
if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.@-]*', args.host):
    parser.error('invalid SSH host')
if not re.fullmatch(r'/[A-Za-z0-9._/-]+', args.root) or '..' in Path(args.root).parts:
    parser.error('root must be an absolute path without parent traversal')
if not args.stage_only and not args.database_verified:
    parser.error('verify the database migration first, then pass --database-verified')
run(['git', 'cat-file', '-e', args.revision + '^{commit}'])
prepare_root = f'''
from pathlib import Path
import stat
root = Path({args.root!r}).resolve()
root.mkdir(mode=0o755, parents=True, exist_ok=True)
for parent in [root, *root.parents]:
    if parent.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise RuntimeError('Release parent is writable by other identities: ' + str(parent))
'''
run(['ssh', args.host, 'python3', '-'], input=prepare_root, text=True)

with tempfile.TemporaryDirectory(prefix='quotevault-release-') as temp:
    temp = Path(temp)
    archive = temp / 'source.tar'
    with archive.open('wb') as out:
        run(['git', 'archive', '--format=tar', args.revision], stdout=out)
    source = temp / 'source'
    source.mkdir()
    with tarfile.open(archive) as package:
        package.extractall(source, filter='data')
    shutil.copyfile(args.env_file, source / '.env')
    (source / '.env').chmod(0o600)
    run(['npm', 'ci'], cwd=source)
    run(['npm', 'test'], cwd=source)
    run(['npm', 'run', 'lint'], cwd=source)
    run(['npm', 'run', 'build'], cwd=source)
    dist = source / 'dist'
    assets = {str(p.relative_to(dist)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in dist.rglob('*') if p.is_file()}
    release_json = json.dumps({'revision': args.revision, 'assets': assets}, indent=2) + '\n'
    (source / 'release.json').write_text(release_json)
    (dist / 'release.json').write_text(release_json)
    client_env = temp / 'client.env'
    client_env.write_text(public_client_env(source / '.env'))
    client_env.chmod(0o600)
    package = temp / 'release.tar.gz'
    with tarfile.open(package, 'w:gz') as out:
        for name in ['dist', 'release.json']:
            out.add(source / name, arcname=name)
    remote = run(['ssh', args.host, 'mktemp', '-d'], capture_output=True, text=True).stdout.strip()
    if not re.fullmatch(r'/tmp/tmp\.[A-Za-z0-9]+', remote):
        raise RuntimeError('Unexpected remote temporary directory')
    try:
        run([
            'scp', str(package), str(source / 'scripts' / 'healthcheck.py'), str(client_env),
            f'{args.host}:{remote}/'
        ])
        script = f'''
from pathlib import Path, PurePosixPath
import hashlib, json, os, re, shutil, stat, subprocess, tarfile
root = Path({args.root!r}).resolve()
for parent in [root, *root.parents]:
    mode = parent.stat().st_mode
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise RuntimeError("Release parent is writable by other identities: " + str(parent))
releases = root / 'releases'
releases.mkdir(mode=0o755, exist_ok=True)
release = releases / {args.revision!r}
if release.exists():
    raise RuntimeError('Release already exists; inspect it before reusing the revision')
release.mkdir(mode=0o755)
with tarfile.open({remote!r} + '/release.tar.gz') as archive:
    # Locally generated archive only; reject links and traversal even so.
    members = archive.getmembers()
    if any(m.issym() or m.islnk() or m.name.startswith('/') or '..' in Path(m.name).parts for m in members):
        raise RuntimeError('Unsafe release archive')
    archive.extractall(release, members=members)
manifest = json.loads((release / 'release.json').read_text())
if manifest.get('revision') != {args.revision!r} or not isinstance(manifest.get('assets'), dict):
    raise RuntimeError('Release manifest is invalid')
for name, expected in manifest['assets'].items():
    if hashlib.sha256((release / 'dist' / name).read_bytes()).hexdigest() != expected:
        raise RuntimeError('Asset digest mismatch: ' + name)
current = root / 'current'
previous = None
if current.exists() or current.is_symlink():
    previous = current.resolve(strict=True)
    if previous.parent != releases.resolve() or not re.fullmatch(r'[a-f0-9]{{40}}', previous.name):
        raise RuntimeError('Current release is not a managed reviewed revision')
    # Retain only the previous build's own hashed assets, not accumulated copies.
    old_manifest = previous / 'release.json'
    if old_manifest.exists():
        old = json.loads(old_manifest.read_text())
        old_assets = old.get('assets')
        if old.get('revision') != previous.name or not isinstance(old_assets, dict):
            raise RuntimeError('Previous release manifest is not trusted')
        for name, expected in old_assets.items():
            if not isinstance(name, str) or not (name.startswith('assets/') or name.startswith('workbox-')):
                continue
            safe_name = PurePosixPath(name)
            if (safe_name.is_absolute() or '..' in safe_name.parts
                    or not isinstance(expected, str) or not re.fullmatch(r'[a-f0-9]{{64}}', expected)):
                raise RuntimeError('Unsafe previous release asset')
            source_asset = previous / 'dist' / Path(*safe_name.parts)
            if (not source_asset.is_file() or source_asset.is_symlink()
                    or hashlib.sha256(source_asset.read_bytes()).hexdigest() != expected):
                raise RuntimeError('Previous release asset digest mismatch: ' + name)
            target = release / 'dist' / Path(*safe_name.parts)
            if not target.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source_asset, target)
if not {args.stage_only!r}:
    pending = root / ('current-' + {args.revision!r})
    pending.symlink_to(release)
    os.replace(pending, current)
    try:
        subprocess.run([
            'python3', {remote!r} + '/healthcheck.py', '--site', {args.site!r},
            '--env-file', {remote!r} + '/client.env', '--revision', {args.revision!r},
            '--disk-path', str(root)
        ], check=True)
    except Exception:
        if previous is None:
            current.unlink(missing_ok=True)
        else:
            rollback = root / ('current-rollback-' + {args.revision!r})
            rollback.symlink_to(previous)
            os.replace(rollback, current)
        raise
print('Verified release ' + manifest['revision'] + {' staged.' if args.stage_only else ' activated.'!r})
'''
        run(['ssh', args.host, 'flock', '-n', args.root + '/.deploy.lock', 'python3', '-'], input=script, text=True)
    finally:
        # The path is the validated directory returned by mktemp for this invocation.
        run(['ssh', args.host, 'rm', '-rf', '--', remote])
