import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

const harness = String.raw`
import hashlib, json, runpy, subprocess, sys, tempfile
from pathlib import Path

mode = sys.argv[1]
revision = '0123456789abcdef0123456789abcdef01234567'
html = b'<html><script src="/assets/app.js"></script></html>'
asset = b'console.log("ok")'
manifest = {
  'revision': revision if mode != 'wrong-revision' else 'fedcba9876543210fedcba9876543210fedcba98',
  'assets': {
    'index.html': hashlib.sha256(html).hexdigest(),
    'assets/app.js': hashlib.sha256(asset if mode != 'stale' else b'old script').hexdigest(),
  },
}
with tempfile.TemporaryDirectory() as temp:
  env = Path(temp) / 'client.env'
  env.write_text('VITE_SUPABASE_URL=https://example.supabase.co\nVITE_SUPABASE_ANON_KEY=sb_publishable_test\n')
  original = subprocess.check_output
  def fake(command, text=True):
    body = Path(command[command.index('-o') + 1])
    url = next(value for value in command if value.startswith('https://'))
    if url.endswith('/auth/v1/settings'):
      body.write_bytes(b'{}')
      return '401' if mode == 'bad-key' else '200'
    if url == 'https://quotes.example.test':
      body.write_bytes(html); return '200'
    if url == 'https://quotes.example.test/assets/app.js':
      body.write_bytes(asset); return '200'
    if url == 'https://quotes.example.test/release.json':
      body.write_bytes(json.dumps(manifest).encode()); return '200'
    if '/rest/v1/' in url:
      body.write_bytes(b'{"message":"denied"}'); return '403'
    raise AssertionError(url)
  subprocess.check_output = fake
  sys.argv = ['healthcheck.py', '--site', 'https://quotes.example.test', '--env-file', str(env), '--revision', revision]
  try:
    runpy.run_path('scripts/healthcheck.py', run_name='__main__')
  finally:
    subprocess.check_output = original
`;

function health(mode) {
  return spawnSync('python3', ['-c', harness, mode], { encoding: 'utf8' });
}

test('health check binds the live asset pair to an accepted public key and revision', () => {
  const result = health('good');
  assert.equal(result.status, 0, result.stderr);
});

test('health check rejects an unaccepted publishable key', () => {
  const result = health('bad-key');
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /public key/);
});

test('health check rejects a stale script under an otherwise current manifest', () => {
  const result = health('stale');
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /does not match/);
});

test('health check rejects a different release revision', () => {
  const result = health('wrong-revision');
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /revision does not match/);
});
