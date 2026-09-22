import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const source = readFileSync(new URL('../src/hooks/useCrypto.tsx', import.meta.url), 'utf8');
assert.match(source, /const getDeviceAuthorization = useCallback/);
assert.doesNotMatch(source, /authorization\s*=\s*useRef/);
assert.doesNotMatch(source, /authorization\.current/);

console.log('device authorization tokens are not cached in CryptoProvider state');
