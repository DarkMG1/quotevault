import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const source = readFileSync(new URL('../src/hooks/useCrypto.tsx', import.meta.url), 'utf8');
assert.match(source, /const getDeviceAuthorization = useCallback/);
assert.doesNotMatch(source, /authorization\s*=\s*useRef/);
assert.doesNotMatch(source, /authorization\.current/);
assert.match(source, /refreshVaultState: \(\) => Promise<void>/);
assert.match(source, /setPreparedTargetMasterKey: \(generation: string, key: Uint8Array\) => void/);
assert.match(source, /preparedMasterKeyBootstrap/);
assert.match(source, /const auth = bootstrap \? null : await getDeviceAuthorization\(\)/);
assert.match(source, /enteringPreparing/);

console.log('device authorization tokens and temporary prepared keys stay out of persisted provider state');
