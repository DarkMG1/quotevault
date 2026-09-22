import { loadEnv } from 'vite';

const env = loadEnv('production', process.cwd(), 'VITE_');
const url = new URL(env.VITE_SUPABASE_URL || 'https://missing.invalid');
const key = env.VITE_SUPABASE_ANON_KEY || '';
const leasePublicJwk = env.VITE_DEVICE_LEASE_PUBLIC_JWK || '';
const localTest = url.origin === 'http://127.0.0.1:54329' && key === 'local-test-key';
let anonymousJwt = false;
try {
  anonymousJwt = JSON.parse(Buffer.from(key.split('.')[1], 'base64url')).role === 'anon';
} catch { /* Publishable keys are not JWTs. */ }
if (!localTest && (url.protocol !== 'https:' || !url.hostname.endsWith('.supabase.co') ||
    (!key.startsWith('sb_publishable_') && !anonymousJwt))) {
  throw new Error('Build requires a Supabase HTTPS URL and a public publishable/anon key. Privileged keys must never enter the client bundle.');
}
try {
  const jwk = JSON.parse(leasePublicJwk);
  if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || typeof jwk.x !== 'string' || typeof jwk.y !== 'string' ||
      jwk.x.length !== 43 || jwk.y.length !== 43 || !/^[A-Za-z0-9_-]+$/.test(jwk.x) || !/^[A-Za-z0-9_-]+$/.test(jwk.y) || 'd' in jwk ||
      Buffer.from(jwk.x, 'base64url').length !== 32 || Buffer.from(jwk.y, 'base64url').length !== 32 ||
      Buffer.from(jwk.x, 'base64url').toString('base64url') !== jwk.x || Buffer.from(jwk.y, 'base64url').toString('base64url') !== jwk.y) throw new Error();
} catch {
  throw new Error('Build requires a pinned VITE_DEVICE_LEASE_PUBLIC_JWK P-256 public key.');
}
for (const name of Object.keys(env)) {
  if (!['VITE_SUPABASE_URL', 'VITE_SUPABASE_ANON_KEY', 'VITE_DEVICE_LEASE_PUBLIC_JWK'].includes(name)) {
    throw new Error(`Unexpected client-exposed environment variable: ${name}`);
  }
}
console.log('Client configuration contains only the expected public variables.');
