import { loadEnv } from 'vite';

const env = loadEnv('production', process.cwd(), 'VITE_');
const url = new URL(env.VITE_SUPABASE_URL || 'https://missing.invalid');
const key = env.VITE_SUPABASE_ANON_KEY || '';
const localTest = url.origin === 'http://127.0.0.1:54329' && key === 'local-test-key';
let anonymousJwt = false;
try {
  anonymousJwt = JSON.parse(Buffer.from(key.split('.')[1], 'base64url')).role === 'anon';
} catch { /* Publishable keys are not JWTs. */ }
if (!localTest && (url.protocol !== 'https:' || !url.hostname.endsWith('.supabase.co') ||
    (!key.startsWith('sb_publishable_') && !anonymousJwt))) {
  throw new Error('Build requires a Supabase HTTPS URL and a public publishable/anon key. Privileged keys must never enter the client bundle.');
}
for (const name of Object.keys(env)) {
  if (!['VITE_SUPABASE_URL', 'VITE_SUPABASE_ANON_KEY'].includes(name)) {
    throw new Error(`Unexpected client-exposed environment variable: ${name}`);
  }
}
console.log('Client configuration contains only the expected public variables.');
