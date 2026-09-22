// Disposable browser smoke-test backend. No production requests or persistent data.
// Run: node tests/browser-server.mjs, then Vite with the environment printed below.
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { webcrypto } from 'node:crypto';
import ts from 'typescript';

const crypt = {};
runInNewContext(ts.transpileModule(readFileSync(new URL('../src/lib/crypto.ts', import.meta.url), 'utf8'),
  { compilerOptions: { module: ts.ModuleKind.CommonJS } }).outputText,
  { exports: crypt, crypto: webcrypto, TextEncoder, TextDecoder, btoa, atob });
const { key, ...config } = await crypt.createVaultConfig('demo-vault-key');
const generation = '11111111-1111-4111-8111-111111111111';
const userFor = (email = 'darkmgdevelopment@gmail.com') => ({ id: '22222222-2222-4222-8222-222222222222', aud: 'authenticated', role: 'authenticated',
  email, email_confirmed_at: new Date().toISOString(),
  app_metadata: { provider: 'email' }, user_metadata: { first_name: 'Demo', last_name: 'Tester' }, created_at: new Date().toISOString() });
const user = userFor();
const tokenFor = (member) => `${Buffer.from('{"alg":"HS256","typ":"JWT"}').toString('base64url')}.${Buffer.from(JSON.stringify({
  sub: member.id, email: member.email, role: 'authenticated', aud: 'authenticated', exp: 9999999999,
})).toString('base64url')}.test-signature`;
const userFromRequest = (req) => {
  try { return userFor(JSON.parse(Buffer.from((req.headers.authorization || '').split('.')[1], 'base64url').toString()).email); }
  catch { return user; }
};
const quotes = new Map();
const importReceipts = new Map();
const bundle = await crypt.encryptData(JSON.stringify({ text: 'A locally generated test quote.', author: 'Demo Tester', context: 'Browser smoke test' }), key);
quotes.set('33333333-3333-4333-8333-333333333333', { id: '33333333-3333-4333-8333-333333333333',
  text: `$$E2E$$${JSON.stringify(bundle)}`, author: 'ENCRYPTED', context: 'ENCRYPTED', quote_date: '2026-09-20',
  created_at: new Date().toISOString(), user_id: user.id, vault_generation: generation });
const importedFixtureId = '44444444-4444-4444-8444-444444444444';
for (const fixture of [
  { id: importedFixtureId, text: 'A synthetic imported quote reserved for edit regression.', author: 'Imported Synthetic Speaker', context: 'Synthetic imported context', source_sender: 'Original Imported Sender', import_source_id: '9'.repeat(64) },
  { id: '55555555-5555-4555-8555-555555555555', text: 'A directed imported attribution remains traceable.', author: 'Demo to Outside Speaker', context: 'Directed attribution context', source_sender: 'Directed Original Sender', import_source_id: 'a'.repeat(64) },
  { id: '66666666-6666-4666-8666-666666666666', text: 'An unknown compound imported attribution stays intact.', author: 'Mystery & Outside Speaker', context: 'Unknown compound context', source_sender: 'Compound Original Sender', import_source_id: '8'.repeat(64) },
]) {
  const importedBundle = await crypt.encryptData(JSON.stringify(fixture), key);
  quotes.set(fixture.id, { id: fixture.id, text: `$$E2E$$${JSON.stringify(importedBundle)}`, author: 'ENCRYPTED', context: 'ENCRYPTED', quote_date: '2026-09-19', created_at: new Date().toISOString(), user_id: user.id, vault_generation: generation });
}
let revision = 1;
const calls = {};
http.createServer(async (req, res) => {
  const path = new URL(req.url, 'http://localhost').pathname;
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', req.headers['access-control-request-headers'] || '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,OPTIONS');
  res.setHeader('Content-Type', 'application/json');
  if (req.method === 'OPTIONS') { res.writeHead(204).end(); return; }
  calls[path] = (calls[path] || 0) + 1;
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString();
  const body = raw ? JSON.parse(raw) : {};
  let response;
  if (path === '/auth/v1/token') {
    const member = userFor(typeof body.email === 'string' ? body.email : user.email);
    response = { access_token: tokenFor(member), refresh_token: 'test-refresh', token_type: 'bearer', expires_in: 3600, user: member };
  } else if (path === '/auth/v1/user') response = userFromRequest(req);
  else if (path === '/auth/v1/logout') { res.writeHead(204).end(); return; }
  else if (path === '/rest/v1/rpc/get_vault_state') response = { generation, legacy_generation: null, ...config };
  else if (path === '/rest/v1/rpc/sync_quotes') {
    const results = [];
    for (const operation of body.p_operations || []) {
      if (operation.action === 'INSERT') quotes.set(operation.quote_id, operation.payload);
      else quotes.delete(operation.quote_id);
      revision++;
      results.push({ operation_id: operation.operation_id, status: 'ok' });
    }
    response = { generation, revision, results, quotes: body.p_revision === revision ? null : [...quotes.values()] };
  } else if (path === '/rest/v1/rpc/checked_import') {
    const operations = body.p_operations || [];
    const completed = operations.every(op => importReceipts.get(op.operation_id) === JSON.stringify(op));
    if (body.p_generation !== generation || (body.p_revision !== revision && !completed)) {
      res.statusCode = 409;
      response = { code: '40001', message: 'Vault changed; refresh and review the import again' };
    } else {
      for (const op of operations) {
        if (!importReceipts.has(op.operation_id)) { quotes.set(op.quote_id, op.payload); revision++; }
        importReceipts.set(op.operation_id, JSON.stringify(op));
      }
      response = { generation, revision, results: operations.map(op => ({operation_id: op.operation_id, status: 'ok'})), quotes: [...quotes.values()] };
    }
  } else if (path === '/rest/v1/rpc/edit_quote') {
    const quote = quotes.get(body.p_quote_id);
    if (body.p_generation !== generation || !quote || quote.text !== body.p_expected_text) {
      res.statusCode = 409;
      response = { code: '40001', message: 'Quote changed; refresh and try again.' };
    } else {
      quote.text = body.p_text;
      quote.quote_date = body.p_quote_date || null;
      revision++;
      response = quote;
    }
  } else if (path === '/rest/v1/rpc/edit_quotes') {
    const edits = Array.isArray(body.p_edits) ? body.p_edits : [];
    if (body.p_generation !== generation || !edits.length || edits.some(edit => !quotes.has(edit.quote_id) || quotes.get(edit.quote_id).text !== edit.expected_text)) {
      res.statusCode = 409;
      response = { code: '40001', message: 'Quote changed; refresh and try again.' };
    } else {
      for (const edit of edits) {
        const quote = quotes.get(edit.quote_id);
        quote.text = edit.text;
        quote.quote_date = edit.quote_date || null;
      }
      revision += edits.length;
      response = { updated: edits.length };
    }
  } else if (path === '/rest/v1/profiles') response = [{ id: user.id, first_name: 'Demo', last_name: 'Tester' }];
  else if (path === '/rest/v1/allowlist') response = [{ id: user.id, email: user.email }];
  else if (path === '/stats') response = calls;
  // Test-only inspection endpoint. It returns only the stored row; browser specs decrypt it themselves.
  else if (path.startsWith('/fixture/quotes/')) {
    const quote = quotes.get(path.slice('/fixture/quotes/'.length));
    if (!quote) { res.statusCode = 404; response = { message: 'Synthetic quote not found' }; }
    else response = quote;
  }
  else { res.statusCode = 404; response = { message: 'Not implemented in local smoke test' }; }
  res.end(JSON.stringify(response));
}).listen(54329, '127.0.0.1', () => console.log('Smoke backend: http://127.0.0.1:54329. Vault key: demo-vault-key. VITE_SUPABASE_ANON_KEY=local-test-key'));
