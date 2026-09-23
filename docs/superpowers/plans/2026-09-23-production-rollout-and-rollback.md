# Production Rollout With Any-Time Rollback — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move production from the shared-key release (`a1bb840`) to device-envelope encryption, and ship a tested one-click path back to the shared key that works at any stage — including weeks after activation — without losing a quote.

**Architecture:** Rollout is staged so each stage has its own verified rollback: (A) database migrations while the old frontend still serves, (B) new frontend with the vault still on the shared key, (C) device enrollment during `preparing`, (D) activation. A new **legacy reversion** feature (SQL staging + atomic commit, client re-encryption to the pre-envelope v1 format) returns the vault to a shared passphrase from `legacy` or `active`, so the old frontend can be restored at any time. Quote integrity is proven at every step with a read-only ciphertext fingerprint and a full `pg_dump` backup.

**Tech Stack:** React 19 + TypeScript + Vite PWA, Dexie, Web Crypto; Supabase (PostgreSQL 17, PostgREST RPC, Auth, Edge Functions/Deno); Node test runner, Playwright, psql; nginx on host `vps`, deployed by `scripts/deploy.py`.

**Spec:** `docs/superpowers/specs/2026-09-22-device-envelope-encryption-design.md` plus the rollout requirements in this plan's *Requirements* section (from the operator, 2026-09-23).

## Requirements (operator, 2026-09-23)

1. Commit and push the audited branch; move production to it.
2. An easy, foolproof rollback that remains available **any time** after cutover.
3. No loss of any quote already stored in Supabase.

## Verified production facts (read-only inspection, 2026-09-23)

- nginx `quotes.darkmg1.dev` serves `root /home/dark/quotevault/current/dist` (`/etc/nginx/sites-available/quotes.conf:12`).
- `current -> /home/dark/quotevault/releases/a1bb8400bf2c6ad013f756ccb6ee7a70c8640eb1` (commit `a1bb840`, 2026-09-21). Ten release directories exist.
- `/pages/quotevault` is a stale, **unserved** git checkout at `a878167`. Do not deploy there.
- VPS root filesystem: 3.1 GB free (84% used). No `sudo` without password.
- `a1bb840` contains migrations through `20260922010000_admin_quote_edit.sql`. Production is expected to have exactly those applied — verify in Task 7.
- Local machine: `pg_dump` 17 installed; **Supabase CLI not installed**; no `~/.pg_service.conf`. Earlier backups in `~/.local/share/quotevault/backups/` are REST JSON exports, not `pg_dump` archives.
- `git push` of `codex/audit-fixes-2026-09-20` is blocked: the HTTPS token lacks `workflow` scope (branch commits touch `.github/workflows/ci.yml`). Operator must run `gh auth refresh -h github.com -s workflow`.

## Compatibility facts that shape the rollback

- Applying `20260922020000`…`20260922140000` changes **no quote rows**; it changes functions, grants, RLS policies, and removes `public.quotes` from the `supabase_realtime` publication (`20260922080000_device_authorized_rpcs.sql:247`).
- The old frontend `a1bb840` calls `get_vault_state()`, `sync_quotes(p_generation,p_revision,p_operations)`, `checked_import(3 args)`, `edit_quote(5)`, `edit_quotes(2)`, `initialize_vault`, `rotate_vault`, and reads/writes `allowlist`/`profiles` directly. In legacy mode these resolve to the new defaulted signatures — Task 1 proves it.
- After migrations the old frontend loses instant `postgres_changes` updates; it still syncs on load, focus, reconnect, and after its own writes. Freshness only, no data impact.
- **The new frontend writes v2 records (authenticated metadata) even in legacy mode** (`src/hooks/useQuotes.tsx:214`, `src/lib/quote-edit.ts:21`, `src/lib/quote-import.ts:152`). The old frontend cannot decrypt v2. Therefore switching the frontend back to `a1bb840` is only safe after a legacy reversion rewrites every row to v1. The new frontend reads both formats.
- Legacy `rotate_vault` **deletes all quotes**; it is never a rollback tool.

## Global Constraints

- Never apply migrations out of timestamp order or paste function bodies into the SQL editor (`docs/operations.md`).
- Never run fixture/test SQL against production.
- The lease signing private JWK exists only in the Supabase secret store; only the public JWK enters `.env` as `VITE_DEVICE_LEASE_PUBLIC_JWK`.
- No plaintext quote, vault key, passphrase, recovery phrase, or device token in any file, log, commit, or backup name.
- `activate_envelope_migration` and `commit_legacy_reversion` on production each require explicit operator approval immediately before the call.
- Keep release `a1bb8400bf2c6ad013f756ccb6ee7a70c8640eb1` on the VPS; do not prune it.
- Commit after every task on branch `codex/audit-fixes-2026-09-20`, ending messages with `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`.

## Review Focus

1. **A member has unsynced offline work when the vault is reverted.** Expect: the work stays on that device (never deleted) and is not uploaded. The server cannot see another device's local queue, so this is a runbook gate (Task 6 step 2: every member shows 0 pending), not an automated test.
2. **A quote written by another member between snapshot and commit.** Expect: commit refuses (`40001`), nothing changes, operator reruns. Pinned by Task 3 SQL test "revision changed after begin" and Task 4 test "aborts without writing when the revision changes during staging".
3. **One undecryptable/damaged quote in the vault.** Expect: reversion aborts before any server write and names the quote ID; no partial state. Pinned by Task 4 test "aborts before any write when a quote cannot be decrypted".
4. **Server tampering with staged rows (missing, extra, foreign ID, v2 text).** Expect: commit refuses; quotes untouched. Pinned by Task 3 SQL tests.
5. **Old frontend after reversion reads every field (multi-author, context, original sender, import provenance).** Expect: identical plaintext. Pinned by Task 2 test replicating `a1bb840`'s decrypt path.

## File Structure

| File | Responsibility |
|---|---|
| `tests/database-legacy-client.sql` (create) | Proves the `a1bb840` client contract works on the final schema in legacy mode |
| `scripts/quote-fingerprint.sql` (create) | Read-only integrity fingerprint of stored quotes (count + ciphertext digest) |
| `src/lib/quote-crypto.ts` (modify) | Add `encryptLegacyQuoteText` (v1 format, no AAD) |
| `supabase/migrations/20260923000000_legacy_reversion.sql` (create) | Reversion tables and `begin/stage/commit_legacy_reversion` RPCs |
| `tests/database-legacy-reversion.sql` (create) | SQL regression for reversion authorization and data preservation |
| `src/lib/legacy-reversion.ts` (create) | Client runner: snapshot → decrypt → v1 re-encrypt → verify → stage → commit (+ dry run) |
| `tests/legacy-reversion.test.mjs` (create) | Runner tests with mocked RPC |
| `src/components/LegacyReversion.tsx` (create) | Admin UI: dry run and confirmed return to shared key |
| `src/components/Admin.tsx` (modify) | Render `LegacyReversion` below `MigrationPanel` |
| `scripts/test-database.sh` (modify) | Wire the new SQL tests and migration |
| `docs/operations.md` (modify) | Production rollout + rollback runbook |

---

## Phase 1 — Rollback tooling (code, local only)

### Task 1: Prove the old frontend works on the final schema, and add the integrity fingerprint

**Files:**
- Create: `tests/database-legacy-client.sql`
- Create: `scripts/quote-fingerprint.sql`
- Modify: `scripts/test-database.sh` (after the `tests/database-audit-fixes.sql` line)

**Interfaces:**
- Produces: `scripts/quote-fingerprint.sql` — read-only query returning one row `(quote_count bigint, id_digest text, ciphertext_digest text, generation uuid, envelope_status text, revision bigint)`. Tasks 7, 8, 10, 12, 13 compare its output before/after each production step.

- [ ] **Step 1: Write the fingerprint query**

`scripts/quote-fingerprint.sql`:
```sql
-- Read-only. Safe on production. Prints no plaintext (quotes are ciphertext).
select count(q.id) as quote_count,
       md5(coalesce(string_agg(q.id::text, ',' order by q.id), '')) as id_digest,
       md5(coalesce(string_agg(q.id::text || ':' || q.text || ':' || q.user_id::text || ':' || q.created_at::text || ':' || coalesce(q.quote_date::text, ''), ',' order by q.id), '')) as ciphertext_digest,
       s.generation, s.envelope_status, s.revision
from public.vault_state s left join public.quotes q on true
where s.singleton
group by s.generation, s.envelope_status, s.revision;
```

- [ ] **Step 2: Write the compatibility test (fails if any old-client call breaks)**

`tests/database-legacy-client.sql`:
```sql
-- The a1bb840 frontend must keep working on the final schema while the vault is legacy.
begin;
insert into public.allowlist(id,email,created_at) values
 ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','darkmgdevelopment@gmail.com',now()),
 ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','legacy-client@example.invalid',now());
insert into auth.users(instance_id,id,aud,role,email,encrypted_password,email_confirmed_at) values
 (gen_random_uuid(),'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','authenticated','authenticated','darkmgdevelopment@gmail.com','x',now()),
 (gen_random_uuid(),'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','authenticated','authenticated','legacy-client@example.invalid','x',now());
update public.vault_state set envelope_status='legacy',prepared_generation=null,active_migration_id=null,
  verifier='{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}' where singleton;
select set_config('qv.g',(select generation::text from public.vault_state where singleton),true);
set local role authenticated;
select set_config('request.jwt.claim.sub','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',true);
do $client$
declare
  g uuid := current_setting('qv.g')::uuid;
  quote_id uuid := gen_random_uuid();
  response jsonb;
  cipher text := '$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}';
begin
  response := public.get_vault_state();
  if response->>'generation' is distinct from g::text or response->'kdf' is null then raise exception 'old get_vault_state() contract broke: %', response; end if;
  response := public.sync_quotes(g, 0, jsonb_build_array(jsonb_build_object(
    'operation_id', gen_random_uuid(), 'action', 'INSERT', 'quote_id', quote_id,
    'actor_id', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'vault_generation', g,
    'payload', jsonb_build_object('id', quote_id, 'text', cipher, 'author', 'ENCRYPTED', 'context', 'ENCRYPTED',
      'quote_date', '2026-09-23', 'created_at', '2026-09-23T12:00:00.000Z',
      'user_id', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'vault_generation', g))));
  if response->'results'->0->>'status' is distinct from 'ok' then raise exception 'old 3-argument sync_quotes insert broke: %', response; end if;
  response := public.sync_quotes(g, null, '[]'::jsonb);
  if jsonb_array_length(response->'quotes') <> 1 then raise exception 'old full snapshot broke: %', response; end if;
  perform 1 from public.profiles limit 1;
end $client$;
select set_config('request.jwt.claim.sub','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',true);
do $admin$
declare
  g uuid := current_setting('qv.g')::uuid;
  q record;
begin
  select id, text into q from public.quotes limit 1;
  perform public.edit_quote(g, q.id, q.text, '$$E2E$${"iv":"BBBBBBBBBBBBBBBB","data":"AAAAAAAAAAAAAAAAAAAAAA=="}', date '2026-09-23');
  perform public.edit_quotes(g, '[]'::jsonb);
  insert into public.allowlist(id,email,created_at) values (gen_random_uuid(),'added-by-old-admin@example.invalid',now());
  delete from public.allowlist where email='added-by-old-admin@example.invalid';
end $admin$;
reset role;
rollback;
```

- [ ] **Step 3: Wire both into the test runner**

In `scripts/test-database.sh`, directly after the line `psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f tests/database-audit-fixes.sql`, add:
```sh
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f tests/database-legacy-client.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f scripts/quote-fingerprint.sql
```

- [ ] **Step 4: Run and read the result**

Run: `PGHOST=localhost PGPORT=55432 PGUSER=postgres npm run test:database`
Expected: exit 0. If a `raise exception 'old …'` fires, STOP: the old frontend is not a safe rollback target on this schema; report which call broke before continuing. (Disposable PostgreSQL: `initdb` + `pg_ctl -o "-p 55432 -k '' -c listen_addresses=localhost"`.)

- [ ] **Step 5: Commit**
```bash
git add tests/database-legacy-client.sql scripts/quote-fingerprint.sql scripts/test-database.sh
git commit -m "Prove the shared-key frontend contract on the final schema"
```

### Task 2: Legacy v1 quote encoder

**Files:**
- Modify: `src/lib/quote-crypto.ts` (imports line 1; append export)
- Test: `tests/quote-crypto.test.mjs` (append)

**Interfaces:**
- Produces: `encryptLegacyQuoteText(privateFields: Record<string, unknown>, key: CryptoKey): Promise<string>` — returns `'$$E2E$$' + JSON.stringify({ iv, data })` with **no** `version` field and no AAD. Consumed by Task 4.

- [ ] **Step 1: Write the failing test** (append to `tests/quote-crypto.test.mjs`; `cryptoApi` and `quoteCrypto` are already defined at the top of that file)
```js
test('legacy v1 text decrypts through the a1bb840 display path and the current reader', async () => {
  const key = await cryptoApi.deriveEncryptionKey('legacy-reversion-test-key');
  const fields = { text: 'first line\nsecond line', author: 'Ada & Grace', context: 'A context', source_sender: 'Original sender', import_source_id: '1'.padStart(64, '0') };
  const text = await quoteCrypto.encryptLegacyQuoteText(fields, key);
  assert.ok(text.startsWith('$$E2E$$'));
  const bundle = JSON.parse(text.slice('$$E2E$$'.length));
  assert.equal(Object.hasOwn(bundle, 'version'), false, 'a1bb840 treats any bundle as v1');
  // a1bb840 src/components/ui.ts decryptQuoteForDisplay: decryptData(bundle, key) then isDecryptedPayload.
  const legacy = JSON.parse(await cryptoApi.decryptData(bundle, key));
  assert.equal(JSON.stringify(legacy), JSON.stringify(fields));
  const current = await quoteCrypto.decryptQuoteRecord({ id: '11111111-1111-4111-8111-111111111111', text, user_id: '22222222-2222-4222-8222-222222222222', vault_generation: '33333333-3333-4333-8333-333333333333', created_at: '2026-09-23T00:00:00.000Z', quote_date: null }, key);
  for (const [name, value] of Object.entries(fields)) assert.equal(current[name], value);
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/quote-crypto.test.mjs`
Expected: FAIL with `quoteCrypto.encryptLegacyQuoteText is not a function`.

- [ ] **Step 3: Implement**

`src/lib/quote-crypto.ts` line 1 becomes:
```ts
import { decryptData, encryptData } from './crypto';
```
Append:
```ts
/** Pre-envelope v1 text (no authenticated metadata): readable by the shared-key release a1bb840. */
export async function encryptLegacyQuoteText(privateFields: QuoteFields, key: CryptoKey): Promise<string> {
    return `${QUOTE_CIPHERTEXT_SENTINEL}${JSON.stringify(await encryptData(JSON.stringify(privateFields), key))}`;
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --test tests/quote-crypto.test.mjs && npx tsc -b --pretty false`
Expected: PASS, tsc exit 0.

- [ ] **Step 5: Commit**
```bash
git add src/lib/quote-crypto.ts tests/quote-crypto.test.mjs
git commit -m "Add legacy v1 quote encoder for shared-key reversion"
```

### Task 3: Server-side legacy reversion (atomic, verified, retained)

**Files:**
- Create: `supabase/migrations/20260923000000_legacy_reversion.sql`
- Create: `tests/database-legacy-reversion.sql`
- Modify: `scripts/test-database.sh` (after Task 1's lines)

**Interfaces:**
- Produces RPCs (all `security definer`, granted only to `authenticated`, admin-only):
  - `begin_legacy_reversion(p_source_generation uuid, p_source_revision bigint, p_device_id uuid, p_token text) → jsonb {reversion_id uuid, target_generation uuid, expected_quote_count int}`
  - `stage_legacy_reversion(p_reversion_id uuid, p_rows jsonb, p_device_id uuid, p_token text) → jsonb {reversion_id, staged_quote_count int}`; `p_rows` = array (≤ 50) of `{quote_id uuid, text string}`
  - `commit_legacy_reversion(p_reversion_id uuid, p_kdf jsonb, p_verifier jsonb, p_device_id uuid, p_token text) → jsonb {generation uuid, revision bigint, envelope_status 'legacy', quote_count int}`
- Allowed source states: `legacy` (no device needed) and `active` (device authorization required). `preparing`/`maintenance` are refused — abandon or finalize/rollback first.
- Retention: every pre-reversion ciphertext row is kept in `vault_legacy_reversion_rows` (`row_kind='source'`) forever; nothing is purged.

- [ ] **Step 1: Write the failing SQL test**

`tests/database-legacy-reversion.sql`:
```sql
-- Legacy reversion preserves every quote and refuses every unsafe request.
begin;
do $test$
declare
  admin_id uuid := 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  member_id uuid := 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  admin_device uuid := '11111111-1111-4111-8111-111111111111';
  g uuid := (select generation from public.vault_state where singleton);
  token text := 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  digest text := rtrim(replace(replace(replace(encode(sha256(decode(token || '=', 'base64')), 'base64'), E'\n', ''), '+', '-'), '/', '_'), '=');
  jwk jsonb := jsonb_build_object('kty','RSA','n',rtrim(replace(replace(replace(encode(decode('80'||repeat('00',383),'hex'),'base64'),E'\n',''),'+','-'),'/','_'),'='),'e','AQAB');
  v1 text := '$$E2E$${"iv":"CCCCCCCCCCCCCCCC","data":"AAAAAAAAAAAAAAAAAAAAAA=="}';
  q1 uuid := '44444444-4444-4444-8444-444444444444';
  q2 uuid := '55555555-5555-4555-8555-555555555555';
  begun jsonb; committed jsonb; r uuid; before_meta text; rev bigint;
begin
  insert into public.allowlist(id,email,created_at) values (admin_id,'darkmgdevelopment@gmail.com',now()),(member_id,'member@example.invalid',now());
  insert into auth.users(instance_id,id,aud,role,email,encrypted_password,email_confirmed_at) values
    (gen_random_uuid(),admin_id,'authenticated','authenticated','darkmgdevelopment@gmail.com','x',now()),
    (gen_random_uuid(),member_id,'authenticated','authenticated','member@example.invalid','x',now());
  insert into public.vault_devices(id,owner_id,status,request_kind,enrollment_fingerprint,public_jwk,public_key_fingerprint,authorization_token_digest,label,protection_mode,protection,encrypted_private_bundle,lease_expires_at)
    values(admin_device,admin_id,'active','first',digest,jwk,public.qv_public_key_fingerprint(jwk),digest,'t','remembered','{"version":1,"mode":"remembered"}'::jsonb,'{"version":2,"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb,now()+interval '1 day');
  insert into public.quotes(id,text,author,context,quote_date,created_at,user_id,vault_generation) values
    (q1,'$$E2E$${"version":2,"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}','ENCRYPTED','ENCRYPTED',date '2026-09-20','2026-09-20T12:00:00.123456Z',member_id,g),
    (q2,'$$E2E$${"version":2,"iv":"BBBBBBBBBBBBBBBB","data":"AAAAAAAAAAAAAAAAAAAAAA=="}','ENCRYPTED','ENCRYPTED',null,'2026-09-21T12:00:00Z',admin_id,g);
  update public.vault_state set envelope_status='active' where singleton;
  before_meta := (select string_agg(id::text||user_id::text||created_at::text||coalesce(quote_date::text,''),',' order by id) from public.quotes);
  rev := (select revision from public.vault_state);

  -- Members cannot start a reversion; active vaults require the admin's device.
  perform set_config('request.jwt.claim.sub',member_id::text,true);
  begin perform public.begin_legacy_reversion(g,rev,null,null); raise exception 'member began a reversion'; exception when sqlstate '42501' then null; end;
  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  begin perform public.begin_legacy_reversion(g,rev,null,null); raise exception 'active vault reverted without device authorization'; exception when sqlstate '42501' then null; end;
  begin perform public.begin_legacy_reversion(g,rev+1,admin_device,token); raise exception 'stale revision accepted'; exception when sqlstate '40001' then null; end;

  begun := public.begin_legacy_reversion(g,rev,admin_device,token); r := (begun->>'reversion_id')::uuid;
  if (begun->>'expected_quote_count')::int <> 2 then raise exception 'wrong expected count %', begun; end if;

  -- Staged text must be v1 legacy ciphertext for a quote in the source generation.
  begin perform public.stage_legacy_reversion(r,jsonb_build_array(jsonb_build_object('quote_id',q1,'text','$$E2E$${"version":2,"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}')),admin_device,token); raise exception 'v2 text staged'; exception when sqlstate '22023' then null; end;
  begin perform public.stage_legacy_reversion(r,jsonb_build_array(jsonb_build_object('quote_id',gen_random_uuid(),'text',v1)),admin_device,token); raise exception 'foreign quote staged'; exception when sqlstate '22023' then null; end;
  begin perform public.stage_legacy_reversion(r,jsonb_build_array(jsonb_build_object('quote_id',q1,'text','plaintext')),admin_device,token); raise exception 'unencrypted text staged'; exception when sqlstate '22023' then null; end;
  perform public.stage_legacy_reversion(r,jsonb_build_array(jsonb_build_object('quote_id',q1,'text',v1)),admin_device,token);

  -- Commit refuses an incomplete set; nothing changes.
  begin perform public.commit_legacy_reversion(r,'{"salt":"MDEyMzQ1Njc4OWFiY2RlZg==","iterations":600000}'::jsonb,'{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb,admin_device,token); raise exception 'incomplete reversion committed'; exception when sqlstate '40001' then null; end;
  if (select envelope_status from public.vault_state)<>'active' or exists(select 1 from public.quotes where text=v1) then raise exception 'failed commit changed state'; end if;

  perform public.stage_legacy_reversion(r,jsonb_build_array(jsonb_build_object('quote_id',q2,'text',v1)),admin_device,token);

  -- A write after begin invalidates the snapshot.
  update public.vault_state set revision=revision+1 where singleton;
  begin perform public.commit_legacy_reversion(r,'{"salt":"MDEyMzQ1Njc4OWFiY2RlZg==","iterations":600000}'::jsonb,'{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb,admin_device,token); raise exception 'revision changed after begin but commit succeeded'; exception when sqlstate '40001' then null; end;
  update public.vault_state set revision=rev where singleton;

  committed := public.commit_legacy_reversion(r,'{"salt":"MDEyMzQ1Njc4OWFiY2RlZg==","iterations":600000}'::jsonb,'{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb,admin_device,token);
  if committed->>'envelope_status'<>'legacy' or (select envelope_status from public.vault_state)<>'legacy'
     or (select generation from public.vault_state)<>(begun->>'target_generation')::uuid
     or (select revision from public.vault_state)<=rev then raise exception 'state not legacy after commit: %', committed; end if;
  if (select count(*) from public.quotes)<>2 or exists(select 1 from public.quotes where text<>v1 or vault_generation<>(begun->>'target_generation')::uuid) then raise exception 'quotes not rewritten exactly'; end if;
  if (select string_agg(id::text||user_id::text||created_at::text||coalesce(quote_date::text,''),',' order by id) from public.quotes) is distinct from before_meta then raise exception 'quote metadata changed'; end if;
  if (select count(*) from public.vault_legacy_reversion_rows where reversion_id=r and row_kind='source')<>2 then raise exception 'source ciphertext not retained'; end if;
  if public.qv_envelope_legacy_mode() is not true then raise exception 'legacy RPCs not reopened'; end if;
end $test$;
rollback;
```

- [ ] **Step 2: Wire it and run to verify it fails**

In `scripts/test-database.sh` after Task 1's lines add:
```sh
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f supabase/migrations/20260923000000_legacy_reversion.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f supabase/migrations/20260923000000_legacy_reversion.sql
psql -X -v ON_ERROR_STOP=1 -d "$test_db" -f tests/database-legacy-reversion.sql
```
Run: `PGHOST=localhost PGPORT=55432 PGUSER=postgres npm run test:database`
Expected: FAIL — `20260923000000_legacy_reversion.sql` does not exist.

- [ ] **Step 3: Implement the migration**

`supabase/migrations/20260923000000_legacy_reversion.sql`:
```sql
-- Return an envelope or legacy vault to a shared passphrase in the pre-envelope
-- v1 format. The client re-encrypts; the server swaps rows atomically after
-- proving the staged set equals the stored set. Safe to reapply after itself.
begin;

create table if not exists public.vault_legacy_reversions (
  id uuid primary key default gen_random_uuid(),
  source_generation uuid not null,
  source_revision bigint not null,
  source_status text not null check (source_status in ('legacy','active')),
  target_generation uuid not null unique,
  expected_quote_count integer not null check (expected_quote_count >= 0),
  status text not null default 'staging' check (status in ('staging','committed','abandoned')),
  created_by uuid not null,
  created_at timestamptz not null default now(),
  committed_at timestamptz
);
create table if not exists public.vault_legacy_reversion_rows (
  reversion_id uuid not null references public.vault_legacy_reversions(id) on delete cascade,
  quote_id uuid not null,
  row_kind text not null check (row_kind in ('staged','source')),
  text text not null,
  primary key (reversion_id, quote_id, row_kind)
);
alter table public.vault_legacy_reversions enable row level security;
alter table public.vault_legacy_reversion_rows enable row level security;
revoke all on table public.vault_legacy_reversions, public.vault_legacy_reversion_rows from public, anon, authenticated;

create or replace function public.qv_reversion_authorized(p_state public.vault_state, p_device_id uuid, p_token text)
returns boolean language plpgsql security definer set search_path = public, pg_temp as $auth$
begin
  if public.qv_is_admin() is not true or public.qv_is_member() is not true then return false; end if;
  if p_state.envelope_status='legacy' then return true; end if;
  return public.qv_authorize_device(p_device_id,p_token,p_state.generation,'state') is not null;
end $auth$;

create or replace function public.qv_legacy_v1_text(p_text text)
returns boolean language plpgsql immutable set search_path = public, pg_temp as $v1$
declare cipher jsonb;
begin
  if left(p_text,7)<>'$$E2E$$' then return false; end if;
  cipher := substring(p_text from 8)::jsonb;
  return jsonb_typeof(cipher)='object' and not cipher ? 'version' and (select count(*) from jsonb_object_keys(cipher))=2
    and public.qv_valid_verifier(cipher) is true and length(cipher->>'data')<=262144;
exception when others then return false;
end $v1$;

create or replace function public.begin_legacy_reversion(p_source_generation uuid,p_source_revision bigint,p_device_id uuid,p_token text)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $begin$
declare state public.vault_state%rowtype; reversion public.vault_legacy_reversions%rowtype;
begin
  select * into state from public.vault_state where singleton for update;
  if public.qv_reversion_authorized(state,p_device_id,p_token) is not true then raise exception 'Administrator device authorization is required' using errcode='42501'; end if;
  if state.envelope_status not in ('legacy','active') then raise exception 'Finish or cancel the open migration first' using errcode='40001'; end if;
  if state.generation is distinct from p_source_generation or state.revision is distinct from p_source_revision then raise exception 'Vault changed; reload and start again' using errcode='40001'; end if;
  delete from public.vault_legacy_reversion_rows where reversion_id in (select id from public.vault_legacy_reversions where status='staging');
  update public.vault_legacy_reversions set status='abandoned' where status='staging';
  insert into public.vault_legacy_reversions(source_generation,source_revision,source_status,target_generation,expected_quote_count,created_by)
    values(state.generation,state.revision,state.envelope_status,gen_random_uuid(),(select count(*) from public.quotes where vault_generation=state.generation),auth.uid())
    returning * into reversion;
  return jsonb_build_object('reversion_id',reversion.id,'target_generation',reversion.target_generation,'expected_quote_count',reversion.expected_quote_count);
end $begin$;

create or replace function public.stage_legacy_reversion(p_reversion_id uuid,p_rows jsonb,p_device_id uuid,p_token text)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $stage$
declare state public.vault_state%rowtype; reversion public.vault_legacy_reversions%rowtype; item jsonb;
begin
  if jsonb_typeof(p_rows)<>'array' or jsonb_array_length(p_rows)>50 then raise exception 'Invalid reversion batch' using errcode='22023'; end if;
  select * into state from public.vault_state where singleton for update;
  if public.qv_reversion_authorized(state,p_device_id,p_token) is not true then raise exception 'Administrator device authorization is required' using errcode='42501'; end if;
  select * into reversion from public.vault_legacy_reversions where id=p_reversion_id for update;
  if not found or reversion.status<>'staging' or state.generation<>reversion.source_generation or state.revision<>reversion.source_revision then raise exception 'Vault changed; reload and start again' using errcode='40001'; end if;
  for item in select value from jsonb_array_elements(p_rows) loop
    if jsonb_typeof(item)<>'object' or (select count(*) from jsonb_object_keys(item))<>2 or item ?& array['quote_id','text'] is not true
       or public.qv_legacy_v1_text(item->>'text') is not true
       or not exists(select 1 from public.quotes where id=(item->>'quote_id')::uuid and vault_generation=reversion.source_generation) then
      raise exception 'Invalid reversion row' using errcode='22023';
    end if;
    insert into public.vault_legacy_reversion_rows(reversion_id,quote_id,row_kind,text) values(reversion.id,(item->>'quote_id')::uuid,'staged',item->>'text')
      on conflict (reversion_id,quote_id,row_kind) do update set text=excluded.text;
  end loop;
  return jsonb_build_object('reversion_id',reversion.id,'staged_quote_count',(select count(*) from public.vault_legacy_reversion_rows where reversion_id=reversion.id and row_kind='staged'));
exception when invalid_text_representation then raise exception 'Invalid reversion row' using errcode='22023';
end $stage$;

create or replace function public.commit_legacy_reversion(p_reversion_id uuid,p_kdf jsonb,p_verifier jsonb,p_device_id uuid,p_token text)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $commit$
declare state public.vault_state%rowtype; reversion public.vault_legacy_reversions%rowtype; quote_count integer;
begin
  if public.qv_valid_kdf(p_kdf) is not true or public.qv_valid_verifier(p_verifier) is not true then raise exception 'Invalid vault cryptography metadata' using errcode='22023'; end if;
  select * into state from public.vault_state where singleton for update;
  if public.qv_reversion_authorized(state,p_device_id,p_token) is not true then raise exception 'Administrator device authorization is required' using errcode='42501'; end if;
  select * into reversion from public.vault_legacy_reversions where id=p_reversion_id for update;
  if not found or reversion.status<>'staging' or state.envelope_status<>reversion.source_status or state.generation<>reversion.source_generation or state.revision<>reversion.source_revision then raise exception 'Vault changed; reload and start again' using errcode='40001'; end if;
  perform 1 from public.quotes for update;
  select count(*) into quote_count from public.quotes;
  if quote_count<>reversion.expected_quote_count
     or exists(select 1 from public.quotes where vault_generation<>reversion.source_generation)
     or exists(select 1 from public.quotes q where not exists(select 1 from public.vault_legacy_reversion_rows s where s.reversion_id=reversion.id and s.row_kind='staged' and s.quote_id=q.id))
     or exists(select 1 from public.vault_legacy_reversion_rows s where s.reversion_id=reversion.id and s.row_kind='staged' and not exists(select 1 from public.quotes q where q.id=s.quote_id)) then
    raise exception 'Staged quotes do not match the vault; nothing was changed' using errcode='40001';
  end if;
  insert into public.vault_legacy_reversion_rows(reversion_id,quote_id,row_kind,text) select reversion.id,q.id,'source',q.text from public.quotes q;
  update public.quotes q set text=s.text,author='ENCRYPTED',context='ENCRYPTED',vault_generation=reversion.target_generation
    from public.vault_legacy_reversion_rows s where s.reversion_id=reversion.id and s.row_kind='staged' and s.quote_id=q.id;
  delete from public.vault_legacy_reversion_rows where reversion_id=reversion.id and row_kind='staged';
  update public.vault_state set generation=reversion.target_generation,revision=state.revision+1,
    kdf=jsonb_build_object('salt',p_kdf->>'salt','iterations',(p_kdf->>'iterations')::integer),
    verifier=jsonb_build_object('iv',p_verifier->>'iv','data',p_verifier->>'data'),
    envelope_status='legacy',legacy_generation=null,prepared_generation=null,active_migration_id=null
    where singleton returning * into state;
  update public.vault_legacy_reversions set status='committed',committed_at=now() where id=reversion.id;
  insert into public.vault_security_events(event_type,actor_id,affected_owner_id,affected_device_id,result,reason_code)
    values('rotation_activated',auth.uid(),auth.uid(),p_device_id,'ok','legacy-reversion');
  if to_regprocedure('realtime.send(jsonb,text,text,boolean)') is not null then
    perform realtime.send(jsonb_build_object('generation',state.generation),'vault-generation','quotevault-sync',true);
  end if;
  return jsonb_build_object('generation',state.generation,'revision',state.revision,'envelope_status','legacy','quote_count',quote_count);
end $commit$;

revoke all on function public.qv_reversion_authorized(public.vault_state,uuid,text), public.qv_legacy_v1_text(text),
  public.begin_legacy_reversion(uuid,bigint,uuid,text), public.stage_legacy_reversion(uuid,jsonb,uuid,text),
  public.commit_legacy_reversion(uuid,jsonb,jsonb,uuid,text) from public, anon, authenticated;
grant execute on function public.begin_legacy_reversion(uuid,bigint,uuid,text), public.stage_legacy_reversion(uuid,jsonb,uuid,text),
  public.commit_legacy_reversion(uuid,jsonb,jsonb,uuid,text) to authenticated;

commit;
```

- [ ] **Step 4: Run to verify it passes**

Run: `PGHOST=localhost PGPORT=55432 PGUSER=postgres npm run test:database`
Expected: exit 0.

- [ ] **Step 5: Mutation check (the test must catch each guard)**

For each edit below, apply it temporarily to the migration, rerun Step 4, confirm FAIL with the named message, then revert:
- remove `or state.revision<>reversion.source_revision` from `commit_legacy_reversion` → `revision changed after begin but commit succeeded`
- replace `public.qv_legacy_v1_text(item->>'text') is not true` with `false` → `v2 text staged`
- remove the `insert … 'source' …` line → `source ciphertext not retained`

- [ ] **Step 6: Commit**
```bash
git add supabase/migrations/20260923000000_legacy_reversion.sql tests/database-legacy-reversion.sql scripts/test-database.sh
git commit -m "Add atomic legacy reversion RPCs with retained source ciphertext"
```

### Task 4: Client reversion runner with dry run

**Files:**
- Create: `src/lib/legacy-reversion.ts`
- Test: `tests/legacy-reversion.test.mjs`

**Interfaces:**
- Consumes: `encryptLegacyQuoteText` (Task 2); RPCs from Task 3; existing `loadMigrationSourceSnapshot` and `MIGRATION_BATCH_SIZE` from `src/lib/vault-migration.ts`; `createVaultConfig`, `decryptData` from `src/lib/crypto.ts`; `decryptQuoteRecord` from `src/lib/quote-crypto.ts`.
- Produces: `revertToLegacy(input: LegacyReversionInput): Promise<LegacyReversionResult>` where
  - `LegacyReversionInput = { sourceGeneration: string; sourceKey: CryptoKey; passphrase: string; deviceId: string | null; token: string | null; dryRun?: boolean; onProgress?: (done: number, total: number) => void }`
  - `LegacyReversionResult = { quoteCount: number; generation: string | null }` (`generation` is null for a dry run).

- [ ] **Step 1: Write the failing tests**

`tests/legacy-reversion.test.mjs`:
```js
import assert from 'node:assert/strict';
import test from 'node:test';
import { webcrypto } from 'node:crypto';
import { loadModule } from './load-module.mjs';

const globals = { crypto: webcrypto, TextEncoder, TextDecoder, btoa, atob, navigator: { onLine: true } };
const cryptoApi = loadModule('src/lib/crypto.ts', {}, globals);
const deviceCrypto = loadModule('src/lib/device-crypto.ts', { './crypto': cryptoApi }, globals);
const quoteCrypto = loadModule('src/lib/quote-crypto.ts', { './crypto': cryptoApi, './device-crypto': deviceCrypto }, globals);
const GEN = '11111111-1111-4111-8111-111111111111';
const USER = '33333333-3333-4333-8333-333333333333';
const REVERSION = '44444444-4444-4444-8444-444444444444';
const TARGET = '55555555-5555-4555-8555-555555555555';

function load(rpc) {
  const supabase = { supabase: { rpc: async (name, args) => rpc(name, args) } };
  const migration = loadModule('src/lib/vault-migration.ts', { './crypto': cryptoApi, './device-crypto': deviceCrypto, './quote-crypto': quoteCrypto, './supabase': supabase }, globals);
  return loadModule('src/lib/legacy-reversion.ts', { './crypto': cryptoApi, './quote-crypto': quoteCrypto, './vault-migration': migration, './supabase': supabase }, globals);
}
const ok = data => ({ data, error: null });
const fields = index => ({ text: `Private quote ${index}`, author: index % 2 ? 'Ada & Grace' : 'Ada', context: `Context ${index}`, source_sender: 'Original sender', import_source_id: String(index).padStart(64, '0') });

async function vault(count) {
  const master = deviceCrypto.generateVaultMasterKey();
  const key = await deviceCrypto.deriveQuoteKey(master, GEN);
  const legacyKey = await cryptoApi.deriveEncryptionKey('pre-envelope-shared-key');
  const quotes = await Promise.all(Array.from({ length: count }, async (_, index) => {
    const id = `${String(index + 1).padStart(8, '0')}-1111-4111-8111-111111111111`;
    const visible = { id, quote_date: '2026-09-22', created_at: '2026-09-22T12:00:00.000Z', user_id: USER, vault_generation: GEN, author: 'ENCRYPTED', context: 'ENCRYPTED' };
    return quoteCrypto.encryptQuoteRecord(fields(index), visible, key);
  }));
  return { key, legacyKey, quotes };
}

test('dry run converts and verifies every quote without writing', async () => {
  const { key, quotes } = await vault(3);
  const calls = [];
  const runner = load((name, args) => { calls.push(name); if (name === 'sync_quotes') return ok({ generation: GEN, revision: 9, results: [], quotes }); throw new Error(`unexpected ${name}`); });
  const result = await runner.revertToLegacy({ sourceGeneration: GEN, sourceKey: key, passphrase: 'a long enough passphrase', deviceId: null, token: null, dryRun: true });
  assert.equal(result.quoteCount, 3);
  assert.equal(result.generation, null);
  assert.deepEqual([...calls], ['sync_quotes']);
});

test('reverts every field to v1 text readable with the new passphrase', async () => {
  const { key, quotes } = await vault(53);
  const batches = []; const stagedRows = []; let commitArgs;
  const runner = load((name, args) => {
    if (name === 'sync_quotes') return ok({ generation: GEN, revision: 9, results: [], quotes });
    if (name === 'begin_legacy_reversion') { assert.equal(args.p_source_revision, 9); return ok({ reversion_id: REVERSION, target_generation: TARGET, expected_quote_count: 53 }); }
    if (name === 'stage_legacy_reversion') { batches.push(args.p_rows.length); stagedRows.push(...args.p_rows); return ok({ reversion_id: REVERSION, staged_quote_count: stagedRows.length }); }
    if (name === 'commit_legacy_reversion') { commitArgs = args; return ok({ generation: TARGET, revision: 10, envelope_status: 'legacy', quote_count: 53 }); }
    throw new Error(`unexpected ${name}`);
  });
  const result = await runner.revertToLegacy({ sourceGeneration: GEN, sourceKey: key, passphrase: 'a long enough passphrase', deviceId: null, token: null });
  assert.equal(result.quoteCount, 53);
  assert.equal(result.generation, TARGET);
  assert.equal(JSON.stringify(batches), JSON.stringify([50, 3]));
  const newKey = await cryptoApi.unlockWithVerifier('a long enough passphrase', commitArgs.p_kdf, commitArgs.p_verifier);
  for (const [index, row] of stagedRows.entries()) {
    const bundle = JSON.parse(row.text.slice('$$E2E$$'.length));
    assert.equal(Object.hasOwn(bundle, 'version'), false);
    assert.equal(await cryptoApi.decryptData(bundle, newKey), JSON.stringify(fields(index)));
  }
});

test('aborts before any write when a quote cannot be decrypted', async () => {
  const { key, quotes } = await vault(2);
  const damaged = [quotes[0], { ...quotes[1], text: quotes[0].text }];
  const calls = [];
  const runner = load((name) => { calls.push(name); if (name === 'sync_quotes') return ok({ generation: GEN, revision: 9, results: [], quotes: damaged }); throw new Error(`unexpected ${name}`); });
  await assert.rejects(runner.revertToLegacy({ sourceGeneration: GEN, sourceKey: key, passphrase: 'a long enough passphrase', deviceId: null, token: null }), /00000002-1111-4111-8111-111111111111/);
  assert.deepEqual([...calls], ['sync_quotes']);
});

test('aborts without writing when the revision changes during staging', async () => {
  const { key, quotes } = await vault(2);
  const calls = [];
  const runner = load((name) => {
    calls.push(name);
    if (name === 'sync_quotes') return ok({ generation: GEN, revision: 9, results: [], quotes });
    if (name === 'begin_legacy_reversion') return ok({ reversion_id: REVERSION, target_generation: TARGET, expected_quote_count: 2 });
    if (name === 'stage_legacy_reversion') return { data: null, error: { code: '40001', message: 'Vault changed; reload and start again' } };
    throw new Error(`unexpected ${name}`);
  });
  await assert.rejects(runner.revertToLegacy({ sourceGeneration: GEN, sourceKey: key, passphrase: 'a long enough passphrase', deviceId: null, token: null }), /Vault changed/);
  assert.equal(calls.includes('commit_legacy_reversion'), false);
});

test('refuses a short passphrase before reading the vault', async () => {
  const { key } = await vault(1);
  const runner = load(() => { throw new Error('no RPC expected'); });
  await assert.rejects(runner.revertToLegacy({ sourceGeneration: GEN, sourceKey: key, passphrase: 'short', deviceId: null, token: null }), /at least 12/);
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/legacy-reversion.test.mjs`
Expected: FAIL — cannot read `src/lib/legacy-reversion.ts`.

- [ ] **Step 3: Implement**

`src/lib/legacy-reversion.ts`:
```ts
import { createVaultConfig, decryptData } from './crypto';
import { decryptQuoteRecord, encryptLegacyQuoteText, QUOTE_CIPHERTEXT_SENTINEL } from './quote-crypto';
import { loadMigrationSourceSnapshot, MIGRATION_BATCH_SIZE } from './vault-migration';
import { supabase } from './supabase';

export interface LegacyReversionInput {
    sourceGeneration: string; sourceKey: CryptoKey; passphrase: string; deviceId: string | null; token: string | null;
    dryRun?: boolean; onProgress?: (done: number, total: number) => void;
}
export interface LegacyReversionResult { quoteCount: number; generation: string | null }

const VISIBLE = ['id', 'vault_generation', 'user_id', 'created_at', 'quote_date'];

async function call(name: string, args: Record<string, unknown>): Promise<Record<string, unknown>> {
    const { data, error } = await (supabase.rpc(name, args) as unknown as Promise<{ data: unknown; error: { code?: string; message?: string } | null }>);
    if (error) throw Object.assign(new Error(error.message || `${name} failed. Nothing was changed.`), { code: error.code });
    if (!data || typeof data !== 'object') throw new Error(`${name} returned no result. Nothing was changed.`);
    return data as Record<string, unknown>;
}

/** Re-encrypts every quote to pre-envelope v1 under a new shared passphrase; verifies all rows before any write. */
export async function revertToLegacy(input: LegacyReversionInput): Promise<LegacyReversionResult> {
    const config = await createVaultConfig(input.passphrase);
    const snapshot = await loadMigrationSourceSnapshot({ sourceGeneration: input.sourceGeneration, deviceId: input.deviceId, token: input.token });
    const rows: Array<{ quote_id: string; text: string }> = [];
    for (const quote of snapshot.quotes) {
        let fields: Record<string, unknown>;
        try { fields = { ...await decryptQuoteRecord(quote, input.sourceKey) }; } catch { throw new Error(`Quote ${quote.id} could not be decrypted. Nothing was changed.`); }
        for (const name of VISIBLE) delete fields[name];
        const text = await encryptLegacyQuoteText(fields, config.key);
        if (await decryptData(JSON.parse(text.slice(QUOTE_CIPHERTEXT_SENTINEL.length)), config.key) !== JSON.stringify(fields)) throw new Error(`Quote ${quote.id} failed verification. Nothing was changed.`);
        rows.push({ quote_id: quote.id, text });
        input.onProgress?.(rows.length, snapshot.quotes.length);
    }
    if (input.dryRun) return { quoteCount: rows.length, generation: null };
    const auth = { p_device_id: input.deviceId, p_token: input.token };
    const begun = await call('begin_legacy_reversion', { p_source_generation: input.sourceGeneration, p_source_revision: snapshot.revision, ...auth });
    if (Number(begun.expected_quote_count) !== rows.length) throw new Error('The vault changed while it was being read. Nothing was changed; start again.');
    for (let start = 0; start < rows.length; start += MIGRATION_BATCH_SIZE) {
        await call('stage_legacy_reversion', { p_reversion_id: begun.reversion_id, p_rows: rows.slice(start, start + MIGRATION_BATCH_SIZE), ...auth });
    }
    const committed = await call('commit_legacy_reversion', { p_reversion_id: begun.reversion_id, p_kdf: config.kdf, p_verifier: config.verifier, ...auth });
    return { quoteCount: rows.length, generation: String(committed.generation) };
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --test tests/legacy-reversion.test.mjs && npx tsc -b --pretty false && npm run lint`
Expected: 5 tests pass; tsc and lint exit 0.

- [ ] **Step 5: Commit**
```bash
git add src/lib/legacy-reversion.ts tests/legacy-reversion.test.mjs
git commit -m "Add verified client runner for returning to the shared vault key"
```

### Task 5: Admin UI for dry run and return to shared key

**Files:**
- Create: `src/components/LegacyReversion.tsx`
- Modify: `src/components/Admin.tsx` (import block; render after `<MigrationPanel />` at line 72)

**Interfaces:**
- Consumes: `revertToLegacy` (Task 4); `useCrypto()` fields `encryptionKey`, `vaultGeneration`, `envelopeStatus`, `deviceApproved`, `getDeviceAuthorization`, `refreshVaultState`.

- [ ] **Step 1: Implement the component**

`src/components/LegacyReversion.tsx`:
```tsx
import { useState } from 'react';
import { useCrypto } from '../hooks/useCrypto';
import { revertToLegacy } from '../lib/legacy-reversion';

const CONFIRMATION = 'RETURN TO SHARED KEY';

export function LegacyReversion() {
    const { encryptionKey, vaultGeneration, envelopeStatus, deviceApproved, getDeviceAuthorization, refreshVaultState } = useCrypto();
    const [passphrase, setPassphrase] = useState(''); const [repeat, setRepeat] = useState(''); const [typed, setTyped] = useState('');
    const [busy, setBusy] = useState(false); const [message, setMessage] = useState(''); const [error, setError] = useState('');
    if (!encryptionKey || !vaultGeneration || (envelopeStatus !== 'active' && envelopeStatus !== 'legacy')) return null;
    const run = async (dryRun: boolean) => {
        setBusy(true); setError(''); setMessage('');
        try {
            if (!dryRun && (passphrase !== repeat || typed !== CONFIRMATION)) throw new Error(`Repeat the passphrase exactly and type ${CONFIRMATION}.`);
            const auth = deviceApproved ? await getDeviceAuthorization() : null;
            const result = await revertToLegacy({ sourceGeneration: vaultGeneration, sourceKey: encryptionKey, passphrase: dryRun ? 'dry-run-only-passphrase' : passphrase,
                deviceId: auth?.deviceId ?? null, token: auth?.token ?? null, dryRun, onProgress: (done, total) => setMessage(`${done}/${total} quotes checked`) });
            if (dryRun) { setMessage(`Dry run passed: all ${result.quoteCount} quotes convert and verify. Nothing was changed.`); return; }
            setMessage(`Returned ${result.quoteCount} quotes to the shared vault key. Members now unlock with the new passphrase.`);
            try { await refreshVaultState(); } catch { /* The commit succeeded; the next reload shows the shared-key gate. */ }
        } catch (cause) { setError(cause instanceof Error ? cause.message : 'Return to shared key failed. Nothing was changed.'); }
        finally { setBusy(false); }
    };
    return <section aria-labelledby="legacy-reversion-heading" className="space-y-3 border-t border-slate-700 pt-6">
        <h3 id="legacy-reversion-heading" className="text-lg font-semibold text-white">Return to shared vault key</h3>
        <p className="text-sm text-slate-300">Re-encrypts every quote under a new shared passphrase in the original format. Ask every member to sync first; the vault must not be preparing or in maintenance.</p>
        <button type="button" disabled={busy} onClick={() => void run(true)} className="w-full border border-slate-600 py-2 rounded-xl">Dry run (no changes)</button>
        <label className="block text-sm text-slate-300">New shared passphrase<input type="password" autoComplete="new-password" minLength={12} value={passphrase} onChange={event => setPassphrase(event.target.value)} className="mt-1 w-full rounded-xl bg-slate-900 border border-slate-700 p-2 text-white" /></label>
        <label className="block text-sm text-slate-300">Repeat passphrase<input type="password" autoComplete="new-password" value={repeat} onChange={event => setRepeat(event.target.value)} className="mt-1 w-full rounded-xl bg-slate-900 border border-slate-700 p-2 text-white" /></label>
        <label className="block text-sm text-slate-300">Type {CONFIRMATION}<input value={typed} onChange={event => setTyped(event.target.value)} className="mt-1 w-full rounded-xl bg-slate-900 border border-slate-700 p-2 text-white" /></label>
        <button type="button" disabled={busy} onClick={() => void run(false)} className="w-full bg-red-700 disabled:opacity-50 py-2 rounded-xl">Return to shared vault key</button>
        {message && <p aria-live="polite" className="text-sm text-slate-200">{message}</p>}
        {error && <p role="alert" className="text-sm text-red-400">{error}</p>}
    </section>;
}
```

- [ ] **Step 2: Render it**

In `src/components/Admin.tsx` add after line 12:
```tsx
import { LegacyReversion } from './LegacyReversion';
```
and replace the line `        <MigrationPanel />` with:
```tsx
        <MigrationPanel />
        <LegacyReversion />
```

- [ ] **Step 3: Verify**

Run: `npx tsc -b --pretty false && npm run lint && npm test && npm run build:smoke`
Expected: all exit 0.

- [ ] **Step 4: Full suite, sequential**

Run in order: `npm run test:browser` (outside sandbox), then `PGHOST=localhost PGPORT=55432 PGUSER=postgres npm run test:database`, then `npm run test:edge`, then `git diff --check`.
Expected: all exit 0 (25 browser tests).

- [ ] **Step 5: Commit and push**
```bash
git add src/components/LegacyReversion.tsx src/components/Admin.tsx
git commit -m "Add admin dry run and return to shared vault key"
git push -u origin codex/audit-fixes-2026-09-20
```
Then confirm GitHub Actions CI is green for the pushed head: `gh run list --branch codex/audit-fixes-2026-09-20 --limit 1`.

### Task 6: Production runbook

**Files:**
- Modify: `docs/operations.md` (new section after "### Device-envelope rollout")

- [ ] **Step 1: Add the section**

Insert:
````markdown
### Rollback to the shared vault key

The rollback works from `legacy` or `active` at any time. It never deletes a
quote: the pre-reversion ciphertext is retained in
`vault_legacy_reversion_rows` (`row_kind='source'`).

1. From `preparing`, first click **Cancel preparation** (abandon). From
   `maintenance`, use **rollback** (within 7 days) or finalize first.
2. Ask every member to open the app online and confirm **Sync now** shows no
   pending changes. Unsynced offline work is not uploaded by a reversion.
3. Record `scripts/quote-fingerprint.sql` output (count and `id_digest`).
4. On an unlocked administrator device: Admin → **Dry run (no changes)**.
   Stop if it reports any quote ID.
5. Enter a new shared passphrase (12+ characters), repeat it, type
   `RETURN TO SHARED KEY`, and click **Return to shared vault key**.
6. Rerun the fingerprint: `quote_count` and `id_digest` must equal step 3,
   `envelope_status` must be `legacy`.
7. Optional: restore the shared-key frontend atomically on the VPS:
   ```sh
   ssh vps 'cd /home/dark/quotevault && ln -sfn releases/a1bb8400bf2c6ad013f756ccb6ee7a70c8640eb1 current.next && mv -Tf current.next current'
   python3 scripts/healthcheck.py --site https://quotes.darkmg1.dev --env-file .env
   ```
   Only after step 6: the old frontend cannot read v2 records.
````

- [ ] **Step 2: Commit**
```bash
git add docs/operations.md
git commit -m "Document any-time rollback to the shared vault key"
```

---

## Phase 2 — Production rollout (operator present; every step verified)

Each task lists **Rollback**. Stop at the first unexpected result.

### Task 7: Pre-flight backups and baseline

- [ ] **Step 1: Push access** — operator runs `gh auth refresh -h github.com -s workflow`; then `git push -u origin codex/audit-fixes-2026-09-20`; CI green.
- [ ] **Step 2: Tools** — `brew install supabase/tap/supabase`; `supabase login` (operator, interactive); `supabase link --project-ref umcprnfdaomntzhvmaoc` (operator enters the database password interactively).
- [ ] **Step 3: Confirm production migration state** — `supabase migration list --linked`. Expected: remote has exactly `20260920000000` … `20260922010000`. If remote history is missing earlier versions, STOP: `db push` would reapply them. Use `supabase migration repair --status applied <version>` only for versions confirmed present by inspecting the schema.
- [ ] **Step 4: Full database backup** — create a private service file (mode 600) outside the repo with the Supabase session-pooler connection (password from the password manager via `.pgpass`, mode 600), then:
```bash
PGSERVICEFILE=$HOME/.config/quotevault/pg_service.conf PGSERVICE=quotevault \
  bash scripts/backup.sh "$HOME/.local/share/quotevault/backups/$(date -u +%Y%m%dT%H%M%SZ)-pre-envelope"
PGHOST=localhost PGPORT=55432 PGUSER=postgres bash scripts/verify-restore.sh "$HOME/.local/share/quotevault/backups/<dir>/<archive>.dump"
```
Expected: archive + `.sha256` written; verify-restore exit 0.
- [ ] **Step 5: Baseline fingerprint** — `PGSERVICEFILE=… PGSERVICE=quotevault psql -X -f scripts/quote-fingerprint.sql > <backup-dir>/fingerprint-0-baseline.txt`. Record `quote_count`, `id_digest`, `ciphertext_digest`.
- [ ] **Step 6: Encrypted application export** — in the live app (old frontend), Admin → download the encrypted backup; store beside the dump. This file + the shared passphrase restores every quote independently of the database.

**Rollback:** nothing changed.

**Task 7 results (2026-09-23):**
- Remote migration history was empty (earlier migrations were applied by hand). Read-only schema markers confirmed `20260920000000`–`20260922010000` live and every envelope migration absent; `supabase migration repair --status applied` recorded exactly those five.
- `supabase migration list` needs the database password (`SUPABASE_DB_PASSWORD`, read with a hidden prompt); without it CLI 2.117 fails creating `cli_login_postgres`. The password was reset in the dashboard; nothing else uses it.
- Direct connections go through the session pooler `aws-1-us-east-1.pooler.supabase.com:5432`, user `postgres.umcprnfdaomntzhvmaoc`. The pooler ignores `PGOPTIONS`; read-only probes must use `begin transaction read only` in the SQL.
- Backup `~/.local/share/quotevault/backups/20260923T205721Z-pre-envelope/` restored locally: 224 quotes, 6 accounts, 1 vault configuration.
- Baseline (`fingerprint-0-baseline.txt`, pre-migration query without `envelope_status`): 224 quotes, `id_digest b59b2b103bacb67df925c3b1e626e1a0`, `ciphertext_digest 14a929293800566ab408fca0d65f666f`, `v2_count 0`, generation `3194f059-d79c-4cfd-a8ca-966217aa096d`, revision 391. Compare fingerprints only through the same pooler connection (timestamps render in the session time zone).
- Step 6 correction: release `a1bb840` has no export button (it arrives with the new frontend's migration panel, used in Task 11). The verified `pg_dump` holds all ciphertext, decryptable with the shared passphrase.

### Task 8: Apply database migrations (old frontend still serving)

- [ ] **Step 0** — In the Supabase dashboard, enable the `pg_cron` extension (required by `20260922120000` for the rollback purge schedule).
- [ ] **Step 1** — `supabase db push --linked` (applies `20260922020000` … `20260923000000` in order).
- [ ] **Step 2** — Fingerprint again → `fingerprint-1-migrated.txt`. Expected: `quote_count`, `id_digest`, `ciphertext_digest`, `generation` **identical** to baseline; `envelope_status = legacy`.
- [ ] **Step 3** — Old frontend smoke test at https://quotes.darkmg1.dev: sign in, unlock with the shared key, read quotes, add a test quote, edit it, delete it, reload. Confirm another device sees changes after focus/reload (instant push is gone by design).

**Rollback:** data is untouched. If Step 3 fails, freeze writes (tell members), restore schema from the Task 7 dump into a fresh branch database to diagnose; do **not** `pg_restore` over production without explicit approval, because quotes written after the backup would be lost.

### Task 9: Edge Function and lease keys

- [ ] **Step 1** — Generate the lease keypair locally, never printing the private half to a file:
```bash
node -e 'const {generateKeyPairSync}=require("crypto");const k=generateKeyPairSync("ec",{namedCurve:"prime256v1"});process.stdout.write(JSON.stringify(k.privateKey.export({format:"jwk"})));' | pbcopy
```
Paste into the password manager as `QuoteVault lease private JWK`, then clear the clipboard with `pbcopy </dev/null`. Then derive the public half from it (paste when prompted):
```bash
node -e 'const c=require("crypto");let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const p=c.createPublicKey(c.createPrivateKey({key:JSON.parse(s),format:"jwk"})).export({format:"jwk"});console.log(JSON.stringify(p));});'
```
Add `VITE_DEVICE_LEASE_PUBLIC_JWK=<public JSON>` to `.env`; run `node scripts/check-client-env.mjs .env`.
- [ ] **Step 2** — Set the secret (docs/operations.md "Deploy the signing function"): `read -r -s DEVICE_LEASE_PRIVATE_JWK; supabase secrets set --project-ref umcprnfdaomntzhvmaoc DEVICE_LEASE_PRIVATE_JWK="$DEVICE_LEASE_PRIVATE_JWK"; unset DEVICE_LEASE_PRIVATE_JWK`.
- [ ] **Step 3** — `supabase functions deploy vault-security --project-ref umcprnfdaomntzhvmaoc`. Verify preflight: `curl -si -X OPTIONS https://umcprnfdaomntzhvmaoc.supabase.co/functions/v1/vault-security -H 'Origin: https://quotes.darkmg1.dev' -H 'Access-Control-Request-Headers: apikey, authorization, content-type, x-client-info' | grep -i access-control-allow-headers` lists all four.

**Rollback:** the old frontend never calls the function; `supabase functions delete vault-security` if desired.

### Task 10: Deploy the new frontend (vault still shared-key)

- [ ] **Step 1** — `ssh vps 'df -h / && du -sh /home/dark/quotevault/releases/*'`; need ≥ 500 MB free. Do not delete `a1bb840…`.
- [ ] **Step 2** — `python3 scripts/deploy.py $(git rev-parse HEAD) --host vps --root /home/dark/quotevault --site https://quotes.darkmg1.dev --env-file .env --database-verified`. It auto-restores the previous symlink if the health check fails.
- [ ] **Step 3** — Verify: shared-key unlock works on each member device; quotes readable; add/edit/delete; fingerprint `quote_count`/`id_digest` unchanged except the test quote rows you created and removed.
- [ ] **Step 4** — Rehearse rollback **now** on production while stakes are lowest: Admin → **Dry run (no changes)** must pass with the baseline quote count.

**Rollback:** if quotes were added/edited by the new frontend, run the Task 6 runbook (same passphrase is fine) before switching `current` back to `a1bb840`; otherwise switch immediately with the Task 6 step 7 command.

### Task 11: Prepare and enroll (vault `preparing`)

- [ ] **Step 1** — Admin: download encrypted backup, prepare migration (vault → `preparing`); members keep using the shared key.
- [ ] **Step 2** — Each member enrolls (remembered device or passkey), confirms the recovery phrase, and keeps the app open until readiness shows no blockers (`missing_device_wrapper` clears after the device unlocks once).
- [ ] **Step 3** — Admin stages quotes and wrappers; coverage must show zero blockers; fingerprint unchanged (staging writes only copy tables).

**Rollback:** Admin → cancel preparation (abandon). Quotes were never modified; vault returns to `legacy`.

### Task 12: Activate, verify, finalize (explicit approval)

- [ ] **Step 1** — Fingerprint → `fingerprint-2-pre-activation.txt`; Admin dry run passes.
- [ ] **Step 2** — **Ask the operator for explicit approval**, then activate. Vault enters `maintenance`; writes pause.
- [ ] **Step 3** — The client verifies every quote decrypts under the new key (automatic); confirm quote count equals Step 1; unlock on a second device; offline unlock; reconnect sync.
- [ ] **Step 4** — Finalize. Fingerprint → `fingerprint-3-active.txt`: `quote_count` and `id_digest` equal Step 1 (ciphertext digest changes by design).
- [ ] **Step 5** — Admin dry run of **Return to shared vault key** passes on the active vault (proves the any-time rollback works on real data). Record the result.

**Rollback:** before finalize → rollback (restores exact source rows). After finalize, at any time → Task 6 runbook.

### Task 13: Post-cutover retention

- [ ] Keep release `a1bb840…`, the Task 7 dump, the encrypted exports, and all fingerprint files for at least 30 days.
- [ ] After 7 days, confirm `purge_expired_vault_rollback` ran and the active generation still reads; rerun the dry run.
- [ ] `/pages/quotevault` is unserved; leave it untouched unless the operator asks to remove it.
