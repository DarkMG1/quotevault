# QuoteVault Device Envelope Encryption Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace repeated shared-key entry with reviewed per-device envelope encryption, personal recovery, 30-day offline authorization, safe member removal, and verified in-place migration without exposing quote plaintext to the server.

**Architecture:** Preserve the existing Supabase Auth allowlist, singleton vault revision lock, encrypted quote rows, Dexie queue, and React providers. Add a random vault master key wrapped to approved device and recovery public keys, device-bound RPC authorization, signed offline leases, and staged generation activation with inaccessible rollback ciphertext. Legacy mode remains live until every member enrolls and an administrator explicitly performs the separately verified cutover.

**Tech Stack:** React 19, TypeScript 5.9, Vite PWA, native Web Crypto/WebAuthn, Dexie 4, Supabase PostgreSQL/RLS/RPC/Edge Functions, Node test runner, PostgreSQL test scripts, Playwright.

**Spec:** `docs/superpowers/specs/2026-09-22-device-envelope-encryption-design.md`

## Global Constraints

- Ponytail full mode applies to every task and review: reuse existing code and platform primitives, keep the smallest secure diff, and add no speculative abstraction.
- Current Safari, Chrome, Edge, and Firefox on iPhone, iPad, Android, macOS, Windows, and Linux are the supported browser floor.
- Supabase, the VPS, database administrators, logs, analytics, the service worker, and notifications must never persist or log quote plaintext, recovery phrases, raw private keys, raw vault keys, or raw device authorization tokens. A raw device token exists transiently in an authenticated TLS request and database function argument only long enough to verify its digest, then is discarded.
- Use native Web Crypto and WebAuthn for cryptography. The only permitted new runtime dependency is `qrcode` for generating an approval URL as a QR image because the browser platform has no QR-generation API; native phone cameras open the URL, so do not add a scanner dependency.
- Keep the existing sync queue, batching, revision checks, operation receipts, and full-snapshot reconciliation. Do not create a second synchronization engine.
- Keep the existing encrypted-Dexie model: stored `Quote` and queued INSERT records contain ciphertext and public synchronization metadata; decrypted display objects remain in React memory only and are cleared on lock.
- The offline authorization lease lasts exactly 30 days and remains a product control, not a remote-wipe claim.
- Keep legacy unlock and legacy RPC authorization available only while `vault_state.envelope_status` is `legacy` or `preparing`; permanently disable that path at cutover.
- Never reuse the destructive `rotate_vault` RPC for retained-history migration or rotation.
- Every behavior change follows red-green-refactor: add the focused failing test, run it and confirm the expected failure, implement the minimum code, then run the focused and full project suites.
- Production cutover is not part of code deployment. Code and additive migrations must be safe in legacy mode until member enrollment and a separate destructive-operation approval.

## Review Focus

- A wrong, cross-account, expired, or revoked device must receive no vault snapshot, wrapper, edit result, import result, or lease; Tasks 2, 4, and 7 test every RPC family.
- Clearing browser site data must restore a PRF-protected device only with the recorded credential, while a remembered-device key is irrecoverably lost locally; Tasks 3 and 5 test both paths.
- A foreground tab must lock at the exact lease expiry and an expired active device must renew online without re-enrollment; Tasks 4 and 6 cover both boundaries.
- Old-generation queued work must convert atomically for retained members and remain rejected for removed members without losing or duplicating operations; Task 9 covers insert, delete, retry, and crash boundaries.
- Interrupted staging, incomplete IDs, changed source revision, missing wrappers, failed post-activation verification, and rollback must leave one complete authoritative generation; Task 8 covers each invariant.

## Parallel Execution Contract

Tasks 1 and 2 may run concurrently in separate worktrees because they share no production files. Their commits are reviewed independently and cherry-picked into the integration worktree in task order. Tasks 3 and 4 may then run concurrently after Tasks 1 and 2 are integrated. All later tasks run in order because they share RPC, provider, and UI interfaces. No agent edits another agent's worktree, and the controller reviews every diff and verification report before integration.

Use `gpt-5.6-luna` for bounded client and test work, `gpt-5.6-terra` or `gpt-5.6-sol` for cryptography, SQL, and integration work, and `gpt-6-astra` only for the final whole-branch security review. Every agent prompt repeats the Ponytail full constraint. Model cost never reduces the controller's required diff review, test replay, or public-safety check.

### Task 1: Native envelope cryptography

**Files:**
- Create: `src/lib/device-crypto.ts`
- Create: `tests/device-crypto.test.mjs`
- Modify: `src/lib/crypto.ts`
- Modify: `src/types/index.ts`

**Interfaces:**
- Consumes: native `crypto.subtle`; existing `EncryptedPayload`, base64 conversion, and legacy PBKDF2 helpers from `src/lib/crypto.ts`.
- Produces:
  - `generateVaultMasterKey(): Uint8Array`
  - `deriveQuoteKey(masterKey: Uint8Array, generation: string): Promise<CryptoKey>`
  - `encryptEnvelope(plaintext: string, key: CryptoKey, aad: string): Promise<EnvelopeCiphertext>`
  - `decryptEnvelope(payload: EnvelopeCiphertext, key: CryptoKey, aad: string): Promise<string>`
  - `generateWrappingKeyPair(): Promise<CryptoKeyPair>`
  - `fingerprintPublicJwk(jwk: JsonWebKey): Promise<string>`
  - `wrapVaultKey(input: VaultKeyWrapperPlaintext, publicKey: CryptoKey): Promise<string>`
  - `unwrapVaultKey(ciphertext: string, privateKey: CryptoKey, expected: VaultKeyWrapperBinding): Promise<Uint8Array>`
  - `generateAuthorizationToken(): string`
  - `digestAuthorizationToken(token: string): Promise<string>`
  - `deriveRecoveryBundleKey(phrase: string, kdf: RecoveryKdf): Promise<CryptoKey>`
  - `encryptPrivateBundle(bundle: PrivateDeviceBundle, key: CryptoKey, binding: BundleBinding): Promise<EnvelopeCiphertext>`
  - `decryptPrivateBundle(payload: EnvelopeCiphertext, key: CryptoKey, binding: BundleBinding): Promise<PrivateDeviceBundle>`
  - `DeviceLeaseClaims` and `DeviceLease` serializable types used by later storage and verification tasks.

- [ ] **Step 1: Write failing envelope tests**

Create tests using Node's `webcrypto` that demand deterministic binding and tamper rejection:

```js
test('quote keys and ciphertext are bound to their generation and record', async () => {
  const master = cryptoApi.generateVaultMasterKey();
  const key = await cryptoApi.deriveQuoteKey(master, GENERATION_A);
  const encrypted = await cryptoApi.encryptEnvelope('private', key, `quote:q1:${GENERATION_A}`);
  assert.equal(await cryptoApi.decryptEnvelope(encrypted, key, `quote:q1:${GENERATION_A}`), 'private');
  await assert.rejects(cryptoApi.decryptEnvelope(encrypted, key, `quote:q2:${GENERATION_A}`));
  await assert.rejects(cryptoApi.decryptEnvelope(encrypted, key, `quote:q1:${GENERATION_B}`));
});

test('a wrapped vault key validates its target and generation', async () => {
  const pair = await cryptoApi.generateWrappingKeyPair();
  const publicJwk = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
  const fingerprint = await cryptoApi.fingerprintPublicJwk(publicJwk);
  const masterKey = cryptoApi.generateVaultMasterKey();
  const wrapped = await cryptoApi.wrapVaultKey({
    version: 1, vaultId: 'quotevault', generation: GENERATION_A,
    targetFingerprint: fingerprint, masterKey,
  }, pair.publicKey);
  assert.deepEqual(await cryptoApi.unwrapVaultKey(wrapped, pair.privateKey, {
    vaultId: 'quotevault', generation: GENERATION_A, targetFingerprint: fingerprint,
  }), masterKey);
  await assert.rejects(cryptoApi.unwrapVaultKey(wrapped, pair.privateKey, {
    vaultId: 'quotevault', generation: GENERATION_B, targetFingerprint: fingerprint,
  }));
});
```

Also test RSA-OAEP parameters, JWK fingerprint stability across property order and irrelevant fields, rejection of malformed/noncanonical JWK values, exact 32-byte authorization-token entropy/encoding, token digest stability without raw-token leakage, PBKDF2 bounds at 600,000 iterations, private-bundle AAD mismatch, malformed base64, and zero-length/wrong-length master keys.

- [ ] **Step 2: Run the test and verify RED**

Run: `node --test tests/device-crypto.test.mjs`

Expected: FAIL because `src/lib/device-crypto.ts` and its exports do not exist.

- [ ] **Step 3: Implement the minimum native crypto module**

Use these exact public types and constants:

```ts
export interface EnvelopeCiphertext { version: 2; iv: string; data: string }
export interface RecoveryKdf { version: 1; salt: string; iterations: 600000 }
export interface BundleBinding {
  accountId: string; recordId: string; publicKeyFingerprint: string;
  protectionMode: 'passkey-prf' | 'remembered' | 'recovery'; version: 1;
}
export interface PrivateDeviceBundle { version: 1; privateJwk: JsonWebKey; authorizationToken: string }
export interface VaultKeyWrapperBinding { vaultId: 'quotevault'; generation: string; targetFingerprint: string }
export interface VaultKeyWrapperPlaintext extends VaultKeyWrapperBinding { version: 1; masterKey: Uint8Array }
export type DeviceLeaseClaims = readonly [1, string, string, string, number, number, string];
export interface DeviceLease { version: 1; claims: DeviceLeaseClaims; signature: string }
export const RECOVERY_ITERATIONS = 600_000;
```

Generate RSA-OAEP with `{ name: 'RSA-OAEP', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }`. Encode AAD as a JSON array of fixed-position primitive fields, never a property-order-dependent object. Export the existing base64 helpers from `crypto.ts` rather than duplicate them. Zero temporary `Uint8Array` master-key copies in `finally` blocks where ownership permits.

Fingerprint only validated public-key material. Require `kty='RSA'`, a canonical unpadded base64url 3072-bit modulus, and exponent `AQAB`; decode and re-encode `n` and `e`, then hash the UTF-8 JSON tuple `[1,'RSA-OAEP','SHA-256',n,e]` with SHA-256 and return unpadded base64url. Generate authorization tokens with `crypto.getRandomValues(new Uint8Array(32))`, encode them as canonical unpadded base64url, and digest the decoded bytes rather than the text representation.

- [ ] **Step 4: Verify GREEN and regression safety**

Run:

```bash
node --test tests/device-crypto.test.mjs
npm test
npm run lint
npm run build
```

Expected: all commands exit 0 with no test failures or lint errors.

- [ ] **Step 5: Commit**

```bash
git add src/lib/crypto.ts src/lib/device-crypto.ts src/types/index.ts tests/device-crypto.test.mjs
git commit -m "Add native device envelope cryptography"
```

### Task 2: Additive device and enrollment database foundation

**Files:**
- Create: `supabase/migrations/20260922020000_envelope_foundation.sql`
- Create: `tests/database-envelope.sql`
- Modify: `scripts/test-database.sh`

**Interfaces:**
- Consumes: `qv_is_member`, `qv_is_admin`, `qv_valid_quote`, `vault_state`, `vault_operation_receipts`, and the lock order established by existing migrations.
- Produces: additive envelope tables, strict validators, `qv_authorize_device`, `request_device`, `approve_device`, `complete_device`, `list_own_devices`, `revoke_own_device`, and preparation-safe `vault_state.envelope_status`.

- [ ] **Step 1: Write failing database security tests**

Add a fresh disposable database sequence to `scripts/test-database.sh`, apply all current migrations plus the new migration, and execute `tests/database-envelope.sql`. The test must attempt and reject:

```sql
-- No direct ciphertext enumeration after envelope activation.
set local role authenticated;
select set_config('request.jwt.claim.sub', :'member_id', true);
do $$ begin
  begin
    perform * from public.quotes;
    raise exception 'direct quote select bypassed device authorization';
  exception when insufficient_privilege then null;
  end;
end $$;

-- Wrong token, cross-account device, revoked device, expired pending request,
-- replayed approval, changed fingerprint, and wrapper-generation mismatch all fail.
```

The same file must prove legacy-mode `sync_quotes` remains callable before cutover, pending rows expose no wrapper, and an approval transaction either activates the device and stores exactly one wrapper or changes nothing.

- [ ] **Step 2: Run the database test and verify RED**

Run: `PGHOST=127.0.0.1 PGPORT=5432 PGUSER="$USER" npm run test:database`

Expected: FAIL because the envelope migration/tables/RPCs do not exist.

- [ ] **Step 3: Implement the additive schema**

Extend `vault_state` with:

```sql
alter table public.vault_state
  add column if not exists envelope_status text not null default 'legacy'
    check (envelope_status in ('legacy','preparing','staging','active','maintenance')),
  add column if not exists prepared_generation uuid,
  add column if not exists active_migration_id uuid;
```

Create only these tables and relationships:

- `vault_devices(id, owner_id, status, request_kind, expires_at, enrollment_fingerprint, public_jwk, public_key_fingerprint, authorization_token_digest, label, protection_mode, protection, encrypted_private_bundle, approved_by_device_id, created_at, last_sync_at, lease_expires_at, revoked_at)`; combine pending approvals into `status='pending'` instead of adding another request table.
- `vault_device_wrappers(device_id, generation, purpose, wrapped_key, created_by_device_id, created_at)` with primary key `(device_id,generation,purpose)`.
- `vault_recovery_keys(id, owner_id, status, public_jwk, public_key_fingerprint, encrypted_private_key, kdf, created_at, confirmed_at, revoked_at)` and `vault_recovery_wrappers(recovery_key_id,generation,wrapped_key,created_by_device_id,created_at)`.
- `vault_recovery_challenges(id,recovery_key_id,expected_digest,expires_at,used_at,created_at)`; ciphertext is produced by the trusted Edge Function and is not stored.
- `vault_migrations(id,source_generation,target_generation,target_verifier,source_revision,expected_quote_count,status,initiating_device_id,prepared_at,activated_at,rollback_expires_at)`.
- `vault_migration_quote_copies(migration_id,copy_kind,quote_id,encrypted_row,vault_generation)` with primary key `(migration_id,copy_kind,quote_id)` and `copy_kind in ('staged','rollback')`. `encrypted_row` is a size-bounded JSON copy of the server's ciphertext row and public synchronization metadata; it must pass the encrypted-quote validator and cannot contain decrypted text, authors, context, sender, or provenance.
- `vault_security_events(id,event_type,actor_id,affected_owner_id,affected_device_id,result,reason_code,metadata,created_at)` with enumerated event/result/reason values and bounded metadata.

Cap JWK/protection/wrapper JSON at 32 KiB, encrypted private bundles at 64 KiB, labels at 100 characters, and approval expiry at ten minutes. All foreign keys use explicit deletion behavior; wrapper and pending-request rows cascade with their device/recovery owner, while audit records retain nullable identifiers.

`qv_authorize_device` must lock `vault_state` first and the device row second, strictly decode the supplied canonical unpadded-base64url token to exactly 32 bytes, hash those bytes with SHA-256, compare the stored digest, verify owner/membership/status/generation, and return only IDs plus safe state. It accepts expired leases only for the lease-renewal operation. Keep legacy RPC behavior gated on `envelope_status in ('legacy','preparing')`.

The approval RPC must atomically bind request ID, account, public JWK fingerprint, authorization-token digest, protection parameters, active wrapper, and approver. `complete_device` must hash the raw token before returning the device's own encrypted wrapper metadata.

- [ ] **Step 4: Verify GREEN, reapplication, and legacy compatibility**

Run the focused database suite twice against a fresh database so `create or replace`, grants, triggers, and policies are idempotent. Then run `npm run test:database`.

Expected: all SQL scripts complete with `ON_ERROR_STOP=1`; legacy database tests still pass.

- [ ] **Step 5: Commit**

```bash
git add supabase/migrations/20260922020000_envelope_foundation.sql tests/database-envelope.sql scripts/test-database.sh
git commit -m "Add envelope device authorization schema"
```

### Task 3: Local device storage and RPC client

**Files:**
- Create: `src/lib/device.ts`
- Create: `tests/device.test.mjs`
- Modify: `src/lib/db.ts`
- Modify: `src/types/index.ts`

**Interfaces:**
- Consumes: Task 1 crypto functions and Task 2 RPC names.
- Consumes: `DeviceLeaseClaims` and `DeviceLease` from Task 1.
- Produces: `DeviceLocalState`, Dexie version 3 `deviceState` table, `requestDevice`, `approveDevice`, `completeDevice`, `listOwnDevices`, `revokeOwnDevice`, `saveDeviceState`, `loadDeviceState`, and `deleteDeviceState`.

- [ ] **Step 1: Write failing storage and RPC tests**

Test one record per account, non-extractable remembered key round-trip, account isolation, malformed server response rejection, approval parameter names, and deletion:

```js
test('device completion stores only encrypted material and a non-extractable remembered key', async () => {
  const state = await device.completeDevice('account-a', 'device-a', rawToken, rememberedKey);
  assert.equal(state.accountId, 'account-a');
  assert.equal(state.rememberedKey.extractable, false);
  assert.equal(JSON.stringify(state).includes(rawToken), false);
  assert.equal(await device.loadDeviceState('account-b'), null);
});
```

- [ ] **Step 2: Run the test and verify RED**

Run: `node --test tests/device.test.mjs`

Expected: FAIL because `src/lib/device.ts` and Dexie version 3 do not exist.

- [ ] **Step 3: Implement one local state record and thin RPC functions**

Add this serializable boundary:

```ts
export interface DeviceLocalState {
  accountId: string;
  deviceId: string;
  protectionMode: 'passkey-prf' | 'remembered';
  protection: Record<string, unknown>;
  encryptedPrivateBundle: EnvelopeCiphertext;
  rememberedKey?: CryptoKey;
  lease?: DeviceLease;
  wrapper?: { generation: string; wrappedKey: string };
}
```

The raw token exists only inside the encrypted private bundle and in a local function variable while calling an RPC. Keep RPC wrappers one function each; parse all JSON responses before storage. `deleteDeviceState` deletes only that account's record unless the caller explicitly selects complete local wipe.

- [ ] **Step 4: Verify GREEN and the full suite**

Run:

```bash
node --test tests/device.test.mjs
npm test
npm run lint
npm run build
```

Expected: all commands exit 0.

- [ ] **Step 5: Commit**

```bash
git add src/lib/device.ts src/lib/db.ts src/types/index.ts tests/device.test.mjs
git commit -m "Store encrypted device credentials locally"
```

### Task 4: Recovery protocol and signed 30-day leases

**Files:**
- Create: `supabase/migrations/20260922030000_envelope_recovery.sql`
- Create: `supabase/functions/vault-security/index.ts`
- Create: `src/lib/lease.ts`
- Create: `tests/lease.test.mjs`
- Create: `tests/database-envelope-recovery.sql`
- Modify: `.env.example`
- Modify: `src/vite-env.d.ts`
- Modify: `scripts/check-client-env.mjs`
- Modify: `scripts/test-database.sh`

**Interfaces:**
- Consumes: Tasks 1-2 device authorization and crypto interfaces; Task 3 later stores the resulting lease and device state.
- Produces: `canonicalLeasePayload`, `verifyDeviceLease`, `renew_device_lease`, `create_recovery_key`, `begin_recovery`, `complete_recovery`, `replace_recovery_key`, and Edge Function `vault-security` routes for lease signing and recovery challenge encryption. Reuse `DeviceLeaseClaims` from Task 1 rather than redefining it.

- [ ] **Step 1: Write failing lease and recovery tests**

The Node test generates a temporary ECDSA P-256 pair and proves signature, claim, account, device, generation, and expiry checks. The SQL test proves a 256-bit recovery challenge is single-use, expires, belongs to one account, returns no wrapper before exact challenge response, and cannot replace an active recovery key without device authorization.

```js
test('lease verification rejects another device and the thirty-day boundary', async () => {
  const lease = await signFixture({ issuedAt: NOW, expiresAt: NOW + 30 * DAY, deviceId: 'a' });
  assert.equal(await verifyDeviceLease(lease, PUBLIC_JWK, { now: NOW + 30 * DAY - 1, deviceId: 'a' }), true);
  assert.equal(await verifyDeviceLease(lease, PUBLIC_JWK, { now: NOW + 30 * DAY, deviceId: 'a' }), false);
  assert.equal(await verifyDeviceLease(lease, PUBLIC_JWK, { now: NOW, deviceId: 'b' }), false);
});
```

- [ ] **Step 2: Run focused tests and verify RED**

Run `node --test tests/lease.test.mjs` and the disposable database suite.

Expected: both fail because the lease module, function, and recovery RPCs do not exist.

- [ ] **Step 3: Implement canonical claims and recovery RPCs**

Use one ordered claims tuple shared by browser and Edge Function:

```ts
export const canonicalLeasePayload = (claims: DeviceLeaseClaims) =>
  new TextEncoder().encode(JSON.stringify(claims));
```

The Edge Function authenticates the Supabase bearer session, calls `renew_device_lease` with the device ID and token, signs only the returned claims with an ECDSA P-256 private JWK from `DEVICE_LEASE_PRIVATE_JWK`, and returns claims plus base64 signature. It never logs the body. The browser validates `VITE_DEVICE_LEASE_PUBLIC_JWK` during build, pins that public JWK, and rejects invalid, future-issued, wrong-target, wrong-generation, or expired claims.

PostgreSQL cannot encrypt RSA-OAEP JWKs directly. A service-role-only internal RPC generates the random 256-bit recovery challenge, stores its digest and expiry, and returns the plaintext challenge plus recovery public JWK only to the trusted Edge Function. The function encrypts the challenge with native Web Crypto and returns ciphertext to the authenticated member. `complete_recovery` hashes the member's decrypted response, consumes the exact unexpired challenge in one transaction, and releases only that member's encrypted recovery wrapper. The internal RPC is revoked from `public`, `anon`, and `authenticated`.

- [ ] **Step 4: Verify GREEN**

Run:

```bash
node --test tests/lease.test.mjs
npm run test:database
npm test
npm run lint
npm run build
```

Expected: all commands exit 0.

- [ ] **Step 5: Commit**

```bash
git add supabase/migrations/20260922030000_envelope_recovery.sql supabase/functions/vault-security/index.ts src/lib/lease.ts tests/lease.test.mjs tests/database-envelope-recovery.sql .env.example src/vite-env.d.ts scripts/check-client-env.mjs scripts/test-database.sh
git commit -m "Add recovery proof and signed device leases"
```

### Task 5: Device enrollment, passkey, recovery, and lock UI

**Files:**
- Create: `src/components/VaultGate.tsx`
- Create: `src/components/DeviceSecurity.tsx`
- Create: `src/lib/recovery-phrase.ts`
- Create: `tests/recovery-phrase.test.mjs`
- Modify: `src/lib/device.ts`
- Modify: `src/hooks/useCrypto.tsx`
- Modify: `src/components/Profile.tsx`
- Modify: `src/components/Admin.tsx`
- Modify: `src/components/Layout.tsx`
- Modify: `tests/ui.test.mjs`
- Modify: `tests/browser-server.mjs`
- Modify: `tests/browser/vault.spec.ts`
- Modify: `package.json`
- Modify: `package-lock.json`

**Interfaces:**
- Consumes: Tasks 1-4 crypto, storage, device RPC, recovery, and lease interfaces.
- Produces: an envelope-aware `CryptoContext` with in-memory master/quote keys, device auth accessor, enrollment/recovery actions, immediate lock, lease timer, and device settings UI.

- [ ] **Step 1: Write failing state-machine and UI tests**

Test these explicit states: `legacy-locked`, `pending-approval`, `recovery-setup`, `device-locked`, `unlocked`, and `lease-expired`. Assert that quote children never render until a valid wrapper and lease produce a quote key. Add browser tests for remembered enrollment, code mismatch, approval replay, immediate lock, and local site-data deletion.

```js
assert.equal(find(tree, node => node.props?.children === 'Remember this device') !== null, true);
await click('Lock vault');
assert.equal(page.getByRole('heading', { name: 'Vault locked' }).isVisible(), true);
```

- [ ] **Step 2: Run focused tests and verify RED**

Run: `node tests/ui.test.mjs` and `npx playwright test tests/browser/vault.spec.ts`.

Expected: FAIL because envelope enrollment and device UI are absent.

- [ ] **Step 3: Implement the minimum gate and settings surfaces**

Keep `useCrypto.tsx` responsible for key lifecycle and move rendering into `VaultGate.tsx`. The context must expose:

```ts
interface CryptoContextType {
  encryptionKey: CryptoKey | null;
  vaultGeneration: string | null;
  deviceId: string | null;
  leaseExpiresAt: number | null;
  getDeviceAuthorization(): Promise<{ deviceId: string; token: string }>;
  lockVault(): void;
  forgetDevice(): Promise<void>;
}
```

For passkeys, store credential ID, 32-byte PRF salt, RP ID `quotes.darkmg1.dev`, and authenticated protection parameters; require user verification. Use a fresh local challenge for offline PRF unlock and server challenges for registration/restoration. If PRF is unavailable or cancelled, offer remembered-device, personal recovery, or admin assistance without silently downgrading.

Generate recovery phrases from a checked-in fixed 256-word unique list using 16 independent random bytes, one word per byte. Confirm three randomly selected positions before saving the encrypted recovery private key. Never log or persist the phrase.

Install `qrcode` and its development-only `@types/qrcode` types only for rendering `https://quotes.darkmg1.dev/#approve?request=<uuid>&fingerprint=<encoded>`; the short code is derived from the same enrollment fingerprint. Do not add camera/scanner code.

Place Lock in `Layout`, own-device/recovery management in `Profile` through `DeviceSecurity`, and pending approval in `Admin`. Remove the old destructive rotation form from the user flow but retain legacy initialization until migration.

- [ ] **Step 4: Verify GREEN and browser storage safety**

Run:

```bash
node --test tests/recovery-phrase.test.mjs
node tests/ui.test.mjs
npm test
npm run lint
npm run build
npm run test:browser
```

Inspect IndexedDB assertions to confirm only encrypted bundles, non-extractable remembered keys, signed leases, wrappers, and ciphertext appear. Confirm Cache Storage contains no device key, token, phrase, wrapper plaintext, or quote plaintext.

- [ ] **Step 5: Commit**

```bash
git add src/components/VaultGate.tsx src/components/DeviceSecurity.tsx src/lib/recovery-phrase.ts src/hooks/useCrypto.tsx src/components/Profile.tsx src/components/Admin.tsx src/components/Layout.tsx tests package.json package-lock.json
git commit -m "Add device enrollment and recovery interface"
```

### Task 6: Generation-bound quote payloads

**Files:**
- Create: `src/lib/quote-crypto.ts`
- Create: `tests/quote-crypto.test.mjs`
- Modify: `src/components/AddQuote.tsx`
- Modify: `src/components/ui.ts`
- Modify: `src/lib/quote-edit.ts`
- Modify: `src/lib/quote-import.ts`
- Modify: `tests/import.test.mjs`
- Modify: `tests/ui.test.mjs`

**Interfaces:**
- Consumes: Task 1 `deriveQuoteKey`, envelope AES-GCM, and the current encrypted quote bundle shape.
- Produces: `encryptQuoteRecord(privateFields, visibleFields, key)` and `decryptQuoteRecord(storedQuote, key)` with AAD and visible-metadata comparison; legacy ciphertext remains readable only during migration.

- [ ] **Step 1: Write failing quote-envelope tests**

Test ID, generation, creator, creation time, and quote-date mismatch rejection; complete private field preservation; legacy read compatibility; v2 write output under the existing `$$E2E$$` sentinel; and that every Dexie quote/queued INSERT remains ciphertext after display decryption and after Lock clears the in-memory display list.

```js
const stored = await encryptQuoteRecord(privateFields, visibleFields, quoteKey);
await assert.rejects(decryptQuoteRecord({ ...stored, id: OTHER_ID }, quoteKey), /authenticated metadata/);
await assert.rejects(decryptQuoteRecord({ ...stored, quote_date: '2030-01-01' }, quoteKey), /authenticated metadata/);
```

- [ ] **Step 2: Run focused tests and verify RED**

Run: `node --test tests/quote-crypto.test.mjs`

Expected: FAIL because the module is absent.

- [ ] **Step 3: Implement one shared quote encryption path**

Use a fixed AAD tuple `[2, id, vault_generation, user_id, created_at, quote_date ?? null]`. Include the same values inside the encrypted JSON and reject any mismatch after decryption. Route Add, display, admin edit, and import through this module so no caller constructs the sentinel or AAD independently. Retain the current legacy decrypt branch without allowing new legacy writes after envelope activation. Preserve the current storage boundary: `db.quotes` and queued INSERT payloads receive the stored ciphertext record, while decrypted copies exist only in component state.

- [ ] **Step 4: Verify GREEN**

Run:

```bash
node --test tests/quote-crypto.test.mjs
npm test
npm run lint
npm run build
```

Expected: all commands exit 0.

- [ ] **Step 5: Commit**

```bash
git add src/lib/quote-crypto.ts tests/quote-crypto.test.mjs src/components/AddQuote.tsx src/components/ui.ts src/lib/quote-edit.ts src/lib/quote-import.ts tests/import.test.mjs tests/ui.test.mjs
git commit -m "Bind encrypted quotes to record metadata"
```

### Task 7: Device-authorized synchronization, edits, imports, and membership

**Files:**
- Create: `supabase/migrations/20260922040000_envelope_device_auth.sql`
- Create: `tests/database-envelope-auth.sql`
- Modify: `src/lib/vault.ts`
- Modify: `src/lib/sync.ts`
- Modify: `src/lib/quote-edit.ts`
- Modify: `src/lib/quote-import.ts`
- Modify: `src/hooks/useQuotes.tsx`
- Modify: `src/components/Admin.tsx`
- Modify: `tests/vault.test.mjs`
- Modify: `tests/sync.test.mjs`
- Modify: `tests/import.test.mjs`
- Modify: `tests/browser-server.mjs`
- Modify: `scripts/test-database.sh`

**Interfaces:**
- Consumes: Task 2 authorization helper, Task 3 auth accessor, Task 4 lease endpoint, and Task 6 quote envelope.
- Produces: device arguments on every protected RPC; RPC-only member listing/add/removal; no direct quote or allowlist table bypass after envelope activation.

- [ ] **Step 1: Write failing RPC and client tests**

For `get_vault_state`, `sync_quotes`, `checked_import`, `edit_quote`, and `edit_quotes`, test missing token, wrong token, another member's device, revoked device, expired lease, stale generation, and valid renewal. Test that authorization happens before a snapshot or row is returned. Test legacy null-device calls only in legacy/preparing mode. Preserve and test both existing sync entry points: automatic sync on reconnect/session restore/visibility return and the visible **Sync now** action, including pending count, last-success time, actionable failure, and lease renewal.

Client tests must assert these exact added arguments:

```js
assert.equal(call.p_device_id, 'device-a');
assert.equal(call.p_device_token, rawToken);
assert.equal(JSON.stringify(call).includes('quote plaintext'), false);
```

- [ ] **Step 2: Run focused tests and verify RED**

Run `node tests/sync.test.mjs`, `node --test tests/vault.test.mjs tests/import.test.mjs`, and the database suite.

Expected: FAIL because the clients and RPC signatures do not require device authorization.

- [ ] **Step 3: Replace RPCs while reusing their current bodies**

Add `p_device_id uuid default null` and `p_device_token text default null` to the current state/sync/import/edit RPCs. At the top, branch only on server `envelope_status`: legacy/preparing reuses membership authorization; staging/active/maintenance calls `qv_authorize_device` before reading any quote or wrapper. Preserve current validators, receipts, request-size caps, lock order, conflict messages, and revision behavior.

Add `list_members`, `add_member`, and non-rotating `remove_member_access` RPCs. Change Admin to use them. Replace direct quote and allowlist policies with policies that permit the legacy access pattern only while `envelope_status in ('legacy','preparing')`; active envelope mode is RPC-only. Remove quotes from realtime publication because the client already uses private generation broadcasts and authorized snapshots.

The client obtains the raw token only by decrypting its local private bundle, passes it into the request, and drops the local variable after completion. Error and retry paths never serialize it. Reuse the existing `useQuotes` triggers and `Feed` **Sync now** control; do not add another timer, queue, or sync button.

- [ ] **Step 4: Verify GREEN and denial behavior**

Run:

```bash
npm run test:database
npm test
npm run lint
npm run build
npm run test:browser
```

Expected: all commands exit 0; denial tests observe no ciphertext snapshot.

- [ ] **Step 5: Commit**

```bash
git add supabase/migrations/20260922040000_envelope_device_auth.sql tests/database-envelope-auth.sql src/lib/vault.ts src/lib/sync.ts src/lib/quote-edit.ts src/lib/quote-import.ts src/hooks/useQuotes.tsx src/components/Admin.tsx tests scripts/test-database.sh
git commit -m "Require device authorization for vault data"
```

### Task 8: Prepared migration, staging, activation, and rollback

**Files:**
- Create: `supabase/migrations/20260922050000_envelope_migration.sql`
- Create: `src/lib/vault-migration.ts`
- Create: `tests/vault-migration.test.mjs`
- Create: `tests/database-envelope-migration.sql`
- Modify: `src/components/Admin.tsx`
- Modify: `tests/browser-server.mjs`
- Modify: `tests/browser/vault.spec.ts`
- Modify: `scripts/test-database.sh`

**Interfaces:**
- Consumes: approved device/recovery wrappers, v2 quote encryption, device auth, singleton revision lock.
- Produces: `prepare_envelope_migration`, `stage_envelope_quotes`, `activate_envelope_migration`, `rollback_envelope_migration`, `finalize_envelope_migration`, and `runEnvelopeMigration`.

- [ ] **Step 1: Write failing migration invariant tests**

Database tests must prove changed source revision, incomplete/extra quote IDs, missing device/recovery wrappers, non-admin device, expired request, replayed batch, and tampered target generation cannot activate. They must prove activation snapshots source rows, replaces all rows and generation in one transaction, remains in maintenance, and rollback restores byte-identical rows/state before writes resume.

Client tests use three encrypted fixtures including multiline dialogue, multiple authors, context, source sender, import ID, date, and timestamps. Compare every decrypted field before and after staging. Database tests also prove rollback is refused after expiry and `purge_expired_vault_rollback` deletes expired ciphertext copies and clears obsolete migration pointers.

- [ ] **Step 2: Run focused tests and verify RED**

Run `node --test tests/vault-migration.test.mjs` and the database suite.

Expected: FAIL because migration RPCs and client orchestration are absent.

- [ ] **Step 3: Implement the staged migration state machine**

Use exactly these client states: `prepared`, `staging`, `ready`, `activated-maintenance`, `active`, `rolled-back`, `abandoned`. Upload at most 50 encrypted quote copies per idempotent batch. The activation RPC locks `vault_state`, migration, devices, and quote set in that order; rechecks source generation/revision, exact ID set, expected count, and wrapper coverage; copies source rows to `copy_kind='rollback'`; replaces active ciphertext; changes generation/revision; and leaves maintenance enabled.

After activation, the admin client fetches and decrypt-compares every active row. Success calls finalize to release maintenance; failure calls rollback while no writes are accepted. Server rollback copies are inaccessible to ordinary clients and are deleted at acceptance or after seven days. Add `purge_expired_vault_rollback`, refuse rollback at or after `rollback_expires_at`, and idempotently schedule the purge with Supabase's native `pg_cron`; make `pg_cron` an explicit production prerequisite and test the cleanup function directly in disposable PostgreSQL. The downloaded encrypted export remains separate disaster-recovery evidence.

Admin UI shows enrollment coverage, empty-queue reports, progress, verification count, and the exact blocking reason. It never offers activation until every allowlisted member has an approved device, confirmed recovery key, and recent queue report.

- [ ] **Step 4: Verify GREEN and resumability**

Run the focused tests, interrupt a browser staging run after one batch, resume it, then run `npm run test:database`, `npm test`, `npm run lint`, `npm run build`, and `npm run test:browser`.

Expected: all commands exit 0 and resume uploads no duplicate rows.

- [ ] **Step 5: Commit**

```bash
git add supabase/migrations/20260922050000_envelope_migration.sql src/lib/vault-migration.ts tests/vault-migration.test.mjs tests/database-envelope-migration.sql src/components/Admin.tsx tests/browser-server.mjs tests/browser/vault.spec.ts scripts/test-database.sh
git commit -m "Add verified envelope migration cutover"
```

### Task 9: Queued-operation conversion and retained-history rotation

**Files:**
- Create: `supabase/migrations/20260922060000_envelope_rotation.sql`
- Create: `tests/database-envelope-rotation.sql`
- Modify: `src/lib/sync.ts`
- Modify: `src/hooks/useQuotes.tsx`
- Modify: `src/components/Admin.tsx`
- Modify: `tests/sync.test.mjs`
- Modify: `tests/browser-server.mjs`
- Modify: `tests/browser/vault.spec.ts`
- Modify: `scripts/test-database.sh`

**Interfaces:**
- Consumes: Task 8 staged migration machinery and Task 6 quote encryption.
- Produces: `convertQueuedOperations`, conversion-only wrapper fetch/acknowledgment, secure member removal choice, and retained-history rotation through the same staging engine.

- [ ] **Step 1: Write failing conversion tests**

Test old insert and delete conversion, the unknown-browser one-time group-key path, cancellation before local replacement, retry idempotency, empty-queue acknowledgment, abandoned device revocation, and removed-member rejection. The key invariant is:

```js
await assert.rejects(syncOldOperationDirectly(oldOperation), /migration required/);
await convertQueuedOperations(context);
assert.equal(await queue.has(oldOperation.operation_id), false);
assert.equal((await queue.pendingFor(newGeneration)).length, 1);
assert.deepEqual(await decryptConverted(), originalPrivatePayload);
```

- [ ] **Step 2: Run focused tests and verify RED**

Run `node tests/sync.test.mjs` and the database suite.

Expected: FAIL because conversion-only wrappers and atomic local conversion are absent.

- [ ] **Step 3: Implement conversion and rotation with existing primitives**

For retained devices, keep the old wrapper with `purpose='conversion_only'`; it cannot authorize an old-generation server write or snapshot. Perform Web Crypto work before opening a Dexie transaction. Then open one short transaction, re-read and verify the unchanged source operation, write the prepared new-generation operation, and delete the old item atomically. A crash before the transaction leaves only the old item; a committed transaction leaves only the new one. Replays use the existing operation receipt behavior. Delete the conversion wrapper after the device reports an empty converted queue or is revoked.

For an unknown legacy browser without a device wrapper, leave the old operation untouched until the updated client asks once for the old group key. Use the legacy decrypt path locally, create the active-generation ciphertext, atomically replace the queue entry as above, and discard the group key from memory. Cancellation or a wrong key preserves the blocked legacy item for retry; neither path can submit an old-generation write.

Member removal always revokes allowlist access, devices, active/conversion wrappers, recovery keys, pending requests, and sessions in one state-then-device lock order. **Remove access** retains generation; **Remove and rotate encryption** invokes the Task 8 staging engine for remaining members. Removed-member pending work never enters the vault.

- [ ] **Step 4: Verify GREEN**

Run `npm run test:database`, `npm test`, `npm run lint`, `npm run build`, and `npm run test:browser`.

Expected: all commands exit 0.

- [ ] **Step 5: Commit**

```bash
git add supabase/migrations/20260922060000_envelope_rotation.sql tests/database-envelope-rotation.sql src/lib/sync.ts src/hooks/useQuotes.tsx src/components/Admin.tsx tests/sync.test.mjs tests/browser-server.mjs tests/browser/vault.spec.ts scripts/test-database.sh
git commit -m "Convert queued work across vault rotations"
```

### Task 10: Operations, browser matrix, and public-safety verification

**Files:**
- Modify: `README.md`
- Modify: `docs/operations.md`
- Modify: `docs/database-prerequisites.md`
- Modify: `vite.config.ts`
- Modify: `tests/browser/auth-recovery.spec.ts`
- Modify: `tests/browser/edit.spec.ts`
- Modify: `tests/browser/import.spec.ts`
- Modify: `tests/browser/vault.spec.ts`
- Modify: `tests/browser-server.mjs`

**Interfaces:**
- Consumes: all prior tasks.
- Produces: deployment/runbook steps, lease-key setup/rotation, enrollment and rollback procedures, complete browser smoke coverage, and evidence that no secret is publishable.

- [ ] **Step 1: Add failing end-to-end coverage for omitted flows**

Add deterministic mocked-PRF browser tests for supported and unsupported paths, account-password recovery remaining separate, personal recovery setup/use/replacement, admin recovery, device forget, lease day 29/day 30, edit/import device auth, migration resume/rollback, and service-worker cache inspection.

- [ ] **Step 2: Run browser tests and verify RED**

Run: `npm run test:browser`

Expected: new cases fail until the smoke backend and remaining integration behavior are complete.

- [ ] **Step 3: Complete the fake backend and runbooks**

Document exact commands to apply additive migrations, deploy the Edge Function, set `DEVICE_LEASE_PRIVATE_JWK` without writing it to a file in the repository, publish the matching public JWK, deploy the static app, verify legacy mode, enroll members, download the encrypted backup, stage, activate under maintenance, verify, finalize, and delete rollback data. Include rollback commands and the rule that production activation requires a separate explicit approval.

Keep `vite-plugin-pwa` asset-only caching. Add no worker key handling. Tighten CSP only as required for the Edge Function and same-origin app; do not permit third-party script origins for QR or passkey behavior.

- [ ] **Step 4: Run the complete verification matrix**

Run fresh:

```bash
npm ci
npm test
npm run test:database
npm run lint
npm run build
npm run build:smoke
npm run test:browser
gitleaks detect --no-git --source . --redact --exit-code 1
```

Then manually verify representative iPhone/iPad Safari PWA, Android Chrome/Firefox, macOS Safari/Chrome/Firefox/Edge, Windows Chrome/Firefox/Edge, and Linux Chrome/Firefox. Record unavailable physical combinations as unverified rather than claiming coverage.

- [ ] **Step 5: Commit**

```bash
git add README.md docs/operations.md docs/database-prerequisites.md vite.config.ts tests/browser
git commit -m "Document and verify envelope encryption rollout"
```

## Final Review and Deployment Boundary

After every task-specific review is clean, generate one whole-branch review package from the integration branch's merge base through HEAD. Dispatch it to the most capable available model with the approved spec, this plan, all task reports, and any ledger rulings. Fix all Critical and Important findings through one reviewed fix wave, then rerun the complete verification matrix.

Code deployment may proceed only after the branch review, test matrix, secret scan, and public-diff review pass. Deployment must leave production in `legacy` or `preparing` mode. Applying the migrations or deploying the compatible client must not activate envelope mode, reject legacy clients, re-encrypt quotes, revoke members, or delete rollback data.

Production activation is a separate security-sensitive and potentially destructive operation. It requires every member's enrollment, an encrypted backup, a fresh production readback, and explicit user approval immediately before the activation RPC.
