import { decryptData, encryptData } from './crypto';
import { deriveQuoteKey, fingerprintPublicJwk, wrapVaultKey } from './device-crypto';
import { decryptQuoteRecord, encryptQuoteRecord } from './quote-crypto';
import { supabase } from './supabase';
import type { Quote } from '../types';

export const MIGRATION_BATCH_SIZE = 50;
type RpcResponse = { data: unknown; error: { code?: string; message?: string } | null };
export type MigrationStatus = 'prepared' | 'staging' | 'ready' | 'activated-maintenance' | 'active' | 'rolled-back' | 'abandoned';
export interface MigrationTargetKey { id: string; publicJwk: JsonWebKey; publicKeyFingerprint?: string; attestation?: unknown; }
export interface MigrationProgress { state: MigrationStatus; migrationId: string; stagedQuoteCount: number; expectedQuoteCount: number; verifiedQuoteCount: number; }
export interface EnvelopeMigrationInput {
    sourceGeneration: string; sourceRevision?: number; sourceKey: CryptoKey; sourceQuotes?: Quote[];
    targetGeneration?: string; targetMasterKey?: Uint8Array; targetVerifier?: { iv: string; data: string }; migrationId?: string;
    deviceId: string | null; token: string | null; actorId: string; deviceWrappers?: MigrationTargetKey[]; recoveryWrappers?: MigrationTargetKey[];
    encryptedExportConfirmed: boolean; getApprovedTargetMasterKey?: (generation: string) => Promise<Uint8Array>; onProgress?: (progress: MigrationProgress) => void;
}
export interface EnvelopeMigrationStageResult { migrationId: string; status: 'staging' | 'ready'; targetGeneration: string; stagedQuoteCount: number; }
export interface EnvelopeMigrationResult { migrationId: string; status: 'finalized'; targetGeneration: string; stagedQuoteCount: number; verifiedQuoteCount: number; }
export interface PendingEnvelopeMigration { migrationId: string | null; status: MigrationStatus | null; sourceGeneration: string | null; targetGeneration: string | null; sourceRevision: number | null; expectedQuoteCount: number | null; stagedQuoteCount: number | null; }
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const sessionKey = (actorId: string, sourceGeneration: string) => `quotevault:migration:${actorId}:${sourceGeneration}`;
const validUuid = (value: string, label: string) => { if (!UUID.test(value)) throw new Error(`Invalid migration ${label}.`); return value; };

async function rpc(name: string, args: Record<string, unknown>): Promise<unknown> {
    const { data, error } = await (supabase.rpc(name, args) as unknown as Promise<RpcResponse>);
    if (error) throw Object.assign(new Error(error.message || `Migration request ${name} failed.`), { code: error.code });
    if (data === null || data === undefined) throw new Error(`Migration request ${name} returned no result.`);
    return data;
}
async function nullableRpc(name: string, args: Record<string, unknown>): Promise<unknown> {
    const { data, error } = await (supabase.rpc(name, args) as unknown as Promise<RpcResponse>);
    if (error) throw Object.assign(new Error(error.message || `Migration request ${name} failed.`), { code: error.code });
    return data;
}
function objectResponse(value: unknown, label: string): Record<string, unknown> { if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`Invalid ${label}.`); return value as Record<string, unknown>; }
function stringResponse(value: unknown, label: string): string { if (typeof value !== 'string' || !value) throw new Error(`Invalid ${label}.`); return value; }
function normalizeMigrationTimestamp(value: unknown): string {
    if (typeof value !== 'string') throw new Error('Invalid migration quote timestamp.');
    const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?(?:Z|\+00:00)$/.exec(value);
    if (!match) throw new Error('Invalid migration quote timestamp.');
    return `${match[1]}.${(match[2] ?? '').padEnd(6, '0')}Z`;
}
function normalizeStatus(value: unknown): MigrationStatus {
    if (!['prepared', 'staging', 'ready', 'activated', 'finalized', 'rolled_back', 'abandoned', 'activated-maintenance', 'active', 'rolled-back'].includes(String(value))) throw new Error('Invalid migration status.');
    return value === 'activated' ? 'activated-maintenance' : value === 'finalized' ? 'active' : value === 'rolled_back' ? 'rolled-back' : value as MigrationStatus;
}
function migrationResponse(value: unknown, fallbackId?: string): { migrationId: string; status: MigrationStatus; stagedQuoteCount: number } {
    const data = objectResponse(value, 'migration response');
    const migrationId = validUuid(stringResponse(data.migration_id ?? fallbackId, 'migration ID'), 'ID');
    const stagedQuoteCount = data.staged_quote_count === undefined || data.staged_quote_count === null ? 0 : data.staged_quote_count;
    if (!Number.isSafeInteger(stagedQuoteCount) || Number(stagedQuoteCount) < 0) throw new Error('Invalid staged quote count.');
    return { migrationId, status: normalizeStatus(data.status), stagedQuoteCount: Number(stagedQuoteCount) };
}
const privateFields = (payload: Record<string, unknown>) => { const copy = { ...payload }; for (const field of ['id', 'vault_generation', 'user_id', 'created_at', 'quote_date']) delete copy[field]; return copy; };
function stable(value: unknown): string { if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`; if (value && typeof value === 'object') return `{${Object.keys(value as object).sort().map(key => `${JSON.stringify(key)}:${stable((value as Record<string, unknown>)[key])}`).join(',')}}`; return JSON.stringify(value); }
function comparePayload(source: Record<string, unknown>, target: Record<string, unknown>, targetGeneration: string, id: string): void {
    if (target.id !== id || target.vault_generation !== targetGeneration || source.id !== target.id || source.user_id !== target.user_id || normalizeMigrationTimestamp(source.created_at) !== normalizeMigrationTimestamp(target.created_at) || source.quote_date !== target.quote_date || stable(privateFields(source)) !== stable(privateFields(target))) throw new Error(`Migration verification failed for quote ${id}.`);
}
function progress(input: EnvelopeMigrationInput, state: MigrationStatus, migrationId: string, stagedQuoteCount: number, expectedQuoteCount: number, verifiedQuoteCount: number) { input.onProgress?.({ state, migrationId, stagedQuoteCount, expectedQuoteCount, verifiedQuoteCount }); }

export async function createEncryptedMigrationExport(input: { generation: string; revision: number; quotes: unknown[]; key: CryptoKey }): Promise<string> {
    if (!UUID.test(input.generation) || !Number.isSafeInteger(input.revision) || input.revision < 0 || !Array.isArray(input.quotes)) throw new Error('Invalid migration export.');
    const encrypted = await encryptData(JSON.stringify({ version: 1, generation: input.generation, revision: input.revision, quotes: input.quotes }), input.key);
    return JSON.stringify({ version: 1, iv: encrypted.iv, data: encrypted.data });
}
export async function loadMigrationSourceSnapshot(input: { sourceGeneration: string; deviceId?: string | null; token?: string | null }): Promise<{ revision: number; quotes: Quote[] }> {
    const data = objectResponse(await rpc('sync_quotes', { p_generation: validUuid(input.sourceGeneration, 'source generation'), p_revision: null, p_operations: [], p_device_id: input.deviceId ?? null, p_device_token: input.token ?? null }), 'source snapshot');
    if (!Number.isSafeInteger(data.revision) || Number(data.revision) < 0 || !Array.isArray(data.quotes)) throw new Error('Migration source snapshot is invalid.');
    return { revision: Number(data.revision), quotes: data.quotes as Quote[] };
}
async function sourceSnapshot(input: EnvelopeMigrationInput): Promise<{ revision: number; quotes: Quote[] }> {
    if (input.sourceQuotes) { if (input.sourceRevision === undefined) throw new Error('Migration source revision is required with a supplied snapshot.'); return { revision: input.sourceRevision, quotes: input.sourceQuotes }; }
    return loadMigrationSourceSnapshot({ sourceGeneration: input.sourceGeneration, deviceId: input.deviceId, token: input.token });
}
type KeyKind = 'device' | 'recovery';
const attestationPlaintext = (kind: KeyKind, id: string, generation: string, fingerprint: string) => JSON.stringify(['quotevault-key-attestation', 1, kind, id, generation, fingerprint]);
/** Proves, to later holders of this generation's key, that a vault-key holder approved this public key. */
export const createKeyAttestation = (key: CryptoKey, kind: KeyKind, id: string, generation: string, fingerprint: string) => encryptData(attestationPlaintext(kind, id, generation, fingerprint), key);
export async function verifyKeyAttestation(attestation: unknown, key: CryptoKey, kind: KeyKind, id: string, generation: string, fingerprint: string): Promise<boolean> {
    try { return await decryptData(attestation as { iv: string; data: string }, key) === attestationPlaintext(kind, id, generation, fingerprint); } catch { return false; }
}
export async function attestVaultKeys(generation: string, auth: { deviceId: string; token: string }, devices: Array<Record<string, unknown>>, recoveries: Array<Record<string, unknown>>): Promise<void> {
    if (devices.length || recoveries.length) await nullableRpc('attest_vault_keys', { p_device_id: auth.deviceId, p_token: auth.token, p_generation: validUuid(generation, 'generation'), p_devices: devices, p_recoveries: recoveries });
}
// The server lists the public keys; only keys attested under the source key are trusted with the target key.
async function wrapTargets(masterKey: Uint8Array, generation: string, targetKey: CryptoKey, sourceKey: CryptoKey, sourceGeneration: string, targets: MigrationTargetKey[], kind: KeyKind) {
    const field = kind === 'device' ? 'device_id' : 'recovery_key_id';
    const wrapped = await Promise.all(targets.map(async target => {
        const id = validUuid(target.id, 'target ID'); const publicKey = await crypto.subtle.importKey('jwk', target.publicJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
        const fingerprint = await fingerprintPublicJwk(target.publicJwk); if (target.publicKeyFingerprint !== undefined && target.publicKeyFingerprint !== fingerprint) throw new Error('Migration public-key fingerprint mismatch.');
        if (!await verifyKeyAttestation(target.attestation, sourceKey, kind, id, sourceGeneration, fingerprint)) return null;
        return { wrapper: { [field]: id, wrapped_key: await wrapVaultKey({ version: 1, vaultId: 'quotevault', generation, targetFingerprint: fingerprint, masterKey }, publicKey) }, attestation: { [field]: id, attestation: await createKeyAttestation(targetKey, kind, id, generation, fingerprint) } };
    }));
    const trusted = wrapped.filter(item => item !== null);
    return { wrappers: trusted.map(item => item.wrapper), attestations: trusted.map(item => item.attestation) };
}

export async function getEnvelopeMigrationStatus(deviceId: string | null, token: string | null): Promise<Record<string, unknown> | null> {
    const data = await nullableRpc('get_pending_envelope_migration', { p_device_id: deviceId === null ? null : validUuid(deviceId, 'device ID'), p_token: token });
    return data === null ? null : objectResponse(data, 'migration status');
}
export async function getPendingEnvelopeMigration(deviceId: string | null, token: string | null): Promise<PendingEnvelopeMigration> {
    const data = await getEnvelopeMigrationStatus(deviceId, token);
    if (data === null) return { migrationId: null, status: null, sourceGeneration: null, targetGeneration: null, sourceRevision: null, expectedQuoteCount: null, stagedQuoteCount: null };
    const migrationId = data.migration_id === null ? null : validUuid(stringResponse(data.migration_id, 'migration ID'), 'ID');
    const status = data.status === null ? null : normalizeStatus(data.status);
    const uuidOrNull = (value: unknown, label: string) => value === null ? null : validUuid(stringResponse(value, label), label);
    const integerOrNull = (value: unknown, label: string) => value === null ? null : Number.isSafeInteger(value) && Number(value) >= 0 ? Number(value) : (() => { throw new Error(`Invalid migration ${label}.`); })();
    return { migrationId, status, sourceGeneration: uuidOrNull(data.source_generation, 'source generation'), targetGeneration: uuidOrNull(data.target_generation, 'target generation'), sourceRevision: integerOrNull(data.source_revision, 'source revision'), expectedQuoteCount: integerOrNull(data.expected_quote_count, 'expected quote count'), stagedQuoteCount: integerOrNull(data.staged_quote_count, 'staged quote count') };
}
export async function abandonEnvelopeMigration(migrationId: string, deviceId: string | null, token: string | null): Promise<void> {
    await rpc('abandon_envelope_migration', { p_migration_id: validUuid(migrationId, 'ID'), p_device_id: deviceId === null ? null : validUuid(deviceId, 'device ID'), p_token: token });
}
export async function rollbackEnvelopeMigration(migrationId: string, deviceId: string, token: string): Promise<void> {
    await rpc('rollback_envelope_migration', { p_migration_id: validUuid(migrationId, 'ID'), p_device_id: validUuid(deviceId, 'device ID'), p_token: token });
}

export interface EnvelopeMigrationCoverage {
    migrationId: string; status: MigrationStatus; sourceGeneration: string; targetGeneration: string; expectedQuoteCount: number; stagedQuoteCount: number; queueReportMaxAgeSeconds: number; ready: boolean;
    members: Array<{ memberId: string | null; email: string | null; devices: Array<{ deviceId: string; publicJwk: JsonWebKey; publicKeyFingerprint: string; attestation: unknown; wrapperStaged: boolean; emptyQueueReportedAt: string | null }>; recoveryKeys: Array<{ recoveryKeyId: string; publicJwk: JsonWebKey; publicKeyFingerprint: string; attestation: unknown; wrapperStaged: boolean }>; blockers: string[] }>;
}
export async function getEnvelopeMigrationCoverage(migrationId: string, deviceId: string, token: string): Promise<EnvelopeMigrationCoverage> {
    const data = objectResponse(await rpc('get_envelope_migration_coverage', { p_migration_id: validUuid(migrationId, 'ID'), p_device_id: validUuid(deviceId, 'device ID'), p_token: token }), 'migration coverage');
    const migration = migrationResponse(data, migrationId); const integer = (value: unknown, label: string) => Number.isSafeInteger(value) && Number(value) >= 0 ? Number(value) : (() => { throw new Error(`Invalid migration ${label}.`); })();
    const members = Array.isArray(data.members) ? data.members.map(member => { const item = objectResponse(member, 'migration member');
        const devices = Array.isArray(item.devices) ? item.devices.map(device => { const value = objectResponse(device, 'migration device'); return { deviceId: validUuid(stringResponse(value.device_id, 'device ID'), 'device ID'), publicJwk: objectResponse(value.public_jwk, 'device public key') as JsonWebKey, publicKeyFingerprint: stringResponse(value.public_key_fingerprint, 'device fingerprint'), attestation: value.attestation, wrapperStaged: value.wrapper_staged === true, emptyQueueReportedAt: value.empty_queue_reported_at === null ? null : normalizeMigrationTimestamp(value.empty_queue_reported_at) }; }) : [];
        const recoveryKeys = Array.isArray(item.recovery_keys) ? item.recovery_keys.map(key => { const value = objectResponse(key, 'migration recovery key'); return { recoveryKeyId: validUuid(stringResponse(value.recovery_key_id, 'recovery key ID'), 'recovery key ID'), publicJwk: objectResponse(value.public_jwk, 'recovery public key') as JsonWebKey, publicKeyFingerprint: stringResponse(value.public_key_fingerprint, 'recovery key fingerprint'), attestation: value.attestation, wrapperStaged: value.wrapper_staged === true }; }) : [];
        const blockers = Array.isArray(item.blockers) && item.blockers.every(value => typeof value === 'string') ? item.blockers as string[] : [];
        return { memberId: item.member_id === null ? null : validUuid(stringResponse(item.member_id, 'member ID'), 'member ID'), email: item.email === null ? null : stringResponse(item.email, 'member email'), devices, recoveryKeys, blockers };
    }) : [];
    return { migrationId: migration.migrationId, status: migration.status, sourceGeneration: validUuid(stringResponse(data.source_generation, 'source generation'), 'source generation'), targetGeneration: validUuid(stringResponse(data.target_generation, 'target generation'), 'target generation'), expectedQuoteCount: integer(data.expected_quote_count, 'expected quote count'), stagedQuoteCount: integer(data.staged_quote_count, 'staged quote count'), queueReportMaxAgeSeconds: integer(data.queue_report_max_age_seconds, 'queue report age'), ready: data.ready === true, members };
}
export async function refreshEnvelopeMigrationSource(migrationId: string, sourceRevision: number, deviceId: string, token: string): Promise<{ migrationId: string; status: MigrationStatus; sourceGeneration: string; sourceRevision: number; expectedQuoteCount: number; reset: boolean }> {
    if (!Number.isSafeInteger(sourceRevision) || sourceRevision < 0) throw new Error('Invalid migration source revision.');
    const data = objectResponse(await rpc('refresh_envelope_migration_source', { p_migration_id: validUuid(migrationId, 'ID'), p_source_revision: sourceRevision, p_device_id: validUuid(deviceId, 'device ID'), p_token: token }), 'migration source refresh');
    const migration = migrationResponse(data, migrationId); const expectedQuoteCount = data.expected_quote_count;
    if (!Number.isSafeInteger(expectedQuoteCount) || Number(expectedQuoteCount) < 0) throw new Error('Invalid migration expected quote count.');
    if (typeof data.reset !== 'boolean') throw new Error('Invalid migration source refresh result.');
    return { migrationId: migration.migrationId, status: migration.status, sourceGeneration: validUuid(stringResponse(data.source_generation, 'source generation'), 'source generation'), sourceRevision: Number(data.source_revision), expectedQuoteCount: Number(expectedQuoteCount), reset: data.reset };
}
export async function reportEnvelopeMigrationEmptyQueue(migrationId: string, sourceRevision: number, deviceId: string, token: string): Promise<{ migrationId: string; status: MigrationStatus; deviceId: string; reportedAt: string; ready: boolean }> {
    if (!Number.isSafeInteger(sourceRevision) || sourceRevision < 0) throw new Error('Invalid migration source revision.');
    const data = objectResponse(await rpc('report_envelope_migration_empty_queue', { p_migration_id: validUuid(migrationId, 'ID'), p_source_revision: sourceRevision, p_device_id: validUuid(deviceId, 'device ID'), p_token: token }), 'empty queue report'); const migration = migrationResponse(data, migrationId);
    return { migrationId: migration.migrationId, status: migration.status, deviceId: validUuid(stringResponse(data.device_id, 'device ID'), 'device ID'), reportedAt: normalizeMigrationTimestamp(data.reported_at), ready: data.ready === true };
}

async function loadSession(actorId: string, sourceGeneration: string, sourceKey: CryptoKey): Promise<{ migrationId: string; targetGeneration: string; sourceRevision: number; sourceQuotes: Quote[] } | null> {
    if (typeof sessionStorage === 'undefined') return null;
    try { const stored = sessionStorage.getItem(sessionKey(actorId, sourceGeneration)); if (!stored) return null; const value = objectResponse(JSON.parse(await decryptData(JSON.parse(stored), sourceKey)), 'migration session');
        if (!Number.isSafeInteger(value.source_revision) || Number(value.source_revision) < 0 || !Array.isArray(value.source_quotes)) throw new Error('Invalid migration session.');
        return { migrationId: validUuid(stringResponse(value.migration_id, 'migration ID'), 'ID'), targetGeneration: validUuid(stringResponse(value.target_generation, 'target generation'), 'target generation'), sourceRevision: Number(value.source_revision), sourceQuotes: value.source_quotes as Quote[] };
    } catch { try { sessionStorage.removeItem(sessionKey(actorId, sourceGeneration)); } catch { /* Storage may be disabled. */ } return null; }
}
async function saveSession(actorId: string, sourceGeneration: string, sourceKey: CryptoKey, session: { migrationId: string; targetGeneration: string; sourceRevision: number; sourceQuotes: Quote[] }): Promise<void> {
    if (typeof sessionStorage === 'undefined') return; const payload = await encryptData(JSON.stringify({ version: 1, migration_id: session.migrationId, target_generation: session.targetGeneration, source_revision: session.sourceRevision, source_quotes: session.sourceQuotes }), sourceKey);
    try { sessionStorage.setItem(sessionKey(actorId, sourceGeneration), JSON.stringify(payload)); } catch { /* Encrypted retry state is best effort when storage is unavailable. */ }
}
function clearSession(actorId: string, sourceGeneration: string): void { if (typeof sessionStorage !== 'undefined') { try { sessionStorage.removeItem(sessionKey(actorId, sourceGeneration)); } catch { /* Storage may be disabled. */ } } }
function requireDeviceAuthorization(input: EnvelopeMigrationInput): { deviceId: string; token: string } { if (!input.deviceId || !input.token) throw new Error('Migration device authorization is required for this operation.'); return { deviceId: validUuid(input.deviceId, 'device ID'), token: input.token }; }
type MigrationContext = { migrationId: string; targetGeneration: string; targetMasterKey: Uint8Array; ownsTargetMasterKey: boolean; sourceRevision: number; sourceQuotes: Quote[]; pending: PendingEnvelopeMigration | null };
async function resolveContext(input: EnvelopeMigrationInput, exactSource: boolean): Promise<MigrationContext> {
    if (!input.encryptedExportConfirmed) throw new Error('Download and keep the encrypted migration export before continuing.');
    const sourceGeneration = validUuid(input.sourceGeneration, 'source generation'); const actorId = validUuid(input.actorId, 'actor ID');
    if (input.sourceRevision !== undefined && (!Number.isSafeInteger(input.sourceRevision) || input.sourceRevision < 0)) throw new Error('Invalid migration source revision.');
    if ((input.deviceId === null) !== (input.token === null)) throw new Error('Migration device authorization must include both device and token.');
    const saved = !input.sourceQuotes ? await loadSession(actorId, sourceGeneration, input.sourceKey) : null; const pending: PendingEnvelopeMigration | null = await getPendingEnvelopeMigration(input.deviceId, input.token); let migrationId = input.migrationId ?? saved?.migrationId;
    if (pending?.migrationId && !saved && !input.sourceQuotes) throw new Error('Resume requires the exact encrypted source snapshot from the prepared migration.');
    const source = input.sourceQuotes ? { revision: input.sourceRevision as number, quotes: input.sourceQuotes } : saved ? { revision: saved.sourceRevision, quotes: saved.sourceQuotes } : (exactSource || migrationId || pending?.migrationId) ? null : await sourceSnapshot(input);
    if (!source || !Number.isSafeInteger(source.revision)) throw new Error('Resume requires the exact encrypted source snapshot from the prepared migration.');
    const targetGeneration = validUuid(input.targetGeneration ?? saved?.targetGeneration ?? pending?.targetGeneration ?? crypto.randomUUID(), 'target generation');
    if (pending?.migrationId && pending.sourceGeneration !== sourceGeneration) throw new Error('A different migration is already prepared for this vault.');
    if (exactSource && pending?.migrationId && pending.sourceRevision !== source.revision) throw new Error('The migration source revision changed; stage a newly downloaded snapshot before activation.');
    if (pending?.migrationId && pending.targetGeneration !== targetGeneration) throw new Error('The migration target generation changed; resume it with its approved target key.');
    let targetMasterKey: Uint8Array<ArrayBufferLike> | null = input.targetMasterKey ?? null;
    let ownsTargetMasterKey = false;
    if (!targetMasterKey && (migrationId || pending?.migrationId || saved)) { if (!input.getApprovedTargetMasterKey) throw new Error('Resume requires the approved device wrapper for the prepared target generation.'); targetMasterKey = await input.getApprovedTargetMasterKey(targetGeneration); ownsTargetMasterKey = true; }
    if (!targetMasterKey) throw new Error('The approved target vault key is required after preparation.');
    if (!migrationId && pending?.migrationId) migrationId = pending.migrationId;
    try {
        const targetKey = await deriveQuoteKey(targetMasterKey, targetGeneration);
        if (!migrationId) { const prepared = migrationResponse(await rpc('prepare_envelope_migration', { p_source_generation: sourceGeneration, p_source_revision: source.revision, p_device_id: null, p_token: null, p_target_generation: targetGeneration, p_target_verifier: input.targetVerifier ?? await encryptData(JSON.stringify({ quotevault: 1 }), targetKey) })); migrationId = prepared.migrationId; }
        validUuid(migrationId, 'migration ID');
        await saveSession(actorId, sourceGeneration, input.sourceKey, { migrationId, targetGeneration, sourceRevision: source.revision, sourceQuotes: source.quotes });
        return { migrationId, targetGeneration, targetMasterKey, ownsTargetMasterKey, sourceRevision: source.revision, sourceQuotes: source.quotes, pending };
    } catch (cause) { if (ownsTargetMasterKey) targetMasterKey.fill(0); throw cause; }
}
export async function prepareEnvelopeMigration(input: { sourceGeneration: string; sourceRevision?: number; sourceKey: CryptoKey; sourceQuotes?: Quote[]; targetGeneration?: string; targetMasterKey: Uint8Array; actorId: string; encryptedExportConfirmed: boolean }): Promise<{ migrationId: string; targetGeneration: string; sourceRevision: number; quoteCount: number }> {
    if (!input.encryptedExportConfirmed) throw new Error('Download and keep the encrypted migration export before continuing.');
    const sourceGeneration = validUuid(input.sourceGeneration, 'source generation'); const actorId = validUuid(input.actorId, 'actor ID');
    const source = input.sourceQuotes ? (input.sourceRevision === undefined ? (() => { throw new Error('Migration source revision is required with a supplied snapshot.'); })() : { revision: input.sourceRevision, quotes: input.sourceQuotes }) : await loadMigrationSourceSnapshot({ sourceGeneration, deviceId: null, token: null });
    const existing = await getPendingEnvelopeMigration(null, null); if (existing.migrationId) throw new Error('A migration is already prepared for this vault.');
    const targetGeneration = validUuid(input.targetGeneration ?? crypto.randomUUID(), 'target generation'); const targetKey = await deriveQuoteKey(input.targetMasterKey, targetGeneration); const verifier = await encryptData(JSON.stringify({ quotevault: 1 }), targetKey);
    const prepared = migrationResponse(await rpc('prepare_envelope_migration', { p_source_generation: sourceGeneration, p_source_revision: source.revision, p_device_id: null, p_token: null, p_target_generation: targetGeneration, p_target_verifier: verifier }));
    await saveSession(actorId, sourceGeneration, input.sourceKey, { migrationId: prepared.migrationId, targetGeneration, sourceRevision: source.revision, sourceQuotes: source.quotes });
    return { migrationId: prepared.migrationId, targetGeneration, sourceRevision: source.revision, quoteCount: source.quotes.length };
}
export async function runEnvelopeMigration(input: EnvelopeMigrationInput): Promise<EnvelopeMigrationStageResult> {
    const auth = requireDeviceAuthorization(input); const context = await resolveContext(input, false); const { migrationId, targetGeneration, targetMasterKey, ownsTargetMasterKey, sourceQuotes } = context;
    try {
        const targetKey = await deriveQuoteKey(targetMasterKey, targetGeneration);
        progress(input, 'staging', migrationId, 0, sourceQuotes.length, 0); const refreshed = await refreshEnvelopeMigrationSource(migrationId, context.sourceRevision, auth.deviceId, auth.token);
        if (refreshed.reset) return { migrationId, status: 'staging', targetGeneration, stagedQuoteCount: 0 };
        const devices = await wrapTargets(targetMasterKey, targetGeneration, targetKey, input.sourceKey, input.sourceGeneration, input.deviceWrappers ?? [], 'device');
        const recoveries = await wrapTargets(targetMasterKey, targetGeneration, targetKey, input.sourceKey, input.sourceGeneration, input.recoveryWrappers ?? [], 'recovery');
        const wrapperResponse = migrationResponse(await rpc('stage_envelope_wrappers', { p_migration_id: migrationId, p_device_id: auth.deviceId, p_token: auth.token, p_devices: devices.wrappers, p_recoveries: recoveries.wrappers }));
        await attestVaultKeys(targetGeneration, auth, devices.attestations, recoveries.attestations); let stagedQuoteCount = wrapperResponse.stagedQuoteCount; let serverStatus = wrapperResponse.status;
        for (let start = 0; start < sourceQuotes.length; start += MIGRATION_BATCH_SIZE) {
            const rows = await Promise.all(sourceQuotes.slice(start, start + MIGRATION_BATCH_SIZE).map(async sourceRow => { const payload = objectResponse(await decryptQuoteRecord(sourceRow, input.sourceKey), 'decrypted quote'); const id = validUuid(stringResponse(payload.id ?? sourceRow.id, 'quote ID'), 'quote ID'); const visible = { id, quote_date: payload.quote_date === undefined ? null : payload.quote_date as string | null, created_at: normalizeMigrationTimestamp(payload.created_at ?? sourceRow.created_at), user_id: validUuid(stringResponse(payload.user_id ?? sourceRow.user_id, 'quote owner'), 'quote owner'), vault_generation: targetGeneration, author: 'ENCRYPTED', context: 'ENCRYPTED' }; return await encryptQuoteRecord(privateFields(payload), visible, targetKey) as unknown as Quote; }));
            const responseValue = migrationResponse(await rpc('stage_envelope_quotes', { p_migration_id: migrationId, p_device_id: auth.deviceId, p_token: auth.token, p_rows: rows })); stagedQuoteCount = Math.max(stagedQuoteCount + rows.length, responseValue.stagedQuoteCount); serverStatus = responseValue.status; progress(input, 'staging', migrationId, stagedQuoteCount, sourceQuotes.length, 0);
        }
        const status = serverStatus === 'ready' && stagedQuoteCount >= sourceQuotes.length ? 'ready' : 'staging'; progress(input, status, migrationId, stagedQuoteCount, sourceQuotes.length, 0); return { migrationId, status, targetGeneration, stagedQuoteCount };
    } finally { if (ownsTargetMasterKey) targetMasterKey.fill(0); }
}
export async function activateEnvelopeMigration(input: EnvelopeMigrationInput): Promise<EnvelopeMigrationResult> {
    const context = await resolveContext(input, true); const auth = requireDeviceAuthorization(input); const { migrationId, targetGeneration, targetMasterKey, ownsTargetMasterKey, sourceQuotes } = context; let activated = context.pending?.status === 'activated-maintenance';
    try {
        const targetKey = await deriveQuoteKey(targetMasterKey, targetGeneration);
        if (!activated) { await rpc('activate_envelope_migration', { p_migration_id: migrationId, p_device_id: auth.deviceId, p_token: auth.token }); activated = true; }
        progress(input, 'activated-maintenance', migrationId, sourceQuotes.length, sourceQuotes.length, 0); const snapshot = objectResponse(await rpc('get_envelope_migration_snapshot', { p_migration_id: migrationId, p_device_id: auth.deviceId, p_token: auth.token }), 'migration snapshot');
        if (snapshot.generation !== targetGeneration || !Array.isArray(snapshot.quotes) || snapshot.quotes.length !== sourceQuotes.length) throw new Error('Migration verification failed: record count or generation changed.');
        const expected = new Map<string, Record<string, unknown>>(); for (const sourceRow of sourceQuotes) { const payload = objectResponse(await decryptQuoteRecord(sourceRow, input.sourceKey), 'source quote'); expected.set(String(payload.id ?? sourceRow.id), payload); }
        let verifiedQuoteCount = 0; for (const row of snapshot.quotes as Quote[]) { const id = stringResponse(row.id, 'snapshot quote ID'); const source = expected.get(id); if (!source) throw new Error(`Migration verification failed for quote ${id}.`); let target: Record<string, unknown>; try { target = objectResponse(await decryptQuoteRecord(row, targetKey), 'target quote'); } catch { throw new Error(`Migration verification failed for quote ${id}.`); } comparePayload(source, target, targetGeneration, id); verifiedQuoteCount++; }
        if (verifiedQuoteCount !== sourceQuotes.length) throw new Error('Migration verification failed: record IDs changed.'); await rpc('finalize_envelope_migration', { p_migration_id: migrationId, p_device_id: auth.deviceId, p_token: auth.token }); clearSession(input.actorId, input.sourceGeneration); progress(input, 'active', migrationId, sourceQuotes.length, sourceQuotes.length, verifiedQuoteCount); return { migrationId, status: 'finalized', targetGeneration, stagedQuoteCount: sourceQuotes.length, verifiedQuoteCount };
    } catch (error) { if (activated) { try { await rpc('rollback_envelope_migration', { p_migration_id: migrationId, p_device_id: auth.deviceId, p_token: auth.token }); clearSession(input.actorId, input.sourceGeneration); progress(input, 'rolled-back', migrationId, 0, sourceQuotes.length, 0); } catch { /* Leave maintenance active for an explicit retry if rollback is unavailable. */ } } throw error; } finally { if (ownsTargetMasterKey) targetMasterKey.fill(0); }
}
