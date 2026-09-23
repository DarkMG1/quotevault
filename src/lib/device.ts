import { db } from './db';
import { supabase } from './supabase';
import type { DeviceLease, DeviceLocalState, EnvelopeCiphertext } from '../types';
import { arrayBufferToBase64, base64ToArrayBuffer } from './crypto';
import { digestAuthorizationToken, fingerprintPublicJwk } from './device-crypto';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const invalid = (message = 'Invalid device response.'): never => { throw new Error(message); };
const stringValue = (value: unknown, name: string): string => typeof value === 'string' && value ? value : invalid(`Invalid device ${name}.`);
const uuidValue = (value: unknown, name: string): string => { const result = stringValue(value, name); return UUID.test(result) ? result : invalid(`Invalid device ${name}.`); };
const canonicalBase64 = (value: unknown): value is string => { if (typeof value !== 'string' || !BASE64.test(value)) return false; try { return arrayBufferToBase64(base64ToArrayBuffer(value)) === value; } catch { return false; } };
const base64urlLength = (value: unknown): number | null => {
    if (typeof value !== 'string' || !BASE64URL.test(value) || value.length % 4 === 1) return null;
    try { const standard = `${value.replace(/-/g, '+').replace(/_/g, '/')}${'==='.slice((value.length + 3) % 4)}`; const bytes = new Uint8Array(base64ToArrayBuffer(standard)); return arrayBufferToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') === value ? bytes.byteLength : null; } catch { return null; }
};
const base64urlBytes = (value: unknown, expected: number): boolean => base64urlLength(value) === expected;
const envelope = (value: unknown): EnvelopeCiphertext => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) invalid('Invalid encrypted device bundle.');
    const candidate = value as Partial<EnvelopeCiphertext>;
    if (candidate.version !== 2 || !canonicalBase64(candidate.iv) || !canonicalBase64(candidate.data) || new Uint8Array(base64ToArrayBuffer(candidate.iv)).byteLength !== 12 || new Uint8Array(base64ToArrayBuffer(candidate.data)).byteLength < 16) invalid('Invalid encrypted device bundle.');
    return { version: 2, iv: candidate.iv as string, data: candidate.data as string };
};
const objectValue = (value: unknown, name: string): Record<string, unknown> => { if (!value || typeof value !== 'object' || Array.isArray(value)) invalid(`Invalid device ${name}.`); return value as Record<string, unknown>; };
const expiry = (value: unknown): string => { const result = stringValue(value, 'expiry'); return Number.isFinite(Date.parse(result)) ? result : invalid('Invalid device expiry.'); };
const rpc = async (name: string, args: Record<string, unknown>): Promise<unknown> => { const { data, error } = await supabase.rpc(name, args); if (error) throw new Error(`Device ${name} failed.`); return data; };

function canonicalJson(value: unknown, seen = new Set<unknown>()): string {
    if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
    if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
    if (typeof value !== 'object' || seen.has(value)) invalid('Invalid device protection.');
    seen.add(value); let result: string;
    if (Array.isArray(value)) result = `[${value.map(item => canonicalJson(item, seen)).join(',')}]`;
    else { const object = value as Record<string, unknown>; result = `{${Object.keys(object).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(object[key], seen)}`).join(',')}}`; }
    seen.delete(value); return result;
}
const mode = (value: unknown): 'passkey-prf' | 'remembered' => value === 'passkey-prf' || value === 'remembered' ? value : invalid('Invalid device protection mode.');
const exactObject = (value: unknown, fields: string[]): Record<string, unknown> => {
    const object = objectValue(value, 'protection');
    if (Object.prototype.toString.call(object) !== '[object Object]' || Object.keys(object).length !== fields.length || !fields.every(field => Object.prototype.hasOwnProperty.call(object, field) && Object.prototype.propertyIsEnumerable.call(object, field) && 'value' in (Object.getOwnPropertyDescriptor(object, field) ?? {}))) invalid('Invalid device protection.');
    return object;
};
export const validateDeviceProtection = (value: unknown, protectionMode: 'passkey-prf' | 'remembered'): Record<string, unknown> => {
    const protection = protectionMode === 'remembered' ? exactObject(value, ['version', 'mode']) : exactObject(value, ['version', 'rpId', 'credentialId', 'prfSalt', 'kdf']);
    if (protectionMode === 'remembered' && (protection.version !== 1 || protection.mode !== 'remembered')) invalid('Invalid device protection.');
    const credentialLength = base64urlLength(protection.credentialId);
    if (protectionMode === 'passkey-prf' && (protection.version !== 1 || protection.rpId !== 'quotes.darkmg1.dev' || protection.kdf !== 'HKDF-SHA-256' || credentialLength === null || credentialLength < 1 || credentialLength > 1023 || !base64urlBytes(protection.prfSalt, 32))) invalid('Invalid device protection.');
    return protection;
};
const kind = (value: unknown): 'first' | 'additional' | 'recovery' => value === 'first' || value === 'additional' || value === 'recovery' ? value : invalid('Invalid device request kind.');
const publicKey = async (value: unknown, expected?: string): Promise<{ jwk: JsonWebKey; fingerprint: string }> => { const jwk = objectValue(value, 'public key') as JsonWebKey; const fingerprint = await fingerprintPublicJwk(jwk); if (expected !== undefined && fingerprint !== expected) invalid('Invalid device public-key fingerprint.'); return { jwk, fingerprint }; };

export async function enrollmentFingerprint(input: { accountId: string; publicKeyFingerprint: string; tokenDigest: string; protectionMode: 'passkey-prf' | 'remembered'; protection: Record<string, unknown> }): Promise<string> {
    uuidValue(input.accountId, 'account ID'); if (!base64urlBytes(input.publicKeyFingerprint, 32) || !base64urlBytes(input.tokenDigest, 32)) invalid('Invalid device fingerprint.');
    const payload = `[1,${JSON.stringify(input.accountId)},${JSON.stringify(input.publicKeyFingerprint)},${JSON.stringify(input.tokenDigest)},${JSON.stringify(input.protectionMode)},${canonicalJson(validateDeviceProtection(input.protection, input.protectionMode))}]`;
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(payload))); return arrayBufferToBase64(digest).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export const computeEnrollmentFingerprint = enrollmentFingerprint;

const ENROLLMENT_CODE_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const ENROLLMENT_CODE_PREFIX = new TextEncoder().encode('quotevault/enrollment-code/v1\0');

export async function formatEnrollmentCode(fingerprint: string): Promise<string> {
    if (!base64urlBytes(fingerprint, 32)) invalid('Invalid enrollment fingerprint.');
    const encoded = `${fingerprint.replace(/-/g, '+').replace(/_/g, '/')}${'==='.slice((fingerprint.length + 3) % 4)}`;
    const fingerprintBytes = new Uint8Array(base64ToArrayBuffer(encoded));
    const input = new Uint8Array(ENROLLMENT_CODE_PREFIX.length + fingerprintBytes.length);
    input.set(ENROLLMENT_CODE_PREFIX);
    input.set(fingerprintBytes, ENROLLMENT_CODE_PREFIX.length);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', input));
    let value = 0n;
    for (const byte of digest.slice(0, 5)) value = (value << 8n) | BigInt(byte);
    let code = '';
    for (let shift = 35n; shift >= 0n; shift -= 5n) code += ENROLLMENT_CODE_ALPHABET[Number((value >> shift) & 31n)];
    return `${code.slice(0, 4)}-${code.slice(4)}`;
}

export interface RequestDeviceInput { deviceId: string; ownerId: string; label: string; publicJwk: JsonWebKey; publicKeyFingerprint: string; tokenDigest: string; protectionMode: 'passkey-prf' | 'remembered'; protection: Record<string, unknown>; encryptedPrivateBundle: EnvelopeCiphertext; requestKind: 'first' | 'additional' | 'recovery' }
export interface DeviceRequest { requestId: string; ownerId: string; requestKind: 'first' | 'additional' | 'recovery'; label: string; publicJwk: JsonWebKey; publicKeyFingerprint: string; authorizationTokenDigest: string; enrollmentFingerprint: string; protectionMode: 'passkey-prf' | 'remembered'; protection: Record<string, unknown>; expiresAt: string }

export async function requestDevice(input: RequestDeviceInput): Promise<{ requestId: string; deviceId: string; enrollmentFingerprint: string; expiresAt: string }> {
    const deviceId = uuidValue(input.deviceId, 'device ID'); const ownerId = uuidValue(input.ownerId, 'owner ID'); if (!input.label || input.label.length > 100) invalid('Invalid device label.');
    const { jwk, fingerprint } = await publicKey(input.publicJwk, input.publicKeyFingerprint); if (!base64urlBytes(input.tokenDigest, 32)) invalid('Invalid device token digest.'); const protectionMode = mode(input.protectionMode); const protection = validateDeviceProtection(input.protection, protectionMode); const bundle = envelope(input.encryptedPrivateBundle); const enrollment = await enrollmentFingerprint({ accountId: ownerId, publicKeyFingerprint: fingerprint, tokenDigest: input.tokenDigest, protectionMode, protection });
    const data = objectValue(await rpc('request_device', { p_device_id: deviceId, p_owner_id: ownerId, p_label: input.label, p_public_jwk: jwk, p_enrollment_fingerprint: enrollment, p_public_key_fingerprint: fingerprint, p_token_digest: input.tokenDigest, p_protection_mode: input.protectionMode, p_protection: protection, p_encrypted_private_bundle: bundle, p_request_kind: kind(input.requestKind) }), 'request response');
    if (uuidValue(data.request_id, 'request ID') !== deviceId || uuidValue(data.device_id, 'device ID') !== deviceId || stringValue(data.enrollment_fingerprint, 'enrollment fingerprint') !== enrollment) invalid('Invalid device request response.');
    return { requestId: deviceId, deviceId, enrollmentFingerprint: enrollment, expiresAt: expiry(data.expires_at) };
}

export async function getDeviceRequest(requestId: string): Promise<DeviceRequest> {
    const id = uuidValue(requestId, 'request ID'); const data = objectValue(await rpc('get_device_request', { p_request_id: id }), 'request response'); if (uuidValue(data.request_id, 'request ID') !== id) invalid('Invalid device request response.');
    const ownerId = uuidValue(data.owner_id, 'owner ID'); const { jwk, fingerprint } = await publicKey(data.public_jwk, stringValue(data.public_key_fingerprint, 'public-key fingerprint')); const tokenDigest = stringValue(data.authorization_token_digest, 'token digest'); if (!base64urlBytes(tokenDigest, 32)) invalid('Invalid device token digest.'); const protectionMode = mode(data.protection_mode); const protection = validateDeviceProtection(data.protection, protectionMode); const enrollment = await enrollmentFingerprint({ accountId: ownerId, publicKeyFingerprint: fingerprint, tokenDigest, protectionMode, protection });
    if (enrollment !== stringValue(data.enrollment_fingerprint, 'enrollment fingerprint') || 'encrypted_private_bundle' in data) invalid('Invalid device request response.');
    return { requestId: id, ownerId, requestKind: kind(data.request_kind), label: stringValue(data.label, 'label'), publicJwk: jwk, publicKeyFingerprint: fingerprint, authorizationTokenDigest: tokenDigest, enrollmentFingerprint: enrollment, protectionMode, protection, expiresAt: expiry(data.expires_at) };
}

export interface ApproveDeviceInput { requestId: string; ownerId: string; publicKeyFingerprint: string; enrollmentFingerprint: string; wrappedKey: string; generation: string; approverDeviceId?: string | null; approverToken?: string | null }
export async function approveDevice(input: ApproveDeviceInput): Promise<{ status: 'approved'; deviceId: string; generation: string }> {
    const requestId = uuidValue(input.requestId, 'request ID'); const ownerId = uuidValue(input.ownerId, 'owner ID'); const generation = uuidValue(input.generation, 'generation'); if (!base64urlBytes(input.publicKeyFingerprint, 32) || !base64urlBytes(input.enrollmentFingerprint, 32) || !base64urlBytes(input.wrappedKey, 384)) invalid('Invalid device approval input.'); const approverDeviceId = input.approverDeviceId == null ? null : uuidValue(input.approverDeviceId, 'approver device ID'); const approverToken = input.approverToken == null ? null : stringValue(input.approverToken, 'approver token'); if ((approverDeviceId === null) !== (approverToken === null) || approverToken !== null && !base64urlBytes(approverToken, 32)) invalid('Invalid device approver.');
    const data = objectValue(await rpc('approve_device', { p_request_id: requestId, p_owner_id: ownerId, p_public_key_fingerprint: input.publicKeyFingerprint, p_enrollment_fingerprint: input.enrollmentFingerprint, p_wrapped_key: input.wrappedKey, p_generation: generation, p_approver_device_id: approverDeviceId, p_approver_token: approverToken }), 'approval response'); if (data.status !== 'approved' || uuidValue(data.device_id, 'device ID') !== requestId || uuidValue(data.generation, 'generation') !== generation) invalid('Invalid device approval response.'); return { status: 'approved', deviceId: requestId, generation };
}

const strictWrapper = (value: unknown): string => base64urlBytes(value, 384) ? value as string : invalid('Invalid device wrapped key.');
export async function getConversionWrapper(sourceGeneration: string, deviceId: string, token: string): Promise<{ generation: string; wrappedKey: string }> {
    const generation = uuidValue(sourceGeneration, 'source generation');
    const device = uuidValue(deviceId, 'device ID');
    if (!base64urlBytes(token, 32)) invalid('Invalid device token.');
    const data = objectValue(await rpc('get_conversion_wrapper', { p_source_generation: generation, p_device_id: device, p_token: token }), 'conversion wrapper response');
    if (uuidValue(data.device_id, 'device ID') !== device || uuidValue(data.generation, 'generation') !== generation || data.purpose !== 'conversion_only') invalid('Invalid conversion wrapper response.');
    return { generation, wrappedKey: strictWrapper(data.wrapped_key) };
}
export async function acknowledgeConversionQueue(sourceGeneration: string, deviceId: string, token: string): Promise<void> {
    const generation = uuidValue(sourceGeneration, 'source generation');
    const device = uuidValue(deviceId, 'device ID');
    if (!base64urlBytes(token, 32)) invalid('Invalid device token.');
    const data = objectValue(await rpc('ack_conversion_queue', { p_source_generation: generation, p_device_id: device, p_token: token }), 'conversion acknowledgement');
    if (data.status !== 'acknowledged' || typeof data.removed !== 'boolean') invalid('Invalid conversion acknowledgement.');
}
export const needsRecoverySetup = (state: Pick<DeviceLocalState, 'recoverySetupRequired'> | null | undefined): boolean => state?.recoverySetupRequired === true;
export const recoverySetupRetryOutcome = (replace: boolean, attemptedRecoveryKeyId: string, activeRecoveryKeyId: string | null): 'committed' | 'other' | 'original' => activeRecoveryKeyId === attemptedRecoveryKeyId ? 'committed' : !replace && activeRecoveryKeyId ? 'other' : 'original';
export interface CompletedDeviceState extends DeviceLocalState { activeRecoveryKeyId: string | null }
export const deviceWrapperForGeneration = (state: DeviceLocalState, generation: string) =>
    state.wrapper?.generation === generation ? state.wrapper : state.preparedWrapper?.generation === generation ? state.preparedWrapper : undefined;
export const needsDeviceCompletion = (state: DeviceLocalState, generation: string) => !deviceWrapperForGeneration(state, generation);
export async function completeDevice(accountId: string, deviceId: string, token: string, rememberedKey?: CryptoKey, generation?: string): Promise<CompletedDeviceState> {
    const account = uuidValue(accountId, 'account ID'); const device = uuidValue(deviceId, 'device ID'); if (!base64urlBytes(token, 32)) invalid('Invalid device token.'); const loaded = await loadDeviceState(account); if (!loaded || loaded.deviceId !== device) invalid('Device enrollment state is missing.'); const current = loaded as DeviceLocalState; if (current.protectionMode === 'remembered' && (!rememberedKey || !await usableRememberedKey(rememberedKey))) invalid('Remembered device keys must be non-extractable AES-GCM keys.'); if (current.protectionMode === 'passkey-prf' && rememberedKey) invalid('Passkey device cannot persist a transient key.'); const targetGeneration = generation ?? current.wrapper?.generation; if (!targetGeneration) invalid('Device generation is missing.');
    const data = objectValue(await rpc('complete_device', { p_device_id: device, p_token: token, p_generation: uuidValue(targetGeneration, 'generation') }), 'completion response'); if ('lease' in data) invalid('Unsigned device lease rejected.'); const responseDevice = uuidValue(data.device_id, 'device ID'); const responseGeneration = uuidValue(data.generation, 'generation'); const activeRecoveryKeyId = data.active_recovery_key_id === null ? null : uuidValue(data.active_recovery_key_id, 'active recovery key ID'); if (responseDevice !== device || responseGeneration !== targetGeneration || typeof data.recovery_setup_required !== 'boolean' || data.recovery_setup_required === (activeRecoveryKeyId !== null)) invalid('Invalid device completion response.'); const next: DeviceLocalState = { accountId: account, deviceId: device, publicKeyFingerprint: current.publicKeyFingerprint, protectionMode: current.protectionMode, protection: current.protection, encryptedPrivateBundle: envelope(current.encryptedPrivateBundle), wrapper: { generation: responseGeneration, wrappedKey: strictWrapper(data.wrapped_key) } }; if (current.protectionMode === 'remembered') next.rememberedKey = rememberedKey; if (current.lease) next.lease = current.lease; if (data.recovery_setup_required) next.recoverySetupRequired = true; expiry(data.lease_expires_at); await saveDeviceState(next); return { ...next, activeRecoveryKeyId };
}

export interface DeviceSummary { id: string; status: 'pending' | 'active' | 'revoked' | 'expired'; label: string; protection_mode: 'passkey-prf' | 'remembered'; created_at: string; last_sync_at: string | null; lease_expires_at: string | null; revoked_at: string | null }
const summary = (value: unknown): DeviceSummary => { const data = objectValue(value, 'device summary'); const status = data.status === 'pending' || data.status === 'active' || data.status === 'revoked' || data.status === 'expired' ? data.status : invalid('Invalid device status.'); return { id: uuidValue(data.id, 'device ID'), status, label: stringValue(data.label, 'label'), protection_mode: mode(data.protection_mode), created_at: expiry(data.created_at), last_sync_at: data.last_sync_at === null ? null : expiry(data.last_sync_at), lease_expires_at: data.lease_expires_at === null ? null : expiry(data.lease_expires_at), revoked_at: data.revoked_at === null ? null : expiry(data.revoked_at) }; };
export async function listOwnDevices(): Promise<DeviceSummary[]> { const data = await rpc('list_own_devices', {}); if (!Array.isArray(data)) invalid('Invalid device list response.'); return (data as unknown[]).map(summary); }
export async function revokeOwnDevice(deviceId: string, token: string): Promise<{ deviceId: string; status: 'revoked' }> { const id = uuidValue(deviceId, 'device ID'); if (!base64urlBytes(token, 32)) invalid('Invalid device token.'); const data = objectValue(await rpc('revoke_own_device', { p_device_id: id, p_token: token }), 'revocation response'); if (data.status !== 'revoked' || uuidValue(data.device_id, 'device ID') !== id) invalid('Invalid device revocation response.'); return { deviceId: id, status: 'revoked' }; }

const structuralLease = (value: unknown): DeviceLease => { const data = objectValue(value, 'lease'); if (data.version !== 1 || !Array.isArray(data.claims) || data.claims.length !== 7 || data.claims[0] !== 1 || typeof data.signature !== 'string') invalid('Invalid device lease.'); return { version: 1, claims: data.claims as DeviceLease['claims'], signature: data.signature as string }; };
const usableRememberedKey = async (value: unknown): Promise<boolean> => {
    if (!value || typeof value !== 'object') return false;
    const key = value as CryptoKey;
    if (key.extractable !== false || key.algorithm?.name !== 'AES-GCM' || (key.algorithm as AesKeyAlgorithm).length !== 256 || key.usages.length !== 2 || !key.usages.includes('encrypt') || !key.usages.includes('decrypt')) return false;
    try { const iv = crypto.getRandomValues(new Uint8Array(12)); const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new Uint8Array(0)); await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data); return true; } catch { return false; }
};
const sanitize = async (value: unknown, accountId: string): Promise<DeviceLocalState> => { const data = objectValue(value, 'local state'); if (uuidValue(data.accountId, 'account ID') !== accountId) invalid('Device state account mismatch.'); const protectionMode = mode(data.protectionMode); const result: DeviceLocalState = { accountId, deviceId: uuidValue(data.deviceId, 'device ID'), publicKeyFingerprint: stringValue(data.publicKeyFingerprint, 'public-key fingerprint'), protectionMode, protection: validateDeviceProtection(data.protection, protectionMode), encryptedPrivateBundle: envelope(data.encryptedPrivateBundle) }; if (!base64urlBytes(result.publicKeyFingerprint, 32)) invalid('Invalid device public-key fingerprint.'); if (data.recoverySetupRequired !== undefined) { if (typeof data.recoverySetupRequired !== 'boolean') invalid('Invalid device local state.'); if (data.recoverySetupRequired) result.recoverySetupRequired = true; } if (data.rememberedKey !== undefined) { if (protectionMode === 'passkey-prf' || !await usableRememberedKey(data.rememberedKey)) invalid('Invalid remembered device key.'); result.rememberedKey = data.rememberedKey as CryptoKey; } for (const field of ['wrapper', 'preparedWrapper'] as const) { if (data[field] === undefined) continue; const wrapper = objectValue(data[field], field); result[field] = { generation: uuidValue(wrapper.generation, 'generation'), wrappedKey: strictWrapper(wrapper.wrappedKey) }; } if (data.lease !== undefined) result.lease = structuralLease(data.lease); return result; };
export async function saveDeviceState(state: DeviceLocalState): Promise<void> { await db.deviceState.put(await sanitize(state, state.accountId)); }
export async function loadDeviceState(accountId: string): Promise<DeviceLocalState | null> { uuidValue(accountId, 'account ID'); const value = await db.deviceState.get(accountId); return value == null ? null : await sanitize(value, accountId); }
export async function deleteDeviceState(accountId: string, completeLocalWipe = false): Promise<void> { uuidValue(accountId, 'account ID'); if (completeLocalWipe) await db.deviceState.clear(); else await db.deviceState.delete(accountId); }

export { digestAuthorizationToken, fingerprintPublicJwk };
