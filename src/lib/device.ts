import { db } from './db';
import { supabase } from './supabase';
import type { DeviceLease, DeviceLocalState, EnvelopeCiphertext } from '../types';
import { digestAuthorizationToken, fingerprintPublicJwk } from './device-crypto';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

const invalid = (message = 'Invalid device response.') => { throw new Error(message); };
const stringValue = (value: unknown, name: string): string => {
    if (typeof value !== 'string' || !value) invalid(`Invalid device ${name}.`);
    return value as string;
};
const uuidValue = (value: unknown, name: string): string => {
    const result = stringValue(value, name);
    if (!UUID.test(result)) invalid(`Invalid device ${name}.`);
    return result;
};
const canonicalBase64 = (value: unknown): boolean => {
    if (typeof value !== 'string' || !BASE64.test(value)) return false;
    try { return btoa(String.fromCharCode(...new Uint8Array(atob(value).split('').map(char => char.charCodeAt(0))))) === value; }
    catch { return false; }
};
const canonicalBase64url = (value: unknown, expectedBytes: number): boolean => {
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) return false;
    try {
        const standard = value.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((value.length + 3) % 4);
        const bytes = atob(standard);
        if (bytes.length !== expectedBytes) return false;
        const canonical = btoa(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        return canonical === value;
    } catch { return false; }
};
const envelope = (value: unknown): EnvelopeCiphertext => {
    if (!value || typeof value !== 'object') invalid();
    const candidate = value as Partial<EnvelopeCiphertext>;
    if (candidate.version !== 2 || !canonicalBase64(candidate.iv) || !canonicalBase64(candidate.data)) invalid();
    const iv = atob(candidate.iv!);
    const data = atob(candidate.data!);
    if (iv.length !== 12 || data.length < 16) invalid();
    return { version: 2, iv: candidate.iv!, data: candidate.data! };
};
const record = (value: unknown, name: string): Record<string, unknown> => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) invalid(`Invalid device ${name}.`);
    return value as Record<string, unknown>;
};
const rpc = async (name: string, args: Record<string, unknown>): Promise<unknown> => {
    const { data, error } = await supabase.rpc(name, args);
    if (error) throw new Error(`Device ${name} failed.`);
    return data;
};

export interface RequestDeviceInput {
    deviceId: string;
    ownerId: string;
    label: string;
    publicJwk: JsonWebKey;
    enrollmentFingerprint: string;
    publicKeyFingerprint: string;
    tokenDigest: string;
    protectionMode: 'passkey-prf' | 'remembered';
    protection: Record<string, unknown>;
    encryptedPrivateBundle: EnvelopeCiphertext;
    requestKind: 'first' | 'additional' | 'recovery';
}

export async function enrollmentFingerprint(input: {
    accountId: string;
    publicKeyFingerprint: string;
    tokenDigest: string;
    protectionMode: RequestDeviceInput['protectionMode'];
    protection: Record<string, unknown>;
    encryptedPrivateBundle: EnvelopeCiphertext;
}): Promise<string> {
    const payload = JSON.stringify([1, input.accountId, input.publicKeyFingerprint, input.tokenDigest,
        input.protectionMode, input.protection, input.encryptedPrivateBundle]);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(payload)));
    return btoa(String.fromCharCode(...digest)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export const computeEnrollmentFingerprint = enrollmentFingerprint;

export async function requestDevice(input: RequestDeviceInput): Promise<{ requestId: string; deviceId: string; enrollmentFingerprint: string; expiresAt: string }> {
    uuidValue(input.deviceId, 'device ID');
    uuidValue(input.ownerId, 'owner ID');
    const data = record(await rpc('request_device', {
        p_device_id: input.deviceId, p_owner_id: input.ownerId, p_label: input.label,
        p_public_jwk: input.publicJwk, p_enrollment_fingerprint: input.enrollmentFingerprint,
        p_public_key_fingerprint: input.publicKeyFingerprint, p_token_digest: input.tokenDigest,
        p_protection_mode: input.protectionMode, p_protection: input.protection,
        p_encrypted_private_bundle: input.encryptedPrivateBundle, p_request_kind: input.requestKind,
    }), 'request response');
    return {
        requestId: uuidValue(data.request_id, 'request ID'),
        deviceId: uuidValue(data.device_id, 'device ID'),
        enrollmentFingerprint: stringValue(data.enrollment_fingerprint, 'enrollment fingerprint'),
        expiresAt: stringValue(data.expires_at, 'expiry'),
    };
}

export interface ApproveDeviceInput {
    requestId: string; ownerId: string; publicKeyFingerprint: string; enrollmentFingerprint: string;
    wrappedKey: string; generation: string; approverDeviceId?: string | null; approverToken?: string | null;
}

export async function approveDevice(input: ApproveDeviceInput): Promise<{ status: 'approved'; deviceId: string; generation: string }> {
    const data = record(await rpc('approve_device', {
        p_request_id: input.requestId, p_owner_id: input.ownerId,
        p_public_key_fingerprint: input.publicKeyFingerprint, p_enrollment_fingerprint: input.enrollmentFingerprint,
        p_wrapped_key: input.wrappedKey, p_generation: input.generation,
        p_approver_device_id: input.approverDeviceId ?? null, p_approver_token: input.approverToken ?? null,
    }), 'approval response');
    if (data.status !== 'approved') invalid('Invalid device approval response.');
    return { status: 'approved', deviceId: uuidValue(data.device_id, 'device ID'), generation: uuidValue(data.generation, 'generation') };
}

export async function completeDevice(accountId: string, deviceId: string, token: string, rememberedKey: CryptoKey, generation?: string): Promise<DeviceLocalState> {
    uuidValue(accountId, 'account ID');
    uuidValue(deviceId, 'device ID');
    if (!rememberedKey || rememberedKey.extractable !== false) invalid('Remembered device keys must be non-extractable.');
    const current = await loadDeviceState(accountId);
    if (!current || current.deviceId !== deviceId) invalid('Device enrollment state is missing.');
    const state = current as DeviceLocalState;
    const targetGeneration = generation ?? state.wrapper?.generation;
    if (!targetGeneration) invalid('Device generation is missing.');
    const data = record(await rpc('complete_device', { p_device_id: deviceId, p_token: token, p_generation: targetGeneration }), 'completion response');
    const responseDeviceId = uuidValue(data.device_id, 'device ID');
    const responseGeneration = uuidValue(data.generation, 'generation');
    const next: DeviceLocalState = {
        ...state, accountId, deviceId: responseDeviceId, rememberedKey,
        encryptedPrivateBundle: envelope(state.encryptedPrivateBundle),
        wrapper: (() => {
            if (!canonicalBase64url(data.wrapped_key, 384)) invalid('Invalid device wrapped key.');
            return { generation: responseGeneration, wrappedKey: data.wrapped_key as string };
        })(),
    };
    if (data.lease && typeof data.lease === 'object') next.lease = data.lease as DeviceLease;
    await saveDeviceState(next);
    return next;
}

export async function listOwnDevices(): Promise<unknown[]> {
    const data = await rpc('list_own_devices', {});
    if (!Array.isArray(data)) invalid('Invalid device list response.');
    return data as unknown[];
}

export async function revokeOwnDevice(deviceId: string, token: string): Promise<{ deviceId: string; status: 'revoked' }> {
    const data = record(await rpc('revoke_own_device', { p_device_id: deviceId, p_token: token }), 'revocation response');
    if (data.status !== 'revoked') invalid('Invalid device revocation response.');
    return { deviceId: uuidValue(data.device_id, 'device ID'), status: 'revoked' };
}

export async function saveDeviceState(state: DeviceLocalState): Promise<void> {
    uuidValue(state.accountId, 'account ID');
    uuidValue(state.deviceId, 'device ID');
    if (!['passkey-prf', 'remembered'].includes(state.protectionMode) || !state.protection || !state.encryptedPrivateBundle) invalid('Invalid local device state.');
    if (state.rememberedKey && state.rememberedKey.extractable !== false) invalid('Remembered device keys must be non-extractable.');
    await db.deviceState.put(state);
}

export async function loadDeviceState(accountId: string): Promise<DeviceLocalState | null> {
    const state = await db.deviceState.get(accountId);
    return state ? state as DeviceLocalState : null;
}

export async function deleteDeviceState(accountId: string, completeLocalWipe = false): Promise<void> {
    if (completeLocalWipe) await db.deviceState.clear();
    else await db.deviceState.delete(accountId);
}

export { digestAuthorizationToken, fingerprintPublicJwk };
