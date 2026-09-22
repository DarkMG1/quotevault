import { loadDeviceState, requestDevice, saveDeviceState, validateDeviceProtection } from './device';
import { decryptPrivateBundle, digestAuthorizationToken, encryptPrivateBundle, fingerprintPublicJwk, generateAuthorizationToken, generateWrappingKeyPair } from './device-crypto';
import { verifyDeviceLease } from './lease';
import { supabase } from './supabase';
import { arrayBufferToBase64, base64ToArrayBuffer } from './crypto';
import type { DeviceLease, DeviceLocalState, EnvelopeCiphertext, PrivateDeviceBundle } from '../types';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const B64URL = /^[A-Za-z0-9_-]+$/;
const B64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const fail = (message = 'Invalid device security response.'): never => { throw new Error(message); };
const object = (value: unknown, message = 'Invalid device security response.'): Record<string, unknown> => value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : fail(message);
const exact = (value: unknown, fields: string[], message = 'Invalid device security response.'): Record<string, unknown> => { const data = object(value, message); if (Object.keys(data).length !== fields.length || !fields.every(field => Object.prototype.hasOwnProperty.call(data, field))) fail(message); return data; };
const uuid = (value: unknown, message = 'Invalid device security response.'): string => typeof value === 'string' && UUID.test(value) ? value : fail(message);
const b64url = (bytes: Uint8Array): string => arrayBufferToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64urlBytes = (value: unknown, min: number, max = min): Uint8Array => {
    if (typeof value !== 'string' || !B64URL.test(value) || value.length % 4 === 1) fail();
    const encoded = value as string; const bytes = new Uint8Array(base64ToArrayBuffer(`${encoded.replace(/-/g, '+').replace(/_/g, '/')}${'==='.slice((encoded.length + 3) % 4)}`));
    if (bytes.byteLength < min || bytes.byteLength > max || b64url(bytes) !== encoded) fail(); return bytes;
};
const b64 = (value: unknown, min: number, max = min): string => { if (typeof value !== 'string' || !B64.test(value)) fail(); const encoded = value as string; const bytes = new Uint8Array(base64ToArrayBuffer(encoded)); if (bytes.byteLength < min || bytes.byteLength > max || arrayBufferToBase64(bytes) !== encoded) fail(); return encoded; };
const envelope = (value: unknown): EnvelopeCiphertext => { const data = exact(value, ['version', 'iv', 'data']); if (data.version !== 2) fail(); return { version: 2, iv: b64(data.iv, 12), data: b64(data.data, 16, Number.MAX_SAFE_INTEGER) }; };
const generation = (value: unknown): string => uuid(value);
const protection = (value: unknown): Record<string, unknown> => validateDeviceProtection(value, 'passkey-prf');
const edge = async (body: Record<string, unknown>): Promise<unknown> => { const { data, error } = await supabase.functions.invoke('vault-security', { body }); if (error) fail('Device security request failed.'); return data; };
const rpc = async (name: string, args: Record<string, unknown>): Promise<unknown> => { const { data, error } = await supabase.rpc(name, args); if (error) fail('Device security request failed.'); return data; };

export interface PasskeyProtection { version: 1; rpId: 'quotes.darkmg1.dev'; credentialId: string; prfSalt: string }
export interface PasskeyRestoreDevice { deviceId: string; generation: string; protection: PasskeyProtection; publicKeyFingerprint: string; encryptedPrivateBundle: EnvelopeCiphertext }

export async function getPasskeyRestoreDevices(): Promise<PasskeyRestoreDevice[]> {
    const response = exact(await rpc('get_passkey_restore_devices', {}), ['generation', 'devices'], 'Invalid passkey restore response.');
    const currentGeneration = generation(response.generation);
    if (!Array.isArray(response.devices)) fail('Invalid passkey restore response.');
    return (response.devices as unknown[]).map(value => { const data = exact(value, ['device_id', 'protection_mode', 'protection', 'public_key_fingerprint', 'encrypted_private_bundle'], 'Invalid passkey restore response.'); if (data.protection_mode !== 'passkey-prf') fail('Invalid passkey restore response.'); b64urlBytes(data.public_key_fingerprint, 32); return { deviceId: uuid(data.device_id, 'Invalid passkey restore response.'), generation: currentGeneration, protection: protection(data.protection) as unknown as PasskeyProtection, publicKeyFingerprint: data.public_key_fingerprint as string, encryptedPrivateBundle: envelope(data.encrypted_private_bundle) }; });
}

const lease = (value: unknown): DeviceLease => { const data = exact(value, ['version', 'claims', 'signature'], 'Invalid device lease.'); if (data.version !== 1 || !Array.isArray(data.claims) || data.claims.length !== 7 || typeof data.signature !== 'string') fail('Invalid device lease.'); b64(data.signature, 1, Number.MAX_SAFE_INTEGER); return { version: 1, claims: data.claims as DeviceLease['claims'], signature: data.signature as string }; };
export async function renewDeviceLease(input: { accountId: string; deviceId: string; token: string; generation: string; publicKeyFingerprint: string; now?: number }): Promise<DeviceLocalState> {
    const state = await loadDeviceState(input.accountId); if (!state || state.deviceId !== input.deviceId) fail('Device enrollment state is missing.'); const current = state as DeviceLocalState;
    b64urlBytes(input.token, 32); b64urlBytes(input.publicKeyFingerprint, 32); const signed = lease(await edge({ action: 'renew', deviceId: input.deviceId, token: input.token }));
    if (!await verifyDeviceLease(signed, { now: input.now ?? Date.now(), deviceId: input.deviceId, accountId: input.accountId, generation: input.generation, publicKeyFingerprint: input.publicKeyFingerprint })) fail('Invalid device lease.');
    const next: DeviceLocalState = { ...current, lease: signed }; await saveDeviceState(next); return next;
}

type PrfCredential = { rawId: ArrayBuffer; getClientExtensionResults(): { prf?: { enabled?: boolean; results?: { first?: ArrayBuffer } } } };
const passkeyError = (error: unknown): never => { if ((error as { name?: unknown })?.name === 'NotAllowedError') throw new Error('Passkey request was cancelled. Use another device, recovery, or an administrator.'); throw new Error('Passkey is unavailable. Use another device, recovery, or an administrator.'); };
export async function unlockPasskey(input: PasskeyProtection, serverChallenge?: string): Promise<CryptoKey> {
    const checked = protection(input) as unknown as PasskeyProtection; const credentialId = b64urlBytes(checked.credentialId, 1, 1024); const salt = b64urlBytes(checked.prfSalt, 32); let challenge: Uint8Array | undefined;
    try { challenge = serverChallenge === undefined ? crypto.getRandomValues(new Uint8Array(32)) : b64urlBytes(serverChallenge, 32); const credentials = (typeof navigator === 'undefined' ? undefined : navigator.credentials) as CredentialsContainer | undefined; if (!credentials) fail('Passkey is unavailable. Use another device, recovery, or an administrator.'); const credential = await (credentials as CredentialsContainer).get({ publicKey: { challenge, rpId: checked.rpId, allowCredentials: [{ type: 'public-key', id: credentialId }], userVerification: 'required', extensions: { prf: { eval: { first: salt } } } } } as CredentialRequestOptions) as unknown as PrfCredential | null; const result = credential?.getClientExtensionResults().prf?.results?.first; if (!result || result.byteLength !== 32) fail('Passkey does not support PRF. Use another device, recovery, or an administrator.'); return crypto.subtle.importKey('raw', result as BufferSource, 'AES-GCM', false, ['encrypt', 'decrypt']); } catch (error) { if (error instanceof Error && error.message.startsWith('Passkey')) throw error; return passkeyError(error); } finally { credentialId.fill(0); salt.fill(0); challenge?.fill(0); }
}

export async function prepareDeviceEnrollment(input: { accountId: string; label: string; requestKind: 'first' | 'additional' | 'recovery'; protectionMode: 'remembered' | 'passkey-prf'; protection: Record<string, unknown>; encryptionKey?: CryptoKey }): Promise<{ deviceId: string; authorizationToken: string; privateKey: CryptoKey; publicKeyFingerprint: string; rememberedKey?: CryptoKey }> {
    const deviceId = crypto.randomUUID(); uuid(input.accountId); const checked = input.protectionMode === 'remembered' ? validateDeviceProtection(input.protection, 'remembered') : protection(input.protection); const key = input.protectionMode === 'remembered' ? await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']) : input.encryptionKey; if (!key) fail('Passkey key is required.');
    const encryptionKey = key as CryptoKey; const pair = await generateWrappingKeyPair(); const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey); const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey); const publicKeyFingerprint = await fingerprintPublicJwk(publicJwk); const authorizationToken = generateAuthorizationToken(); const tokenDigest = await digestAuthorizationToken(authorizationToken); const encryptedPrivateBundle = await encryptPrivateBundle({ version: 1, privateJwk, authorizationToken }, encryptionKey, { accountId: input.accountId, recordId: deviceId, publicKeyFingerprint, protectionMode: input.protectionMode, version: 1 }); const state: DeviceLocalState = { accountId: input.accountId, deviceId, publicKeyFingerprint, protectionMode: input.protectionMode, protection: checked, encryptedPrivateBundle }; if (input.protectionMode === 'remembered') state.rememberedKey = encryptionKey; await saveDeviceState(state); await requestDevice({ deviceId, ownerId: input.accountId, label: input.label, publicJwk, publicKeyFingerprint, tokenDigest, protectionMode: input.protectionMode, protection: checked, encryptedPrivateBundle, requestKind: input.requestKind }); return { deviceId, authorizationToken, privateKey: pair.privateKey, publicKeyFingerprint, ...(input.protectionMode === 'remembered' ? { rememberedKey: encryptionKey } : {}) };
}

export async function decryptDeviceBundle(state: DeviceLocalState, key: CryptoKey): Promise<{ privateKey: CryptoKey; authorizationToken: string }> { const bundle: PrivateDeviceBundle = await decryptPrivateBundle(state.encryptedPrivateBundle, key, { accountId: state.accountId, recordId: state.deviceId, publicKeyFingerprint: state.publicKeyFingerprint, protectionMode: state.protectionMode, version: 1 }); const privateKey = await crypto.subtle.importKey('jwk', bundle.privateJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']); return { privateKey, authorizationToken: bundle.authorizationToken }; }
