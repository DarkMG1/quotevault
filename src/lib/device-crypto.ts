import { arrayBufferToBase64, base64ToArrayBuffer } from './crypto';
import type {
    BundleBinding,
    EnvelopeCiphertext,
    PrivateDeviceBundle,
    RecoveryKdf,
    VaultKeyWrapperBinding,
    VaultKeyWrapperPlaintext,
} from '../types';

export type {
    BundleBinding,
    DeviceLease,
    DeviceLeaseClaims,
    EnvelopeCiphertext,
    PrivateDeviceBundle,
    RecoveryKdf,
    VaultKeyWrapperBinding,
    VaultKeyWrapperPlaintext,
} from '../types';

export const RECOVERY_ITERATIONS = 600_000;
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;

const fail = (): never => { throw new Error('Invalid encrypted device data.'); };
const text = (value: unknown): value is string => typeof value === 'string' && value.length > 0;
const source = (bytes: Uint8Array): BufferSource => bytes as unknown as BufferSource;
const bytesToBase64 = (bytes: Uint8Array): string => arrayBufferToBase64(bytes);
const base64ToBytes = (value: unknown): Uint8Array => {
    if (typeof value !== 'string') return fail();
    const encoded = value;
    if (!BASE64.test(encoded)) fail();
    const bytes = new Uint8Array(base64ToArrayBuffer(encoded));
    if (bytesToBase64(bytes) !== encoded) fail();
    return bytes;
};
const bytesToBase64url = (bytes: Uint8Array): string => bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const base64urlToBytes = (value: unknown): Uint8Array => {
    if (typeof value !== 'string') return fail();
    const encoded = value;
    if (!BASE64URL.test(encoded) || encoded.length % 4 === 1) fail();
    const bytes = base64ToBytes(encoded.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((encoded.length + 3) % 4));
    if (bytesToBase64url(bytes) !== encoded) fail();
    return bytes;
};
const exactMasterKey = (value: unknown): Uint8Array => {
    if (!(value instanceof Uint8Array) || value.byteLength !== 32) fail();
    return value as Uint8Array;
};
const validBinding = (binding: BundleBinding): void => {
    if (!text(binding.accountId) || !text(binding.recordId) || !text(binding.publicKeyFingerprint) || binding.version !== 1 ||
        !['passkey-prf', 'remembered', 'recovery'].includes(binding.protectionMode)) fail();
};
const bundleAad = (binding: BundleBinding): string => {
    validBinding(binding);
    return JSON.stringify([1, binding.accountId, binding.recordId, binding.publicKeyFingerprint, binding.protectionMode, binding.version]);
};

export const generateVaultMasterKey = (): Uint8Array => crypto.getRandomValues(new Uint8Array(32));

export const deriveQuoteKey = async (masterKey: Uint8Array, generation: string): Promise<CryptoKey> => {
    exactMasterKey(masterKey);
    if (!text(generation)) fail();
    const material = await crypto.subtle.importKey('raw', source(masterKey), 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt: source(new Uint8Array()), info: source(encoder.encode(JSON.stringify([2, 'quote', generation]))) },
        material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
};

export const encryptEnvelope = async (plaintext: string, key: CryptoKey, aad: string): Promise<EnvelopeCiphertext> => {
    if (typeof plaintext !== 'string' || typeof aad !== 'string') fail();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: source(iv), additionalData: source(encoder.encode(aad)) }, key, source(encoder.encode(plaintext)));
    return { version: 2, iv: bytesToBase64(iv), data: arrayBufferToBase64(data) };
};

export const decryptEnvelope = async (payload: EnvelopeCiphertext, key: CryptoKey, aad: string): Promise<string> => {
    try {
        if (!payload || payload.version !== 2 || typeof aad !== 'string') fail();
        const iv = base64ToBytes(payload.iv);
        if (iv.byteLength !== 12) fail();
        const data = base64ToBytes(payload.data);
        if (data.byteLength < 16) fail();
        return decoder.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: source(iv), additionalData: source(encoder.encode(aad)) }, key, source(data)));
    } catch {
        return fail();
    }
};

export const generateWrappingKeyPair = (): Promise<CryptoKeyPair> => crypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']
) as Promise<CryptoKeyPair>;

export const fingerprintPublicJwk = async (jwk: JsonWebKey): Promise<string> => {
    if (!jwk || jwk.kty !== 'RSA') fail();
    if (typeof jwk.n !== 'string' || typeof jwk.e !== 'string') fail();
    const modulus = base64urlToBytes(jwk.n);
    const exponent = base64urlToBytes(jwk.e);
    if (modulus.byteLength !== 384 || (modulus[0] & 0x80) === 0 || jwk.e !== 'AQAB' || exponent.byteLength !== 3 || exponent[0] !== 1 || exponent[1] !== 0 || exponent[2] !== 1) fail();
    const canonical = JSON.stringify([1, 'RSA-OAEP', 'SHA-256', jwk.n, jwk.e]);
    return bytesToBase64url(new Uint8Array(await crypto.subtle.digest('SHA-256', source(encoder.encode(canonical)))));
};

export const wrapVaultKey = async (input: VaultKeyWrapperPlaintext, publicKey: CryptoKey): Promise<string> => {
    if (!input || input.version !== 1 || input.vaultId !== 'quotevault' || !text(input.generation) || !text(input.targetFingerprint)) fail();
    const masterKey = exactMasterKey(input.masterKey);
    const plaintext = encoder.encode(JSON.stringify([1, input.vaultId, input.generation, input.targetFingerprint, bytesToBase64url(masterKey)]));
    try {
        return bytesToBase64url(new Uint8Array(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, source(plaintext))));
    } finally {
        plaintext.fill(0);
    }
};

export const unwrapVaultKey = async (ciphertext: string, privateKey: CryptoKey, expected: VaultKeyWrapperBinding): Promise<Uint8Array> => {
    let plaintext: Uint8Array | undefined;
    try {
        if (!expected || expected.vaultId !== 'quotevault' || !text(expected.generation) || !text(expected.targetFingerprint)) fail();
        plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, source(base64urlToBytes(ciphertext))));
        const value: unknown = JSON.parse(decoder.decode(plaintext));
        if (!Array.isArray(value) || value.length !== 5 || value[0] !== 1 || value[1] !== expected.vaultId || value[2] !== expected.generation || value[3] !== expected.targetFingerprint) fail();
        return exactMasterKey(base64urlToBytes((value as unknown[])[4]));
    } catch {
        return fail();
    } finally {
        plaintext?.fill(0);
    }
};

export const generateAuthorizationToken = (): string => {
    const token = crypto.getRandomValues(new Uint8Array(32));
    try { return bytesToBase64url(token); } finally { token.fill(0); }
};

export const digestAuthorizationToken = async (token: string): Promise<string> => {
    const bytes = base64urlToBytes(token);
    try {
        if (bytes.byteLength !== 32) fail();
        return bytesToBase64url(new Uint8Array(await crypto.subtle.digest('SHA-256', source(bytes))));
    } finally {
        bytes.fill(0);
    }
};

export const deriveRecoveryBundleKey = async (phrase: string, kdf: RecoveryKdf): Promise<CryptoKey> => {
    if (!text(phrase) || !kdf || kdf.version !== 1 || kdf.iterations !== RECOVERY_ITERATIONS) fail();
    const salt = base64ToBytes(kdf.salt);
    if (salt.byteLength < 16 || salt.byteLength > 64) fail();
    const phraseBytes = encoder.encode(phrase);
    try {
        const material = await crypto.subtle.importKey('raw', source(phraseBytes), 'PBKDF2', false, ['deriveKey']);
        return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: source(salt), iterations: RECOVERY_ITERATIONS, hash: 'SHA-256' }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    } finally {
        phraseBytes.fill(0);
        salt.fill(0);
    }
};

const validBundle = async (value: unknown, binding: BundleBinding): Promise<boolean> => {
    if (!value || typeof value !== 'object') return false;
    const bundle = value as Partial<PrivateDeviceBundle>;
    if (bundle.version !== 1 || !bundle.privateJwk || typeof bundle.privateJwk !== 'object' || typeof bundle.authorizationToken !== 'string') return false;
    try {
        const token = base64urlToBytes(bundle.authorizationToken);
        try {
            if (token.byteLength !== 32) return false;
        } finally {
            token.fill(0);
        }
        const privateJwk = bundle.privateJwk as JsonWebKey;
        for (const field of ['d', 'p', 'q', 'dp', 'dq', 'qi'] as const) {
            const bytes = base64urlToBytes(privateJwk[field]);
            try {
                if (bytes.byteLength === 0) return false;
            } finally {
                bytes.fill(0);
            }
        }
        if (await fingerprintPublicJwk(privateJwk) !== binding.publicKeyFingerprint) return false;
        await crypto.subtle.importKey('jwk', privateJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
        return true;
    } catch {
        return false;
    }
};

export const encryptPrivateBundle = async (bundle: PrivateDeviceBundle, key: CryptoKey, binding: BundleBinding): Promise<EnvelopeCiphertext> => {
    if (!await validBundle(bundle, binding)) fail();
    return encryptEnvelope(JSON.stringify(bundle), key, bundleAad(binding));
};

export const decryptPrivateBundle = async (payload: EnvelopeCiphertext, key: CryptoKey, binding: BundleBinding): Promise<PrivateDeviceBundle> => {
    try {
        const bundle: unknown = JSON.parse(await decryptEnvelope(payload, key, bundleAad(binding)));
        if (!await validBundle(bundle, binding)) fail();
        return bundle as PrivateDeviceBundle;
    } catch {
        return fail();
    }
};
