import type { DeviceLease, DeviceLeaseClaims } from '../types';

const DAY = 24 * 60 * 60 * 1000;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;

export interface LeaseExpectation {
    now: number;
    deviceId: string;
    accountId?: string;
    generation?: string;
    publicKeyFingerprint?: string;
}

export const canonicalLeasePayload = (claims: DeviceLeaseClaims): Uint8Array => new TextEncoder().encode(JSON.stringify(claims));

const bytes = (value: string): Uint8Array | null => {
    if (!BASE64.test(value)) return null;
    try {
        const binary = atob(value);
        const decoded = Uint8Array.from(binary, char => char.charCodeAt(0));
        return btoa(binary) === value ? decoded : null;
    } catch {
        return null;
    }
};

const base64urlBytes = (value: unknown): Uint8Array | null => {
    if (typeof value !== 'string' || !BASE64URL.test(value) || value.length % 4 === 1) return null;
    const decoded = bytes(value.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((value.length + 3) % 4));
    if (!decoded) return null;
    const canonical = btoa(String.fromCharCode(...decoded)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return canonical === value ? decoded : null;
};

const validPublicJwk = (jwk: JsonWebKey): boolean => {
    if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || 'd' in jwk) return false;
    const x = base64urlBytes(jwk.x);
    const y = base64urlBytes(jwk.y);
    try {
        return x?.byteLength === 32 && y?.byteLength === 32;
    } finally {
        x?.fill(0);
        y?.fill(0);
    }
};

const validClaims = (claims: unknown, expected: LeaseExpectation): claims is DeviceLeaseClaims => {
    if (!Array.isArray(claims) || claims.length !== 7 || claims[0] !== 1 ||
        !claims.slice(1, 4).every(value => typeof value === 'string' && value.length > 0) ||
        !Number.isSafeInteger(claims[4]) || !Number.isSafeInteger(claims[5]) ||
        typeof claims[6] !== 'string' || claims[6].length === 0 ||
        !Number.isSafeInteger(expected.now) || claims[4] > expected.now ||
        claims[5] - claims[4] !== 30 * DAY || expected.now >= claims[5] ||
        claims[1] !== expected.deviceId ||
        expected.accountId !== undefined && claims[2] !== expected.accountId ||
        expected.generation !== undefined && claims[3] !== expected.generation ||
        expected.publicKeyFingerprint !== undefined && claims[6] !== expected.publicKeyFingerprint) return false;
    return true;
};

export const verifyDeviceLease = async (lease: DeviceLease, publicJwk: JsonWebKey, expected: LeaseExpectation): Promise<boolean> => {
    try {
        if (!lease || lease.version !== 1 || !validClaims(lease.claims, expected) || !validPublicJwk(publicJwk)) return false;
        const signature = bytes(lease.signature);
        if (!signature) return false;
        try {
            const key = await crypto.subtle.importKey('jwk', publicJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
            return await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, signature as unknown as BufferSource, canonicalLeasePayload(lease.claims) as unknown as BufferSource);
        } finally {
            signature.fill(0);
        }
    } catch {
        return false;
    }
};
