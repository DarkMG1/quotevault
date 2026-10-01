// Utility to convert ArrayBuffer to Base64 string
const arrayBufferToBase64 = (buffer: ArrayBuffer): string => {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
};

// Utility to convert Base64 string back to ArrayBuffer
const base64ToArrayBuffer = (base64: string): ArrayBuffer => {
    const binary_string = atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
};

export interface VaultKdf { salt: string; iterations: number }
// Existing ciphertext must retain its original derivation until an explicit vault reset.
export const LEGACY_KDF: VaultKdf = { salt: btoa('QuoteVault-FixedSalt-2026'), iterations: 100000 };

export const deriveEncryptionKey = async (password: string, kdf: VaultKdf = LEGACY_KDF): Promise<CryptoKey> => {
    const salt = base64ToArrayBuffer(kdf.salt);
    if (salt.byteLength < 16 || salt.byteLength > 64 || !Number.isInteger(kdf.iterations) ||
        kdf.iterations < 100000 || kdf.iterations > 2000000) {
        throw new Error('Invalid vault encryption settings.');
    }
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    return await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: kdf.iterations,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
};

export interface EncryptedPayload {
    iv: string; // Base64 Initialization Vector
    data: string; // Base64 Ciphertext
}

/**
 * Encrypts a plaintext string (typically JSON.stringify) using the provided key.
 */
export const encryptData = async (plaintext: string, key: CryptoKey): Promise<EncryptedPayload> => {
    const encoder = new TextEncoder();
    const encodedData = encoder.encode(plaintext);

    // AES-GCM requires a unique Initialization Vector per encryption
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const ciphertext = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        encodedData
    );

    return {
        iv: arrayBufferToBase64(iv.buffer),
        data: arrayBufferToBase64(ciphertext)
    };
};

/**
 * Decrypts an EncryptedPayload back into plaintext using the provided key.
 */
export const decryptData = async (payload: EncryptedPayload, key: CryptoKey): Promise<string> => {
    try {
        const ivBuffer = base64ToArrayBuffer(payload.iv);
        const dataBuffer = base64ToArrayBuffer(payload.data);

        const decryptedBuffer = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: ivBuffer
            },
            key,
            dataBuffer
        );

        const decoder = new TextDecoder();
        return decoder.decode(decryptedBuffer);
    } catch {
        throw new Error('Incorrect vault key or damaged encrypted data.');
    }
};

export const createVaultConfig = async (password: string) => {
    if (password.length < 12) throw new Error('Use a vault passphrase of at least 12 characters.');
    const kdf = { salt: arrayBufferToBase64(crypto.getRandomValues(new Uint8Array(16)).buffer), iterations: 600000 };
    const key = await deriveEncryptionKey(password, kdf);
    return { kdf, verifier: await encryptData(JSON.stringify({ quotevault: 1 }), key), key };
};

export const unlockWithVerifier = async (password: string, kdf: VaultKdf, verifier: EncryptedPayload) => {
    const key = await deriveEncryptionKey(password, kdf);
    const value: unknown = JSON.parse(await decryptData(verifier, key));
    if (!value || typeof value !== 'object' ||
        !('quotevault' in value && value.quotevault === 1) &&
        !('text' in value && typeof value.text === 'string' && 'author' in value && typeof value.author === 'string')) {
        throw new Error('Invalid vault verification data.');
    }
    return key;
};
