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

/**
 * Derives an AES-GCM 256-bit CryptoKey from a user's chosen password
 * Uses a hardcoded salt since this is an offline-first PWA where the salt 
 * cannot be securely fetched prior to decryption.
 */
export const deriveEncryptionKey = async (password: string): Promise<CryptoKey> => {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
    );

    const salt = encoder.encode("QuoteVault-FixedSalt-2026"); // In a real prod environment, this could be user-specific if fetched from a non-e2ee store

    return await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
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
    } catch (error) {
        console.error("Decryption failed. Invalid key or corrupted data.", error);
        throw new Error("Failed to decrypt generic payload. Invalid vault key.");
    }
};

/**
 * Generates a SHA-256 hash of a string to be used strictly for verification.
 * This allows the server to verify if a Vault Key is correct WITHOUT ever
 * storing the actual decryption key in the database.
 */
export const hashVaultKey = async (password: string): Promise<string> => {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
};
