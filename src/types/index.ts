export interface Quote {
    id: string; // UUID
    text: string;
    author: string;
    context?: string | null;
    quote_date?: string | null; // YYYY-MM-DD
    created_at: string; // ISO string
    user_id: string;
    vault_generation: string;
    sync_status?: 'synced' | 'pending' | 'rejected'; // Local only flag
    source_sender?: string; // Display-only: populated solely after decrypting the payload bundle
}

export interface SyncQueueItem {
    id: string; // operation_id; never reuse a quote ID as a queue key
    operation_id: string;
    action: 'INSERT' | 'DELETE';
    quote_id: string;
    actor_id?: string;
    vault_generation?: string;
    payload?: Quote; // INSERT only; DELETE must never retain quote contents
    created_at: string;
    status?: 'pending' | 'rejected' | 'blocked';
    error?: string;
}

export interface SyncMetadata {
    id: string;
    value: string | number;
}

export interface EnvelopeCiphertext { version: 2; iv: string; data: string }
export interface RecoveryKdf { version: 1; salt: string; iterations: 600000 }
export interface PasskeyPrfProtection { version: 1; rpId: 'quotes.darkmg1.dev'; credentialId: string; prfSalt: string; kdf: 'HKDF-SHA-256' }
export interface BundleBinding {
    accountId: string; recordId: string; publicKeyFingerprint: string;
    protectionMode: 'passkey-prf' | 'remembered' | 'recovery'; version: 1;
    recoveryKdf?: RecoveryKdf;
    protection?: PasskeyPrfProtection;
}
export interface PrivateDeviceBundle { version: 1; privateJwk: JsonWebKey; authorizationToken: string }
export interface VaultKeyWrapperBinding { vaultId: 'quotevault'; generation: string; targetFingerprint: string }
export interface VaultKeyWrapperPlaintext extends VaultKeyWrapperBinding { version: 1; masterKey: Uint8Array }
export type DeviceLeaseClaims = readonly [1, string, string, string, number, number, string];
export interface DeviceLease { version: 1; claims: DeviceLeaseClaims; signature: string }
export interface DeviceLocalState {
    accountId: string;
    deviceId: string;
    publicKeyFingerprint: string;
    protectionMode: 'passkey-prf' | 'remembered';
    protection: Record<string, unknown>;
    encryptedPrivateBundle: EnvelopeCiphertext;
    rememberedKey?: CryptoKey;
    lease?: DeviceLease;
    wrapper?: { generation: string; wrappedKey: string };
}
