import { supabase } from './supabase';
import type { EncryptedPayload, VaultKdf } from './crypto';

export interface VaultState {
    generation: string;
    legacy_generation: string | null;
    kdf: VaultKdf;
    verifier: EncryptedPayload | null;
}

export function parseVaultState(value: unknown): VaultState {
    if (!value || typeof value !== 'object') throw new Error('Missing vault settings.');
    const state = value as VaultState;
    if (typeof state.generation !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(state.generation) ||
        !state.kdf || typeof state.kdf.salt !== 'string' || !Number.isInteger(state.kdf.iterations) ||
        state.kdf.iterations < 100000 || state.kdf.iterations > 2000000 ||
        state.legacy_generation !== null && state.legacy_generation !== state.generation ||
        state.verifier !== null && (!state.verifier || typeof state.verifier.iv !== 'string' || typeof state.verifier.data !== 'string')) {
        throw new Error('Invalid vault settings.');
    }
    try {
        const saltLength = atob(state.kdf.salt).length;
        if (saltLength < 16 || saltLength > 64 || state.verifier &&
            (atob(state.verifier.iv).length !== 12 || atob(state.verifier.data).length < 16)) {
            throw new Error('Invalid metadata');
        }
    } catch {
        throw new Error('Invalid vault settings.');
    }
    return state;
}

const cacheKey = (userId: string) => `quotevault:settings:${userId}`;
export function cacheVaultState(userId: string, state: VaultState) {
    // Public derivation metadata and authenticated ciphertext only; never the key/password.
    try { localStorage.setItem(cacheKey(userId), JSON.stringify(state)); } catch { /* Storage may be disabled. */ }
}

export async function loadVaultState(userId: string): Promise<VaultState> {
    let cached: VaultState | null = null;
    try { cached = parseVaultState(JSON.parse(localStorage.getItem(cacheKey(userId)) || 'null')); } catch { /* No valid cache yet. */ }
    if (!navigator.onLine) {
        if (cached) return cached;
        throw new Error('Connect once to prepare this account for offline access.');
    }
    const { data, error } = await supabase.rpc('get_vault_state');
    if (error) {
        if (!error.code && cached) return cached; // Transport failure, not an authorization denial.
        throw new Error(error.message || 'Could not load vault settings.');
    }
    const state = parseVaultState(data);
    cacheVaultState(userId, state);
    return state;
}
