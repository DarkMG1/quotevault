import { supabase } from './supabase';
import type { EncryptedPayload, VaultKdf } from './crypto';

type EnvelopeStatus = 'legacy' | 'preparing' | 'staging' | 'active' | 'maintenance';
interface VaultStateBase { envelope_status: EnvelopeStatus; generation: string; prepared_generation: string | null }
export interface LegacyVaultState extends VaultStateBase {
    envelope_status: 'legacy' | 'preparing';
    legacy_generation: string | null;
    kdf: VaultKdf;
    verifier: EncryptedPayload | null;
}
export interface EnvelopeVaultState extends VaultStateBase { envelope_status: 'preparing' | 'staging' | 'active' | 'maintenance' }
export type VaultState = LegacyVaultState | EnvelopeVaultState;
export const LEGACY_CONVERSION_KEY_REQUIRED = 'Enter your previous group vault key once to convert older saved changes.';

const uuid = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
const invalid = (): never => { throw new Error('Invalid vault settings.'); };

export function isLegacyVaultState(value: VaultState | null): value is LegacyVaultState {
    return value?.envelope_status === 'legacy' || value?.envelope_status === 'preparing' && 'kdf' in value;
}

export const quoteGeneration = (state: VaultState): string => state.generation;
export const enrollmentGeneration = (state: VaultState): string => state.envelope_status === 'preparing' && state.prepared_generation ? state.prepared_generation : state.generation;
// A retained rotation keeps the source readable until the staged target is activated.
export const approvalGeneration = (state: VaultState): string => state.envelope_status === 'preparing' && !isLegacyVaultState(state) ? state.generation : enrollmentGeneration(state);

export function parseVaultState(value: unknown): VaultState {
    if (!value || typeof value !== 'object' || Array.isArray(value)) invalid();
    const state = value as Record<string, unknown>;
    const status = state.envelope_status;
    const generation = state.generation;
    const preparedGeneration = state.prepared_generation;
    if (!uuid(generation) || !('prepared_generation' in state) || preparedGeneration !== null && !uuid(preparedGeneration)
        || !['legacy', 'preparing', 'staging', 'active', 'maintenance'].includes(status as string)) invalid();
    const base: VaultStateBase = { envelope_status: status as EnvelopeStatus, generation: generation as string, prepared_generation: preparedGeneration as string | null };
    const hasLegacyFields = ['kdf', 'verifier', 'legacy_generation'].some(key => key in state);
    if (status !== 'legacy' && (status !== 'preparing' || !hasLegacyFields)) {
        if ('kdf' in state || 'verifier' in state || 'legacy_generation' in state) invalid();
        return base as EnvelopeVaultState;
    }
    const kdf = state.kdf as VaultKdf;
    const verifier = state.verifier as EncryptedPayload | null;
    if (!kdf || typeof kdf.salt !== 'string' || !Number.isInteger(kdf.iterations) || kdf.iterations < 100000 || kdf.iterations > 2000000
        || state.legacy_generation !== null && state.legacy_generation !== state.generation
        || verifier !== null && (!verifier || typeof verifier.iv !== 'string' || typeof verifier.data !== 'string')) invalid();
    try {
        const saltLength = atob(kdf.salt).length;
        if (saltLength < 16 || saltLength > 64 || verifier && (atob(verifier.iv).length !== 12 || atob(verifier.data).length < 16)) invalid();
    } catch {
        invalid();
    }
    return { ...base, envelope_status: status, legacy_generation: state.legacy_generation as string | null, kdf, verifier } as LegacyVaultState;
}

export function parseLegacyVaultMutation(value: unknown): LegacyVaultState {
    if (!value || typeof value !== 'object' || Array.isArray(value)
        || 'envelope_status' in value || 'prepared_generation' in value) invalid();
    return parseVaultState({ ...(value as Record<string, unknown>), envelope_status: 'legacy', prepared_generation: null }) as LegacyVaultState;
}

const cacheKey = (userId: string) => `quotevault:settings:${userId}`;
const legacyConversionKey = (userId: string) => `quotevault:legacy-conversion:${userId}`;
export interface LegacyConversionState { generation: string; kdf: VaultKdf; verifier: EncryptedPayload }
export function cacheVaultState(userId: string, state: VaultState) {
    // Public derivation metadata and authenticated ciphertext only; never the key/password.
    try { localStorage.setItem(cacheKey(userId), JSON.stringify(state)); if (isLegacyVaultState(state) && state.verifier) localStorage.setItem(legacyConversionKey(userId), JSON.stringify({ generation: state.generation, kdf: state.kdf, verifier: state.verifier })); } catch { /* Storage may be disabled. */ }
}

export function readLegacyConversionState(userId: string): LegacyConversionState | null {
    try {
        const value = JSON.parse(localStorage.getItem(legacyConversionKey(userId)) || 'null') as Record<string, unknown> | null;
        if (!value) return null;
        const parsed = parseVaultState({ envelope_status: 'legacy', generation: value.generation, prepared_generation: null, legacy_generation: value.generation, kdf: value.kdf, verifier: value.verifier });
        return isLegacyVaultState(parsed) && parsed.verifier ? { generation: parsed.generation, kdf: parsed.kdf, verifier: parsed.verifier } : null;
    } catch { return null; }
}

export function clearLegacyConversionState(userId: string): void {
    try { localStorage.removeItem(legacyConversionKey(userId)); } catch { /* Storage may be disabled. */ }
}

export function readCachedVaultState(userId: string): VaultState | null {
    try {
        const value: unknown = JSON.parse(localStorage.getItem(cacheKey(userId)) || 'null');
        const cached = value && typeof value === 'object' && !Array.isArray(value) && !('envelope_status' in value)
            ? { ...(value as Record<string, unknown>), envelope_status: 'legacy', prepared_generation: null }
            : value;
        return parseVaultState(cached);
    } catch {
        return null;
    }
}

export function clearCachedVaultState(userId: string): void {
    try { localStorage.removeItem(cacheKey(userId)); localStorage.removeItem(legacyConversionKey(userId)); } catch { /* Storage may be disabled. */ }
}

export async function loadVaultState(userId: string, localOnly = false): Promise<VaultState> {
    const cached = readCachedVaultState(userId);
    if (localOnly || !navigator.onLine) {
        if (cached) return cached;
        throw new Error('Connect once to prepare this account for offline access.');
    }
    const { data, error } = await supabase.rpc('get_vault_bootstrap_state');
    if (error) {
        if (!error.code && cached) return cached; // Transport failure, not an authorization denial.
        clearCachedVaultState(userId);
        throw new Error(error.message || 'Could not load vault settings.');
    }
    const state = parseVaultState(data);
    if (cached && isLegacyVaultState(cached) && cached.verifier) cacheVaultState(userId, cached);
    cacheVaultState(userId, state);
    return state;
}
