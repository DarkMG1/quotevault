import { supabase } from './supabase';

export interface AuthorProfile {
    id?: string;
    first_name: string;
    last_name?: string | null;
}

interface CachedProfiles {
    profiles: AuthorProfile[];
    fetchedAt: number;
}

const PROFILE_CACHE_TTL_MS = 5 * 60 * 1000;
const profileMemory = new Map<string, CachedProfiles>();
const profileRequests = new Map<string, Promise<AuthorProfile[]>>();

function normalizeProfiles(data: unknown): AuthorProfile[] {
    if (!Array.isArray(data)) return [];
    return data.filter((profile): profile is AuthorProfile => {
        if (typeof profile !== 'object' || profile === null) return false;
        const candidate = profile as Record<string, unknown>;
        return typeof candidate.first_name === 'string' &&
            (candidate.id === undefined || typeof candidate.id === 'string') &&
            (candidate.last_name === undefined || candidate.last_name === null || typeof candidate.last_name === 'string');
    });
}

function profileStorageKey(userId: string): string {
    return `quotevault:profiles:${userId}`;
}

function readCachedProfiles(userId: string): CachedProfiles | null {
    try {
        const stored = localStorage.getItem(profileStorageKey(userId));
        if (!stored) return null;
        const parsed: unknown = JSON.parse(stored);
        if (typeof parsed !== 'object' || parsed === null || !('profiles' in parsed) || !('fetchedAt' in parsed) || typeof parsed.fetchedAt !== 'number') return null;
        const profiles = normalizeProfiles(parsed.profiles);
        return profiles.length > 0 ? { profiles, fetchedAt: parsed.fetchedAt } : null;
    } catch {
        return null;
    }
}

function cacheProfiles(userId: string, profiles: AuthorProfile[]): AuthorProfile[] {
    const cached = { profiles, fetchedAt: Date.now() };
    profileMemory.set(userId, cached);
    try { localStorage.setItem(profileStorageKey(userId), JSON.stringify(cached)); } catch { /* Storage can be unavailable in private mode. */ }
    return profiles;
}

export function clearProfileCache(userId: string): void {
    profileMemory.delete(userId);
    profileRequests.delete(userId);
    try { localStorage.removeItem(profileStorageKey(userId)); } catch { /* Storage can be unavailable in private mode. */ }
}

export async function loadProfiles(userId: string, canFetch = true): Promise<AuthorProfile[]> {
    const cached = profileMemory.get(userId) ?? readCachedProfiles(userId);
    if (cached) profileMemory.set(userId, cached);
    if (cached && Date.now() - cached.fetchedAt < PROFILE_CACHE_TTL_MS) return cached.profiles;
    if (!canFetch || !navigator.onLine) {
        if (cached) return cached.profiles;
        throw new Error('Authors are unavailable offline. Connect once to load the author list.');
    }
    const pending = profileRequests.get(userId);
    if (pending) return pending;

    const request: Promise<AuthorProfile[]> = Promise.resolve().then(async () => {
        try {
            const { data, error } = await supabase.from('profiles').select('id, first_name, last_name').order('first_name');
            if (error) throw error;
            const profiles = normalizeProfiles(data);
            if (!profiles.length) throw new Error('No authors are available. Update your profile or retry loading the list.');
            if (profileRequests.get(userId) !== request) throw new Error('Author list request was superseded. Retry loading the list.');
            return cacheProfiles(userId, profiles);
        } catch (error: unknown) {
            if (profileRequests.get(userId) !== request) throw new Error('Author list request was superseded. Retry loading the list.');
            if (cached) return cached.profiles;
            throw error;
        }
    }).finally(() => {
        if (profileRequests.get(userId) === request) profileRequests.delete(userId);
    });
    profileRequests.set(userId, request);
    return request;
}
