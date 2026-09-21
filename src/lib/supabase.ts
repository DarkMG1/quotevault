import { createClient, type User } from '@supabase/supabase-js';

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
const supabaseKey = import.meta.env.VITE_SUPABASE_ANON_KEY;
if (!supabaseUrl || !supabaseKey) {
    throw new Error('QuoteVault requires VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY.');
}

// Preserve the SDK's existing key so installed devices keep their saved sessions.
const storageKey = `sb-${new URL(supabaseUrl).hostname.split('.')[0]}-auth-token`;
export const localSignOutKey = `${storageKey}:signed-out`;

export function isLocallySignedOut(): boolean {
    try { return localStorage.getItem(localSignOutKey) === '1'; }
    catch { return false; }
}

export function setLocalSignedOut(signedOut: boolean): void {
    if (signedOut) localStorage.setItem(localSignOutKey, '1');
    else localStorage.removeItem(localSignOutKey);
}

export function readCachedSessionUser(): User | null {
    try {
        if (isLocallySignedOut()) return null;
        const session = JSON.parse(localStorage.getItem(storageKey) || 'null');
        const user = session?.user;
        // This is only a local identity hint, never proof of server authorization.
        return typeof session?.access_token === 'string' && typeof session?.refresh_token === 'string'
            && typeof user?.id === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(user.id)
            ? user as User : null;
    } catch { return null; }
}

export function clearCachedSession(): void {
    try { localStorage.removeItem(storageKey); } catch { /* Storage may be unavailable. */ }
}

export const supabase = createClient(supabaseUrl, supabaseKey, { auth: { storageKey } });
