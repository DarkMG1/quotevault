import { useEffect, useRef, useState } from 'react';
import { Save, Quote as QuoteIcon, X } from 'lucide-react';
import { useQuotes } from '../hooks/useQuotes';
import { useAuth } from '../hooks/useAuth';
import { useCrypto } from '../hooks/useCrypto';
import { encryptData } from '../lib/crypto';
import { supabase } from '../lib/supabase';
import { getErrorMessage, localDateInputValue, useModalDialog } from './ui';

interface AddQuoteProps { isOpen: boolean; onClose: () => void; }

interface AuthorProfile { id?: string; first_name: string; last_name?: string | null; }

const PROFILE_CACHE_TTL_MS = 5 * 60 * 1000;
interface CachedProfiles { profiles: AuthorProfile[]; fetchedAt: number; }
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

function profileStorageKey(userId: string): string { return `quotevault:profiles:${userId}`; }

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

function cacheProfiles(userId: string, profiles: AuthorProfile[]): CachedProfiles {
    const cached = { profiles, fetchedAt: Date.now() };
    profileMemory.set(userId, cached);
    try { localStorage.setItem(profileStorageKey(userId), JSON.stringify(cached)); } catch { /* Storage can be unavailable in private mode. */ }
    return cached;
}

async function loadProfiles(userId: string): Promise<AuthorProfile[]> {
    const cached = profileMemory.get(userId) ?? readCachedProfiles(userId);
    if (cached) profileMemory.set(userId, cached);
    if (cached && Date.now() - cached.fetchedAt < PROFILE_CACHE_TTL_MS) return cached.profiles;
    if (!navigator.onLine) {
        if (cached) return cached.profiles;
        throw new Error('Authors are unavailable offline. Connect once to load the author list.');
    }
    const pending = profileRequests.get(userId);
    if (pending) return pending;

    const request = (async () => {
        try {
            const { data, error } = await supabase.from('profiles').select('id, first_name, last_name').order('first_name');
            if (error) throw error;
            const profiles = normalizeProfiles(data);
            if (!profiles.length) throw new Error('No authors are available. Update your profile or retry loading the list.');
            return cacheProfiles(userId, profiles).profiles;
        } catch (error: unknown) {
            if (cached) return cached.profiles;
            throw error;
        }
    })().finally(() => { profileRequests.delete(userId); });
    profileRequests.set(userId, request);
    return request;
}

export const AddQuote = ({ isOpen, onClose }: AddQuoteProps) => {
    const [text, setText] = useState('');
    const [author, setAuthor] = useState('');
    const [context, setContext] = useState('');
    const [quoteDate, setQuoteDate] = useState(localDateInputValue());
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [saveError, setSaveError] = useState('');
    const { addQuote } = useQuotes();
    const { user } = useAuth();
    const { encryptionKey, isLocked } = useCrypto();
    const [profiles, setProfiles] = useState<AuthorProfile[]>([]);
    const [profileError, setProfileError] = useState('');
    const [profileRetry, setProfileRetry] = useState(0);
    const dialogRef = useRef<HTMLDialogElement>(null);
    const textRef = useRef<HTMLTextAreaElement>(null);

    useModalDialog(dialogRef, isOpen, onClose, textRef);

    useEffect(() => {
        let active = true;
        if (!user?.id) return () => { active = false; };
        loadProfiles(user.id).then((data) => {
            if (active) {
                setProfiles(data);
                setProfileError('');
                if (data.length > 0) {
                    const firstProfile = data[0];
                    const firstDisplayName = [firstProfile.first_name, firstProfile.last_name].filter(Boolean).join(' ');
                    setAuthor((current) => current || firstDisplayName);
                }
            }
        }).catch((error: unknown) => {
            if (active) setProfileError(getErrorMessage(error, 'Unable to load authors. Check your connection and retry.'));
        });
        return () => { active = false; };
    }, [profileRetry, user?.id]);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (isSubmitting || !text.trim() || !author.trim()) return;
        setIsSubmitting(true);
        setSaveError('');
        try {
            if (isLocked || !encryptionKey) throw new Error('Cannot save: Vault is locked.');
            const payloadToEncrypt = JSON.stringify({ text: text.trim(), author: author.trim(), context: context.trim() });
            const encryptedBundle = await encryptData(payloadToEncrypt, encryptionKey);
            const serializedCiphertext = `$$E2E$$${JSON.stringify(encryptedBundle)}`;
            await addQuote(serializedCiphertext, 'ENCRYPTED', 'ENCRYPTED', quoteDate, user?.id);
            setText('');
            setAuthor('');
            setContext('');
            onClose();
        } catch (error: unknown) {
            setSaveError(getErrorMessage(error, 'Unable to save quote. Your draft is still here.'));
        } finally {
            setIsSubmitting(false);
        }
    };

    return (
        <dialog
            ref={dialogRef}
            role="dialog"
            aria-labelledby="add-quote-title"
            className="fixed inset-x-4 inset-y-12 sm:inset-0 sm:m-auto z-50 w-[calc(100%-2rem)] sm:w-[90%] sm:max-w-lg sm:h-fit max-h-[85vh] bg-surface border border-slate-700/50 rounded-3xl shadow-2xl overflow-hidden p-0 text-white [&::backdrop]:bg-black/60 [&::backdrop]:backdrop-blur-sm"
        >
            <div className="flex items-center justify-between p-6 border-b border-white/5">
                <div className="flex items-center space-x-2">
                    <QuoteIcon aria-hidden="true" className="w-5 h-5 text-primary-400" />
                    <h2 id="add-quote-title" className="text-xl font-semibold">Add Quote</h2>
                </div>
                <button type="button" onClick={onClose} aria-label="Close add quote dialog" className="p-2 -mr-2 text-slate-400 hover:text-white transition-colors rounded-full hover:bg-white/5">
                    <X aria-hidden="true" className="w-5 h-5" />
                </button>
            </div>

            <form onSubmit={handleSubmit} className="p-6 space-y-5 overflow-y-auto overscroll-contain max-h-[calc(85vh-5rem)]">
                {saveError && <p role="alert" className="rounded-xl border border-red-500/20 bg-red-500/10 p-3 text-sm text-red-300">{saveError}</p>}
                <div>
                    <label htmlFor="quote-text" className="block text-sm font-medium text-slate-300 mb-1">Quote</label>
                    <textarea ref={textRef} id="quote-text" required value={text} onChange={(e) => setText(e.target.value)} placeholder="&quot;The only limit to our realization of tomorrow...&quot;" rows={4} className="w-full bg-slate-800/50 border border-slate-700 rounded-xl py-3 px-4 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-primary-500 transition-all resize-none" />
                </div>

                <div>
                    <label htmlFor="quote-author" className="block text-sm font-medium text-slate-300 mb-1">Author</label>
                    {profileError && <div role="alert" className="mb-2 flex items-center justify-between gap-3 rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-sm text-red-300"><span>{profileError}</span><button type="button" onClick={() => setProfileRetry((value) => value + 1)} className="font-medium text-red-200 underline">Retry</button></div>}
                    <select id="quote-author" required value={author} onChange={(e) => setAuthor(e.target.value)} className="w-full bg-slate-800/50 border border-slate-700 rounded-xl py-3 px-4 text-white focus:outline-none focus:ring-2 focus:ring-primary-500 transition-all appearance-none">
                        <option value="" disabled>Select an Author</option>
                        {profiles.map((profile) => {
                            const displayName = [profile.first_name, profile.last_name].filter(Boolean).join(' ');
                            return <option key={profile.id ?? displayName} value={displayName}>{displayName}</option>;
                        })}
                    </select>
                </div>

                <div>
                    <label htmlFor="quote-context" className="block text-sm font-medium text-slate-300 mb-1">Context <span className="text-slate-500 font-normal">(Optional)</span></label>
                    <input id="quote-context" type="text" value={context} onChange={(e) => setContext(e.target.value)} placeholder="In a letter to a friend, 1945" className="w-full bg-slate-800/50 border border-slate-700 rounded-xl py-3 px-4 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-primary-500 transition-all" />
                </div>

                <div className="max-w-full overflow-hidden">
                    <label htmlFor="quote-date" className="block text-sm font-medium text-slate-300 mb-1">Date Said <span className="text-slate-500 font-normal">(Optional)</span></label>
                    <input id="quote-date" type="date" value={quoteDate} onChange={(e) => setQuoteDate(e.target.value)} className="w-full max-w-full bg-slate-800/50 border border-slate-700 rounded-xl py-3 px-4 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-primary-500 transition-all [color-scheme:dark]" />
                </div>

                <div className="pt-4 mt-auto">
                    <button type="submit" disabled={isSubmitting} className="w-full bg-primary-600 hover:bg-primary-500 disabled:opacity-50 text-white font-medium py-3.5 rounded-xl transition-colors flex items-center justify-center space-x-2">
                        <Save aria-hidden="true" className="w-5 h-5" />
                        <span>{isSubmitting ? 'Saving...' : 'Save Quote'}</span>
                    </button>
                </div>
            </form>
        </dialog>
    );
};
