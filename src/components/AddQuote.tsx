import { useEffect, useRef, useState } from 'react';
import { Save, Quote as QuoteIcon, X } from 'lucide-react';
import { useQuotes } from '../hooks/useQuotes';
import { useAuth } from '../hooks/useAuth';
import { useCrypto } from '../hooks/useCrypto';
import { encryptData } from '../lib/crypto';
import { saveQuoteEdit } from '../lib/quote-edit';
import { isAdminUser } from '../lib/access';
import type { Quote } from '../types';
import { loadProfiles, type AuthorProfile } from '../lib/profile-cache';
import { getErrorMessage, isCiphertextWithinLimit, localDateInputValue, useModalDialog } from './ui';

interface AddQuoteProps { onClose: () => void; edit?: { stored: Quote; display: Quote }; }

function authorLabel(profile: AuthorProfile): string {
    return [profile.first_name, profile.last_name].filter(Boolean).join(' ');
}

export const AddQuote = ({ onClose, edit }: AddQuoteProps) => {
    const [text, setText] = useState(edit?.display.text || '');
    const [author, setAuthor] = useState(edit?.display.author || '');
    const [context, setContext] = useState(edit?.display.context || '');
    const [quoteDate, setQuoteDate] = useState(edit ? edit.stored.quote_date || '' : localDateInputValue());
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [saveError, setSaveError] = useState('');
    const { addQuote, refresh } = useQuotes();
    const { user, canSync } = useAuth();
    const { encryptionKey, isLocked, vaultGeneration } = useCrypto();
    const lifecycle = useRef(0);
    const [profiles, setProfiles] = useState<AuthorProfile[]>([]);
    const [isLoadingProfiles, setIsLoadingProfiles] = useState(false);
    const [profileError, setProfileError] = useState('');
    const [profileRetry, setProfileRetry] = useState(0);
    const dialogRef = useRef<HTMLDialogElement>(null);
    const textRef = useRef<HTMLTextAreaElement>(null);

    useModalDialog(dialogRef, true, onClose, textRef);

    useEffect(() => {
        const current = lifecycle;
        current.current++;
        return () => { current.current++; };
    }, [user?.id, user?.email, encryptionKey, vaultGeneration, canSync]);

    useEffect(() => {
        let active = true;
        if (!user?.id) return () => { active = false; };
        // The loading flag describes the asynchronous profile request started below.
        // eslint-disable-next-line react-hooks/set-state-in-effect
        setIsLoadingProfiles(true);
        loadProfiles(user.id, canSync).then((data) => {
            if (active) {
                setProfiles(data);
                setProfileError('');
                if (data.length > 0 && !edit) {
                    const firstProfile = data[0];
                    const firstDisplayName = authorLabel(firstProfile);
                    setAuthor((current) => current || firstDisplayName);
                }
            }
        }).catch((error: unknown) => {
            if (active) setProfileError(getErrorMessage(error, 'Unable to load authors. Check your connection and retry.'));
        }).finally(() => { if (active) setIsLoadingProfiles(false); });
        return () => { active = false; };
    }, [canSync, profileRetry, user?.id, edit]);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (isSubmitting) return;
        if (!text.trim() || !author.trim()) {
            setSaveError('Enter a quote and choose an author.');
            return;
        }
        setIsSubmitting(true);
        setSaveError('');
        const epoch = lifecycle.current;
        try {
            if (isLocked || !encryptionKey) throw new Error('Cannot save: Vault is locked.');
            if (edit) {
                if (!isAdminUser(user) || !canSync || vaultGeneration !== edit.stored.vault_generation) {
                    throw new Error('An online admin session is required to edit quotes.');
                }
                await saveQuoteEdit(edit.stored, { text, author, context, quoteDate }, encryptionKey, () => lifecycle.current === epoch);
                if (lifecycle.current === epoch) { await refresh(); onClose(); }
                return;
            }
            const submitter = profiles.find(profile => profile.id === user?.id);
            const sourceSender = submitter ? authorLabel(submitter) :
                [user?.user_metadata?.first_name, user?.user_metadata?.last_name].filter(value => typeof value === 'string' && value.trim()).join(' ');
            if (!user || !sourceSender.trim()) throw new Error('Your name is unavailable. Update your profile before submitting a quote.');
            const payloadToEncrypt = JSON.stringify({ text: text.trim(), author: author.trim(), context: context.trim(), ...(sourceSender.trim() ? { source_sender: sourceSender.trim() } : {}) });
            const encryptedBundle = await encryptData(payloadToEncrypt, encryptionKey);
            if (!isCiphertextWithinLimit(encryptedBundle)) {
                throw new Error('This quote is too large to save. Shorten the quote or context and try again.');
            }
            const serializedCiphertext = `$$E2E$$${JSON.stringify(encryptedBundle)}`;
            await addQuote(serializedCiphertext, 'ENCRYPTED', 'ENCRYPTED', quoteDate);
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
                    <h2 id="add-quote-title" className="text-xl font-semibold">{edit ? 'Edit Quote' : 'Add Quote'}</h2>
                </div>
                <button type="button" onClick={onClose} aria-label={edit ? 'Close edit quote dialog' : 'Close add quote dialog'} className="p-2 -mr-2 text-slate-400 hover:text-white transition-colors rounded-full hover:bg-white/5">
                    <X aria-hidden="true" className="w-5 h-5" />
                </button>
            </div>

            <form onSubmit={handleSubmit} className="p-6 space-y-5 overflow-y-auto overscroll-contain max-h-[calc(85vh-5rem)]">
                {saveError && <p role="alert" className="rounded-xl border border-red-500/20 bg-red-500/10 p-3 text-sm text-red-300">{saveError}</p>}
                {edit && <p className="text-sm text-slate-400">Editing requires a connection. Original sender and import history are preserved.</p>}
                <div>
                    <label htmlFor="quote-text" className="block text-sm font-medium text-slate-300 mb-1">Quote</label>
                    <textarea ref={textRef} id="quote-text" required value={text} onChange={(e) => setText(e.target.value)} placeholder="&quot;The only limit to our realization of tomorrow...&quot;" rows={4} className="w-full bg-slate-800/50 border border-slate-700 rounded-xl py-3 px-4 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-primary-500 transition-all resize-none" />
                </div>

                <div>
                    <label htmlFor="quote-author" className="block text-sm font-medium text-slate-300 mb-1">Author</label>
                    {profileError && <div role="alert" className="mb-2 flex items-center justify-between gap-3 rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-sm text-red-300"><span>{profileError}</span><button type="button" onClick={() => setProfileRetry((value) => value + 1)} className="font-medium text-red-200 underline">Retry</button></div>}
                    {edit && <datalist id="quote-author-options">{profiles.map(profile => <option key={profile.id || authorLabel(profile)} value={authorLabel(profile)} />)}</datalist>}
                    {edit ? <input id="quote-author" list="quote-author-options" required value={author} onChange={e => setAuthor(e.target.value)} className="w-full bg-slate-800/50 border border-slate-700 rounded-xl py-3 px-4 text-white focus:outline-none focus:ring-2 focus:ring-primary-500" /> : <select id="quote-author" required disabled={isLoadingProfiles} value={author} onChange={(e) => setAuthor(e.target.value)} className="w-full bg-slate-800/50 border border-slate-700 rounded-xl py-3 px-4 text-white focus:outline-none focus:ring-2 focus:ring-primary-500 transition-all appearance-none disabled:opacity-60">
                        <option value="" disabled>{isLoadingProfiles ? 'Loading authors…' : 'Select an Author'}</option>
                        {profiles.map((profile) => {
                            const displayName = authorLabel(profile);
                            return <option key={profile.id ?? displayName} value={displayName}>{displayName}</option>;
                        })}
                    </select>}
                </div>

                <div>
                    <label htmlFor="quote-context" className="block text-sm font-medium text-slate-300 mb-1">Context <span className="text-slate-500 font-normal">(Optional)</span></label>
                    <textarea id="quote-context" rows={2} value={context} onChange={(e) => setContext(e.target.value)} placeholder="In a letter to a friend, 1945" className="w-full bg-slate-800/50 border border-slate-700 rounded-xl py-3 px-4 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-primary-500 transition-all" />
                </div>

                {edit?.display.source_sender && <p className="text-sm text-slate-400">Originally shared by {edit.display.source_sender}</p>}

                <div className="max-w-full overflow-hidden">
                    <label htmlFor="quote-date" className="block text-sm font-medium text-slate-300 mb-1">Date Said <span className="text-slate-500 font-normal">(Optional)</span></label>
                    <input id="quote-date" type="date" value={quoteDate} onChange={(e) => setQuoteDate(e.target.value)} className="w-full max-w-full bg-slate-800/50 border border-slate-700 rounded-xl py-3 px-4 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-primary-500 transition-all [color-scheme:dark]" />
                </div>

                <div className="pt-4 mt-auto">
                    <button type="submit" disabled={isSubmitting || (!!edit && !canSync)} className="w-full bg-primary-600 hover:bg-primary-500 disabled:opacity-50 text-white font-medium py-3.5 rounded-xl transition-colors flex items-center justify-center space-x-2">
                        <Save aria-hidden="true" className="w-5 h-5" />
                        <span>{isSubmitting ? 'Saving...' : edit ? 'Save Changes' : 'Save Quote'}</span>
                    </button>
                </div>
            </form>
        </dialog>
    );
};
