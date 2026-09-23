import { useEffect, useRef, useState } from 'react';
import { useAuth } from '../hooks/useAuth';
import { useCrypto } from '../hooks/useCrypto';
import { useQuotes } from '../hooks/useQuotes';
import { isAdminUser } from '../lib/access';
import { loadProfiles } from '../lib/profile-cache';
import { authorName, matchAuthor } from '../lib/quote-authors';
import { readQuotePayload, saveAuthorMatches } from '../lib/quote-edit';
import { getErrorMessage, useModalDialog } from './ui';
import type { Quote } from '../types';

export function MatchAuthors({ onClose }: { onClose: () => void }) {
    const { user, canSync } = useAuth();
    const { encryptionKey, vaultGeneration, deviceId, getDeviceAuthorization } = useCrypto();
    const { quotes, refresh, loading, initialFetchPending } = useQuotes();
    const [rows, setRows] = useState<{ quote: Quote; author: string }[]>([]);
    const [names, setNames] = useState<string[]>([]);
    const [mapping, setMapping] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState(true);
    const [error, setError] = useState('');
    const dialog = useRef<HTMLDialogElement>(null);
    const close = useRef<HTMLButtonElement>(null);
    const lifecycle = useRef(0);
    useModalDialog(dialog, true, onClose, close);
    const actorId = user?.id;
    useEffect(() => {
        const current = lifecycle;
        const epoch = ++current.current;
        if (actorId && encryptionKey && !loading && !initialFetchPending) {
            void Promise.all([loadProfiles(actorId, canSync), Promise.all((quotes || []).filter(quote => quote.text.startsWith('$$E2E$$') && quote.sync_status !== 'pending' && quote.sync_status !== 'rejected').map(async quote => {
                const payload = await readQuotePayload(quote, encryptionKey);
                return payload.import_source_id ? { quote, author: payload.author } : null;
            }))]).then(([profiles, values]) => {
                if (current.current !== epoch) return;
                const imported = values.filter((value): value is { quote: Quote; author: string } => value !== null);
                setRows(imported); setNames(profiles.map(authorName));
                setMapping(previous => Object.fromEntries(imported.map(row => [row.author, previous[row.author] ?? matchAuthor(row.author, profiles)])));
            }).catch(cause => { if (current.current === epoch) setError(getErrorMessage(cause, 'Could not load authors.')); })
                .finally(() => { if (current.current === epoch) setBusy(false); });
        }
        return () => { current.current++; };
    }, [actorId, encryptionKey, canSync, loading, initialFetchPending, quotes]);
    const changes = rows.filter(row => mapping[row.author]?.trim() && mapping[row.author].trim() !== row.author)
        .map(row => ({ quote: row.quote, author: mapping[row.author] }));
    async function save() {
        if (busy || !isAdminUser(user) || !canSync || !encryptionKey || rows.some(row => row.quote.vault_generation !== vaultGeneration)) return;
        const epoch = lifecycle.current;
        setBusy(true); setError('');
        try {
            await saveAuthorMatches(changes.slice(0, 500), encryptionKey, () => lifecycle.current === epoch, deviceId ? getDeviceAuthorization : undefined);
            if (lifecycle.current === epoch) { await refresh(); onClose(); }
        } catch (cause) { if (lifecycle.current === epoch) setError(getErrorMessage(cause, 'Could not save author corrections.')); }
        finally { if (lifecycle.current === epoch) setBusy(false); }
    }
    return <dialog ref={dialog} aria-labelledby="match-authors-title" className="fixed inset-4 m-auto max-h-[90vh] w-[calc(100%-2rem)] max-w-2xl overflow-y-auto rounded-2xl border border-slate-700 bg-surface p-6 text-white [&::backdrop]:bg-black/70">
        <div className="flex items-center justify-between gap-4"><h2 id="match-authors-title" className="text-xl font-semibold">Match imported authors</h2><button ref={close} onClick={onClose} className="rounded border border-slate-600 px-3 py-2">Close</button></div>
        <p className="my-4 text-sm text-slate-300">Match names to existing profiles. For conversations, separate full names with &amp;. Keep unknown or outside speakers as written. Directed attributions are preserved in context. Only imported quotes are changed.</p>
        <datalist id="matched-author-names">{names.map(name => <option key={name} value={name} />)}</datalist>
        {error && <p role="alert" className="my-3 rounded bg-red-950/50 p-3 text-red-200">{error}</p>}
        {Object.keys(mapping).sort().map(before => <label key={before} className="my-3 block text-sm">{before}<span className="text-slate-500"> ({rows.filter(row => row.author === before).length})</span><input aria-label={`Replace author ${before}`} list="matched-author-names" value={mapping[before]} disabled={busy} onChange={event => setMapping({ ...mapping, [before]: event.target.value })} className="mt-1 block w-full rounded border border-slate-600 bg-slate-800 p-2 text-white" /></label>)}
        <p role="status" className="my-4">{busy ? 'Checking authors…' : `${changes.length} author corrections ready`}</p>
        {changes.length > 500 && <p className="my-3 text-sm">Save the first 500 corrections, then reopen to match the remaining authors.</p>}
        <button disabled={busy || !canSync || !changes.length} onClick={() => void save()} className="rounded bg-primary-600 px-4 py-2 disabled:opacity-50">Save {Math.min(changes.length, 500)} author corrections</button>
    </dialog>;
}
