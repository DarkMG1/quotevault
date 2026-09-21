import { useEffect, useMemo, useRef, useState } from 'react';
import { useAuth } from '../hooks/useAuth';
import { useCrypto } from '../hooks/useCrypto';
import { useQuotes } from '../hooks/useQuotes';
import { checkImports, loadImportSnapshot, parseImportFile, prepareImport, readPendingImport, sendPendingImport } from '../lib/quote-import';
import type { ImportRow, ImportSnapshot, PendingImport } from '../lib/quote-import';
import { getErrorMessage, useModalDialog } from './ui';

export function ImportQuotes({ onClose }: { onClose: () => void }) {
    const { user, canSync } = useAuth();
    const { encryptionKey, vaultGeneration, lockVault } = useCrypto();
    const { refresh } = useQuotes();
    const [rows, setRows] = useState<ImportRow[]>([]);
    const [snapshot, setSnapshot] = useState<ImportSnapshot | null>(null);
    const [pending, setPending] = useState<PendingImport | null>(null);
    const [busy, setBusy] = useState(true);
    const [error, setError] = useState('');
    const [message, setMessage] = useState('');
    const dialog = useRef<HTMLDialogElement>(null);
    const close = useRef<HTMLButtonElement>(null);
    const lifecycle = useRef(0);
    const running = useRef(false);
    const actorId = user?.id;
    const context = useMemo(() => actorId && vaultGeneration ? { actorId, generation: vaultGeneration, onGenerationMismatch: lockVault } : null,
        [actorId, vaultGeneration, lockVault]);
    useModalDialog(dialog, true, onClose, close);
    useEffect(() => {
        const currentLifecycle = lifecycle;
        const epoch = ++currentLifecycle.current;
        running.current = false;
        const current = () => lifecycle.current === epoch;
        if (context && encryptionKey) {
            void readPendingImport(context, encryptionKey).then(value => { if (current()) setPending(value); })
                .catch(cause => { if (current()) setError(getErrorMessage(cause, 'Could not read saved import.')); })
                .finally(() => { if (current()) setBusy(false); });
        }
        return () => { currentLifecycle.current++; };
    }, [context, encryptionKey]);
    const checks = useMemo(() => checkImports(rows, snapshot?.quotes || []), [rows, snapshot]);
    const selected = rows.filter((row, index) => row.selected && !checks[index].duplicate);
    const duplicateCount = checks.filter(check => check.duplicate).length;

    async function checkFile(file: File) {
        if (!context || !encryptionKey || running.current) return;
        const epoch = lifecycle.current;
        const current = () => lifecycle.current === epoch;
        running.current = true; setBusy(true); setError(''); setMessage('');
        try {
            if (!canSync) throw new Error('Reconnect your session before checking duplicates.');
            if (file.size > 5 * 1024 * 1024) throw new Error('Choose a review file smaller than 5 MiB.');
            const parsed = parseImportFile(await file.text());
            const fresh = await loadImportSnapshot(context, encryptionKey);
            if (!current()) return;
            const matches = checkImports(parsed, fresh.quotes);
            setRows(parsed.map((row, index) => ({ ...row, selected: row.selected && !matches[index].duplicate && !matches[index].similar })));
            setSnapshot(fresh);
        } catch (cause) { if (current()) { setRows([]); setSnapshot(null); setError(getErrorMessage(cause, 'Could not check this file.')); } }
        finally { if (current()) { running.current = false; setBusy(false); } }
    }

    async function importSelected(resume = false) {
        if (!context || !encryptionKey || running.current) return;
        const epoch = lifecycle.current;
        const current = () => lifecycle.current === epoch;
        running.current = true; setBusy(true); setError(''); setMessage('');
        try {
            if (!canSync) throw new Error('Reconnect your session before importing.');
            let batch = resume ? pending : null;
            if (!batch) {
                if (!snapshot || !selected.length) throw new Error('Select the quotes to import.');
                const latest = await loadImportSnapshot(context, encryptionKey);
                if (!current()) return;
                if (latest.revision !== snapshot.revision) {
                    const matches = checkImports(rows, latest.quotes);
                    setRows(rows.map((row, index) => ({ ...row, selected: row.selected && !matches[index].duplicate && !matches[index].similar })));
                    setSnapshot(latest);
                    throw new Error('The vault changed. Duplicate checks have been updated; review the selection and try again.');
                }
                batch = await prepareImport(selected, latest, context, encryptionKey, () => current());
                if (current()) setPending(batch);
            }
            if (!current()) return;
            const count = await sendPendingImport(batch, context);
            if (!current()) return;
            setPending(null); setRows([]); setSnapshot(null);
            setMessage(`${count} quotes imported and encrypted. Reimporting this file will check and skip existing quotes.`);
            await refresh();
        } catch (cause) {
            if (current()) {
                setError(getErrorMessage(cause, 'Could not confirm the import. Check the saved import status.'));
                try { const saved = await readPendingImport(context, encryptionKey); if (current()) setPending(saved); }
                catch { if (current()) setError('Could not read the saved import. Reopen this dialog before trying again.'); }
            }
        } finally { if (current()) { running.current = false; setBusy(false); } }
    }

    return <dialog ref={dialog} aria-labelledby="import-title" className="fixed inset-4 m-auto w-[calc(100%-2rem)] max-w-3xl max-h-[90vh] overflow-y-auto rounded-2xl border border-slate-700 bg-surface p-6 text-white [&::backdrop]:bg-black/70">
        <div className="flex items-center justify-between gap-4"><h2 id="import-title" className="text-xl font-semibold">Import quotes</h2><button ref={close} onClick={onClose} className="rounded border border-slate-600 px-3 py-2">Close</button></div>
        <p className="mt-4 text-sm text-slate-300">Load a reviewed QuoteVault JSON file. Exact duplicates are skipped; possible matches need your review. Quotes, context, and original senders are encrypted in this browser before they are saved.</p>
        <details className="my-4 text-sm text-slate-300"><summary className="cursor-pointer">How to prepare another backup</summary><ol className="ml-6 mt-2 list-decimal space-y-1"><li>Make a new encrypted iPhone backup on your Mac.</li><li>Use the QuoteVault backup preparation command to extract the chosen chat and build a private review page.</li><li>Review the quotes, then download selected quotes or save a full draft.</li><li>Load that JSON file here, check duplicates, and import your selection.</li></ol><p className="mt-2">The backup password stays on your Mac. Your vault key is entered only in QuoteVault. Raw backups are never uploaded here.</p></details>
        {error && <p role="alert" className="my-4 rounded bg-red-950/50 p-3 text-red-200">{error}</p>}
        {message && <p role="status" className="my-4 rounded bg-green-950/50 p-3 text-green-200">{message}</p>}
        {pending ? <div className="my-4 rounded border border-amber-700 p-4"><p>A saved import of {pending.operations.length} quotes needs confirmation. Checking it is safe to repeat.</p><button disabled={busy || !canSync} onClick={() => void importSelected(true)} className="mt-3 rounded bg-primary-600 px-4 py-2 disabled:opacity-50">Check saved import</button></div> : <label className="my-4 block">Reviewed quotes or full draft<input type="file" accept=".json,application/json" disabled={busy || !canSync} className="mt-2 block w-full" onChange={event => { const file = event.target.files?.[0]; if (file) void checkFile(file); event.target.value = ''; }} /></label>}
        {busy && <p role="status">Checking the vault…</p>}
        {!!rows.length && !pending && <>
            <div className="sticky top-0 z-10 my-4 flex flex-wrap items-center gap-3 border-y border-slate-700 bg-surface py-3"><p role="status">{selected.length} selected · {duplicateCount} duplicates skipped</p><button disabled={busy} className="rounded border border-slate-600 px-3 py-2" onClick={() => setRows(rows.map((row, index) => ({ ...row, selected: !checks[index].duplicate && !checks[index].similar })))}>Select new quotes</button><button disabled={busy || !selected.length || !canSync} onClick={() => void importSelected()} className="rounded bg-primary-600 px-4 py-2 disabled:opacity-50">Import {selected.length} selected quotes</button></div>
            {rows.map((row, index) => <article key={index} className={`my-3 rounded-xl border border-slate-700 p-4 ${checks[index].duplicate ? 'opacity-60' : ''}`}>
                <label className="flex items-center gap-2"><input type="checkbox" checked={row.selected && !checks[index].duplicate} disabled={busy || checks[index].duplicate} onChange={event => setRows(rows.map((item, at) => at === index ? { ...item, selected: event.target.checked } : item))} />Quote {index + 1}{checks[index].duplicate && ' — already present'}</label>
                <blockquote className="my-3 whitespace-pre-wrap">{row.text}</blockquote><p>— {row.author}</p><p className="mt-2 text-sm text-slate-400">Originally shared by {row.source_sender}{row.quote_date && ` · ${row.quote_date}`}</p>{row.context && <p className="mt-2 whitespace-pre-wrap text-sm text-slate-300">Context: {row.context}</p>}
                {checks[index].similar && <p className="mt-3 whitespace-pre-wrap rounded bg-amber-950/50 p-3 text-sm text-amber-200">Possible duplicate — select only if this is a separate quote:<br />{checks[index].similar}</p>}
            </article>)}
        </>}
    </dialog>;
}
