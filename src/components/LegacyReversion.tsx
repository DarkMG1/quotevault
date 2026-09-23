import { useState } from 'react';
import { useCrypto } from '../hooks/useCrypto';
import { revertToLegacy } from '../lib/legacy-reversion';

const CONFIRMATION = 'RETURN TO SHARED KEY';

export function LegacyReversion() {
    const { encryptionKey, vaultGeneration, envelopeStatus, deviceApproved, getDeviceAuthorization, refreshVaultState } = useCrypto();
    const [passphrase, setPassphrase] = useState(''); const [repeat, setRepeat] = useState(''); const [typed, setTyped] = useState('');
    const [busy, setBusy] = useState(false); const [message, setMessage] = useState(''); const [error, setError] = useState('');
    if (!encryptionKey || !vaultGeneration || (envelopeStatus !== 'active' && envelopeStatus !== 'legacy')) return null;
    const run = async (dryRun: boolean) => {
        setBusy(true); setError(''); setMessage('');
        try {
            if (!dryRun && (passphrase !== repeat || typed !== CONFIRMATION)) throw new Error(`Repeat the passphrase exactly and type ${CONFIRMATION}.`);
            const auth = deviceApproved ? await getDeviceAuthorization() : null;
            const result = await revertToLegacy({ sourceGeneration: vaultGeneration, sourceKey: encryptionKey, passphrase: dryRun ? 'dry-run-only-passphrase' : passphrase,
                deviceId: auth?.deviceId ?? null, token: auth?.token ?? null, dryRun, onProgress: (done, total) => setMessage(`${done}/${total} quotes checked`) });
            if (dryRun) { setMessage(`Dry run passed: all ${result.quoteCount} quotes convert and verify. Nothing was changed.`); return; }
            setMessage(`Returned ${result.quoteCount} quotes to the shared vault key. Members now unlock with the new passphrase.`);
            try { await refreshVaultState(); } catch { /* The commit succeeded; the next reload shows the shared-key gate. */ }
        } catch (cause) { setError(cause instanceof Error ? cause.message : 'Return to shared key failed. Nothing was changed.'); }
        finally { setBusy(false); }
    };
    return <section aria-labelledby="legacy-reversion-heading" className="space-y-3 border-t border-slate-700 pt-6">
        <h3 id="legacy-reversion-heading" className="text-lg font-semibold text-white">Return to shared vault key</h3>
        <p className="text-sm text-slate-300">Re-encrypts every quote under a new shared passphrase in the original format. Ask every member to sync first; the vault must not be preparing or in maintenance.</p>
        <button type="button" disabled={busy} onClick={() => void run(true)} className="w-full border border-slate-600 py-2 rounded-xl">Dry run (no changes)</button>
        <label className="block text-sm text-slate-300">New shared passphrase<input type="password" autoComplete="new-password" minLength={12} value={passphrase} onChange={event => setPassphrase(event.target.value)} className="mt-1 w-full rounded-xl bg-slate-900 border border-slate-700 p-2 text-white" /></label>
        <label className="block text-sm text-slate-300">Repeat passphrase<input type="password" autoComplete="new-password" value={repeat} onChange={event => setRepeat(event.target.value)} className="mt-1 w-full rounded-xl bg-slate-900 border border-slate-700 p-2 text-white" /></label>
        <label className="block text-sm text-slate-300">Type {CONFIRMATION}<input value={typed} onChange={event => setTyped(event.target.value)} className="mt-1 w-full rounded-xl bg-slate-900 border border-slate-700 p-2 text-white" /></label>
        <button type="button" disabled={busy} onClick={() => void run(false)} className="w-full bg-red-700 disabled:opacity-50 py-2 rounded-xl">Return to shared vault key</button>
        {message && <p aria-live="polite" className="text-sm text-slate-200">{message}</p>}
        {error && <p role="alert" className="text-sm text-red-400">{error}</p>}
    </section>;
}
