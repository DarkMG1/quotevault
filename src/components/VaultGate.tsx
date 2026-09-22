/* eslint-disable react-refresh/only-export-components */
import { useEffect, useState } from 'react';
import QRCode from 'qrcode';
import type { FormEvent } from 'react';
import { Lock, Loader2 } from 'lucide-react';

export type VaultGateState = 'legacy-locked' | 'pending-approval' | 'recovery-setup' | 'device-locked' | 'unlocked' | 'lease-expired';

export function vaultGateState(input: { legacy?: boolean; pending?: boolean; recovery?: boolean; device?: boolean; key?: boolean; leaseValid?: boolean }): VaultGateState {
    if (input.legacy) return 'legacy-locked';
    if (input.pending) return 'pending-approval';
    if (input.recovery) return 'recovery-setup';
    if (input.device && input.leaseValid === false) return 'lease-expired';
    if (input.device && input.key && input.leaseValid) return 'unlocked';
    return 'device-locked';
}

export interface VaultGateProps {
    state: Exclude<VaultGateState, 'unlocked'>;
    busy?: boolean;
    error?: string;
    initializing?: boolean;
    onLegacyUnlock?: (event: FormEvent<HTMLFormElement>) => void;
    onRememberedUnlock?: () => void;
    onPasskeyUnlock?: () => void;
    onEnroll?: (mode: 'remembered' | 'passkey-prf') => void;
    onCheckApproval?: () => void;
    onRecover?: (phrase: string, mode: 'remembered' | 'passkey-prf') => void;
    approvalUrl?: string; approvalCode?: string;
    passkeyRestoreIds?: string[]; onFindPasskeyRestores?: () => void; onRestorePasskey?: (deviceId: string) => void;
    onRetry?: () => void;
    onSignOut?: () => void;
}

export function VaultGate({ state, busy, error, initializing, onLegacyUnlock, onRememberedUnlock, onPasskeyUnlock, onEnroll, onCheckApproval, onRecover, onRetry, onSignOut, approvalUrl, approvalCode, passkeyRestoreIds, onFindPasskeyRestores, onRestorePasskey }: VaultGateProps) {
    const legacy = state === 'legacy-locked';
    const expired = state === 'lease-expired';
    const pending = state === 'pending-approval';
    const [recovery, setRecovery] = useState(false); const [phrase, setPhrase] = useState('');
    const [qr, setQr] = useState('');
    useEffect(() => { let live = true; if (approvalUrl) void QRCode.toDataURL(approvalUrl, { margin: 1, width: 240 }).then(image => { if (live) setQr(image); }); return () => { live = false; }; }, [approvalUrl]);
    return <main className="min-h-[100dvh] flex items-center justify-center bg-background p-4">
        <section className="w-full max-w-sm bg-surface p-8 rounded-3xl border border-slate-700 text-center">
            <Lock className="w-10 h-10 mx-auto text-primary-400 mb-6" aria-hidden="true" />
            <h1 className="text-2xl font-bold mb-3">{legacy ? (initializing ? 'Initialize Group Vault' : 'Vault locked') : expired ? 'Lease expired' : pending ? 'Device approval pending' : 'Vault locked'}</h1>
            <p className="text-sm text-slate-400 mb-6">{legacy
                ? initializing ? 'An administrator must choose a shared passphrase of at least 12 characters.' : "Enter your group's shared vault key."
                : expired ? 'Connect to renew this device authorization before opening encrypted quotes.'
                : pending ? 'This device request expires in ten minutes. Approve it from an unlocked device or ask an administrator.'
                : 'Unlock an approved device. Remembered devices use this browser profile; passkeys require user verification.'}</p>
            {error && <p role="alert" className="mb-4 text-red-400 text-sm">{error}</p>}
            {legacy ? <form onSubmit={onLegacyUnlock} className="space-y-4">
                <label htmlFor="vault-key" className="block text-sm text-slate-300">Group Vault Key</label>
                <input id="vault-key" name="vault-key" type="password" required autoComplete={initializing ? 'new-password' : 'off'} minLength={initializing ? 12 : undefined} className="w-full bg-slate-900 border border-slate-700 rounded-xl p-3 text-white" />
                <button type="submit" disabled={busy} className="w-full bg-primary-600 disabled:opacity-50 py-3 rounded-xl">{busy ? <Loader2 className="w-5 h-5 animate-spin mx-auto" /> : initializing ? 'Initialize Vault' : 'Unlock Vault'}</button>
            </form> : <div className="space-y-3">
                {pending && approvalUrl && <div className="space-y-2"><p className="font-mono text-xl tracking-wider text-white">{approvalCode}</p>{qr && <img src={qr} alt="Device approval QR code" className="mx-auto bg-white p-2 rounded-xl" />}<p className="text-xs text-slate-400 break-all">{approvalUrl}</p></div>}
                {(expired || pending) && <button type="button" onClick={onCheckApproval} disabled={busy} className="w-full bg-primary-600 disabled:opacity-50 py-3 rounded-xl">{expired ? 'Renew authorization' : 'Check approval'}</button>}
                {!pending && <><button type="button" onClick={onRememberedUnlock} disabled={busy} className="w-full bg-primary-600 disabled:opacity-50 py-3 rounded-xl">Unlock remembered device</button>
                    <button type="button" onClick={onPasskeyUnlock} disabled={busy} className="w-full border border-slate-600 py-3 rounded-xl">Unlock with passkey</button>
                    <button type="button" onClick={onFindPasskeyRestores} disabled={busy} className="w-full text-sm text-primary-400">Restore cleared passkey device</button>
                    {passkeyRestoreIds?.map(id => <button key={id} type="button" onClick={() => onRestorePasskey?.(id)} disabled={busy} className="w-full text-xs text-slate-300 border border-slate-700 py-2 rounded-xl">Restore {id}</button>)}
                    <button type="button" onClick={() => onEnroll?.('remembered')} disabled={busy} className="w-full text-sm text-primary-400">Remember this device</button>
                    <button type="button" onClick={() => onEnroll?.('passkey-prf')} disabled={busy} className="w-full text-sm text-primary-400">Set up a passkey device</button>
                </>}
                <button type="button" onClick={() => setRecovery(value => !value)} disabled={busy} className="w-full text-sm text-slate-300">Use personal recovery</button>
                {recovery && <div className="space-y-3 text-left"><label className="block text-sm text-slate-300">Recovery phrase<textarea aria-label="Recovery phrase" value={phrase} onChange={event => setPhrase(event.target.value)} className="mt-1 w-full rounded-xl bg-slate-900 border border-slate-700 p-3 text-white" /></label><button type="button" disabled={busy || !phrase.trim()} onClick={() => onRecover?.(phrase, 'remembered')} className="w-full border border-slate-600 py-2 rounded-xl">Recover remembered device</button><button type="button" disabled={busy || !phrase.trim()} onClick={() => onRecover?.(phrase, 'passkey-prf')} className="w-full border border-slate-600 py-2 rounded-xl">Recover passkey device</button></div>}
            </div>}
            {onRetry && error && <button type="button" onClick={onRetry} className="mt-4 text-primary-400">Retry connection</button>}
            {onSignOut && <button type="button" disabled={busy} onClick={onSignOut} className="block mx-auto mt-6 text-sm text-slate-400">Sign out</button>}
        </section>
    </main>;
}
