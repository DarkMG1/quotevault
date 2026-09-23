import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
import type { FormEvent, ReactNode } from 'react';
import { createVaultConfig, unlockWithVerifier } from '../lib/crypto';
import { cacheVaultState, clearCachedVaultState, enrollmentGeneration, isLegacyVaultState, loadVaultState, parseLegacyVaultMutation, quoteGeneration, readCachedVaultState } from '../lib/vault';
import type { VaultState } from '../lib/vault';
import { supabase } from '../lib/supabase';
import { useAuth } from './useAuth';
import { isAdminUser } from '../lib/access';
import { VaultGate, vaultGateState } from '../components/VaultGate';
import { RecoverySetup } from '../components/RecoverySetup';
import { approveDevice, completeDevice, deleteDeviceState, formatEnrollmentCode, getDeviceRequest, loadDeviceState, needsRecoverySetup, recoverySetupRetryOutcome, revokeOwnDevice, saveDeviceState } from '../lib/device';
import { activateRecoveredDevice, beginRecovery, completeRecovery, createRecoveryKey, decryptDeviceBundle, getPasskeyRestoreDevices, prepareDeviceEnrollment, registerPasskey, renewDeviceLease, renewThenCompleteDevice, unlockPasskey, webauthnChallenge } from '../lib/device-security';
import { decryptPrivateBundle, deriveQuoteKey, deriveRecoveryBundleKey, encryptPrivateBundle, fingerprintPublicJwk, generateAuthorizationToken, generateWrappingKeyPair, unwrapVaultKey, wrapVaultKey } from '../lib/device-crypto';
import { arrayBufferToBase64 } from '../lib/crypto';
import { verifyDeviceLease } from '../lib/lease';
import { clearLocalSyncState } from '../lib/sync';
import { db } from '../lib/db';
import { clearProfileCache } from '../lib/profile-cache';
import type { DeviceLocalState } from '../types';

interface CryptoContextType {
    encryptionKey: CryptoKey | null; isLocked: boolean; vaultGeneration: string | null; legacyVaultGeneration: string | null;
    preparedGeneration: string | null; deviceId: string | null; leaseExpiresAt: number | null;
    refreshVaultState: () => Promise<void>;
    getDeviceAuthorization: () => Promise<{ deviceId: string; token: string }>;
    setPreparedTargetMasterKey: (generation: string, key: Uint8Array) => void;
    clearPreparedTargetMasterKey: (generation?: string) => void;
    getApprovedTargetMasterKey: (generation: string) => Promise<Uint8Array>;
    enrollDevice: (mode: 'remembered' | 'passkey-prf') => Promise<void>;
    checkDeviceApproval: () => Promise<void>;
    renewDeviceLease: (authorization: { deviceId: string; token: string }) => Promise<void>;
    lockVault: () => void; forgetDevice: () => Promise<void>; approveDeviceRequest: (requestId: string, fingerprint: string, code: string, preparedKey?: Uint8Array) => Promise<void>;
    setupRecovery: (phrase: string, replace?: boolean) => Promise<void>; recoverDevice: (phrase: string, mode: 'remembered' | 'passkey-prf') => Promise<void>;
    findPasskeyRestores: () => Promise<string[]>; restorePasskeyDevice: (deviceId: string) => Promise<void>;
}
const CryptoContext = createContext<CryptoContextType>({ encryptionKey: null, isLocked: true, vaultGeneration: null, legacyVaultGeneration: null, preparedGeneration: null, deviceId: null, leaseExpiresAt: null,
    refreshVaultState: async () => {}, getDeviceAuthorization: async () => { throw new Error('Unlock an approved device first.'); }, setPreparedTargetMasterKey: () => {}, clearPreparedTargetMasterKey: () => {}, getApprovedTargetMasterKey: async () => { throw new Error('Unlock an approved prepared device first.'); }, enrollDevice: async () => {}, checkDeviceApproval: async () => {}, renewDeviceLease: async () => { throw new Error('Unlock an approved device first.'); }, lockVault: () => {}, forgetDevice: async () => {}, approveDeviceRequest: async () => {}, setupRecovery: async () => {}, recoverDevice: async () => {}, findPasskeyRestores: async () => [], restorePasskeyDevice: async () => {} });
const MAX_TIMEOUT = 0x7fffffff;

export const CryptoProvider = ({ children }: { children: ReactNode }) => {
    const { user, canSync, signOut } = useAuth();
    const [encryptionKey, setEncryptionKey] = useState<CryptoKey | null>(null);
    const [state, setState] = useState<VaultState | null>(() => user ? readCachedVaultState(user.id) : null);
    const stateRef = useRef(state); const [busy, setBusy] = useState(!state); const [error, setError] = useState('');
    const [deviceState, setDeviceState] = useState<DeviceLocalState | null>(null); const [leaseExpiresAt, setLeaseExpiresAt] = useState<number | null>(null); const [leaseExpired, setLeaseExpired] = useState(false); const [pendingRequest, setPendingRequest] = useState<{ requestId: string; fingerprint: string; code: string } | null>(null); const [passkeyRestores, setPasskeyRestores] = useState<string[]>([]); const [recoveryRequired, setRecoveryRequired] = useState(false);
    const request = useRef(0), unlockRequest = useRef(0), keyGeneration = useRef<string | null>(null);
    const masterKey = useRef<Uint8Array | null>(null);
    const userId = user?.id;
    const preparedMasterKey = useRef<Uint8Array | null>(null);
    const preparedMasterKeyGeneration = useRef<string | null>(null);
    const preparedMasterKeyBootstrap = useRef(false);
    const clearKeys = useCallback(() => { masterKey.current?.fill(0); masterKey.current = null; preparedMasterKey.current?.fill(0); preparedMasterKey.current = null; preparedMasterKeyGeneration.current = null; preparedMasterKeyBootstrap.current = false; keyGeneration.current = null; setEncryptionKey(null); setLeaseExpiresAt(null); }, []);
    const refreshSettings = useCallback(async () => {
        if (!userId) return; const version = ++request.current;
        try { const next = await loadVaultState(userId, !canSync); if (request.current !== version) return;
            const previous = stateRef.current; const enteringPreparing = previous?.envelope_status === 'legacy' && next.envelope_status === 'preparing' && previous.generation === next.generation;
            if (previous && (previous.generation !== next.generation || previous.prepared_generation !== next.prepared_generation && !enteringPreparing)) clearKeys(); stateRef.current = next; setState(next);
            if (next.envelope_status === 'preparing' || !isLegacyVaultState(next)) { const local = await loadDeviceState(userId); setDeviceState(local); setRecoveryRequired(needsRecoverySetup(local)); setLeaseExpired(!!local?.lease && local.lease.claims[5] <= Date.now()); setPendingRequest(null); if (local && !local.wrapper && canSync && navigator.onLine) { try { const pending = await getDeviceRequest(local.deviceId); setPendingRequest({ requestId: pending.requestId, fingerprint: pending.enrollmentFingerprint, code: await formatEnrollmentCode(pending.enrollmentFingerprint) }); } catch { setPendingRequest(null); } } }
        } catch (cause) { if (request.current === version) { clearKeys(); stateRef.current = null; setState(null); setError(cause instanceof Error ? cause.message : 'Could not load vault settings.'); } }
        finally { if (request.current === version) setBusy(false); }
    }, [canSync, clearKeys, userId]);
    const refreshVaultState = useCallback(async () => { await refreshSettings(); }, [refreshSettings]);
    // Settings are external state; cancellation counters prevent stale writes.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    useEffect(() => { const settingsRequest = request; const settingsUnlock = unlockRequest; void refreshSettings(); return () => { settingsRequest.current++; settingsUnlock.current++; }; }, [refreshSettings]);
    useEffect(() => () => clearKeys(), [clearKeys, userId]);
    const lockVault = useCallback((expired = false) => { unlockRequest.current++; clearKeys(); setLeaseExpired(expired); setError(''); if (isLegacyVaultState(stateRef.current)) { stateRef.current = null; setState(null); setBusy(true); void refreshSettings(); } }, [clearKeys, refreshSettings]);
    const validLease = useCallback((local: DeviceLocalState, generation: string, now = Date.now()) => local.lease ? verifyDeviceLease(local.lease, { now, deviceId: local.deviceId, accountId: local.accountId, generation, publicKeyFingerprint: local.publicKeyFingerprint }) : Promise.resolve(false), []);
    const unlockDevice = useCallback(async (mode: 'remembered' | 'passkey-prf') => {
        const vault = stateRef.current; if (!user || !vault) return;
        const version = ++unlockRequest.current; setBusy(true); setError('');
        try {
            const stored = await loadDeviceState(user.id); if (!stored || stored.protectionMode !== mode) throw new Error(mode === 'remembered' ? 'No remembered device is available in this browser.' : 'No passkey device is available in this browser.'); let local: DeviceLocalState = stored;
            const bundleKey = mode === 'remembered' ? local.rememberedKey : await unlockPasskey(local.protection as never); if (!bundleKey) throw new Error('Remembered-device key is unavailable. Use recovery or approve a replacement device.');
            const bundle = await decryptDeviceBundle(local, bundleKey);
            const targetGeneration = enrollmentGeneration(vault); const preparing = vault.envelope_status === 'preparing';
            if (!local.wrapper) { if (!canSync || !navigator.onLine) throw new Error('This device is awaiting approval. Connect and try again after approval.'); local = preparing
                ? await completeDevice(user.id, local.deviceId, bundle.authorizationToken, mode === 'remembered' ? local.rememberedKey : undefined, targetGeneration)
                : await renewThenCompleteDevice({ accountId: user.id, deviceId: local.deviceId, token: bundle.authorizationToken, generation: targetGeneration, publicKeyFingerprint: local.publicKeyFingerprint, rememberedKey: mode === 'remembered' ? local.rememberedKey : undefined }); }
            else if (!preparing && !await validLease(local, targetGeneration)) { if (!canSync || !navigator.onLine) throw new Error('This device lease has expired. Connect to renew authorization.'); local = await renewDeviceLease({ accountId: user.id, deviceId: local.deviceId, token: bundle.authorizationToken, generation: targetGeneration, publicKeyFingerprint: local.publicKeyFingerprint }); }
            if (!local.wrapper || local.wrapper.generation !== targetGeneration || !preparing && !await validLease(local, targetGeneration)) throw new Error('Device authorization is invalid.');
            const opened = await unwrapVaultKey(local.wrapper.wrappedKey, bundle.privateKey, { vaultId: 'quotevault', generation: targetGeneration, targetFingerprint: local.publicKeyFingerprint });
            if (unlockRequest.current !== version) { opened.fill(0); return; }
            if (preparing) { preparedMasterKey.current?.fill(0); preparedMasterKey.current = opened; preparedMasterKeyGeneration.current = targetGeneration; preparedMasterKeyBootstrap.current = false; setDeviceState(local); setLeaseExpired(false); setRecoveryRequired(needsRecoverySetup(local)); return; }
            const quoteKey = await deriveQuoteKey(opened, quoteGeneration(vault)); clearKeys(); masterKey.current = opened; keyGeneration.current = targetGeneration; setDeviceState(local); setLeaseExpired(false); setLeaseExpiresAt(local.lease?.claims[5] ?? null); setRecoveryRequired(needsRecoverySetup(local)); setEncryptionKey(quoteKey);
        } catch (cause) { if (unlockRequest.current === version) setError(cause instanceof Error ? cause.message : 'Could not unlock this device.'); }
        finally { if (unlockRequest.current === version) setBusy(false); }
    }, [canSync, clearKeys, user, validLease]);
    useEffect(() => {
        if (!leaseExpiresAt || !encryptionKey) return; let timer: number | undefined;
        const check = () => { const delay = leaseExpiresAt - Date.now(); if (delay <= 0) { lockVault(true); return; } timer = window.setTimeout(check, Math.min(delay, MAX_TIMEOUT)); };
        const foreground = () => { if (document.visibilityState === 'visible') check(); }; check(); document.addEventListener('visibilitychange', foreground); window.addEventListener('focus', foreground);
        return () => { if (timer !== undefined) window.clearTimeout(timer); document.removeEventListener('visibilitychange', foreground); window.removeEventListener('focus', foreground); };
    }, [encryptionKey, leaseExpiresAt, lockVault]);
    const handleLegacyUnlock = async (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault(); const form = event.currentTarget; const vault = stateRef.current; const password = new FormData(form).get('vault-key'); if (!vault || !isLegacyVaultState(vault) || !user || busy || typeof password !== 'string' || !password) return;
        const version = ++unlockRequest.current; setBusy(true); setError('');
        try { let key: CryptoKey; let generation = vault.generation;
            if (vault.verifier) key = await unlockWithVerifier(password, vault.kdf, vault.verifier); else { if (!canSync) throw new Error('Connect to initialize the vault.'); if (!isAdminUser(user)) throw new Error('The administrator must initialize the vault first.'); const config = await createVaultConfig(password); const { data, error: initError } = await supabase.rpc('initialize_vault', { p_expected_generation: vault.generation, p_kdf: config.kdf, p_verifier: config.verifier }); if (initError) throw new Error(initError.message); const initialized = parseLegacyVaultMutation(data); cacheVaultState(user.id, initialized); stateRef.current = initialized; setState(initialized); key = config.key; generation = initialized.generation; }
            if (unlockRequest.current === version) { keyGeneration.current = generation; setEncryptionKey(key); form.reset(); }
        } catch (cause) { if (unlockRequest.current === version) setError(cause instanceof Error ? cause.message : 'Could not unlock the vault.'); } finally { if (unlockRequest.current === version) setBusy(false); }
    };
    const enroll = useCallback(async (mode: 'remembered' | 'passkey-prf') => {
        if (!user || !stateRef.current || stateRef.current.envelope_status === 'legacy' || !canSync) { setError('Connect to request a device.'); return; } setBusy(true); setError('');
        try { const passkey = mode === 'passkey-prf' ? await registerPasskey({ userId: user.id, userName: user.email ?? user.id, displayName: user.user_metadata?.first_name ?? 'QuoteVault member' }) : undefined;
            const { key: passkeyKey, ...passkeyProtection } = passkey ?? {};
            const pending = await prepareDeviceEnrollment({ accountId: user.id, label: navigator.userAgent.slice(0, 100) || 'Browser', requestKind: deviceState ? 'additional' : 'first', protectionMode: mode, protection: mode === 'remembered' ? { version: 1, mode: 'remembered' } : passkeyProtection, encryptionKey: passkeyKey }); setPendingRequest({ requestId: pending.requestId, fingerprint: pending.enrollmentFingerprint, code: await formatEnrollmentCode(pending.enrollmentFingerprint) }); setDeviceState(await loadDeviceState(user.id));
        } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not request this device.'); } finally { setBusy(false); }
    }, [canSync, deviceState, user]);
    const setPreparedTargetMasterKey = useCallback((generation: string, key: Uint8Array) => {
        if (!(key instanceof Uint8Array) || key.byteLength !== 32 || !generation) throw new Error('Invalid prepared vault key.');
        preparedMasterKey.current?.fill(0); preparedMasterKey.current = key.slice(); preparedMasterKeyGeneration.current = generation; preparedMasterKeyBootstrap.current = true;
    }, []);
    const clearPreparedTargetMasterKey = useCallback((generation?: string) => {
        if (generation && preparedMasterKeyGeneration.current !== generation) return;
        preparedMasterKey.current?.fill(0); preparedMasterKey.current = null; preparedMasterKeyGeneration.current = null; preparedMasterKeyBootstrap.current = false;
    }, []);
    const getApprovedTargetMasterKey = useCallback(async (generation: string) => {
        const vault = stateRef.current;
        if (!user || !vault || vault.envelope_status !== 'preparing' || vault.prepared_generation !== generation) throw new Error('The prepared vault key is unavailable. Unlock an approved prepared device first.');
        if (preparedMasterKey.current && preparedMasterKeyGeneration.current === generation) return preparedMasterKey.current.slice();
        const local = await loadDeviceState(user.id);
        if (!local || local.wrapper?.generation !== generation) throw new Error('The prepared vault key is unavailable. Unlock an approved prepared device first.');
        const key = local.protectionMode === 'remembered' ? local.rememberedKey : await unlockPasskey(local.protection as never);
        if (!key) throw new Error('Unlock this device to recover the prepared vault key.');
        const bundle = await decryptDeviceBundle(local, key);
        const opened = await unwrapVaultKey(local.wrapper.wrappedKey, bundle.privateKey, { vaultId: 'quotevault', generation, targetFingerprint: local.publicKeyFingerprint });
        preparedMasterKey.current?.fill(0); preparedMasterKey.current = opened; preparedMasterKeyGeneration.current = generation; preparedMasterKeyBootstrap.current = false;
        return opened.slice();
    }, [user]);
    const checkDeviceApproval = useCallback(async () => {
        const mode = deviceState?.protectionMode;
        if (!mode) throw new Error('Request a device before checking approval.');
        await unlockDevice(mode);
    }, [deviceState, unlockDevice]);
    const getDeviceAuthorization = useCallback(async () => {
        if (!encryptionKey || !user) throw new Error('Unlock an approved device first.');
        const local = await loadDeviceState(user.id); if (!local) throw new Error('Device enrollment state is missing.');
        const key = local.protectionMode === 'remembered' ? local.rememberedKey : await unlockPasskey(local.protection as never);
        if (!key) throw new Error('Unlock this device to authorize the request.');
        const bundle = await decryptDeviceBundle(local, key);
        return { deviceId: local.deviceId, token: bundle.authorizationToken };
    }, [encryptionKey, user]);
    const renewAuthorizationLease = useCallback(async (auth: { deviceId: string; token: string }) => {
        const vault = stateRef.current;
        if (!user || !vault || isLegacyVaultState(vault) || !deviceState) return;
        const next = await renewDeviceLease({ accountId: user.id, deviceId: auth.deviceId, token: auth.token,
            generation: vault.generation, publicKeyFingerprint: deviceState.publicKeyFingerprint });
        setDeviceState(next); setLeaseExpired(false); setLeaseExpiresAt(next.lease?.claims[5] ?? null);
    }, [deviceState, user]);
    const forgetDevice = useCallback(async () => {
        const local = deviceState; if (local && canSync && navigator.onLine) { const auth = await getDeviceAuthorization(); await revokeOwnDevice(local.deviceId, auth.token); }
        await clearLocalSyncState(); await db.deviceState.clear(); if (user) { clearCachedVaultState(user.id); clearProfileCache(user.id); }
        if ('caches' in window) await Promise.all((await caches.keys()).map(name => caches.delete(name))); setDeviceState(null); lockVault();
    }, [canSync, deviceState, getDeviceAuthorization, lockVault, user]);
    const approveDeviceRequest = useCallback(async (requestId: string, fingerprint: string, code: string, preparedKey?: Uint8Array) => {
        const vault = stateRef.current; if (!vault) throw new Error('Unlock an approved device first.');
        const generation = enrollmentGeneration(vault); const bootstrap = vault.envelope_status === 'preparing' && (preparedKey !== undefined || preparedMasterKeyBootstrap.current && preparedMasterKeyGeneration.current === generation); const master = vault.envelope_status === 'preparing' ? preparedKey?.slice() ?? await getApprovedTargetMasterKey(generation) : masterKey.current;
        if (!master) throw new Error('Unlock an approved device first.');
        const request = await getDeviceRequest(requestId); if (request.enrollmentFingerprint !== fingerprint || await formatEnrollmentCode(request.enrollmentFingerprint) !== code.trim().toUpperCase()) throw new Error('The verification code does not match this device request.');
        try {
            const publicKey = await crypto.subtle.importKey('jwk', request.publicJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']); const wrappedKey = await wrapVaultKey({ version: 1, vaultId: 'quotevault', generation, targetFingerprint: request.publicKeyFingerprint, masterKey: master }, publicKey);
            const auth = bootstrap ? null : await getDeviceAuthorization();
            await approveDevice({ requestId, ownerId: request.ownerId, publicKeyFingerprint: request.publicKeyFingerprint, enrollmentFingerprint: request.enrollmentFingerprint, wrappedKey, generation, approverDeviceId: auth?.deviceId ?? null, approverToken: auth?.token ?? null });
            if (bootstrap) preparedMasterKeyBootstrap.current = false;
        } finally { if (vault.envelope_status === 'preparing') master.fill(0); }
    }, [getApprovedTargetMasterKey, getDeviceAuthorization]);
    const setupRecovery = useCallback(async (phrase: string, replace = false) => {
        const vault = stateRef.current; if (!user || !vault) throw new Error('Unlock the vault before setting up recovery.');
        const generation = enrollmentGeneration(vault); const master = vault.envelope_status === 'preparing' ? await getApprovedTargetMasterKey(generation) : masterKey.current;
        if (!master) throw new Error('Unlock the vault before setting up recovery.');
        const salt = crypto.getRandomValues(new Uint8Array(16)); const kdf = { version: 1 as const, salt: arrayBufferToBase64(salt), iterations: 600000 as const }; salt.fill(0);
        const recoveryKeyId = crypto.randomUUID(); const pair = await generateWrappingKeyPair(); const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey); const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey); const publicKeyFingerprint = await fingerprintPublicJwk(publicJwk); const encryptionKey = await deriveRecoveryBundleKey(phrase, kdf); const token = generateAuthorizationToken();
        try { const encryptedPrivateKey = await encryptPrivateBundle({ version: 1, privateJwk, authorizationToken: token }, encryptionKey, { accountId: user.id, recordId: recoveryKeyId, publicKeyFingerprint, protectionMode: 'recovery', version: 1, recoveryKdf: kdf }); const wrappedKey = await wrapVaultKey({ version: 1, vaultId: 'quotevault', generation, targetFingerprint: publicKeyFingerprint, masterKey: master }, pair.publicKey); const auth = await getDeviceAuthorization(); try { await createRecoveryKey({ recoveryKeyId, publicJwk, publicKeyFingerprint, encryptedPrivateKey, kdf, generation, wrappedKey, deviceId: auth.deviceId, token: auth.token }, replace); } catch (cause) { const local = await loadDeviceState(user.id); let completed: Awaited<ReturnType<typeof completeDevice>> | null = null; try { if (local) completed = await completeDevice(user.id, local.deviceId, auth.token, local.rememberedKey, generation); } catch { /* The original creation failure is more useful. */ } const outcome = completed ? recoverySetupRetryOutcome(replace, recoveryKeyId, completed.activeRecoveryKeyId) : 'original'; if (outcome === 'committed') { setDeviceState(completed); setRecoveryRequired(false); return; } if (outcome === 'other') { setDeviceState(completed); throw new Error('Recovery was configured on another device. This displayed phrase was not saved; reload to continue.'); } throw cause; } const local = await loadDeviceState(user.id); if (local?.recoverySetupRequired) { await saveDeviceState({ ...local, recoverySetupRequired: false }); setDeviceState({ ...local, recoverySetupRequired: false }); } }
        finally { if (vault.envelope_status === 'preparing') master.fill(0); }
    }, [getApprovedTargetMasterKey, getDeviceAuthorization, user]);
    const recoverDevice = useCallback(async (phrase: string, mode: 'remembered' | 'passkey-prf') => {
        if (!user || !canSync || !navigator.onLine) throw new Error('Connect to use personal recovery.');
        const recovery = await beginRecovery(); const key = await deriveRecoveryBundleKey(phrase, recovery.kdf); const bundle = await decryptPrivateBundle(recovery.encryptedPrivateKey, key, { accountId: user.id, recordId: recovery.recoveryKeyId, publicKeyFingerprint: recovery.publicKeyFingerprint, protectionMode: 'recovery', version: 1, recoveryKdf: recovery.kdf }); const privateKey = await crypto.subtle.importKey('jwk', bundle.privateJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
        const responseBytes = new Uint8Array(await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, Uint8Array.from(atob(recovery.ciphertext.replace(/-/g, '+').replace(/_/g, '/')), char => char.charCodeAt(0)))); const response = arrayBufferToBase64(responseBytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); responseBytes.fill(0);
        const completed = await completeRecovery({ challengeId: recovery.challengeId, recoveryKeyId: recovery.recoveryKeyId, response }); const master = await unwrapVaultKey(completed.wrappedKey, privateKey, { vaultId: 'quotevault', generation: completed.generation, targetFingerprint: recovery.publicKeyFingerprint });
        try { const passkey = mode === 'passkey-prf' ? await registerPasskey({ userId: user.id, userName: user.email ?? user.id, displayName: user.user_metadata?.first_name ?? 'QuoteVault member' }) : undefined; const { key: passkeyKey, ...protection } = passkey ?? {}; const enrollment = await prepareDeviceEnrollment({ accountId: user.id, label: navigator.userAgent.slice(0, 100) || 'Recovered browser', requestKind: 'recovery', protectionMode: mode, protection: mode === 'remembered' ? { version: 1, mode: 'remembered' } : protection, encryptionKey: passkeyKey }); const request = await getDeviceRequest(enrollment.deviceId); const publicKey = await crypto.subtle.importKey('jwk', request.publicJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']); const wrappedKey = await wrapVaultKey({ version: 1, vaultId: 'quotevault', generation: completed.generation, targetFingerprint: request.publicKeyFingerprint, masterKey: master }, publicKey); await activateRecoveredDevice({ challengeId: recovery.challengeId, transitionToken: completed.transitionToken, requestId: enrollment.deviceId, enrollmentFingerprint: request.enrollmentFingerprint, generation: completed.generation, wrappedKey }); const pending = await loadDeviceState(user.id); if (!pending) throw new Error('Recovered device state is missing.'); await renewThenCompleteDevice({ accountId: user.id, deviceId: enrollment.deviceId, token: enrollment.authorizationToken, generation: completed.generation, publicKeyFingerprint: pending.publicKeyFingerprint, rememberedKey: enrollment.rememberedKey }); setDeviceState(await loadDeviceState(user.id)); }
        finally { master.fill(0); }
    }, [canSync, user]);
    const findPasskeyRestores = useCallback(async () => (await getPasskeyRestoreDevices()).map(device => device.deviceId), []);
    const restorePasskeyDevice = useCallback(async (deviceId: string) => {
        if (!user || !canSync || !navigator.onLine) throw new Error('Connect to restore a passkey device.');
        if (await loadDeviceState(user.id)) throw new Error('Forget the existing local device before restoring a passkey device.');
        const candidate = (await getPasskeyRestoreDevices()).find(device => device.deviceId === deviceId); if (!candidate) throw new Error('That passkey device is no longer available.');
        const key = await unlockPasskey(candidate.protection, await webauthnChallenge('restoration'));
        const local: DeviceLocalState = { accountId: user.id, deviceId: candidate.deviceId, publicKeyFingerprint: candidate.publicKeyFingerprint, protectionMode: 'passkey-prf', protection: candidate.protection as unknown as Record<string, unknown>, encryptedPrivateBundle: candidate.encryptedPrivateBundle };
        const bundle = await decryptDeviceBundle(local, key); await saveDeviceState(local);
        try {
            const completed = await renewThenCompleteDevice({ accountId: user.id, deviceId: local.deviceId, token: bundle.authorizationToken, generation: candidate.generation, publicKeyFingerprint: local.publicKeyFingerprint }); const vault = stateRef.current;
            if (!vault || isLegacyVaultState(vault) || completed.wrapper?.generation !== vault.generation) throw new Error('Restored device does not match the active vault.');
            const opened = await unwrapVaultKey(completed.wrapper.wrappedKey, bundle.privateKey, { vaultId: 'quotevault', generation: vault.generation, targetFingerprint: completed.publicKeyFingerprint }); const quoteKey = await deriveQuoteKey(opened, vault.generation);
            clearKeys(); masterKey.current = opened; keyGeneration.current = vault.generation; setDeviceState(completed); setLeaseExpired(false); setLeaseExpiresAt(completed.lease?.claims[5] ?? null); setRecoveryRequired(needsRecoverySetup(completed)); setPendingRequest(null); setEncryptionKey(quoteKey);
        } catch (cause) { await deleteDeviceState(user.id); throw cause; }
    }, [canSync, clearKeys, user]);
    if (!user) return children;
    if (encryptionKey && recoveryRequired) return <RecoverySetup onComplete={async phrase => { await setupRecovery(phrase); setRecoveryRequired(false); }} />;
    if (!encryptionKey) { const legacy = isLegacyVaultState(state); const preparing = state?.envelope_status === 'preparing'; const pending = preparing && !!deviceState && !deviceState.wrapper; const gate = vaultGateState({ legacy, pending: false, device: !legacy, key: false, leaseValid: !leaseExpired });
        const approvalUrl = pendingRequest ? `https://quotes.darkmg1.dev/#approve?request=${pendingRequest.requestId}&fingerprint=${encodeURIComponent(pendingRequest.fingerprint)}` : undefined;
        return <VaultGate state={gate as Exclude<typeof gate, 'unlocked'>} preparing={preparing} preparingPending={pending} busy={busy} error={error} initializing={legacy && !state?.verifier} approvalUrl={approvalUrl} approvalCode={pendingRequest?.code} passkeyRestoreIds={passkeyRestores} onFindPasskeyRestores={() => { void findPasskeyRestores().then(setPasskeyRestores).catch(cause => setError(cause instanceof Error ? cause.message : 'Could not find passkey devices.')); }} onRestorePasskey={id => { void restorePasskeyDevice(id).then(() => setPasskeyRestores([])).catch(cause => setError(cause instanceof Error ? cause.message : 'Could not restore passkey device.')); }} onLegacyUnlock={handleLegacyUnlock} onRememberedUnlock={() => void unlockDevice('remembered')} onPasskeyUnlock={() => void unlockDevice('passkey-prf')} onEnroll={mode => void enroll(mode)} onCheckApproval={() => void unlockDevice(deviceState?.protectionMode ?? 'remembered')} onRecover={(phrase, mode) => { void recoverDevice(phrase, mode).then(() => unlockDevice(mode)).catch(cause => setError(cause instanceof Error ? cause.message : 'Recovery failed.')); }} onRetry={() => void refreshSettings()} onSignOut={() => void signOut()} />;
    }
        return <CryptoContext.Provider value={{ encryptionKey, isLocked: false, vaultGeneration: state ? quoteGeneration(state) : null, legacyVaultGeneration: isLegacyVaultState(state) ? state.legacy_generation : null, preparedGeneration: state?.envelope_status === 'preparing' ? state.prepared_generation : null, deviceId: deviceState?.deviceId ?? null, leaseExpiresAt, refreshVaultState, getDeviceAuthorization, setPreparedTargetMasterKey, clearPreparedTargetMasterKey, getApprovedTargetMasterKey, enrollDevice: enroll, checkDeviceApproval, renewDeviceLease: renewAuthorizationLease, lockVault, forgetDevice, approveDeviceRequest, setupRecovery, recoverDevice, findPasskeyRestores, restorePasskeyDevice }}>{children}</CryptoContext.Provider>;
};
export const useCrypto = () => useContext(CryptoContext);
