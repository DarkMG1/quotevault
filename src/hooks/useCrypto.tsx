import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
import type { FormEvent, ReactNode } from 'react';
import { createVaultConfig, unlockWithVerifier } from '../lib/crypto';
import { approvalGeneration, cacheVaultState, clearCachedVaultState, clearLegacyConversionState, enrollmentGeneration, isLegacyVaultState, LEGACY_CONVERSION_KEY_REQUIRED, loadVaultState, parseLegacyVaultMutation, quoteGeneration, readCachedVaultState, readLegacyConversionState } from '../lib/vault';
import type { VaultState } from '../lib/vault';
import { supabase } from '../lib/supabase';
import { useAuth } from './useAuth';
import { isAdminUser } from '../lib/access';
import { VaultGate, vaultGateState } from '../components/VaultGate';
import { RecoverySetup } from '../components/RecoverySetup';
import { acknowledgeConversionQueue, approveDevice, completeDevice, deleteDeviceState, deviceWrapperForGeneration, formatEnrollmentCode, getConversionWrapper, getDeviceRequest, loadDeviceState, needsDeviceCompletion, needsRecoverySetup, recoverySetupRetryOutcome, revokeOwnDevice, saveDeviceState } from '../lib/device';
import { activateRecoveredDevice, beginRecovery, completeRecovery, createRecoveryKey, decryptDeviceBundle, getPasskeyRestoreDevices, prepareDeviceEnrollment, registerPasskey, renewDeviceLease, renewThenCompleteDevice, unlockPasskey, webauthnChallenge } from '../lib/device-security';
import { decryptPrivateBundle, deriveQuoteKey, deriveRecoveryBundleKey, encryptPrivateBundle, fingerprintPublicJwk, generateAuthorizationToken, generateWrappingKeyPair, unwrapVaultKey, wrapVaultKey } from '../lib/device-crypto';
import { arrayBufferToBase64 } from '../lib/crypto';
import { verifyDeviceLease } from '../lib/lease';
import { acknowledgeEmptyConversion, clearLocalSyncState } from '../lib/sync';
import { db } from '../lib/db';
import { clearProfileCache } from '../lib/profile-cache';
import type { DeviceLocalState } from '../types';
import { attestVaultKeys, createKeyAttestation, getPendingEnvelopeMigration, reportEnvelopeMigrationEmptyQueue } from '../lib/vault-migration';
import { normalizeRecoveryPhrase } from '../lib/recovery-phrase';

interface CryptoContextType {
    encryptionKey: CryptoKey | null; isLocked: boolean; vaultGeneration: string | null; legacyVaultGeneration: string | null;
    envelopeStatus: VaultState['envelope_status'] | null; preparedGeneration: string | null; deviceId: string | null; deviceApproved: boolean; leaseExpiresAt: number | null;
    deviceApproval: { url: string; code: string } | null;
    refreshVaultState: () => Promise<void>;
    getDeviceAuthorization: () => Promise<{ deviceId: string; token: string }>;
    getConversionQuoteKey: (sourceGeneration: string) => Promise<CryptoKey>;
    unlockLegacyQueuedChanges: (password: string) => Promise<void>;
    acknowledgeConversion: (sourceGeneration: string) => Promise<void>;
    setPreparedTargetMasterKey: (generation: string, key: Uint8Array) => void;
    clearPreparedTargetMasterKey: (generation?: string) => void;
    getApprovedTargetMasterKey: (generation: string) => Promise<Uint8Array>;
    enrollDevice: (mode: 'remembered' | 'passkey-prf') => Promise<void>;
    checkDeviceApproval: () => Promise<void>;
    reportMigrationEmptyQueue: (revision: number) => Promise<void>;
    renewDeviceLease: (authorization: { deviceId: string; token: string }) => Promise<void>;
    lockVault: () => void; forgetDevice: () => Promise<void>; approveDeviceRequest: (requestId: string, fingerprint: string, code: string) => Promise<void>;
    setupRecovery: (phrase: string, replace?: boolean) => Promise<void>; recoverDevice: (phrase: string, mode: 'remembered' | 'passkey-prf') => Promise<void>;
    findPasskeyRestores: () => Promise<string[]>; restorePasskeyDevice: (deviceId: string) => Promise<void>;
}
const CryptoContext = createContext<CryptoContextType>({ encryptionKey: null, isLocked: true, vaultGeneration: null, legacyVaultGeneration: null, envelopeStatus: null, preparedGeneration: null, deviceId: null, deviceApproved: false, leaseExpiresAt: null, deviceApproval: null,
    refreshVaultState: async () => {}, getDeviceAuthorization: async () => { throw new Error('Unlock an approved device first.'); }, getConversionQuoteKey: async () => { throw new Error('Unlock an approved device first.'); }, unlockLegacyQueuedChanges: async () => { throw new Error(LEGACY_CONVERSION_KEY_REQUIRED); }, acknowledgeConversion: async () => {}, setPreparedTargetMasterKey: () => {}, clearPreparedTargetMasterKey: () => {}, getApprovedTargetMasterKey: async () => { throw new Error('Unlock an approved prepared device first.'); }, enrollDevice: async () => {}, checkDeviceApproval: async () => {}, reportMigrationEmptyQueue: async () => {}, renewDeviceLease: async () => { throw new Error('Unlock an approved device first.'); }, lockVault: () => {}, forgetDevice: async () => {}, approveDeviceRequest: async () => {}, setupRecovery: async () => {}, recoverDevice: async () => {}, findPasskeyRestores: async () => [], restorePasskeyDevice: async () => {} });
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
    const keyEpoch = useRef(0);
    const legacyConversionKey = useRef<{ generation: string; key: CryptoKey } | null>(null);
    // Kept for the unlocked session so background sync never re-prompts a passkey.
    const deviceAuthorization = useRef<{ deviceId: string; token: string } | null>(null);
    const attestedDevice = useRef('');
    const clearKeys = useCallback(() => { keyEpoch.current++; masterKey.current?.fill(0); masterKey.current = null; preparedMasterKey.current?.fill(0); preparedMasterKey.current = null; preparedMasterKeyGeneration.current = null; preparedMasterKeyBootstrap.current = false; legacyConversionKey.current = null; deviceAuthorization.current = null; keyGeneration.current = null; setEncryptionKey(null); setLeaseExpiresAt(null); }, []);
    const refreshSettings = useCallback(async () => {
        if (!userId) return; const version = ++request.current;
        try { const next = await loadVaultState(userId, !canSync); if (request.current !== version) return;
            const previous = stateRef.current; const enteringPreparing = previous?.envelope_status !== 'preparing' && next.envelope_status === 'preparing' && previous?.generation === next.generation;
            if (previous && (previous.generation !== next.generation || previous.prepared_generation !== next.prepared_generation && !enteringPreparing)) clearKeys(); stateRef.current = next; setState(next);
            if (next.envelope_status === 'preparing' || !isLegacyVaultState(next)) { const local = await loadDeviceState(userId); setDeviceState(local); setRecoveryRequired(needsRecoverySetup(local)); setLeaseExpired(!!local?.lease && local.lease.claims[5] <= Date.now()); setPendingRequest(null); if (local && !local.wrapper && !local.preparedWrapper && canSync && navigator.onLine) { try { const pending = await getDeviceRequest(local.deviceId); setPendingRequest({ requestId: pending.requestId, fingerprint: pending.enrollmentFingerprint, code: await formatEnrollmentCode(pending.enrollmentFingerprint) }); } catch { setPendingRequest(null); } } }
            else if (next.envelope_status === 'legacy') { setDeviceState(null); setPendingRequest(null); }
        } catch (cause) { if (request.current === version) { clearKeys(); stateRef.current = null; setState(null); setError(cause instanceof Error ? cause.message : 'Could not load vault settings.'); } }
        finally { if (request.current === version) setBusy(false); }
    }, [canSync, clearKeys, userId]);
    const refreshVaultState = useCallback(async () => { await refreshSettings(); }, [refreshSettings]);
    // Settings are external state; cancellation counters prevent stale writes.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    useEffect(() => { const settingsRequest = request; const settingsUnlock = unlockRequest; void refreshSettings(); return () => { settingsRequest.current++; settingsUnlock.current++; }; }, [refreshSettings]);
    useEffect(() => () => clearKeys(), [clearKeys, userId]);
    const lockVault = useCallback((expired: unknown = false) => { unlockRequest.current++; clearKeys(); setLeaseExpired(expired === true); setError(''); stateRef.current = null; setState(null); setBusy(true); void refreshSettings(); }, [clearKeys, refreshSettings]);
    const validLease = useCallback((local: DeviceLocalState, generation: string, now = Date.now()) => local.lease ? verifyDeviceLease(local.lease, { now, deviceId: local.deviceId, accountId: local.accountId, generation, publicKeyFingerprint: local.publicKeyFingerprint }) : Promise.resolve(false), []);
    const unlockDevice = useCallback(async (mode: 'remembered' | 'passkey-prf') => {
        const vault = stateRef.current; if (!user || !vault) return;
        const version = ++unlockRequest.current; setBusy(true); setError('');
        try {
            const stored = await loadDeviceState(user.id); if (!stored || stored.protectionMode !== mode) throw new Error(mode === 'remembered' ? 'No remembered device is available in this browser.' : 'No passkey device is available in this browser.'); let local: DeviceLocalState = stored;
            const bundleKey = mode === 'remembered' ? local.rememberedKey : await unlockPasskey(local.protection as never); if (!bundleKey) throw new Error('Remembered-device key is unavailable. Use recovery or approve a replacement device.');
            const bundle = await decryptDeviceBundle(local, bundleKey);
            const targetGeneration = enrollmentGeneration(vault); const preparing = vault.envelope_status === 'preparing';
            if (preparing && !isLegacyVaultState(vault)) {
                const savedTarget = deviceWrapperForGeneration(local, targetGeneration);
                if (needsDeviceCompletion(local, vault.generation)) {
                    const completed = await renewThenCompleteDevice({ accountId: user.id, deviceId: local.deviceId, token: bundle.authorizationToken, generation: vault.generation, publicKeyFingerprint: local.publicKeyFingerprint, rememberedKey: mode === 'remembered' ? local.rememberedKey : undefined });
                    local = savedTarget ? { ...completed, preparedWrapper: savedTarget } : completed; await saveDeviceState(local);
                } else if (!await validLease(local, vault.generation)) {
                    if (!canSync || !navigator.onLine) throw new Error('This device lease has expired. Connect to renew authorization.');
                    local = await renewDeviceLease({ accountId: user.id, deviceId: local.deviceId, token: bundle.authorizationToken, generation: vault.generation, publicKeyFingerprint: local.publicKeyFingerprint });
                }
                const sourceWrapper = deviceWrapperForGeneration(local, vault.generation); if (!sourceWrapper || !await validLease(local, vault.generation)) throw new Error('Device authorization is invalid.');
                let targetWrapper = deviceWrapperForGeneration(local, targetGeneration);
                if (!targetWrapper && canSync && navigator.onLine) { try { const completed = await completeDevice(user.id, local.deviceId, bundle.authorizationToken, mode === 'remembered' ? local.rememberedKey : undefined, targetGeneration); targetWrapper = deviceWrapperForGeneration(completed, targetGeneration); if (targetWrapper) { local = { ...completed, wrapper: sourceWrapper, preparedWrapper: targetWrapper }; await saveDeviceState(local); } } catch { /* Source access remains available while target wrappers are staged. */ } }
                const sourceOpened = await unwrapVaultKey(sourceWrapper.wrappedKey, bundle.privateKey, { vaultId: 'quotevault', generation: vault.generation, targetFingerprint: local.publicKeyFingerprint });
                let targetOpened: Uint8Array | null = null; let retained = false;
                try { targetOpened = targetWrapper ? await unwrapVaultKey(targetWrapper.wrappedKey, bundle.privateKey, { vaultId: 'quotevault', generation: targetGeneration, targetFingerprint: local.publicKeyFingerprint }) : null; const quoteKey = await deriveQuoteKey(sourceOpened, vault.generation); if (unlockRequest.current !== version || stateRef.current?.generation !== vault.generation || stateRef.current?.prepared_generation !== targetGeneration) return; clearKeys(); masterKey.current = sourceOpened; if (targetOpened) { preparedMasterKey.current = targetOpened; preparedMasterKeyGeneration.current = targetGeneration; preparedMasterKeyBootstrap.current = false; } retained = true; keyGeneration.current = vault.generation; setDeviceState(local); setLeaseExpired(false); setLeaseExpiresAt(local.lease?.claims[5] ?? null); setRecoveryRequired(needsRecoverySetup(local)); setEncryptionKey(quoteKey); }
                finally { if (!retained) { sourceOpened.fill(0); targetOpened?.fill(0); } }
                return;
            }
            if (needsDeviceCompletion(local, targetGeneration)) { if (!canSync || !navigator.onLine) throw new Error('This device needs its current vault authorization. Connect and try again.'); local = await renewThenCompleteDevice({ accountId: user.id, deviceId: local.deviceId, token: bundle.authorizationToken, generation: targetGeneration, leaseGeneration: preparing ? vault.generation : targetGeneration, publicKeyFingerprint: local.publicKeyFingerprint, rememberedKey: mode === 'remembered' ? local.rememberedKey : undefined }); }
            else if (!preparing && !await validLease(local, targetGeneration)) { if (!canSync || !navigator.onLine) throw new Error('This device lease has expired. Connect to renew authorization.'); local = await renewDeviceLease({ accountId: user.id, deviceId: local.deviceId, token: bundle.authorizationToken, generation: targetGeneration, publicKeyFingerprint: local.publicKeyFingerprint }); }
            const wrapper = deviceWrapperForGeneration(local, targetGeneration); if (!wrapper || !preparing && !await validLease(local, targetGeneration)) throw new Error('Device authorization is invalid.');
            if (!preparing && local.wrapper !== wrapper) { const previous = local.wrapper?.generation; local = { ...local, wrapper, preparedWrapper: undefined }; await saveDeviceState(local);
                // Best effort: queued older work is acknowledged after conversion instead, and a rollback leaves nothing to release.
                if (previous && previous !== wrapper.generation && canSync && navigator.onLine) { const deviceId = local.deviceId; void acknowledgeEmptyConversion(user.id, previous, source => acknowledgeConversionQueue(source, deviceId, bundle.authorizationToken)).catch(() => undefined); } }
            const opened = await unwrapVaultKey(wrapper.wrappedKey, bundle.privateKey, { vaultId: 'quotevault', generation: targetGeneration, targetFingerprint: local.publicKeyFingerprint });
            if (unlockRequest.current !== version) { opened.fill(0); return; }
            if (preparing) { preparedMasterKey.current?.fill(0); preparedMasterKey.current = opened; preparedMasterKeyGeneration.current = targetGeneration; preparedMasterKeyBootstrap.current = false; setDeviceState(local); setLeaseExpired(false); setRecoveryRequired(needsRecoverySetup(local)); return; }
            let retained = false;
            try { const quoteKey = await deriveQuoteKey(opened, quoteGeneration(vault)); if (unlockRequest.current !== version || stateRef.current?.generation !== vault.generation || stateRef.current?.envelope_status !== vault.envelope_status) return; clearKeys(); masterKey.current = opened; retained = true; deviceAuthorization.current = { deviceId: local.deviceId, token: bundle.authorizationToken }; keyGeneration.current = targetGeneration; setDeviceState(local); setLeaseExpired(false); setLeaseExpiresAt(local.lease?.claims[5] ?? null); setRecoveryRequired(needsRecoverySetup(local)); setEncryptionKey(quoteKey); }
            finally { if (!retained) opened.fill(0); }
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
            if (unlockRequest.current === version && stateRef.current?.generation === generation) { keyGeneration.current = generation; setEncryptionKey(key); form.reset(); }
        } catch (cause) { if (unlockRequest.current === version) setError(cause instanceof Error ? cause.message : 'Could not unlock the vault.'); } finally { if (unlockRequest.current === version) setBusy(false); }
    };
    const enroll = useCallback(async (mode: 'remembered' | 'passkey-prf') => {
        if (!user || !stateRef.current || stateRef.current.envelope_status === 'legacy' || !canSync) { setError('Connect to request a device.'); return; } setBusy(true); setError('');
        try { const passkey = mode === 'passkey-prf' ? await registerPasskey({ userId: user.id, userName: user.email ?? user.id, displayName: user.user_metadata?.first_name ?? 'QuoteVault member' }) : undefined;
            const { key: passkeyKey, ...passkeyProtection } = passkey ?? {};
            const pending = await prepareDeviceEnrollment({ accountId: user.id, label: navigator.userAgent.slice(0, 100) || 'Browser', requestKind: deviceState?.wrapper ? 'additional' : 'first', protectionMode: mode, protection: mode === 'remembered' ? { version: 1, mode: 'remembered' } : passkeyProtection, encryptionKey: passkeyKey }); setPendingRequest({ requestId: pending.requestId, fingerprint: pending.enrollmentFingerprint, code: await formatEnrollmentCode(pending.enrollmentFingerprint) }); setDeviceState(await loadDeviceState(user.id));
        } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not request this device.'); } finally { setBusy(false); }
    }, [canSync, deviceState, user]);
    const setPreparedTargetMasterKey = useCallback((generation: string, key: Uint8Array) => {
        if (!(key instanceof Uint8Array) || key.byteLength !== 32 || !generation) throw new Error('Invalid prepared vault key.');
        keyEpoch.current++;
        preparedMasterKey.current?.fill(0); preparedMasterKey.current = key.slice(); preparedMasterKeyGeneration.current = generation; preparedMasterKeyBootstrap.current = true;
    }, []);
    const clearPreparedTargetMasterKey = useCallback((generation?: string) => {
        if (generation && preparedMasterKeyGeneration.current !== generation) return;
        keyEpoch.current++;
        preparedMasterKey.current?.fill(0); preparedMasterKey.current = null; preparedMasterKeyGeneration.current = null; preparedMasterKeyBootstrap.current = false;
    }, []);
    const getApprovedTargetMasterKey = useCallback(async (generation: string) => {
        const vault = stateRef.current;
        if (!user || !vault || vault.envelope_status !== 'preparing' || vault.prepared_generation !== generation) throw new Error('The prepared vault key is unavailable. Unlock an approved prepared device first.');
        if (preparedMasterKey.current && preparedMasterKeyGeneration.current === generation) return preparedMasterKey.current.slice();
        const epoch = keyEpoch.current;
        let local = await loadDeviceState(user.id);
        if (!local) throw new Error('The prepared vault key is unavailable. Unlock an approved prepared device first.');
        const key = local.protectionMode === 'remembered' ? local.rememberedKey : await unlockPasskey(local.protection as never);
        if (!key) throw new Error('Unlock this device to recover the prepared vault key.');
        const bundle = await decryptDeviceBundle(local, key);
        if (needsDeviceCompletion(local, generation)) {
            if (!canSync || !navigator.onLine) throw new Error('Connect to fetch this device\'s prepared vault authorization.');
            const sourceWrapper = !isLegacyVaultState(vault) ? deviceWrapperForGeneration(local, vault.generation) : undefined;
            const completed = await renewThenCompleteDevice({ accountId: user.id, deviceId: local.deviceId, token: bundle.authorizationToken, generation, leaseGeneration: vault.generation, publicKeyFingerprint: local.publicKeyFingerprint, rememberedKey: local.protectionMode === 'remembered' ? local.rememberedKey : undefined });
            const targetWrapper = deviceWrapperForGeneration(completed, generation);
            local = sourceWrapper && targetWrapper ? { ...completed, wrapper: sourceWrapper, preparedWrapper: targetWrapper } : completed;
            if (sourceWrapper && targetWrapper) await saveDeviceState(local);
        }
        const wrapper = deviceWrapperForGeneration(local, generation); if (!wrapper) throw new Error('The prepared vault key is unavailable. Unlock an approved prepared device first.');
        const opened = await unwrapVaultKey(wrapper.wrappedKey, bundle.privateKey, { vaultId: 'quotevault', generation, targetFingerprint: local.publicKeyFingerprint });
        if (keyEpoch.current !== epoch || stateRef.current?.envelope_status !== 'preparing' || stateRef.current.prepared_generation !== generation) { opened.fill(0); throw new Error('The prepared vault key request was cancelled.'); }
        preparedMasterKey.current?.fill(0); preparedMasterKey.current = opened; preparedMasterKeyGeneration.current = generation; preparedMasterKeyBootstrap.current = false;
        return opened.slice();
    }, [canSync, user]);
    const checkDeviceApproval = useCallback(async () => {
        const mode = deviceState?.protectionMode;
        if (!mode) throw new Error('Request a device before checking approval.');
        await unlockDevice(mode);
    }, [deviceState, unlockDevice]);
    const getDeviceAuthorization = useCallback(async () => {
        if (!encryptionKey || !user) throw new Error('Unlock an approved device first.');
        if (deviceAuthorization.current) return deviceAuthorization.current;
        const epoch = keyEpoch.current;
        const local = await loadDeviceState(user.id); if (!local) throw new Error('Device enrollment state is missing.');
        const key = local.protectionMode === 'remembered' ? local.rememberedKey : await unlockPasskey(local.protection as never);
        if (!key) throw new Error('Unlock this device to authorize the request.');
        const bundle = await decryptDeviceBundle(local, key);
        const authorization = { deviceId: local.deviceId, token: bundle.authorizationToken };
        if (keyEpoch.current === epoch) deviceAuthorization.current = authorization;
        return authorization;
    }, [encryptionKey, user]);
    // Migrations wrap a new vault key only for public keys attested under the current key.
    useEffect(() => {
        const vault = stateRef.current; const generation = keyGeneration.current;
        if (!encryptionKey || !deviceState || !vault || isLegacyVaultState(vault) || generation !== vault.generation || !canSync) return;
        const attestation = `${deviceState.deviceId}:${generation}`; if (attestedDevice.current === attestation) return; attestedDevice.current = attestation;
        void (async () => { try { const auth = await getDeviceAuthorization(); await attestVaultKeys(generation, auth, [{ device_id: auth.deviceId, attestation: await createKeyAttestation(encryptionKey, 'device', auth.deviceId, generation, deviceState.publicKeyFingerprint) }], []); } catch { attestedDevice.current = ''; } })();
    }, [canSync, deviceState, encryptionKey, getDeviceAuthorization]);
    const getConversionQuoteKey = useCallback(async (sourceGeneration: string) => {
        const legacy = user ? readLegacyConversionState(user.id) : null;
        if (legacy?.generation === sourceGeneration) {
            if (legacyConversionKey.current?.generation === sourceGeneration) return legacyConversionKey.current.key;
            throw new Error(LEGACY_CONVERSION_KEY_REQUIRED);
        }
        if (!user || !canSync || !navigator.onLine) throw new Error('Connect an approved device before converting older saved changes.');
        const auth = await getDeviceAuthorization();
        const local = await loadDeviceState(user.id);
        if (!local) throw new Error('Device enrollment state is missing.');
        const bundleKey = local.protectionMode === 'remembered' ? local.rememberedKey : await unlockPasskey(local.protection as never);
        if (!bundleKey) throw new Error('Unlock this device to convert older saved changes.');
        const bundle = await decryptDeviceBundle(local, bundleKey);
        const wrapper = await getConversionWrapper(sourceGeneration, auth.deviceId, auth.token);
        const oldMaster = await unwrapVaultKey(wrapper.wrappedKey, bundle.privateKey, { vaultId: 'quotevault', generation: sourceGeneration, targetFingerprint: local.publicKeyFingerprint });
        try { return await deriveQuoteKey(oldMaster, sourceGeneration); } finally { oldMaster.fill(0); }
    }, [canSync, getDeviceAuthorization, user]);
    const unlockLegacyQueuedChanges = useCallback(async (password: string) => {
        if (!user) throw new Error(LEGACY_CONVERSION_KEY_REQUIRED);
        const legacy = readLegacyConversionState(user.id);
        if (!legacy) throw new Error('No previous vault key is needed on this device.');
        const epoch = keyEpoch.current; const currentGeneration = stateRef.current?.generation;
        const key = await unlockWithVerifier(password, legacy.kdf, legacy.verifier);
        if (keyEpoch.current !== epoch || stateRef.current?.generation !== currentGeneration) throw new Error('Vault access changed; enter the previous group vault key again.');
        legacyConversionKey.current = { generation: legacy.generation, key };
    }, [user]);
    const acknowledgeConversion = useCallback(async (sourceGeneration: string) => {
        if (user && readLegacyConversionState(user.id)?.generation === sourceGeneration) {
            legacyConversionKey.current = null;
            clearLegacyConversionState(user.id);
            return;
        }
        const auth = await getDeviceAuthorization();
        await acknowledgeConversionQueue(sourceGeneration, auth.deviceId, auth.token);
    }, [getDeviceAuthorization, user]);
    const reportMigrationEmptyQueue = useCallback(async (revision: number) => {
        if (stateRef.current?.envelope_status !== 'preparing') return;
        const auth = await getDeviceAuthorization();
        const pending = await getPendingEnvelopeMigration(auth.deviceId, auth.token);
        if (!pending.migrationId || pending.sourceRevision !== revision) return;
        await reportEnvelopeMigrationEmptyQueue(pending.migrationId, revision, auth.deviceId, auth.token);
    }, [getDeviceAuthorization]);
    const renewAuthorizationLease = useCallback(async (auth: { deviceId: string; token: string }) => {
        const vault = stateRef.current;
        // Stored state, not deviceState: each renewal replaces deviceState and must not re-create the sync context.
        const local = user ? await loadDeviceState(user.id) : null;
        if (!user || !vault || isLegacyVaultState(vault) || !local) return;
        const next = await renewDeviceLease({ accountId: user.id, deviceId: auth.deviceId, token: auth.token,
            generation: vault.generation, publicKeyFingerprint: local.publicKeyFingerprint });
        setDeviceState(next); setLeaseExpired(false); setLeaseExpiresAt(next.lease?.claims[5] ?? null);
    }, [user]);
    const forgetDevice = useCallback(async () => {
        const local = deviceState; if ((local?.wrapper || local?.preparedWrapper) && canSync && navigator.onLine) { const auth = await getDeviceAuthorization(); await revokeOwnDevice(local.deviceId, auth.token); }
        await clearLocalSyncState(); await db.deviceState.clear(); if (user) { clearCachedVaultState(user.id); clearProfileCache(user.id); }
        if ('caches' in window) await Promise.all((await caches.keys()).map(name => caches.delete(name))); setDeviceState(null); lockVault();
    }, [canSync, deviceState, getDeviceAuthorization, lockVault, user]);
    const approveDeviceRequest = useCallback(async (requestId: string, fingerprint: string, code: string) => {
        const vault = stateRef.current; if (!vault) throw new Error('Unlock an approved device first.');
        const epoch = keyEpoch.current; const generation = approvalGeneration(vault); const bootstrap = isLegacyVaultState(vault) && vault.envelope_status === 'preparing' && preparedMasterKeyBootstrap.current && preparedMasterKeyGeneration.current === generation; const master = vault.envelope_status === 'preparing' && isLegacyVaultState(vault) ? await getApprovedTargetMasterKey(generation) : masterKey.current?.slice() ?? null;
        if (!master) throw new Error('Unlock an approved device first.');
        try {
            const request = await getDeviceRequest(requestId); if (request.enrollmentFingerprint !== fingerprint || await formatEnrollmentCode(request.enrollmentFingerprint) !== code.trim().toUpperCase()) throw new Error('The verification code does not match this device request.');
            if (keyEpoch.current !== epoch) throw new Error('Vault access changed; unlock and approve the device again.');
            const publicKey = await crypto.subtle.importKey('jwk', request.publicJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']); const wrappedKey = await wrapVaultKey({ version: 1, vaultId: 'quotevault', generation, targetFingerprint: request.publicKeyFingerprint, masterKey: master }, publicKey);
            const auth = bootstrap ? null : await getDeviceAuthorization();
            if (keyEpoch.current !== epoch) throw new Error('Vault access changed; unlock and approve the device again.');
            await approveDevice({ requestId, ownerId: request.ownerId, publicKeyFingerprint: request.publicKeyFingerprint, enrollmentFingerprint: request.enrollmentFingerprint, wrappedKey, generation, approverDeviceId: auth?.deviceId ?? null, approverToken: auth?.token ?? null });
            if (bootstrap) preparedMasterKeyBootstrap.current = false;
        } finally { master.fill(0); }
    }, [getApprovedTargetMasterKey, getDeviceAuthorization]);
    const setupRecovery = useCallback(async (phrase: string, replace = false) => {
        const vault = stateRef.current; if (!user || !vault) throw new Error('Unlock the vault before setting up recovery.');
        const epoch = keyEpoch.current; const generation = approvalGeneration(vault); const preparingLegacy = vault.envelope_status === 'preparing' && isLegacyVaultState(vault); const master = preparingLegacy ? await getApprovedTargetMasterKey(generation) : masterKey.current?.slice() ?? null;
        if (!master) throw new Error('Unlock the vault before setting up recovery.');
        try { const salt = crypto.getRandomValues(new Uint8Array(16)); const kdf = { version: 1 as const, salt: arrayBufferToBase64(salt), iterations: 600000 as const }; salt.fill(0);
            const recoveryKeyId = crypto.randomUUID(); const pair = await generateWrappingKeyPair(); const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey); const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey); const publicKeyFingerprint = await fingerprintPublicJwk(publicJwk); const encryptionKey = await deriveRecoveryBundleKey(phrase, kdf); const token = generateAuthorizationToken();
            const encryptedPrivateKey = await encryptPrivateBundle({ version: 1, privateJwk, authorizationToken: token }, encryptionKey, { accountId: user.id, recordId: recoveryKeyId, publicKeyFingerprint, protectionMode: 'recovery', version: 1, recoveryKdf: kdf }); if (keyEpoch.current !== epoch) throw new Error('Vault access changed; unlock and set up recovery again.'); const wrappedKey = await wrapVaultKey({ version: 1, vaultId: 'quotevault', generation, targetFingerprint: publicKeyFingerprint, masterKey: master }, pair.publicKey); const auth = await getDeviceAuthorization(); if (keyEpoch.current !== epoch) throw new Error('Vault access changed; unlock and set up recovery again.'); try { await createRecoveryKey({ recoveryKeyId, publicJwk, publicKeyFingerprint, encryptedPrivateKey, kdf, generation, wrappedKey, deviceId: auth.deviceId, token: auth.token }, replace); } catch (cause) { const local = await loadDeviceState(user.id); let completed: Awaited<ReturnType<typeof completeDevice>> | null = null; try { if (local) { const savedTarget = vault.envelope_status === 'preparing' && !isLegacyVaultState(vault) && vault.prepared_generation ? deviceWrapperForGeneration(local, vault.prepared_generation) : undefined; completed = await completeDevice(user.id, local.deviceId, auth.token, local.rememberedKey, generation); if (savedTarget) { completed = { ...completed, preparedWrapper: savedTarget }; await saveDeviceState(completed); } } } catch { /* The original creation failure is more useful. */ } const outcome = completed ? recoverySetupRetryOutcome(replace, recoveryKeyId, completed.activeRecoveryKeyId) : 'original'; if (outcome === 'committed') { setDeviceState(completed); setRecoveryRequired(false); return; } if (outcome === 'other') { setDeviceState(completed); throw new Error('Recovery was configured on another device. This displayed phrase was not saved; reload to continue.'); } throw cause; } try { await attestVaultKeys(generation, auth, [], [{ recovery_key_id: recoveryKeyId, attestation: await createKeyAttestation(await deriveQuoteKey(master, generation), 'recovery', recoveryKeyId, generation, publicKeyFingerprint) }]); } catch { /* An unattested recovery key shows as a migration blocker until it is replaced. */ } const local = await loadDeviceState(user.id); if (local?.recoverySetupRequired) { await saveDeviceState({ ...local, recoverySetupRequired: false }); setDeviceState({ ...local, recoverySetupRequired: false }); } }
        finally { master.fill(0); }
    }, [getApprovedTargetMasterKey, getDeviceAuthorization, user]);
    const recoverDevice = useCallback(async (phrase: string, mode: 'remembered' | 'passkey-prf') => {
        if (!user || !canSync || !navigator.onLine) throw new Error('Connect to use personal recovery.');
        const recovery = await beginRecovery(); const key = await deriveRecoveryBundleKey(normalizeRecoveryPhrase(phrase), recovery.kdf); const bundle = await decryptPrivateBundle(recovery.encryptedPrivateKey, key, { accountId: user.id, recordId: recovery.recoveryKeyId, publicKeyFingerprint: recovery.publicKeyFingerprint, protectionMode: 'recovery', version: 1, recoveryKdf: recovery.kdf }); const privateKey = await crypto.subtle.importKey('jwk', bundle.privateJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
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
        const epoch = keyEpoch.current;
        try {
            const vault = stateRef.current; if (!vault) throw new Error('Restored device does not match the current vault.'); const targetGeneration = enrollmentGeneration(vault);
            let completed = await renewThenCompleteDevice({ accountId: user.id, deviceId: local.deviceId, token: bundle.authorizationToken, generation: candidate.generation, leaseGeneration: vault.envelope_status === 'preparing' ? vault.generation : candidate.generation, publicKeyFingerprint: local.publicKeyFingerprint });
            const candidateWrapper = deviceWrapperForGeneration(completed, candidate.generation); if (!candidateWrapper) throw new Error('Restored device does not match the current vault.');
            if (vault.envelope_status === 'preparing' && !isLegacyVaultState(vault)) {
                const source = candidate.generation === vault.generation ? completed : await completeDevice(user.id, local.deviceId, bundle.authorizationToken, undefined, vault.generation); const sourceWrapper = deviceWrapperForGeneration(source, vault.generation); if (!sourceWrapper) throw new Error('Restored device does not match the current vault.');
                let targetWrapper = candidate.generation === targetGeneration ? candidateWrapper : undefined;
                if (!targetWrapper) { try { const target = await completeDevice(user.id, local.deviceId, bundle.authorizationToken, undefined, targetGeneration); targetWrapper = deviceWrapperForGeneration(target, targetGeneration); } catch { /* The device can use the source while target wrappers are staged. */ } }
                completed = { ...source, wrapper: sourceWrapper, ...(targetWrapper ? { preparedWrapper: targetWrapper } : {}) }; await saveDeviceState(completed);
                const sourceOpened = await unwrapVaultKey(sourceWrapper.wrappedKey, bundle.privateKey, { vaultId: 'quotevault', generation: vault.generation, targetFingerprint: completed.publicKeyFingerprint }); let targetOpened: Uint8Array | null = null; let retained = false;
                try { targetOpened = targetWrapper ? await unwrapVaultKey(targetWrapper.wrappedKey, bundle.privateKey, { vaultId: 'quotevault', generation: targetGeneration, targetFingerprint: completed.publicKeyFingerprint }) : null; const quoteKey = await deriveQuoteKey(sourceOpened, vault.generation); if (keyEpoch.current !== epoch || stateRef.current?.generation !== vault.generation || stateRef.current?.prepared_generation !== targetGeneration) throw new Error('Passkey restoration was cancelled.'); clearKeys(); masterKey.current = sourceOpened; if (targetOpened) { preparedMasterKey.current = targetOpened; preparedMasterKeyGeneration.current = targetGeneration; preparedMasterKeyBootstrap.current = false; } retained = true; keyGeneration.current = vault.generation; setDeviceState(completed); setLeaseExpired(false); setLeaseExpiresAt(completed.lease?.claims[5] ?? null); setRecoveryRequired(needsRecoverySetup(completed)); setPendingRequest(null); setEncryptionKey(quoteKey); return; }
                finally { if (!retained) { sourceOpened.fill(0); targetOpened?.fill(0); } }
            }
            const targetWrapper = deviceWrapperForGeneration(completed, targetGeneration); if (!targetWrapper) throw new Error('Restored device does not match the current vault.');
            const opened = await unwrapVaultKey(targetWrapper.wrappedKey, bundle.privateKey, { vaultId: 'quotevault', generation: targetGeneration, targetFingerprint: completed.publicKeyFingerprint }); let retained = false;
            try { if (keyEpoch.current !== epoch || stateRef.current?.envelope_status !== vault.envelope_status || enrollmentGeneration(stateRef.current) !== targetGeneration) throw new Error('Passkey restoration was cancelled.');
                if (vault.envelope_status === 'preparing') { preparedMasterKey.current?.fill(0); preparedMasterKey.current = opened; retained = true; preparedMasterKeyGeneration.current = targetGeneration; preparedMasterKeyBootstrap.current = false; setDeviceState(completed); setLeaseExpired(false); setRecoveryRequired(needsRecoverySetup(completed)); setPendingRequest(null); return; }
                if (isLegacyVaultState(vault)) throw new Error('Restored device does not match the active vault.');
                const quoteKey = await deriveQuoteKey(opened, vault.generation); if (keyEpoch.current !== epoch || stateRef.current?.generation !== vault.generation || stateRef.current?.envelope_status !== vault.envelope_status) throw new Error('Passkey restoration was cancelled.'); clearKeys(); masterKey.current = opened; retained = true; deviceAuthorization.current = { deviceId: local.deviceId, token: bundle.authorizationToken }; keyGeneration.current = vault.generation; setDeviceState(completed); setLeaseExpired(false); setLeaseExpiresAt(completed.lease?.claims[5] ?? null); setRecoveryRequired(needsRecoverySetup(completed)); setPendingRequest(null); setEncryptionKey(quoteKey);
            } finally { if (!retained) opened.fill(0); }
        } catch (cause) { await deleteDeviceState(user.id); throw cause; }
    }, [canSync, clearKeys, user]);
    if (!user) return children;
    if (encryptionKey && recoveryRequired) return <RecoverySetup onComplete={async phrase => { await setupRecovery(phrase); setRecoveryRequired(false); }} />;
    if (!encryptionKey) { const legacy = isLegacyVaultState(state); const preparing = state?.envelope_status === 'preparing'; const unapproved = !!deviceState && !deviceState.wrapper && !deviceState.preparedWrapper; const pending = preparing && unapproved; const gate = vaultGateState({ legacy, pending: unapproved && !!pendingRequest, device: !legacy, key: false, leaseValid: !leaseExpired });
        const approvalUrl = pendingRequest ? `https://quotes.darkmg1.dev/#approve?request=${pendingRequest.requestId}&fingerprint=${encodeURIComponent(pendingRequest.fingerprint)}` : undefined;
        return <VaultGate state={gate as Exclude<typeof gate, 'unlocked'>} preparing={preparing} preparingPending={pending} busy={busy} error={error} initializing={legacy && !state?.verifier} approvalUrl={approvalUrl} approvalCode={pendingRequest?.code} passkeyRestoreIds={passkeyRestores} onFindPasskeyRestores={() => { void findPasskeyRestores().then(setPasskeyRestores).catch(cause => setError(cause instanceof Error ? cause.message : 'Could not find passkey devices.')); }} onRestorePasskey={id => { void restorePasskeyDevice(id).then(() => setPasskeyRestores([])).catch(cause => setError(cause instanceof Error ? cause.message : 'Could not restore passkey device.')); }} onLegacyUnlock={handleLegacyUnlock} onRememberedUnlock={() => void unlockDevice('remembered')} onPasskeyUnlock={() => void unlockDevice('passkey-prf')} onEnroll={mode => void enroll(mode)} onCheckApproval={() => void unlockDevice(deviceState?.protectionMode ?? 'remembered')} onRecover={(phrase, mode) => { void recoverDevice(phrase, mode).then(() => unlockDevice(mode)).catch(cause => setError(cause instanceof Error ? cause.message : 'Recovery failed.')); }} onRetry={() => void refreshSettings()} onSignOut={() => void signOut()} />;
    }
        return <CryptoContext.Provider value={{ encryptionKey, isLocked: false, vaultGeneration: state ? quoteGeneration(state) : null, legacyVaultGeneration: isLegacyVaultState(state) ? state.legacy_generation : null, envelopeStatus: state?.envelope_status ?? null, preparedGeneration: state?.envelope_status === 'preparing' ? state.prepared_generation : null, deviceId: deviceState?.deviceId ?? null, deviceApproved: !!(deviceState?.wrapper || deviceState?.preparedWrapper), leaseExpiresAt, deviceApproval: pendingRequest ? { url: `https://quotes.darkmg1.dev/#approve?request=${pendingRequest.requestId}&fingerprint=${encodeURIComponent(pendingRequest.fingerprint)}`, code: pendingRequest.code } : null, refreshVaultState, getDeviceAuthorization, getConversionQuoteKey, unlockLegacyQueuedChanges, acknowledgeConversion, setPreparedTargetMasterKey, clearPreparedTargetMasterKey, getApprovedTargetMasterKey, enrollDevice: enroll, checkDeviceApproval, reportMigrationEmptyQueue, renewDeviceLease: renewAuthorizationLease, lockVault, forgetDevice, approveDeviceRequest, setupRecovery, recoverDevice, findPasskeyRestores, restorePasskeyDevice }}>{children}</CryptoContext.Provider>;
};
export const useCrypto = () => useContext(CryptoContext);
