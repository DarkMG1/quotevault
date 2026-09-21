# Sync, import, and vault-key roadmap

This is a forward-looking product and security review of the current QuoteVault source. It is not a migration plan and does not reopen historical audit items that have already been remediated. The current implementation has no acute cryptographic defect identified in this review.

## Current position

New vaults derive a non-extractable AES-256-GCM key from the group passphrase with a random 16-byte salt and PBKDF2-HMAC-SHA-256 at 600,000 iterations. The stored verifier is ciphertext, so it verifies the derived key without retaining a raw passphrase hash. Legacy ciphertext deliberately retains its fixed salt and 100,000-iteration derivation until an explicit destructive vault rotation. The shared passphrase and derived key are memory-only; neither is intentionally written to IndexedDB or local storage.

This is a reasonable model for a small trusted group. It is still a **shared-secret** model: every member who knows the key can read past content they have copied. Removing an email from the allowlist blocks future server access, but cannot revoke knowledge of a key already shared. Current rotation is intentionally destructive: it changes generation and removes existing quotes rather than promising cryptographic offboarding with retained history.

Quote text, author, and context are encrypted locally before queueing. Some operational metadata remains visible to the service, including identifiers, creator, timestamps, generation, and an optional quote date. That is normal for the present synchronization design; this roadmap does not claim all metadata is encrypted.

The implemented sync changes retry temporary failures after 1, 2, 4 seconds and so on, capped at 30 seconds, while online and visible. A 15-second deadline releases stalled sync requests; authentication recovery retries after 30 seconds. Reconnect, returning to a visible page, and the visible **Sync now** button request synchronization. The button also retries session restoration when needed, shows real progress, and explains offline status. Healthy clients do not poll. Permission denials do not enter the retry loop; acknowledgments and operation IDs preserve retry safety.

A browser cannot guarantee execution while the app is closed or suspended. Pending encrypted operations remain for the next foreground session/unlock, subject to the user retaining browser storage. No service worker receives a vault key. No database migration or encryption-format change is included.

## Ranked practical work

1. **Make the shared secret easier to make strong.** Change the existing-unlock field from `autocomplete="off"` to password-manager-compatible `current-password`, and offer a generated high-entropy group key or Diceware-style guidance when an administrator initializes a vault. Twelve characters are a minimum length, not a measure of resistance to an offline guess. This is a small frontend change with immediate benefit and no schema work.

2. **Expose the existing manual lock action.** The app already clears the in-memory key when locking. Add a clearly visible Lock Vault control in the main layout. It protects an unattended unlocked screen without deleting local ciphertext or changing offline behavior. An idle timer can follow only if it preserves drafts and is tested on mobile; it is not needed for the first version.

3. **Build a local message-import preview.** Start with a paste/file workflow that runs entirely in the browser: parse, preview, edit, select, encrypt, and enqueue. Recognize message bodies matching `“quote” — speaker` or `"quote" - speaker`, including multiline quotes and common dash variants. Leave unmatched or ambiguous messages for review instead of guessing; the message sender is not necessarily the quoted speaker. Compare normalized text and speaker against both the batch and already decrypted vault quotes, and display potential duplicates for the user to decide. Do not persist plaintext hashes as dedupe metadata. Selected rows should reuse the existing local encryption and bounded sync queue. Preserve message timestamps as provenance rather than silently assuming they are the date the quote was spoken. This requires no AI API calls or plaintext upload.

   The actual import adapter awaits the phone, messaging application, and a representative export. On Android, SMS Backup & Restore can create a local XML backup of the chosen conversation, including MMS for group/RCS messages. [SyncTech FAQ](https://www.synctech.com.au/sms-backup-restore/sms-faqs/) Check both oldest/newest messages and sent/received messages: the vendor reports [outgoing RCS omissions](https://www.synctech.com.au/faqs/why-are-my-outgoing-rcs-messages-not-being-backed-up/) and [restricted encrypted RCS access on Android 16/17](https://www.synctech.com.au/faqs/why-are-some-messages-missing-from-the-backup/). Do not assume the first export is complete. On iPhone, iMazing supports RCS conversation exports; prefer CSV or text over PDF for parsing. It may require a paid license. [iMazing export guide](https://imazing.com/guides/how-to-export-iphone-text-messages-sms-and-imessages-to-your-computer-as-pdf-excel-csv-or-rsmf) No private messages were accessed or imported during this work.

4. **Add an encrypted portable export before elaborate sharing.** Export versioned ciphertext plus vault metadata needed to unlock it, locally, after an explicit user action. It improves user-controlled backup and migration without introducing a plaintext service. A readable export is useful later, but must be generated locally and have an equally explicit warning.

5. **Redesign keys when individual unlock or retained-history offboarding is needed.** Generate a random vault key and keep per-user or per-device encrypted wrappers. Existing unlocked members would create wrappers for new members; the server would never possess the plaintext vault key. Rewrapping alone cannot revoke a former member's known key: rotate that key and re-encrypt retained server data. Even then, already copied messages cannot be revoked. Passkeys improve login but do not decrypt a group vault by themselves. A future WebAuthn PRF-based device wrapper needs feature detection, recovery, and a passphrase fallback. [WebAuthn PRF](https://www.w3.org/TR/webauthn-3/#prf-extension)

Other small app improvements: Supabase account-password recovery before the vault gate (separate from vault-key recovery), editable quotes with server ownership checks, and local context/author/date filtering. Search already exists; extending it is more useful than another search service. No new queue, backend, state framework, or dependency is justified by this review.

## Boundaries and validation

The full-snapshot sync is appropriate at present scale. Revisit pagination or incremental reconciliation only after measured response size, unlock time, or memory pressure shows a problem. Do not add a server-side plaintext search service; local decrypted search preserves the current privacy boundary.

The highest-priority operational gap is still a verified production backup and isolated restore. Management access cannot create a temporary login with the database-owner role, so a direct PostgreSQL credential or managed backup capability is required. This is separate from the application and should remain the first operations follow-up.

Current validation passed 17 Node checks and seven browser checks. Those checks do not establish cross-device passkey support, message-export compatibility, physical-device RCS completeness, or production disaster recovery. Any import or key-architecture work should add one browser flow covering review, encryption, offline queueing, reconnect, and a rejected row.
