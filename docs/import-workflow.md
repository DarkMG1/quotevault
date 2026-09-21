# Private quote preparation

Prepare a review from an existing iMessage-exporter TXT transcript:

```sh
npm run import:prepare -- /private/chat.txt --chat "Example Chat" --self-name "Avery" --output /private/quote-review
```

The command creates a new mode-700 output directory and writes mode-600 `quote-review.html` and `quote-review-data.json`. It refuses an existing directory so it cannot overwrite a previous review. Open the HTML file locally, review every quote, and download the selected JSON. Nothing is uploaded and no quote is imported into QuoteVault by this command.

People quoted and the message sender are separate fields. The parser preserves multi-part conversations and shows linked corrections as review context; it never changes quote text automatically. Output records include `source.id` and `source.chat`. The ID is a SHA-256 hash of the chat name, original sender, canonical timestamp, and normalized original message body, so it stays stable when source line numbers change.

For an encrypted iOS backup, let iMessage-exporter request the password interactively:

```sh
npm run import:prepare -- --chat "Example Chat" --self-name "Avery" --output /private/quote-review --exporter /path/to/imessage-exporter --backup /private/ios-backup
```

The exporter runs as iOS TXT export with attachments disabled, the exact `chat-name:` filter, and a private temporary directory. This exact group-name filter requires the QuoteVault-patched iMessage-exporter build; upstream participant filters can broaden a group into other chats. Do not pass a backup password on the command line or in an environment variable.

To replace display names without changing source IDs, use a local JSON object such as `{"Rowan": "R."}`. Aliases ignore case. In an attribution such as `me & Rowan`, `me` becomes the message sender and aliases apply to each name:

```sh
npm run import:prepare -- /private/chat.txt --chat "Example Chat" --self-name "Avery" --aliases /private/aliases.json --output /private/quote-review
```

Save and restore full drafts only with the same generated review: draft restore verifies the source fingerprint and preserves selected and unselected edits. Generate a fresh review when the transcript changes.

## Build the exact-chat exporter once

The existing local QuoteVault exporter can be reused. To rebuild it, install Rust from its official distribution, then use the pinned upstream source and the small included patch:

```sh
git clone https://github.com/ReagentX/imessage-exporter.git /path/to/imessage-exporter
cd /path/to/imessage-exporter
git checkout 4d90fc8d20a745c0a8acc1e01c0631c4bab89cb4
git apply /path/to/QuoteVault/scripts/import/exact-chat-filter.patch
cargo test -p imessage-exporter exact_chat_name_is_scoped_and_fails_closed
cargo build --release --locked -p imessage-exporter
```

The executable is `target/release/imessage-exporter`. The filter refuses zero or multiple chats with the chosen name instead of broadening the export to other conversations.

## Review and import in QuoteVault

1. Keep the backup, transcript, review page, and full draft in a private folder outside the repository. Ask your local assistant to review candidate quotes and source context there; no cloud parsing API is required.
2. Download the selected quotes from the review page. Keep a full draft as the editable archive, including rejected candidates and notes.
3. Sign in and unlock QuoteVault normally, choose **Import quotes**, and load the reviewed JSON. The app also accepts a full draft and preserves its checkboxes.
4. Exact normalized quote/author matches and previously imported message identities are skipped. Possible matches (including different attributions or similar wording) are unchecked for manual review. These heuristics cannot decide every paraphrase or ambiguous attribution; review the flagged matches.
5. Select the additions and press **Import N selected quotes**. This final action saves one atomic encrypted batch. Existing quotes are never overwritten. The account that imports is recorded separately from the original chat sender.
6. If the vault changed during review, review the refreshed duplicate check. If a response is lost, reopen Import quotes and choose **Check saved import**; the encrypted saved batch reuses the same operation IDs and cannot be inserted twice.

Imports require a live session and a fresh vault snapshot. Manual additions still work offline through normal synchronization. Import batches are limited to 500 candidates and 800 KiB of encrypted operations; larger reviews must be split. No message IDs, quote hashes, senders, or context are sent in plaintext. Password recovery changes the account password only, never the vault encryption key.

Before deploying the frontend, apply `supabase/migrations/20260922000000_checked_import.sql` as the existing database owner. Configure Supabase Site URL as the deployed HTTPS origin and add the exact `/?recovery=1` URL to Redirect URLs. Configure custom SMTP with a verified sender for production password-reset delivery; Supabase's built-in email service is limited. Do not put service keys, database passwords, backups, or real review artifacts in this repository.
