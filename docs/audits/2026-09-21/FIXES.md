# Remediation of the September 21 review

The review in [REVIEW.md](REVIEW.md) describes the starting revision `a878167`.
This record distinguishes implemented fixes from outstanding production work.

| Finding | Remediation |
| --- | --- |
| R1 | Database trigger prevents deleting or renaming the configured administrator's allowlist entry; its UI removal action is disabled. |
| R2 | Refresh retries local initialization. Lifecycle guards cancel stale initialization and sync work after identity changes. |
| U1 | Sign-out failures are surfaced through the persistent authentication provider, including when the SDK removes the local session. |
| U2 | Feed and author loading states, pending counts, sync times, accessible feedback, and pending-action guards are implemented. |
| D1 | New quote timestamps must match browser-compatible finite ISO timestamps, including bounded hours, minutes, and seconds. |
| I1, I3 | Nginx now serves the protected release root. Missing assets return 404; a QuoteVault-only Cloudflare rule respects origin edge/browser cache headers. Live headers verify revalidation for HTML, service worker, manifest and errors, and immutable caching for hashed assets. |
| I2 | Reviewed application revision `1398bc812363219f7998e62e171a4538eac853c4` was published on main and the audit branch and activated in production. Its served release metadata, HTML and script hashes were verified; the offline-startup follow-up below builds on that release. |

Additional safeguards include private generation notifications, byte-aware sync
batches, limits on new ciphertext and requests, guarded authentication retries,
author cache invalidation, CI, clean revision builds, asset verification,
atomic deployment with rollback, public-client configuration checks, health
checks, and standard PostgreSQL backup/restore scripts.

Ponytail cleanup removes cosmetic animation wrappers, unused configuration,
redundant dialog props/resets, and duplicate ownership/admin decisions. The
encryption format, operation receipts, full-snapshot sync, and swipe interaction
remain because they serve existing behavior. Optional password recovery,
portable exports, and search filters remain product suggestions, not defects.

## Verification and production boundaries

- The database hardening migration was rehearsed with rollback against the
  hosted schema before applying it; the additive browser timestamp follow-up
  was also applied and verified. All six application tables match private
  pre-migration snapshots exactly; 18 encrypted quotes and six accounts remain.
- Hosted Realtime now requires private channels. Live WebSocket probes reject
  public joins and deny anonymous private-channel access.
- PostgreSQL 17 regression checks cover authorization, migration compatibility,
  reapplication, limits, timestamp validation, and private broadcast membership.
- The real browser check uses synthetic accounts and a loopback backend to
  exercise installed-PWA offline create/delete/reconnect, ciphertext storage,
  dialog keyboard focus, and failed sign-out feedback.
- The standard backup scripts restored a populated synthetic account, quote,
  and vault configuration into a fresh local database. This does not establish
  hosted disaster recovery. The managed backup API returned no backup entries;
  a transactional, non-login role rehearsal confirmed that management access
  cannot grant the database-owner role to a temporary dump identity. The probe
  role was removed and catalog absence verified. Direct PostgreSQL credentials
  and a full production dump/restore remain outstanding. No database password
  was changed and no backup login was retained.
- Public-safety checks include redacted Gitleaks scans of reachable Git history
  and outgoing files, manual inspection of configuration/test artifacts, and
  regression checks rejecting privileged keys and unexpected `VITE_` variables.
  Historical tracked environment entries contain a publishable key or placeholders.
  Private snapshots, operator tokens, database archives, and browser traces are
  outside the outgoing files.

Use [operations.md](../../operations.md) for release, restore, and health commands.
Physical-device installation and authenticated hosted Realtime delivery still
require separate verification; synthetic browser and SQL tests do not prove them.

Production checks passed after Nginx activation and the CDN correction: HTTPS
release/asset hashes, anonymous table denial, security/cache headers, Nginx
service state, protected release directory permissions, and a Chromium sign-in
page smoke check with no page errors. The application revision
`1398bc812363219f7998e62e171a4538eac853c4` also passed GitHub Actions.

Final local checks passed: 16 Node runner entries, lint, production build,
PostgreSQL regression suites, and the real Chromium PWA flow. The dependency
audit reported zero vulnerabilities. The existing large-bundle warning remains;
code splitting is deferred until startup profiling demonstrates a benefit.

## Offline startup follow-up

A cold start with an expired saved access token previously waited for Supabase
session renewal before showing the local unlock screen. A real Chromium
regression reproduced this even with the app shell and encrypted vault cached.
Prepared devices now show local unlock immediately, including when the browser
reports online but the authentication server is unreachable. Remote sync,
Realtime, author loading and account controls wait for a usable SDK session;
the server continues to enforce authorization.

The shared passphrase and derived key remain memory-only. Wrong passphrases
cannot unlock; quotes and pending inserts remain ciphertext. Explicit sign-out
sets a durable local latch before waiting for remote logout, preventing another
tab or restart from reviving access. Only a successful new sign-in clears it.
Observed session or membership denial locks the vault and removes cached
preparation. Disconnected devices cannot learn of remote revocation until they
reconnect.

Verification: 17 automated Node checks, lint, and five real Chromium scenarios
passed: expired-session offline reload/create/delete/reconnect, unreachable
session renewal followed by rejection, offline sign-out/reload, membership
revocation after local unlock, and a second tab during pending online sign-out.
The expired-session and second-tab regressions were observed failing before
their fixes. A separate cheaper-agent security review was checked by the
primary agent. No database migration or encryption-format change is required.
