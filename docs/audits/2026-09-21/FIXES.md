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
| I1, I3 | Protected release directory and reviewed Nginx configuration are prepared. Activating the new root/cache policy requires the host administrator's sudo step. |
| I2 | Publish the reviewed commit and integrate it into the default branch after checks pass; record the resulting revision in release metadata. |

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
- PostgreSQL 17 regression checks cover authorization, migration compatibility,
  reapplication, limits, timestamp validation, and private broadcast membership.
- The real browser check uses synthetic accounts and a loopback backend to
  exercise installed-PWA offline create/delete/reconnect, ciphertext storage,
  dialog keyboard focus, and failed sign-out feedback.
- The standard backup scripts restored a populated synthetic account, quote,
  and vault configuration into a fresh local database. This does not establish
  hosted disaster recovery. The managed backup API returned no backup entries;
  direct PostgreSQL credentials and a full production restore remain outstanding.
- Public-safety checks include redacted Gitleaks scans of reachable Git history
  and outgoing files, manual inspection of configuration/test artifacts, and
  regression checks rejecting privileged keys and unexpected `VITE_` variables.
  Historical tracked environment entries contain a publishable key or placeholders.
  Private snapshots, operator tokens, database archives, and browser traces are
  outside the outgoing files.

Use [operations.md](../../operations.md) for release, restore, and health commands.
Physical-device installation and authenticated hosted Realtime delivery still
require separate verification; synthetic browser and SQL tests do not prove them.

Final local checks passed: 16 Node runner entries, lint, production build,
PostgreSQL regression suites, and the real Chromium PWA flow. The dependency
audit reported zero vulnerabilities. The existing large-bundle warning remains;
code splitting is deferred until startup profiling demonstrates a benefit.
