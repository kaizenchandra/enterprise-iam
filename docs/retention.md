# Automated retention and cleanup

The worker is part of the single-primary PostgreSQL IAM baseline. Distributed logout adds outbox/participant retention
coordination described in [backchannel-logout.md](backchannel-logout.md). Authentication decisions reject
expired/revoked state immediately; physical deletion is asynchronous and may lag behind the eligibility deadline.

## Policy and configuration

| Property                                                            | Default | Meaning                                                                                                         |
|---------------------------------------------------------------------|---------|-----------------------------------------------------------------------------------------------------------------|
| `iam.retention.enabled` / `IAM_RETENTION_ENABLED`                   | `true`  | Enable scheduled cleanup; no external cleanup API is exposed                                                    |
| `iam.retention.batch-size` / `IAM_RETENTION_BATCH_SIZE`             | `100`   | Candidate/deletion limit per stage; permitted range 1–1000                                                      |
| `iam.retention.after-expiry` / `IAM_RETENTION_AFTER_EXPIRY`         | `P1D`   | Retain history and lifecycle/session records for this interval after their absolute expiry; minimum two minutes |
| `iam.retention.fixed-delay-ms` / `IAM_RETENTION_FIXED_DELAY_MS`     | `60000` | Delay after one scheduled invocation finishes before the next starts                                            |
| `iam.retention.initial-delay-ms` / `IAM_RETENTION_INITIAL_DELAY_MS` | `60000` | Startup delay before the first invocation                                                                       |

Every pod may run the job. Each invocation attempts eight bounded stages, at most `7 * batch-size` deletions plus
`batch-size` delivery-expiry updates, without a drain-until-empty loop. Each candidate is handled in an independent
five-second transaction; candidate and maintenance SQL also have a five-second query timeout. Busy principals and the
shared creation-floor row are skipped instead of waited on. There is no unbounded retry loop. The next scheduled
invocation retries remaining work.

| Stage                         | Eligibility and effect                                                                                                                                                                                                |
|-------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Overdue delivery intent       | Mark deadline-expired pending/in-flight deliveries DEAD even when sending is paused.                                                                                                                                  |
| Terminal deliveries           | Delete completed/dead deliveries after completion plus retention. Pending/recent records pin lifecycle/session metadata.                                                                                              |
| Expired grant material        | Delete the framework authorization when its effective token/state expiry or absolute family deadline has passed, or it is revoked. Mark the lifecycle revoked and increment its revision in the same transaction.     |
| Known-family refresh history  | Delete individual digest rows only after the family's **absolute** deadline plus the retention interval. The age of R1 alone never makes it eligible.                                                                 |
| Legacy orphan history         | After its own creation time plus retention, delete a history row only if no lifecycle row exists. V4 deliberately invalidated these legacy grants. Recheck after locking the history row.                             |
| Lifecycle records/tombstones  | After the absolute deadline plus retention, delete only when neither framework token material nor refresh history remains. Advance the durable creation floor in the same transaction.                                |
| RP participants               | Purge individually only after parent session revocation and expiry/grace, no lifecycle and no delivery references.                                                                                                    |
| OP session records/tombstones | After committed session revocation and the session's absolute expiry plus retention, delete only when no lifecycle or RP participant/delivery row references it. Advance the creation floor atomically with deletion. |

`grant_expires_at` records the latest relevant uninvalidated code/access/refresh/ID-token expiry, capped by the fixed
family deadline. Pending consent has no issued token and remains bounded by that family deadline. This allows
short-lived machine grants and expired codes to release token material before their longer lifecycle/replay-retention
horizon. A lifecycle retained for replay detection is not an active grant.

Normal OP-session registration now records an immutable absolute expiry (default eight hours) and a browser-renewed idle
deadline (default 20 minutes). Both deadlines gate existing refresh grants and pending/new authorizations immediately. A
durable worker revokes the session, linked grants and enqueues RP logout atomically. Cleanup must keep unprocessed due
sessions and participants until that revocation commits, including after their grant/lifecycle material has been cleaned
up. See [session expiry](session-expiry.md) for V7 rollout, activity semantics and outage behavior.

## Why deleting tombstones does not restore stale writes

Persisted authorization snapshots carry a revision. A save with a revision and no lifecycle row is rejected. That
remains true after deletion.

An initial framework authorization object may not yet carry a revision. Merely checking the version would allow that old
initial object to be saved again after GC. The bounded, durable `authorization_retention_state` singleton closes this
gap:

1. New authorizations have a retained birth time: the framework authorization request receives a server-owned DB-time
   stamp, including pending consent; token-only initial grants use their framework token's issued-at time.
   Client-provided birth parameters are overwritten by a converter that delegates all protocol parsing to Spring.
2. Initial saves reject births at/before the durable floor and births more than 60 seconds ahead of DB time. The same
   check protects OP-session registration using the DB-time stamp captured before login processing.
3. Before deleting a lifecycle or session record, cleanup advances the floor to at least that record's creation time
   plus 60 seconds. Every accepted original birth is at/before this value. The floor and deletion commit or roll back
   together.
4. The minimum two-minute post-expiry grace keeps this floor safely behind fresh requests and exceeds the allowed issuer
   clock lead and the normal ten-second protocol transaction budget.

Writers hold a shared floor-row lock while checking/inserting initial state. Cleaners acquire its exclusive lock with
`SKIP LOCKED`, then **try** the principal advisory lock without waiting. Existing lifecycle writes and cleanup also
coordinate through principal locks. This avoids a floor/principal lock-order deadlock and prevents a check/insert race
with deletion.

Framework-generated authorization IDs must remain unique; custom server adapters must retain the original birth/revision
when retrying an existing authorization. They must not manufacture a new object with a reused ID and a fresh birth time.
No external API accepts an authorization object or lets callers choose framework IDs.

OP sessions are explicitly registered at successful login. An authorization save never lazily registers a missing
session. Missing or expired session records fail browser checks; missing records also fail token-state eligibility. Thus
a surviving stale Redis session cannot recreate its purged registration. A delayed login completion retains its old
request birth and is fenced after the corresponding purge. A fresh login rotates the session ID and registers a fresh
correlation key.

Refresh replay remains detectable for every generation while its family can still be used. After family expiry plus
retention and final purge, an old token is simply unknown and still rejected; historical attribution from digest state
is no longer available. Security audit events are not deleted by this job.

## Failure and recovery

Each deletion is idempotent. Partial batches are expected: token material may already be gone while history/tombstones
remain. A failed transaction rolls back its row changes and floor advancement. On process/DB failure, a later invocation
resumes from durable state. Never reset/delete the floor to repair a backlog. Back up and restore it with the issuer's
other authoritative state.

All workers must use the same intended retention policy and primary writer. The job makes no asynchronous multi-region
safety guarantee. Continuous load/hot principals can delay cleanup, so batch/cadence and database capacity must be
measured. Deletion throughput and large-directory query plans have not been benchmarked. Use PostgreSQL
autovacuum/normal index maintenance to reclaim physical space; row deletion alone does not promise immediate disk
shrinkage.

Metrics:

- `iam.retention.deleted{kind=grants|history|orphan_history|lifecycles|sessions|logout_deliveries|logout_participants}`
  counts committed deletions.
- `iam.retention.skipped{reason=principal_busy|floor_busy}` records contention.
- `iam.retention.failures`, `iam.retention.duration`, `iam.retention.last.success.epoch.seconds` report job health.

Identifiers/tokens are not metric tags. Scheduler failures log the exception class without credential-bearing exception
messages/parameters. Alert on failures, stale last-success time, sustained skips and database growth. A successful
invocation may still leave a backlog; monitor table growth and expiry age separately using a controlled operational
query/exporter.

## Migration V5

Drain old application writers before V5 and deploy only floor-aware writers before enabling cleanup. Old binaries do not
enforce the deletion fence. V5 preserves existing V4 grants and registrations, conservatively backfills their effective
grant expiry from the existing family deadline, and gives legacy session metadata an eight-hour maintenance horizon.
Existing Redis authentication-freshness checks still apply; the backfill does not extend access-token or refresh-family
lifetimes. A legacy authenticated session with no registered correlation key must reauthenticate.

Upgrading directly from V3 still executes V4's deliberate legacy-grant invalidation. The prior workload-subject
namespace rollout requirements also apply. Neither migration nor cleanup retroactively invalidates an offline JWT.

## Executed evidence

The current Java 21 Maven suite passes 103 tests with no failures, errors or skips. The original retention increment
added 16 PostgreSQL tests, three scheduler tests and three full-server HTTP tests using PostgreSQL/Redis. They cover
row-bounded history removal, grace periods, orphan history, concurrent workers, principal/floor contention, cleanup
racing fresh/stale issuance/refresh/revocation, replay preservation, pending consent, deleted-session fencing and
injected rollback failure. The consent HTTP test completes the standard framework flow and verifies that a client cannot
supply the server birth stamp. The scheduler test observes actual Spring timer invocations. The seeded upgrade test
confirms V5 grant/history preservation and conservative expiry backfill; the subsequent V7 migration deliberately
expires legacy sessions with unknown idle age before the worker revokes their grants. Back-channel additions also verify
delivery retention pins/release, cleanup during retries and deadline expiry while the sender is paused;
see [back-channel logout](backchannel-logout.md). No load or distributed-failure benchmark was performed.
