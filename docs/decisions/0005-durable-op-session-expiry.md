# ADR 0005: authoritative session expiry and logout coordination

Status: accepted for the development baseline.

Redis stores browser session contexts, but expiry events cannot serve as a durable revocation queue. Previously the OP
absolute check blocked new browser grants while existing refresh families could remain eligible, and idle loss did not
trigger durable logout.

Record immutable absolute expiry and a monotonic, capped idle deadline in PostgreSQL. Only authenticated, CSRF-eligible
OP browser activity advances idle time. Token refresh and RP API traffic do not count as activity. Bind existing grant
lookup/persistence to both deadlines. Use a bounded, restart-safe expiry worker and the existing principal transaction
lock to revoke grants, enqueue OIDC logout and write audit atomically. Keep due sessions and RP participants until this
transaction has committed, then honor existing delivery pins, replay retention and creation-floor fencing.

The worker does not depend on Redis reads or notifications. Deadline eligibility remains fail closed before maintenance
completes. Per-session bulk child writes preserve atomicity under bounded transaction timeouts; large-session/backlog
performance remains unmeasured. Offline JWT lifetime is unchanged; remote RP invalidation remains asynchronous with
finite retries. Direct Redis deletion is not a durable logout command, and no offline-access profile is implemented.

V7 requires draining old writers and conservatively expiring legacy sessions because their recent activity cannot be
reconstructed safely. It preserves grants/history/participants/outbox until application revocation/retention handles
them. Reauthentication and backlog monitoring are required.
See [session-expiry guarantees, tests and rollout](../session-expiry.md).
