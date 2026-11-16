# ADR 0003: bounded retention with a monotonic creation floor

Accepted for the retention increment.

Expired token material can be deleted earlier than the records needed to identify replay or fence stale saves. History
age alone is not sufficient: an old refresh generation can belong to a still-active family. Conversely, retaining every
per-authorization tombstone forever creates unbounded directory state.

Keep history and lifecycle/session state through absolute expiry plus a configurable grace (default one day, minimum two
minutes). Use independent, row-bounded transactions and nonblocking principal/floor locks. New token material has a
separate effective expiry, capped by the family's immutable deadline.

Persist one monotonic issuer creation-time floor. Deleting lifecycle/session records advances this floor atomically past
their possible original birth times. Versioned stale saves already reject a missing lifecycle; the floor also rejects
old initial objects without a revision. A Spring-delegating converter retains a server birth stamp for consent state,
which otherwise has no issued token timestamp. Explicit login-time session registration and missing-session rejection
prevent stale Redis sessions re-registering themselves after tombstone deletion.

Consequences: one global floor row coordinates initial creation with tombstone purge; hot principals are skipped and may
delay reclamation. All writes must use the authoritative PostgreSQL primary. Old writers must be drained before
V5/cleanup. Initial-grant adapters must preserve original birth/revision and framework IDs must not be reused. Row
bounds and tests establish safety, not scale/SLO performance. Audit retention remains separate
work. [ADR 0004](0004-durable-oidc-backchannel-logout.md) subsequently adds distributed logout and coordinates its
delivery retention with these creation-floor guarantees.
