# ADR 0004: durable session-specific OIDC back-channel logout

Accepted for the distributed logout increment.

Remember opted-in RPs independently of grant rows. Publish unique delivery intent atomically with principal-locked
session/user revocation. Preserve Spring's actual ID-token SID, sign standard short-lived logout JWTs with
Spring/Nimbus, and deliver outside database transactions using leased/fenced claims and finite retry/deadline policy.
Use explicit egress origins and no redirects.

Use Spring Security's native RP endpoint/verification with a JDBC invalidation handler and persistent OIDC registry,
rather than cookie-dependent loopback logout. Persist receipts and SID tombstones atomically with session removal. Store
authorized clients in the JDBC HTTP session; guard every authenticated request and fence delayed callbacks. Use the
maintained Redis-backed OP SessionRegistry for node-independent SID correlation.

Pin lifecycle/session retention while deliveries exist. Independently terminalize overdue deliveries even when the
sender is paused, retain terminal records through grace, and remove participants in row-bounded stages before deleting
parent session records. RP-side tombstone reclamation advances a durable creation floor.

This chooses a registered SID-required, RS256, explicitly typed, empty-event profile. Delivery is at least once, never a
cross-database/network transaction or an immediate-global-JWT-revocation guarantee. Dead-letter review/redrive, generic
subject-only RP support and high-volume/multi-region evaluation remain separate work.
