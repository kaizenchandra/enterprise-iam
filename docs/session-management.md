# Session management APIs

These APIs manage OP login sessions and their linked grants/RP sessions, not physical devices. Public management UUIDs
are randomly generated independently of cookie IDs, internal correlation keys and OIDC `sid`. No token, cookie, IP
address, user-agent fingerprint or MFA secret is returned. A session may span multiple applications and organizations.

| Operation                                             | Required bearer authority                          | Result                                           |
|-------------------------------------------------------|----------------------------------------------------|--------------------------------------------------|
| `GET /api/v1/users/me/sessions?limit=50&after=<UUID>` | `iam-session-management` audience, `sessions.read` | Owner-only session page                          |
| `DELETE /api/v1/users/me/sessions/{sessionId}`        | Same audience, `sessions.write`                    | 204 after durable revocation/enqueue commits     |
| `POST /api/v1/admin/users/{userId}/revoke-sessions`   | `iam-admin` audience, `iam.admin`                  | 204 after global user revocation/enqueue commits |

All calls use signed access JWTs with the existing issuer, RS256, type and time validation. The controller also checks
the actual framework grant's current eligibility under the actor's principal lock, so a revoked/expired
session-management JWT cannot continue management operations merely because it validates offline. Self-service
additionally requires an ACTIVE directory user, a human grant and an OP-session binding. Machine tokens cannot use
`/me`, even with a matching scope/audience. Cookie authentication is not accepted by the stateless API chain. Bearer API
requests do not renew OP idle time.

Register `sessions.read`/`sessions.write` only for approved confidential first-party Authorization Code + S256 clients
through controlled provisioning. The existing general client-registration API cannot grant these scopes or
administrative scope. The issuer selects the management audience from the **authorized scopes**, not merely from scopes
registered on the client. Request management scopes separately from business API scopes; a management token cannot call
the sample enterprise resource server. No browser token-storage or new password grant is introduced. Local demo clients
now explicitly add the approved management scopes and a separate callback for the [session UI](session-ui.md); their
business token requests remain unchanged. HTTP integration tests register isolated management clients and perform actual
code/PKCE exchanges.

## Ownership and tenant isolation

Self-service always derives the owner from the validated token and current persisted authorization; it accepts no user
or tenant selector. The list query and target lookup are constrained by that owner. A different owner's UUID and an
unknown UUID both produce 404. Same-organization membership does not confer session ownership.

The OP's SSO sessions are global, so tenant administrators cannot safely revoke only one tenant's portion of a session.
Organization roles, caller-supplied tenant claims and shared memberships do not authorize the global admin route. Only
the dedicated platform authority above can revoke all of a user's global sessions. No tenant-administration session
route is claimed. Future tenant-scoped administration needs a separately defined tenant-bound session/grant model;
adding a tenant claim to a shared OP session would not establish that isolation.

## Listing contract

The response is `{ "items": [...], "nextCursor": UUID-or-null }`. Each item contains `id`, `createdAt`, `lastSeenAt`,
`idleExpiresAt`, `absoluteExpiresAt`, `status` (`ACTIVE`, `EXPIRED` or `REVOKED`) and `current`. `current` refers to the
OP session bound to the supplied management token. Retained tombstones remain visible until normal cleanup removes them.
Legacy `lastSeenAt` is conservatively backfilled from creation time and becomes current on subsequent qualifying OP
activity; it is not a reconstructed historical device log.

`limit` defaults to 50 and must be 1..100. `after` is a UUID keyset cursor; the owner remains fixed independently of the
cursor. Pagination is ordered by management UUID and is not a multi-request snapshot: concurrent insertions/removals can
affect subsequent pages. No total count or session-count side channel for another identity is exposed. Listing and
successful mutations use `Cache-Control: no-store`.

Invalid parameters return 400; missing/invalid bearer authentication returns 401; insufficient audience/scope or an
ineligible actor grant returns 403. Unknown/unowned targets return 404. Database/transaction failure at the management
controller returns sanitized RFC 9457 Problem Details with 503 and no-store. No SQL exception messages or token values
are included. Successful revocation is not an assertion that remote delivery has already completed.

## Revocation and concurrency

Individual revocation first locks the authenticated principal and resolves the public UUID within that owner. It calls
the existing session revocation transaction, fencing subsequent issuance, marking linked lifecycle rows revoked,
deleting framework grants/pending codes and durably enqueueing RP logout. Replay history and tombstones remain until
their original retention horizons. The actor and public target UUID are recorded in `SESSION_SELF_REVOKED` audit events.
Repeating deletion of a retained revoked target with an independent eligible management token returns 204 without
another audit or delivery. Revoking the current session succeeds, then its management token becomes ineligible; a retry
with that token returns 403. Once a target is cleaned up, its UUID returns 404.

Admin revoke-all locks actor and target principals in deterministic order, verifies a live administrative grant and the
target user, and revokes all target sessions/grants atomically. It writes `USER_SESSIONS_REVOKED` with actor and target.
A user-level `sessions_not_before` cutoff rejects login registrations whose server birth time predates or equals that
operation. This closes the race where a password login started before revoke-all but had not yet persisted a session. A
fresh login started afterward remains possible; revoke-all does not suspend the account. The cutoff remains on the user
record after session/history GC. Registration, revocation, suspension and expiry use the same principal lock.

Only newly revoked sessions enqueue deliveries. Repeating revocation after completed delivery rows have been retained
and purged cannot recreate deliveries for an already-revoked session. Duplicate concurrent commands, expiry and logout
preserve monotonic tombstones and unique delivery constraints. Multi-session revocation and its audit roll back together
on enqueue/database failure. Operations use ten-second transaction bounds and five-second management SQL timeouts; large
user/session fan-out performance remains unmeasured. There is no request idempotency-key store; effect idempotency and
audit behavior are as described above.

OP/RP stale-session guards, delivery leases/retries, idle/absolute deadlines, creation floors and retention pins remain
active. Remote RP invalidation is asynchronous and can terminate in DEAD requiring operator recovery. Existing access
JWTs can still validate at offline business resource servers through expiry/skew. The management API deliberately uses
fresh grant checks instead.

## Migration and verification

V8 adds public UUIDs, last-seen timestamps, audit attribution and the user login cutoff. Drain older writers before
deployment: they do not enforce the cutoff. Unlike V7, V8 does not itself expire existing eligible sessions. Keep V7's
idle policy, indexed Redis/RP JDBC rollout constraints and signing-key overlap. Never reset the cutoff or creation
floors to restore a revoked session.

Run `mvn -f enterprise-iam/pom.xml verify` with Java 21 and Docker. New tests use actual HTTP code/PKCE-issued JWTs and
PostgreSQL/Redis to exercise pagination, ownership across same/different organizations, audience/scope/human-only
checks, current-session deletion, admin revoke-all, sanitized rollback/retry, concurrent expiry/refresh/delete and
admin/issuance races. PostgreSQL tests also cover delayed registration racing revoke-all and cutoff persistence after
retention. The [web-client UI](session-ui.md) now implements owner session controls. Production throughput and a full
administration UI remain unverified/unimplemented.
