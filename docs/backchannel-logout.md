# Distributed OIDC back-channel logout

This increment implements an OP sender with durable delivery and a JDBC-backed RP receiver. OAuth/OIDC grant processing
remains in Spring Authorization Server. Logout tokens use Spring/Nimbus JWT signing; the RP's endpoint and
signature/claim verification use Spring Security's `oidcLogout` configuration. The custom handler owns persistent
invalidation, replay receipts and session fences.

Protocol references verified against the selected stack:

- [OIDC Back-Channel Logout 1.0, errata set 1](https://openid.net/specs/openid-connect-backchannel-1_0.html)
- [Spring Security 6.5 OIDC logout](https://docs.spring.io/spring-security/reference/6.5/servlet/oauth2/login/logout.html)
- [Spring Session Redis repository configuration](https://docs.spring.io/spring-session/reference/configuration/redis.html)

## Supported profile

The supplied web RPs register `backchannel_logout_uri` and `backchannel_logout_session_required=true`. They accept
session-specific tokens (`sid`, optionally also `sub`), not subject-only logout. The OP sends both. The deployment
profile uses RS256, explicit `typ=logout+jwt`, one exact client audience, `iss`, `iat`, `exp`, unique `jti`, `sid` and
the standard back-channel event with an empty object. No `nonce` is permitted. Logout tokens last 120 seconds; RP
validation permits at most 30 seconds of issuer clock lead and requires a recent issuance time and a still-valid signed
expiration.

Unknown top-level claims are ignored. This strict profile is intentionally narrower than every possible external OP/RP
deployment; generic subject-only, encrypted logout tokens and external-provider interoperability/conformance
certification are not claimed. Existing access JWTs continue to follow their own expiry/revocation model.

OIDC discovery advertises `backchannel_logout_supported` and `backchannel_logout_session_supported`. Dynamic client
registration remains disabled. A platform administrator can configure the static endpoint using:

```http
POST /api/v1/admin/clients/{clientId}/backchannel
Authorization: Bearer <iam-admin audience / iam.admin scope>
Content-Type: application/json

{"backchannelLogoutUri":"https://portal.example/logout/connect/back-channel/iam"}
```

This response contains endpoint metadata, never credentials. URI configuration and credential rotation serialize their
registered-client row updates. Delivery uses the recorded endpoint only while it still matches the current registration;
a changed/deleted registration becomes a terminal configuration failure, rather than sending identity data to an
unexpected new destination.

## Transactional publication

After an ID token is generated, `TrackedAuthorizationService` remembers its actual framework `sid`, subject, registered
client and endpoint in `oidc_rp_sessions`. This is independent of the framework token row: an RP can still need logout
after its original code/access token material is cleaned up. SID values are preserved from Spring's ID tokens, keeping
RP-Initiated Logout correlation intact; no parallel session-token format is invented.

The same principal lock fences ID-token persistence and revocation. `revokeSession`/`revokeUser` insert
`logout_deliveries` before deleting authorization state, in the same PostgreSQL transaction. A unique participant
constraint prevents duplicate events for repeated revocation. If enqueue fails, revocation rolls back; successful
revocation never silently loses its notification intent.

The OP uses an indexed Redis repository and `SpringSessionBackedSessionRegistry` instead of an in-memory session
registry. Session lookup can therefore be performed by another registry/node using the same authoritative Redis state.
This is not a claim of global consistency across asynchronously replicated regions.

```mermaid
sequenceDiagram
    participant B as Browser / BFF A
    participant OP as IAM
    participant DB as PostgreSQL
    participant W as Delivery worker
    participant RP as RP B + shared JDBC sessions
    B->>OP: Validated RP-Initiated Logout
    OP->>DB: Principal lock; revoke session/grants + insert unique outbox rows
    DB-->>OP: Commit
    OP-->>B: Logout redirect (delivery is asynchronous)
    W->>DB: Claim due row with lease; commit
    W->>RP: POST logout_token (signed JWT)
    RP->>RP: Spring signature/claims checks
    RP->>DB: Atomically record sid/jti and delete RP sessions
    DB-->>RP: Commit
    RP-->>W: 200 / no-store
    W->>DB: Fenced acknowledgement for current lease
```

## Durable bounded delivery

| Setting / policy                                      | Value                                                                             |
|-------------------------------------------------------|-----------------------------------------------------------------------------------|
| `iam.backchannel.enabled`                             | `true`; false pauses automatic sending, not event publication                     |
| `iam.backchannel.batch-size`                          | 10; allowed 1–100; sequential work per invocation                                 |
| `iam.backchannel.max-attempts`                        | 8; allowed 1–20; configure consistently across workers                            |
| `iam.backchannel.fixed-delay-ms` / `initial-delay-ms` | 1000 / 1000                                                                       |
| Connection / response-header timeout                  | 1 / 3 seconds                                                                     |
| Claim lease                                           | 30 seconds                                                                        |
| Delivery deadline                                     | 24 hours after enqueue                                                            |
| Retry delay                                           | Exponential base 2 seconds, jitter between half and full delay, maximum 5 minutes |
| Success                                               | HTTP 200 or 204                                                                   |
| Retryable                                             | Transport/signing failures, HTTP 408, 429 and 5xx                                 |
| Permanent                                             | Other HTTP statuses, disallowed or changed endpoint registration                  |

Workers claim with `FOR UPDATE SKIP LOCKED`. Claiming increments attempts and records a fresh lease ID/issuance time in
a short transaction. Network calls occur after commit. Acknowledgement updates only an unexpired matching lease; a
delayed worker cannot overwrite a newer claim. An abandoned claim can be recovered after lease expiry. Attempts at the
cap and overdue events become `DEAD`, including abandoned `INFLIGHT` claims. Cleanup also terminalizes overdue events
when sending is disabled, so paused delivery cannot pin data indefinitely.

A new attempt signs a fresh short-lived token with its lease ID as `jti`; no raw logout JWT is stored in the outbox. The
sender follows no redirects and closes the response body after reading status headers, so an unfinished body cannot keep
the worker waiting. At-least-once delivery is intentional: losing a successful HTTP response or crashing before
acknowledgement can cause another delivery. Exactly-once network delivery is not promised.

## RP invalidation and replay safety

The native endpoint is `POST /logout/connect/back-channel/iam`. Spring verifies the signed token before the custom
handler. Structural bounds return controlled 400 responses for malformed inputs; verifier outages return 503. The
boundary strips Spring's private loopback selector from external input so it cannot bypass the durable handler. Local
browser logout retains CSRF protection; signed back-channel requests do not require browser cookies or CSRF tokens.

The receiver serializes login/logout/maintenance for its issuer/client. In one JDBC transaction it:

1. Checks the strict profile and any available subject/SID association.
2. Detects an existing `(issuer, client, jti)` receipt. Identical retransmission succeeds idempotently; reuse with a
   changed signed payload is rejected.
3. Records a SID tombstone even if no matching RP session exists yet.
4. Deletes matching Spring Session rows and their attributes, removes bindings, and records a fingerprint/receipt.
5. Returns 200 only after commit. Database failure returns 503 and leaves no partial acknowledgement.

The custom `OidcSessionRegistry` rejects a login callback for a revoked SID. A request guard rejects absent, expired or
revoked bindings, including a stale/recreated framework session row after a racing save. Thus delivery before callback
completion cannot restore authenticated access. Other SIDs for the same subject remain eligible. Already-running
business requests are not aborted atomically with logout.

Both HTTP sessions and session-bound authorized clients/tokens use JDBC-backed session storage. Another BFF node with
the same RP schema can serve the session and observes its invalidation. Each RP should have its own schema and
production database role. Serialized framework session state includes sensitive tokens/client-registration data:
restrict writers/readers, use authenticated private connections and encrypted storage/backups, and prohibit
body/parameter logging.

In Security 6.5, `OidcLogoutToken#getExpiresAt()` is a sentinel. This implementation validates
`getClaimAsInstant("exp")`, the signed claim; tests cover valid, missing and expired values. This distinction must
survive future refactoring.

## Retention coordination

OP cleanup now has eight bounded stages: the existing five, plus delivery deadline expiry, terminal-delivery removal,
and participant removal. Pending/in-flight and grace-retained terminal deliveries pin their corresponding
lifecycle/session records. Terminal deliveries are deleted only after `completed_at + iam.retention.after-expiry`.
Participants are individually purged only after their parent session's expiry/grace, no lifecycle references and no
delivery references. The session is then eligible for the existing creation-floor-protected deletion. Raw token material
may still be retired promptly; delivery payload fields remain in participant state.

The RP retains receipts through token expiry plus 30 seconds. SID tombstones remain for one day, then bounded cleanup
advances a persistent creation-time floor atomically with deletion. Callback registration rejects old ID-token issuance
times and births at/before this floor; purging a tombstone cannot revive an old callback. Bindings have an eight-hour
absolute lifetime and bounded expiry cleanup. Spring Session separately enforces idle expiry. RP cleanup uses
five-second transactions/query timeouts and at most 100 candidates per category.

## Egress and deployment

`iam.backchannel.allowed-origins` is an explicit comma-separated origin allowlist; its production default is empty
(deny). HTTPS is required unless `iam.backchannel.allow-http=true` is explicitly enabled. No request chooses the
outbound URI, no URI may contain user-info or a fragment, and redirects are not followed. Approved origins still require
trusted DNS, normal certificate validation and network egress restrictions; a hostname allowlist alone does not solve
DNS rebinding or a compromised authorized RP.

The local profile permits loopback HTTP and initializes both demo registrations. Compose overrides them to the internal
`portal-a`/`portal-b` origins. Production TLS, proxy trust and scoped database roles still require deployment review.

Drain old writers before V6/retention activation. Review the change to indexed Redis sessions; use a fresh Redis
namespace and require reauthentication when upgrading incompatible existing session state. RP migration creates
framework session tables and logout state in a dedicated schema; old in-memory RP sessions require a new login. Do not
mix RP schemas/roles across unrelated applications. Local Bootstrap is development-only and now supports
`PORTAL_A_PORT`/`PORTAL_B_PORT` plus explicit back-channel URI overrides.

## Operations and limitations

`iam.logout.delivery{outcome=success|retry|dead}` and `iam.logout.worker.failures` accompany durable outbox status,
attempts, timing and last-outcome fields. Alerts must investigate `DEAD`, repeated retries and growing pending queues. A
permanent outage/configuration error can exhaust the bounded policy; there is no unlimited automatic redrive or claim
that every RP must have acknowledged at OP response time. Fix the cause and review affected sessions; a secured operator
redrive UI/API is not implemented.

Retention metrics include delivery/participant deletions. Cleanup can expire pending deliveries even while the sender is
paused. Offline access JWTs retain their own lifetime, independent of RP-session invalidation. Idle/absolute OP expiry
now uses this same durable enqueue path; see [session expiry](session-expiry.md). Front-channel logout, subject-only
receiver logout, federation chaining, multi-region active-active delivery and production queue-throughput/SLO benchmarks
remain unverified/unimplemented.

## Reproduce verification

With Java 21 and Docker available:

```sh
mvn -f enterprise-iam/pom.xml verify
```

The Maven suite contains OP HTTP/outbox tests and RP HTTP tests with isolated PostgreSQL/Redis/JWKS fixtures. For the
actual packaged applications, from `enterprise-iam/` after building, generating `.env` and starting Compose
PostgreSQL/Redis:

```sh
python3 tests/backchannel_stack_test.py
```

This launches IAM, the resource server, two distinct BFFs and a peer node sharing one BFF's JDBC schema on isolated
ports. It verifies real SSO callbacks, protected API calls from both BFFs and the peer, automatic logout delivery,
cross-node invalidation and preservation of another OP session. Only generated schemas/Redis namespace and spawned
processes are cleaned up. Test durations are not throughput measurements.

The back-channel increment Java 21 Maven verification passed 78 tests with zero failures, errors or skips. The
five-process packaged-app scenario also passed against the final artifacts; neither result establishes production
throughput or external interoperability.

The subsequent session-expiry increment and its current verification are recorded in [status](status.md). Expiry modes
are available as `--mode idle` and `--mode absolute` on the packaged-app script.
