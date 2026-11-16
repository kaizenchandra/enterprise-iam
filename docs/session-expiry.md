# Durable OP session expiry

The OP now couples idle and absolute session expiry to refresh-family revocation and durable OIDC back-channel logout.
PostgreSQL deadlines are authoritative. Redis continues to hold the browser security context; missing Redis
notifications, eviction, an OP restart or an outage cannot prevent deadline evaluation after PostgreSQL recovers.

## Policy and activity

| Setting                                                                       | Default | Meaning                                                                    |
|-------------------------------------------------------------------------------|---------|----------------------------------------------------------------------------|
| `iam.session.idle-timeout` / `IAM_SESSION_IDLE_TIMEOUT`                       | `PT20M` | New OP session idle duration; whole seconds, 1 second through 1 day        |
| `iam.session.absolute-timeout` / `IAM_SESSION_ABSOLUTE_TIMEOUT`               | `PT8H`  | Immutable new OP session lifetime; at least idle duration, at most 30 days |
| `iam.session.expiry-enabled` / `IAM_SESSION_EXPIRY_ENABLED`                   | `true`  | Enable scheduled revocation; deadline checks stay enabled when paused      |
| `iam.session.expiry-batch-size` / `IAM_SESSION_EXPIRY_BATCH_SIZE`             | `100`   | Maximum session candidates per invocation; 1 through 1,000                 |
| `iam.session.expiry-fixed-delay-ms` / `IAM_SESSION_EXPIRY_DELAY_MS`           | `5000`  | Poll delay after completion                                                |
| `iam.session.expiry-initial-delay-ms` / `IAM_SESSION_EXPIRY_INITIAL_DELAY_MS` | `5000`  | Initial poll delay                                                         |

The idle environment setting also configures Spring's browser-session timeout. PostgreSQL records the idle duration per
session, so configuration changes apply to new sessions. Existing sessions never receive a longer lifetime merely
because a process restarts or its configuration changes. Set consistent values on every OP node. The sample RPs also
have independent idle and eight-hour binding limits; extending the OP policy does not extend those limits.

Eligible authenticated browser activity at the OP advances `idle_expires_at`, bounded by the original `expires_at`. The
activity filter runs after security-context loading and CSRF validation, before OAuth authorization handlers. An expired
or revoked session cannot be renewed. Repeated session registration does not reset either deadline. Updates use the
primary database clock and `greatest` to avoid regressing the idle deadline.

Refresh, Client Credentials, introspection, revocation, UserInfo, discovery, JWKS, health and logout calls do not count
as activity. API requests at an RP also do not count as OP browser activity. Consequently an application actively using
its own session or repeatedly refreshing tokens can still lose its OP-linked refresh grants after 20 minutes without
eligible OP activity. This profile does not implement offline-access grants independent of the OP session. Do not add a
caller-controlled heartbeat or use refresh as proof of user activity.

Redis's physical TTL and PostgreSQL's deadline can differ, especially when protocol requests access a Redis cookie
without qualifying as activity. A retained Redis security context does not grant access after either PostgreSQL
deadline. OP expiry is logical invalidation; Redis cleanup/idle TTL handles remaining physical context state, and a
subsequent guarded browser request invalidates its stale cookie session. Direct administrative Redis deletion is not
itself a durable logout operation; use application revocation paths.

## Consistency and revocation

All relevant paths use the existing transaction-scoped principal advisory lock: browser heartbeats, grant creation,
refresh persistence, explicit logout, suspension and expiry. The expiry worker selects a bounded candidate list,
attempts the principal lock without waiting, then rechecks the deadline and revocation state under the lock. A stale
candidate is harmless. Busy principals are skipped for a later pass. Each candidate has an independent five-second
transaction and five-second worker SQL timeout; there is no drain-until-empty loop.

Within the winning transaction:

1. Mark the identity session revoked.
2. Enqueue all recorded RP participants, using their existing unique delivery constraint.
3. Mark session-linked authorization lifecycles revoked and increment their revisions; delete their framework grant
   material, including pending codes and refresh tokens.
4. Write `SESSION_IDLE_EXPIRED` or `SESSION_ABSOLUTE_EXPIRED` to the security audit table.
5. Commit before reporting browser rejection or enabling delivery.

Repeated workers, a foreground expired-session request and explicit logout cannot duplicate deliveries or reactivate a
session. A failure in enqueue, audit or persistence rolls the entire session operation back. Existing replay digests and
lifecycle tombstones remain subject to the original family horizon and retention grace; the expiry path does not remove
or shorten them.

`findById`, token lookup and final authorization persistence check **both session deadlines**, including for an existing
refresh family. They reject expired state even before the worker runs or while it is paused. Browser activity
discovering expiry performs the same durable revocation before returning 401. A dependency failure during that check
returns 503 without granting access. Grant lookup does not run a hidden maintenance transaction: token requests may
reject before revocation/notification commits on a later worker pass.

Issuance and revocation serialize through the principal lock. Issuance that commits before expiry/revocation can still
have a delayed HTTP response; that does not guarantee the returned refresh token remains usable upon receipt. An issued
self-contained access JWT remains independently valid at offline resource servers through its own expiry/skew. This
change does not claim instantaneous JWT revocation.

Batch limits count **sessions**, not child grant/participant rows. Child invalidation and enqueue use set-based SQL in
the same bounded transaction. Extremely large sessions may exceed transaction limits and require operator investigation;
no throughput or worst-case backlog/SLO guarantee has been measured. The application scheduler has three threads to keep
a slow logout sender from occupying the only maintenance thread.

## Retention and failures

Retention cannot delete an unrevoked expired identity session or its RP participants. This includes sessions whose raw
grants and lifecycle rows have already expired and been cleaned up. The expiry worker must first commit
revocation/enqueue. Existing pending and grace-retained terminal delivery pins then apply. Only after all references and
grace requirements are satisfied may cleanup purge participants and session tombstones and atomically advance the
creation floor. A delayed Redis context, old login birth stamp or stale lifecycle snapshot cannot recreate purged state.

| Failure                                  | Behavior and recovery                                                                                                                                                                                                                               |
|------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| PostgreSQL unavailable                   | Session checks and issuance fail closed; expiry cannot commit. Restore the authoritative primary; persisted deadlines remain due and the next pass revokes/enqueues. JDBC has bounded connect, socket and cancel timeouts; no local grant fallback. |
| Redis unavailable or notification lost   | Browser session paths fail closed. The worker and durable revocation do not query Redis and can enqueue/deliver while Redis is unavailable. Recovered stale cookies remain fenced.                                                                  |
| RP unavailable                           | Expiry commits locally and persists delivery. Existing bounded back-channel retries, deadline and DEAD handling apply; operator recovery is still required for terminal failures.                                                                   |
| Expiry transaction/queue insert fails    | No partial session revocation or grant deletion commits. Deadline eligibility still denies use; retry after the dependency is restored.                                                                                                             |
| OP crashes or response is lost           | Uncommitted work rolls back; committed revocation and deliveries survive. A later worker rechecks or a delivery worker resumes its lease.                                                                                                           |
| Worker paused, busy principal or backlog | Deadline rejection remains active, while notifications can lag. Unprocessed session/participant rows are retained. Reenable/resume and monitor backlog and failures.                                                                                |
| Clock changes                            | Primary database time controls checks. Revocation is irreversible even if the clock later moves backward; monitor time synchronization.                                                                                                             |

PostgreSQL driver defaults are connect 2 seconds, socket 5 seconds and cancel 2 seconds, in addition to pool and
transaction bounds. URL parameters can override driver properties; review production datasource configuration. See
the [pgJDBC timeout documentation](https://jdbc.postgresql.org/documentation/use/). Redis events are not a durable
delivery mechanism;
see [Spring Session Redis behavior](https://docs.spring.io/spring-session/reference/configuration/redis.html).

## Upgrade and operations

**Drain old writers before V7.** Older binaries neither maintain idle deadlines nor enforce them on existing grants. V7
adds the durable idle deadline/duration and a partial due-session index. Prior Redis last-access times cannot be safely
reconstructed, so V7 conservatively marks legacy sessions idle-expired. Their grants, replay history, RP participants
and existing outbox entries survive migration; new code denies them immediately, and the worker completes
revocation/logout. Users must reauthenticate. Drain outstanding expiry/delivery backlogs after upgrade, preserve
signing-key overlap for logout token verification and observe the existing indexed Redis/JDBC RP migration requirements.
Do not roll back to binaries that ignore these deadlines.

Monitor `iam.session.expired{reason=IDLE|ABSOLUTE}` (worker winners), `iam.session.expiry.failures`,
`iam.session.expiry.skipped{reason=principal_busy}`, `iam.session.expiry.duration`, audit expiry events and the existing
logout/retention metrics. Foreground expiry is recorded in audit; the worker-winner counter does not count it.
Restricted operators can inspect unrevoked rows where `least(expires_at,idle_expires_at)<=clock_timestamp()` to assess
due backlog. Do not extend expired rows, delete replay history or reset creation floors to clear alarms.

## Reproduction

With Java 21 and Docker available:

```sh
mvn -f enterprise-iam/pom.xml verify
```

Tests use real PostgreSQL and real HTTP against the OP, including paused PostgreSQL/Redis containers, real elapsed short
idle/absolute deadlines, CSRF rejection, worker recovery, enqueue rollback, concurrent heartbeats/workers, stale
issuance, retention and migration. Existing RP replay, outage and shared-session tests remain part of the suite.

After building, initializing the ignored local `.env`/keys and starting Compose PostgreSQL/Redis, run from
`enterprise-iam/`:

```sh
python3 tests/backchannel_stack_test.py --mode idle
python3 tests/backchannel_stack_test.py --mode absolute
python3 tests/backchannel_stack_test.py --mode logout
```

These run the actual IAM, resource server, two distinct BFFs and a shared-session BFF peer. Expiry modes advance only
the targeted test session's database deadline, then require the real scheduled worker and signed HTTP delivery to
invalidate all its RP sessions while preserving an independent session. Generated schemas/Redis namespace and spawned
processes are cleaned up. This is functional evidence, not a load, certification or production-readiness claim.

Executed verification: the Java 21 Maven reactor passed **103 tests with zero failures, errors or skips**. All three
packaged scenarios above passed against the final artifacts. Compose configuration validated; production throughput,
external interoperability, regional behavior and Kubernetes rollout remain unverified.
