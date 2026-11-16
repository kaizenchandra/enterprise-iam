# Human username/password login and platform administration — pending live rollout

Implemented Next `/login` and anonymous/expired-session redirects. Both normal and administrator
entry points use the existing IAM username/password login via Code+S256 PKCE, retaining provider
MFA/passkey/CSRF/lockout handling. The browser machine-credential exchange endpoint is disabled (410), and its
credential form is removed. Existing machine administrator grants cannot be used
through the frontend. Personal identity changes clear prior administrator/delegated grants.

Additive V15 creates an explicit `platform_administrators` relation, separate from tenant RBAC.
Admin authorization-code token issuance requires this role. Every human admin API request checks
current role membership, ACTIVE state and a live authorization grant. Tenant roles and requesting
admin scope cannot promote a user. Machine administrator automation remains a separate API use.
Local bootstrap can provision an absent `admin` using the initializer-generated private
`ADMIN_PASSWORD`; existing users/passwords are never overwritten or implicitly promoted.

Verification: full Java 21 reactor verification passed **242 tests, zero failures/errors/skips**,
including actual-HTTP human admin issuance, normal-user rejection, role-removal denial and account
suspension denial. Frontend **12 tests**, TypeScript and production build passed. A serializable
role-claim representation was corrected after the first regression run; the final full run passes.
The updated IAM Docker image was built. Live human-login verification is provided in
`tests/frontend_human_login_test.py` but has not run against the live deployment.

**Rollout is pending approval.** Automatic approval review rejected applying the migration,
provisioning privileged local admin access and restarting the running services because explicit
live-deployment authorization was required. No live V15 migration or administrator provisioning
was performed. Approve those actions before applying/restarting. Existing services were not
stopped by this task. After rollout, run the human login regression and verify both account types.
Credentials and instructions: [frontend setup](../frontend/README.md) and [help](../help.md).

# Capability and verification status

This delivery is an executable IAM development baseline. **The complete master-prompt definition of done is not met. Do
not deploy it as a production identity provider.**

## Local Flyway history reconciliation — 2026-11-17

Reconciled the local Compose database's V1–V14 checksum mismatches without replaying migrations or
changing application records. A fresh reference database built from the packaged SQL matched the
existing public schema exactly. Private full backup/original history/verification receipt were saved
under `secrets/backups/flyway-626cd7622c84/`. Flyway repair ran while application tables were held
under SHARE locks; before/after SHA-256 row fingerprints matched, and history comparison confirmed
that only checksum fields changed. Validation remained enabled.

Actual packaged-server startup succeeded: all 14 migrations validated, schema V14 was up to date,
Tomcat started on port 9000, health/readiness returned UP and OIDC discovery returned the configured
issuer. The local launcher regression and two schema-comparison guard tests passed. No full Maven
rerun was required for this operational repair; Java application sources/migrations were unchanged.
See [the guarded procedure and limitations](../help.md#guarded-local-flyway-checksum-reconciliation).

## Current Next.js console increment

Added a Next.js 16.4.6 / React 19.3.1 administration and personal-security frontend. Its checked
catalog covers all **30 implemented bearer API operations across 22 paths**, including user
lifecycle, membership, machine client secrets/public keys, role/permission assignments, owner
sessions and PDP decisions. Browser-sensitive MFA/passkey/recovery/verification ceremonies remain
on the existing IAM origin, linked from the console. OIDC UserInfo and the protected orders sample
are available through delegated server-side access. Unsupported backend features are not simulated.

The Next BFF retains tokens only in Redis, with opaque HttpOnly cookies, separate audience grants,
exact-Origin mutation checks, a bounded allowlisted API proxy, Code+PKCE/state/nonce verification,
nonce-based script CSP and signed back-channel session invalidation. Credentials issued by the
backend appear only in the current one-time result panel. The local profile provisions an exact
confidential `next-console` client and approves the port-3000 logout origin. Operator access uses
an explicitly supplied machine admin credential; human administrator federation/SSO remains future
backend work. See [coverage and trust boundaries](frontend.md).

Verification on 2026-11-16:

- Java 21 full reactor `mvn verify`: **241 tests, zero failures/errors/skips**, all modules packaged.
- After fixing an HTTP negotiation issue found by the real frontend stack, focused protocol/client
  verification passed **105 tests, zero failures/errors/skips**, and the IAM JAR was rebuilt. These
  are separate runs; no final full-run claim is made for that HTTP client configuration change.
- Frontend tests: **8 passed**, covering API catalog completeness, path/method allowlisting, typed
  request building, Origin/configuration checks, opaque cookie parsing, streamed body bounds and
  safe error responses. TypeScript and optimized Next production build passed.
- Final `tests/frontend_stack_test.py` passed using actual packaged Next/IAM/resource processes and
  isolated PostgreSQL schemas/Redis namespaces. It verifies security headers/nonces, authorization
  gates, lifecycle/version conflicts, membership/RBAC, credential issuance/rotation, Code+PKCE,
  UserInfo, resource access, live PDP allow/deny and signed distributed logout. Test-owned processes
  and data were cleaned up; existing stores were left running.
- Production dependency `npm audit --omit=dev` reported **zero known vulnerabilities** at check time.
  An exact-value check of 61 source/doc files found no local configuration credential matches; this
  is a limited check, not a comprehensive secret audit.

The real stack exposed Java's default cleartext HTTP/2 upgrade being rejected by the local Node 26
Next server (closed connection before headers). Back-channel delivery now explicitly uses HTTP/1.1;
TLS validation, bounded timeouts and redirect rejection remain intact.

Visual/browser QA could not run: the browser access host was unavailable and native Chrome returned
no usable window. Responsive CSS and accessibility behavior are implemented, but visual and
assistive-technology certification is not claimed. No frontend deployment, penetration test or
representative production load/HA verification occurred. See [setup](../frontend/README.md),
[testing walkthrough](../help.md) and [integration limits](frontend.md).

## Previous organization-membership and authorization-administration increment

Implemented platform-admin-only membership creation/list/removal at the prompt's organization API.
Creation requires an ACTIVE user; removal atomically deletes that organization's assignments so
rejoining cannot restore privileges. Shared organization row locking serializes membership changes
with role assignment/revocation. Role creation, permission creation and assignment revocation now
commit only with their audit record. User/organization/policy/membership pagination has validated
bounds and deterministic ordering. No positive authorization cache was introduced.

Java 21 full `mvn -B verify` passed **239 tests, zero failures/errors/skips**, packaging all three
modules. After adding the final HTTP security/pagination and RBAC rollback regressions, focused
verification passed **14 tests, zero failures/errors/skips** (13 state integration tests plus one
full-server membership HTTP test). These are separate runs; no final 241-test full-run claim is made.
The HTTP test uses actual PostgreSQL/Redis and verifies anonymous/ordinary-token denial, admin
creation/list/deletion, duplicate rejection, input validation and pagination overflow rejection.
State regressions cover immediate PDP denial, tenant isolation, rejoin safety, audit rollback and
concurrent membership removal versus assignment. OpenAPI JSON was validated. Separate packaged
Python/browser tests and production load were not rerun.

No schema migration is required. Drain older admin writers before rollout because their mutation
paths lack the new organization lock/audit behavior. See [authorization guarantees and remaining
limits](authorization-model.md) and [testing guide](../help.md). Rich ABAC/SoD, policy version history,
business PEP integration, actor/context-rich tamper-evident audit export and production contention
measurements remain outstanding; membership does not grant platform administration.

## Previous administrative lifecycle increment

Added administrator-only username profile updates with required optimistic user version, deactivation
and logical deletion. Profile writes cannot edit email verification bindings, credentials or account
state. Deactivation/deletion use the existing principal locks, durable session cutoff, grant revocation
and back-channel outbox in the same transaction as the state change and audit. Deleted identities
cannot be activated or edited. Logical deletion preserves security evidence and credentials in the
database; personal-data erasure and retention policy remain outstanding. Existing offline access
JWTs retain their documented expiry window.

Added database-backed lifecycle regressions and repaired missing imports in the retention/session
expiry test classes. See [end-to-end test walkthrough](../help.md) and [OpenAPI](openapi.json).
Java 21 full `mvn -B verify` passed on 2026-11-16: **235 tests, 0 failures,
0 errors and 0 skips**, all three modules built and packaged. Docker used the
explicit active OrbStack socket via `DOCKER_HOST`. OpenAPI JSON and guide code fences were
validated. The separate Python/browser packaged scenarios and production load were not rerun
in this increment; their commands are in the guide. Older counts below are historical.

The master prompt remains incomplete. In particular, federation/OIDC brokering, SAML, SCIM,
full administration portal, richer ABAC/SoD policy evaluation, mTLS/workload federation,
representative production SLO/soak/failover evidence and multi-region deployment remain release
work. Existing architecture documents do not constitute implemented or verified capabilities.

## Current private_key_jwt increment

Implemented opt-in asymmetric OAuth client authentication using the maintained Spring Authorization Server provider and
Spring/Nimbus verification. Public RS256 client keys are administrator-provisioned; no remote JWKS fetch runs on the
token path. Assertions require exact issuer/subject/client identity and endpoint audience, bounded lifetime/clock skew,
approved algorithm/type/key ID and a fresh single-use JTI. Basic authentication and BCrypt cost 12 remain intact. New
private-only registration never issues a secret; existing clients can add assertions while retaining Basic.

V14 adds public-key policies/revisions and hashed replay evidence. Shared client-row locks fence issuance/revocation
against exclusive administrative changes. Explicit old/new overlap, immediate retirement, disable tombstones and
compare-and-set revisions prevent stale policy replacement. Replay claims commit independently before token responses
and survive later grant rollback. Replay state is keyed by external client ID and does not cascade on registry deletion.
Bounded cleanup preserves evidence through expiry/skew; authoritative time is rechecked after insert lock waits, closing
a stale-insert/cleanup race. Database/policy/replay failures fail closed. Audit failure rolls back key changes. Existing
access-token expiry and logout/revocation limits are unchanged.

Java 21 full `mvn verify` passed **231 tests with zero failures, errors or skips**. After the final
expiry-race/provisioning hardening and additional protocol cases, focused `PrivateKeyClientIntegrationTest` verification
passed **26 tests**, and the runnable IAM JAR was rebuilt. These are separate runs, not a claim that a final 233-test
full run occurred. Tests use actual HTTP and isolated PostgreSQL/Redis: signatures/claims/audience/algorithm/type,
malformed/duplicate assertions, endpoint-bound introspection/revocation, concurrent replay and distinct assertions,
independent replay-store instances, key overlap/retirement/kid reuse, competing revisions, issuance on both sides of a
rotation, private-only registration/admin denial, grant/replay/audit outages, deletion/recreation, expiry/cleanup lock
races, confidential Code+PKCE, OIDC, refresh-family replay and logout. A test/wiring issue that could have displaced
password authentication was corrected; the framework provider is installed only in the protocol chain.

The packaged same-Java-driver comparison completed **50/50 requests per method, zero errors/drops**, at five offered
requests/second and eight maximum in flight. Basic p50/p95/p99 was **318.733/491.285/583.593 ms**; private_key_jwt was
**23.209/48.615/61.981 ms**, including fresh client signing and durable replay commits. Both used the same
client/scopes, 256 MiB IAM heap and local stores; hash, JWT, scope and lifecycle controls were preserved. These are
sequential local 50-sample observations, not saturation, production throughput or SLO certification. The earlier
Python-driver series is separate. See [raw comparison](../benchmarks/results/token-auth-comparison.json)
and [measurement boundaries](../benchmarks/README.md).

The final packaged Chromium platform ES256 regression also passed enrollment/login/removal, saved OIDC
continuation/protected APIs, replay/concurrency, exact origin, UV, audit-outage rollback, MFA/recovery, stale assertions
and distributed logout across the two clients and peer RP. Temporary processes/schemas/Redis namespaces were cleaned;
unrelated listeners and running stores were left intact. OpenAPI/report JSON and Python/Node syntax checks passed. A
limited exact-generated-value scan of 177 source/test/doc/report files found no development credential matches; this is
not a comprehensive secret audit. Remote CI, image/Kubernetes deployment, physical-device tests and production load were
not executed in this increment.

See [protocol, key APIs, rotation, failure handling and exact commands](private-key-jwt.md), [OpenAPI](openapi.json)
and [ADR 0012](decisions/0012-private-key-jwt.md). Production key custody, representative TLS/data/topology, sustained
load, pool admission/sizing, cleanup capacity and multi-region fencing remain release gates. Replay claims need an
additional pooled connection; bounded pool exhaustion fails closed. The default cleanup cadence is a development
baseline requiring measured sizing. No production readiness is claimed.

## Previous live-metadata and verification increment

Implemented optional `PASSKEY_METADATA_SOURCE=LIVE` with the maintained Yubico 2.10.1 signature/PKIX/CRL verifier, exact
publisher certificate SAN validation, explicit signer/manufacturer trust roots, restricted retrieval origins and a
bounded disposable verifier JVM. OFFLINE remains the default and passkeys remain disabled by default. Live metadata is
fetched only by maintenance, with durable fleet leases, hourly polling/backoff and fenced publication. Cold nodes fail
closed until their local signed cache is verified. V13 retains signed evidence and canonical digests; peers revalidate
it without external requests. Signed serials, original acceptance age, expiry and permanent adverse-model tombstones
cannot be reset by retries, outages or stale publishers. Existing credential/session revocation and durable back-channel
delivery remain in place.

Java 21 full Maven verification passed **206 tests with zero failures, errors or skips**. After the final
publisher-identity and evidence-canonicalization changes, focused verification passed **49 tests** (16 live-metadata and
33 hardware-attestation); the packaged JAR was rebuilt. These are separate runs, not a claim that a final 207-test full
run occurred. Controlled tests cover signed metadata/CRLs, malformed signatures, unsafe models, expiry/outages, private
origins, redirects/body limits, worker deadline/interruption cleanup, durable rate backoff, lease loss, peer evidence
renewal and publisher identity. All use generated test PKI and real PostgreSQL, not physical authenticators. Compose
base/opt-in LIVE configuration was validated; no production deployment occurred.

Actual public evidence includes signed catalog serial 301 (11,148,970 bytes, 537 entries, 365 FIDO2 models) verified
against the configured publisher trust and three real signer CRLs. A direct Java retrieval encountered HTTP 429; the
diagnostic used a previously downloaded candidate and live CRLs. A final packaged two-node test verified that same
public candidate through a loopback mirror with live HTTPS CRLs, explicit publisher identity and 256 MiB server heaps;
both nodes became ready. **Zero manufacturer models were approved by these probes.** The reports label seed/mirror
retrieval and do not claim a fresh public metadata download on every run.

The local 50-request Client Credentials workload achieved 50 successes, no errors/drops and 4.953 requests/second at an
offered 5 requests/second; p50/p95/p99 was 283.272/523.868/616.833 ms. The 100 ms token target was not met in this
environment. A separate CPU-only sampled run also completed 50/50; BCrypt client authentication accounted for 99.34% of
1,211 measured HTTP executor samples. This is CPU sampling, not wall-time attribution or production bottleneck
certification. Hash controls were preserved. See [measured workloads and boundaries](../benchmarks/README.md).

An interactive physical-device runner is provided, but no device holder or representative staging environment was
available. Physical-vendor interoperability, hardware certification and production throughput/SLOs remain unverified.
See [live configuration and evidence](live-mds.md), [physical acceptance procedure](physical-passkey-tests.md)
and [ADR 0011](decisions/0011-live-mds-worker.md). No production readiness is claimed.

The final packaged platform ES256 browser regression passed actual Chromium enrollment/login/removal,
replay/concurrency, exact origin, UV, audit-outage rollback, account recovery, MFA and distributed logout. A separate
latest 20-login virtual measurement passed with zero failures: combined client/CDP p50/p95/p99 143.488/335.342/336.071
ms, achieved closed-loop rate 2.533 ceremonies/second. An initial timing attempt stopped before samples due to an
unrelated port-forward conflict; the retry used configurable portal ports and completed. Cleanup was fixed to attempt
SQL despite Redis failure and preserve original exceptions. Reports contain aggregate timings/status only; a limited
exact-value scan across source/tests/docs/reports found no generated development credentials (not a comprehensive secret
audit).

## Previous hardware-attestation increment

Implemented opt-in REQUIRED hardware-attested passkeys using Yubico core/attestation 2.10.1, explicit metadata signing
and manufacturer CA roots, provisioned CRLs and signed offline FIDO2 MDS-format bundles. NONE remains the default.
REQUIRED rejects none/self/untrusted, unknown/revoked models and backup-eligible credentials. Stored hardware
paths/status are rechecked at authentication; existing MFA/recovery and owner removal remain intact.

V12 persists metadata serial/digest, policy revision/configuration/mode, bounded expiry, model eligibility and permanent
compromise tombstones. Publication and ceremonies use shared/exclusive metadata locks before existing principal locks.
Replayed metadata cannot slide its deadline; older nodes/publishers cannot restore a superseded policy. A misconfigured
NONE node cannot bypass an accepted REQUIRED state. The bounded sweep atomically marks affected credentials revoked,
advances user/session cutoffs, revokes grants, preserves refresh history and enqueues existing back-channel logout. Root
withdrawal and missing models stop new assertions; existing sessions are revoked asynchronously subject to
worker/outage/backlog limits. Offline JWT lifetimes remain unchanged.

The final full Java 21 build passed **191 tests, zero failures, errors or skips**, including 33 new hardware/metadata
cases. These use runtime-generated test PKI, actual signed packed registrations/assertions, signed metadata, real
PostgreSQL and standard maintained-library verification. They cover unsafe statuses, signing-certificate CRL revocation,
malformed signatures/headers, expiry/outages, root withdrawal, conflicting revisions, peer caches, global mode, MFA,
owner removal, audit rollback and concurrency. The final focused attestation/passkey-state run also passed; ambiguous
headers and software/unspecified key-protection metadata are rejected. A standalone browser test exposed a test-scoped
CBOR dependency masking a required runtime dependency; the scope was corrected and the full build rerun. The packaged
JAR was checked for the runtime library. The final packaged browser matrix passed for platform ES256, USB RS256 and
synced ES256 in explicitly isolated NONE-mode stacks, including replay/origin/UV/signature checks, concurrent finish,
account recovery, MFA, owner removal and distributed logout. These stacks do not use deployment trust files. The earlier
enrollment-options 500 caused by the masked CBOR runtime dependency is fixed. Compose base/opt-in override and OpenAPI
JSON were validated; no production deploy was attempted.

See [hardware policy, supported metadata profile, rollout and limitations](hardware-attestation.md)
and [ADR 0010](decisions/0010-hardware-attestation.md). The supported feed is a provisioned, signed **offline FIDO2**
profile; it rejects certificate retrieval URLs and does not integrate the live public FIDO Metadata Service. Physical
manufacturer devices, TPM/Android/Apple interoperability/certification, new assurance claims and production
fan-out/latency remain unverified. Operational delivery of valid roots/CRLs/bundles is required before enabling
REQUIRED.

## Previous passkey increment

Implemented opt-in Yubico WebAuthn 2.10.1 enrollment, discoverable user-verified primary authentication, owner
credential listing and reauthenticated removal. Exact RP origins, browser/purpose/configuration-bound two-minute SQL
challenges, single-use validation, signature counters and principal locking preserve the existing lifecycle fences.
Enrollment/removal atomically update public credentials, version/cutoff, grants, durable logout and audit, then end the
browser session. Passkey login rotates session/CSRF context and resumes a saved local OAuth authorization request.
Existing TOTP requirements remain enforced. Recovery preserves registered keys and MFA; older prepared assertions cannot
survive reset/removal.

Full Java 21 Maven verification now passes **158 tests, zero failures, errors or skips**. Fourteen additions comprise
eleven database-backed passkey state/security/concurrency/failure tests and three full-server HTTP
default-disabled/CSRF/body-limit/throttle-isolation tests. The follow-up also verifies the no-attestation policy and
offered algorithms; disabling ceremonies with pending state cannot consume it. A USB/RSA negative test found a
malformed-signature JCA exception producing 500; the specific wrapped signature exception now produces
rejection/consumption without swallowing database failures. Review fixed passkey traffic spending the recovery throttle
allowance, static script access during pending MFA, and missing RP-initiated OAuth continuation. The existing throttling
fixture was updated for fixed flow buckets. Compose configuration and OpenAPI JSON validated. A limited exact-value
source/test/docs check found no generated development secrets; this is not a comprehensive secret scan.

The final packaged five-process scenario passed with real Chromium WebAuthn signatures: RP-initiated OIDC
callback/protected API, exact foreign-port rejection, required UV, browser binding, replay/concurrent completion,
MFA/recovery preservation, prepared assertions after reset/removal, atomic audit-storage rollback and back-channel
invalidation across both clients and a peer RP. It used isolated schemas, Redis namespace and an ephemeral Chrome
profile. CI was configured but not run remotely. No physical-device test, production load benchmark or external
conformance/security assessment was performed.

The follow-up matrix passed on the final artifact for virtual platform/CTAP 2.0 ES256, USB/CTAP 2.1 RS256 and
synced/CTAP 2.1 ES256 credentials. It checks stored backup flags, required UV despite a downgraded browser option,
invalid signatures with consumed challenges/no new sessions, and the complete existing
recovery/replay/outage/removal/logout scenario for each profile. The runner respects public throttle windows between
stacks; CI now runs the three-profile matrix, but remote CI was not executed here. Virtual transports are not
physical-device evidence, and attestation NONE is not hardware trust. Physical acceptance and production capacity remain
open; see the detailed verification boundaries in the guide.

An earlier bounded follow-up measured 20 fresh signed ES256 logins with zero failures: combined client/CDP ceremony
p50/p95/p99 102.429/136.938/151.680 ms, finish HTTP/CDP p95 57.221 ms and closed-loop rate 3.095 ceremonies/second. This
is historical evidence from the previous increment; the JSON report now contains the latest measurement recorded above.
These single-client, one-identity, localhost virtual-authenticator results do not verify production SLOs or capacity;
p99 is only the maximum of 20 observations. During that earlier run the three stores were resumed then restored to their
original paused state. During the current increment they were already running and remain running.

See [implementation, browser verification and rollout](passkeys.md), [ADR 0009](decisions/0009-passkeys.md)
and [OpenAPI](openapi.json). V11 is additive; drain old writers and configure exact HTTPS origins before enabling. The
feature defaults disabled. Passkey-only account creation, lost-all-factors recovery, new ACR/AMR contracts, broad
physical-device interoperability and production throughput remain unverified/unimplemented. Existing offline JWT
lifetime and asynchronous logout limits are unchanged. No production readiness is claimed.

## Previous account-action increment

Implemented public account-verification/password-reset request and completion forms, trusted platform email binding,
purpose-bound single-use expiring tokens, encrypted durable request/mail queues and real SMTP delivery. Existing
addresses stay null/unverified until explicitly bound/proven. No public signup or automatic account linking is
introduced. Public requests use the same generic response without a synchronous identity lookup.

Reset atomically changes the adaptive hash, invalidates outstanding actions, revokes target sessions/grants, advances
the login cutoff, queues back-channel logout and a security notification. MFA credentials, recovery codes and attempt
lockout remain intact. Delivery uses finite leased retries and fenced acknowledgements; action payloads are wiped after
success/deadline, and bounded retention preserves live references. A stale request predating revocation cannot mint a
new action. Trusted binding overrides a pre-binding public cooldown so verification is not suppressed.
Invalid/replayed/expired/wrong-purpose actions cannot restore suspended identities.

Full Java 21 Maven verification passed **144 tests with zero failures, errors or skips** (20 new HTTP/SMTP account
tests). The SMTP-outage health check was rerun successfully after the final configuration change. The packaged
five-process Mailpit scenario passed against the final server, including verification/reset replay, old-password
rejection, fresh protected API access, shared-node logout and other-owner isolation. Mailpit was pulled/started locally
and Compose configuration is validated; no external email, production rollout, SMTP TLS-provider certification or load
benchmark was performed.

See [account contracts, delivery and rollout](account-actions.md)
and [ADR 0008](decisions/0008-account-verification-and-recovery.md). Account actions default disabled until custody
inputs and SMTP are configured. V10 is additive; legacy accounts are never implicitly verified. Self-service email
changes, public registration, lost-MFA recovery, breached-password screening and production SMTP/key/SLO validation
remain release gates.

## Previous MFA assurance increment

Closed an authorization bypass: MFA checks now execute before OAuth authorization handlers and token persistence/lookup
requires durable OP-session proof for enrolled users. Redis markers cannot grant assurance. Session-bound verification,
OTP/recovery consumption, durable per-user lockout and audit share the issuance/revocation principal lock. TOTP
verification and replay tracking now use one timestamp. Framework saved-request handling restores the original PKCE
authorization after successful MFA.

Enrollment confirmation now revokes old sessions/families, advances the login cutoff and enqueues logout atomically,
then displays recovery codes once in a no-store response before requiring fresh login. Store/transaction failures are
sanitized. V9 drains incompatible writers and revokes legacy enrolled sessions while preserving refresh history and
delivery dependencies. It does not trust Redis assurance for migration.

Java 21 `mvn -f enterprise-iam/pom.xml verify` passed **124 tests with zero failures, errors or skips**. Ten additions
are eight full-server HTTP tests, a deterministic OTP timestamp test and a V8-to-V9 migration test. The final regression
also exercises MFA verification racing local logout. The packaged five-process session UI scenario passed after the
protocol changes; the last controller-only logout response fix was covered by targeted and full Maven runs. No
production load or external conformance assessment was performed.

See [MFA guarantees and rollout](mfa-assurance.md). This increment prioritizes an existing security defect over adding
recovery. Public registration/verification/password recovery, passkeys, mandatory tenant enrollment, removal/reset and
operation-specific step-up remain unfinished. No new ACR/AMR or phishing-resistance claim is made.

## Previous session UI increment

Implemented a functional server-rendered `/sessions` page in the web client: session timestamps/status, current-session
marker, keyset pagination, individual revoke forms and a signed-out page. Management uses a separate `iam-management`
Authorization Code + S256 registration with the same approved confidential client identity. Its tokens remain in the
JDBC HTTP session authorized-client repository; ordinary business tokens retain their own audience and access.

The management callback requires matching issuer, subject and OP sid against the existing BFF identity. Browser revoke
actions are CSRF-protected POSTs; IAM still enforces live-grant ownership. Missing/expired tokens require
reauthorization rather than automatic management refresh. Revoked grants show a sanitized reconnect page.
Current-session revocation invalidates the local session immediately, tolerating a concurrent back-channel invalidation,
and logout propagates to connected RPs. Secure cookies now default on with explicit local HTTP overrides. Local-only
bootstrap provisions the management scopes and second callback.

Java 21 Maven verification passed **114 tests with zero failures, errors or skips**. The 11 client tests were rerun
successfully after the final login-routing change. The packaged `python3 tests/backchannel_stack_test.py --mode ui`
scenario passed, including account-switch rejection, concurrent revoke forms and management token use from a peer BFF.
Compose configuration validated. The GitHub Actions workflow was configured but was not executed remotely in this
session.

See [session UI setup and security](session-ui.md). The packaged five-process UI test covers real OAuth callbacks,
rendered forms, current markers, independent management/business grants, peer use of stored tokens, CSRF and GET
rejection, other-owner isolation, OP-account-switch rejection, concurrent duplicate revocation, reconnect and
current-session distributed logout. The CI workflow now includes this standalone scenario after Maven verification. No
JavaScript browser/visual certification, production load benchmark or full administrative portal is claimed.

## Previous session-management increment

Java 21 `mvn -f enterprise-iam/pom.xml verify` passed **114 tests with zero failures, errors or skips**. Eleven
additions comprise nine full-server HTTP API tests and two PostgreSQL cutoff/retention/concurrency tests. Existing
protocol, expiry, RP, MFA, policy and JWT tests pass.

Implemented owner-only paginated session listing, individual revocation and platform-admin revoke-all. Public random
UUIDs, timestamps/status/current-session fields replace exposure of internal session/cookie/OIDC identifiers.
Self-service requires a dedicated audience/scope, a live human grant and ACTIVE user; same-tenant memberships never
grant another owner's session access. Shared OP sessions span tenants, so organization roles do not authorize the global
administration route. Admin actions require dedicated platform authority and a live persisted grant.

Revocation commits existing grant deletion, tombstones, RP enqueue and attributed audit atomically. The new user-level
login cutoff prevents a previously started password login registering after revoke-all, even after session retention.
Review also found repeated revocation could recreate delivered work after outbox retention; enqueue now occurs only for
newly revoked sessions. Tests cover owned/unowned lookup, pagination/limits, same/different-organization ownership,
insufficient scope/audience, machine-token rejection, revoked management tokens, current-session deletion, rollback with
sanitized 503, expiry/refresh/delete races, admin/code-issuance races, delayed login and cutoff preservation after GC.
The audience customizer now selects from authorized scopes rather than all client registrations.

See [session API contracts and rollout](session-management.md), [OpenAPI](openapi.json)
and [ADR 0006](decisions/0006-owner-scoped-session-management.md). V8 requires draining older writers that ignore the
login cutoff; it does not itself expire eligible sessions. Physical device fingerprinting, management UI,
tenant-specific session partitions, human-admin step-up and production fan-out benchmarks remain outside scope. Remote
RP invalidation stays asynchronous; offline JWT lifetimes are unchanged. The separate packaged five-process Python
scenarios were not rerun in this increment; their prior evidence is recorded below.

## Previous session-expiry increment

Java 21 `mvn -f enterprise-iam/pom.xml verify` passed: **103 tests, zero failures, errors or skips**. The 25 additions
are 13 PostgreSQL expiry/migration/concurrency tests, three scheduler tests and nine full-server HTTP
expiry/security/outage tests. Existing retention, token, RP replay/outage, MFA, policy and JWT tests still pass.

Implemented authoritative idle and absolute OP deadlines, monotonic browser-only idle renewal, immediate expiry checks
for existing grants and final persistence, and bounded durable expiry revocation. The winning principal-locked
transaction revokes session-linked refresh families/pending codes, enqueues recorded RP logout and writes an expiry
audit event. Expired/revoked sessions cannot be renewed; worker retries and explicit logout do not duplicate deliveries.
Cleanup retains unprocessed expired sessions/participants and preserves existing delivery pins, refresh-history horizons
and creation floors.

Executed tests include real elapsed idle/absolute deadlines, repeated heartbeat without absolute extension, two workers,
busy principal skipping, stale issuance, concurrent refresh/logout/cleanup, queue-insert rollback, V6-to-V7
preservation, paused PostgreSQL and Redis containers, recovered stale cookies, pre-worker token/introspection rejection
and protocol-filter ordering. A new test exposed rejected CSRF requests extending idle time; moving activity handling
after CSRF validation fixed it. Outage checks also led to explicit bounded PostgreSQL driver timeouts. The scheduler
uses three threads so a slow logout batch does not occupy its only maintenance thread.

All three packaged five-process scenarios passed against the final artifacts:
`python3 tests/backchannel_stack_test.py --mode idle`, `--mode absolute` and `--mode logout` from `enterprise-iam/`.
Both BFFs and the shared-session peer lost the targeted session through real signed delivery, while an independent
session retained protected API access. Compose configuration validated. A limited exact-value check found no generated
development secrets in checked source/test output; this was not a comprehensive secret scan. No image rebuild or
Kubernetes rollout was performed in this increment.

See [session-expiry guarantees and rollout](session-expiry.md)
and [ADR 0005](decisions/0005-durable-op-session-expiry.md). Defaults are 20-minute OP idle, eight-hour absolute, 100
expiry candidates and five-second poll delay. Refresh calls and RP API activity do not renew OP idle time. V7 requires
draining old writers and conservatively expires legacy sessions whose idle age cannot be reconstructed. Remote RP
invalidation remains asynchronous and finite; offline JWT lifetimes are unchanged. No production load, SLO or external
interoperability claim is made.

## Previous distributed-logout increment

Java 21 `mvn -f enterprise-iam/pom.xml verify` passed: **78 tests, zero failures, errors or skips**. The 24 new tests
comprise 13 full-server OP tests and 11 real-HTTP RP tests with PostgreSQL/Redis or a controlled JWKS issuer. Previous
retention, lifecycle, MFA, policy and JWT-validation tests still pass.

Implemented session-specific OIDC back-channel logout for opted-in clients: transactional participant registration and
durable enqueue, leased delivery claims, fenced acknowledgements, bounded jittered retries and terminal failure
handling. Signed short-lived logout tokens are generated for each attempt; raw logout tokens are not persisted. The
supplied RPs verify the signed issuer/audience/SID profile, consume replay receipts and delete shared JDBC sessions and
stored OAuth clients in one transaction. SID tombstones and creation floors fence late login callbacks. OP retention
pins dependent session/lifecycle records until delivery retention completes, and cleanup expires overdue delivery rows
even while sending is paused.

Executed tests cover signed payloads, replay and altered-payload rejection, duplicate delivery, receiver/database/JWKS
outages, worker restart, expired leases and stale acknowledgements, concurrent claims and login/logout,
registration/credential-rotation races, retention pins and release, paused-sender deadlines, rollback and unfinished
response bodies. Verification exposed and fixed the framework logout-token expiration sentinel, private
loopback-selector handling, response-body waiting and paused-sender retention defects.

`JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home python3 tests/backchannel_stack_test.py` passed
against final packaged artifacts from `enterprise-iam/`. Five actual processes exercised two-BFF SSO and protected APIs,
an additional BFF node sharing JDBC sessions, automatic delivery and logout invalidation, and preservation of an
independent OP session. Generated test schemas/Redis namespace and spawned processes are cleaned up. No throughput
benchmark, image rebuild, external OP/RP interoperability suite or production rollout was performed for this increment.

See [back-channel logout](backchannel-logout.md) and [ADR 0004](decisions/0004-durable-oidc-backchannel-logout.md).
Drain old writers before V6 and retention activation. Review indexed Redis session migration and require
reauthentication for incompatible state; each RP requires its own JDBC schema. Delivery is asynchronous and finite:
terminal failures require operator recovery. Offline JWT lifetime is unchanged. Front-channel logout, subject-only
receiver logout and automatic idle-expiry family revocation remain outside this increment.

## Previous automated-retention increment

Java 21 `mvn -f enterprise-iam/pom.xml verify` passed: **54 tests, zero failures, errors or skips**. This includes 22
additions: 16 PostgreSQL retention tests, three scheduler tests and three full-server HTTP tests using PostgreSQL/Redis.
Previous lifecycle, MFA, policy and JWT-validation tests also pass.

Implemented scheduled row-bounded cleanup of expired framework grants, known-family and legacy-orphan refresh history,
lifecycle tombstones and unreferenced expired session records. Defaults: 100 candidates per stage, one-minute cadence,
one-day post-expiry history/tombstone retention. A durable creation floor, preserved server birth stamps,
shared/exclusive floor locking and explicit login-time session registration protect against stale writes after deletion.

Executed tests include multiple concurrent cleaners, active replay protection while cleanup runs, cleanup racing
fresh/stale issuance/refresh/revocation, principal/floor lock contention, bounded history progress, grace periods,
orphan cleanup, pending-consent birth fencing, session tombstone deletion with real stale Redis state, scheduler
disable/retry, actual Spring timer execution, V4-to-V5 grant preservation and an injected transaction failure. A test
exposed a stale-session FK error; the service now rejects the missing session before insertion. A real consent flow
confirms that the server overwrites a client-supplied birth stamp and completes the framework exchange.

See [retention policy, proof and rollout](retention.md). V5 requires draining old writers. The worker is enabled by
default; it has no public maintenance API. Distributed logout was not changed in that increment; the current
implementation is described above. No new load benchmark, Docker image rebuild, two-BFF Python rerun or production
rollout was performed in this increment.

## Previous token-lifecycle increment

Java 21 `mvn -f enterprise-iam/pom.xml verify` passed: **32 tests, zero failures, errors or skips**. Docker was
available for PostgreSQL/Redis Testcontainers. All containers and the test HTTP server are isolated and torn down by the
suite.

New evidence included in Maven/CI:

- 9 PostgreSQL lifecycle tests: fixed deadline/clamped refresh expiry, expired family rejection, stale issuance fencing,
  concurrent snapshot single winner, stale-generation revocation, OP-session isolation, logout-before-first-grant
  fencing, suspension/reactivation, idempotent revocation after suspension, and seeded V3-to-V4 migration. Some tests
  cover multiple assertions/scenarios.
- 2 response-envelope tests: successful token bodies publish after commit; an injected commit failure returns 503
  without exposing the buffered token.
- 13 full-server HTTP tests with PostgreSQL/Redis: expiry, local/OIDC logout, logout without an OP cookie, other-session
  preservation, CSRF, pending-code invalidation, invalid logout rejection, concurrent code exchange,
  refresh/revocation/logout races, administrative suspension racing issuance, historical refresh revocation/client
  ownership, revoked Redis-session fencing/fresh login, and machine/human identity separation.

The machine-ID collision test was first observed failing (user revocation incorrectly removed the colliding workload
grant), then passed after workload subjects and persisted principals were consistently namespaced as
`client:<clientId>`. Machine grants never inherit browser-session bindings.

The standalone two-BFF Python suite and Docker image builds listed below were executed in the previous increment; they
were not rerun/rebuilt for this lifecycle change. The new Maven HTTP tests exercise the actual server filter chain
rather than mocked security contexts. No performance claim is derived from test durations.

## Executed evidence

- Previous increment: Java 21 `mvn verify` passed with 8 tests. Current verification is recorded above.
- `UserStateTest`: 2 unit tests for terminal deletion and explicit activation transitions.
- `StateIntegrationTest`: 4 tests against a real Testcontainers PostgreSQL 17 container: encrypted/confirmed TOTP
  enrollment and replay rejection, concurrent OTP single-winner semantics, recovery-code one-time consumption,
  tenant/resource/permission/state isolation.
- `JwtValidationTest`: 2 tests with a real local HTTP JWKS endpoint: overlap/retirement plus issuer, audience,
  expiration, token type and unknown signing-key rejection.
- `python3 tests/protocol_test.py`: 13 real-HTTP tests passed against IAM, resource server and two independent
  web-client processes, PostgreSQL and Redis. Includes actual BFF authorization callbacks, client-side OIDC processing,
  both protected API calls, SSO, code/PKCE/redirect negatives, Client Credentials, refresh replay/concurrency,
  introspection/revocation, public JWKS, and nonadmin rejection.
- Actual Flyway migrations succeeded against PostgreSQL 17.12.
- `docker compose config --quiet` passed.
- `docker compose build iam resource portal-a` passed for all three multi-stage images. A complete container-stack
  startup was not executed; functional HTTP tests used the built Java artifacts with containerized PostgreSQL/Redis.
- A limited exact-value scan found none of the generated development secrets in deliverable source or observed
  application logs. This is not a comprehensive secret scanner or security assessment.
- No load/performance benchmark executed. The 10.852-second HTTP-suite duration is only a test-run duration and is not
  throughput/latency evidence.
- No OWASP ZAP, dependency CVE scan, penetration test, formal OIDC conformance suite, Kubernetes rollout, regional drill
  or full outage campaign executed.

Maven test reports are under each module's `target/surefire-reports/`. The HTTP suite is standalone and must be run
against started local services; `mvn verify` does not silently substitute mocked contexts for those flows. GitHub
Actions runs Maven tests, including the new isolated full-server token lifecycle HTTP tests. It does not run the
separate two-BFF Python suite.

## Implemented boundaries

| Phase                     | Implemented                                                                                                                                                                                                         | Incomplete / release gates                                                                                           |
|---------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| Requirements/architecture | Modular boundaries, sequence diagrams, capacity assumptions, STRIDE, 35 failure scenarios, 50-question review                                                                                                       | Independent security review and fully traced acceptance matrix                                                       |
| AS foundation             | Boot-managed SAS, PostgreSQL framework state, discovery, registered clients, external signing file                                                                                                                  | Production client bootstrap/custody, all endpoint conformance cases                                                  |
| Identity                  | BCrypt, active-state login, explicit user transitions, admin create/list/get/suspend/activate, trusted email binding, verification and password reset with durable SMTP                                             | Public registration, self-service email change, full profile/deletion lifecycle, access review                       |
| OIDC/SSO                  | ID tokens, UserInfo, two-client SSO, RP-initiated logout, durable SID-specific back-channel propagation, shared RP-session invalidation and idle/absolute expiry revocation                                         | Front-channel logout, subject-only receiver logout, external interoperability                                        |
| MFA / passkeys            | Library TOTP, encrypted secrets, durable session proof/lockout, hashed recovery codes; library WebAuthn, reauthenticated enrollment/removal, optional offline/live signed hardware metadata with bounded revocation | Mandatory tenant policy, lost-all-factors recovery, assurance claims and physical-vendor attestation/step-up testing |
| Tokens/keys               | Short JWTs, RS256, aud/type/issuer/scope/time enforcement, fixed family deadline, version/tombstone fencing, logout-linked revocation, historical refresh revocation, commit-before-response                        | Large-scale retention benchmarks, multi-region fencing, automated key/KMS custody                                    |
| Authorization             | Current-state tenant/resource RBAC query, constrained PAP subset, default deny                                                                                                                                      | Policy version history, SoD/limit ABAC, business PEP integration, safe distributed caches                            |
| Machine identity          | Client Credentials, Basic and private_key_jwt, public-key registration/overlap/retirement, durable replay fencing, secret rotation and bounded comparison                                                           | Production asymmetric key custody, mTLS, workload federation and capacity validation                                 |
| Federation/SCIM           | Architecture guidance                                                                                                                                                                                               | No implemented OIDC broker, SAML or SCIM support                                                                     |
| Demos/admin               | Two functional BFF instances, resource API, machine client and admin API subset                                                                                                                                     | Owner session UI is functional; full administration portal/API catalog remain incomplete                             |
| Hardening                 | CSRF browser flows, session ID rotation, cookie defaults, Redis login throttles, selected audit events                                                                                                              | Account-based distributed stuffing defenses, password compromise screening, XSS/CSP review, exhaustive admin audit   |
| Reliability/telemetry     | Timeouts/pools, transaction guards, health and Micrometer/Prometheus, indexed Redis OP sessions, JDBC RP sessions, durable logout outbox and delivery metrics                                                       | General audit outbox, complete domain metrics, Grafana dashboards, OTel tracing, broad outage drills                 |
| Deployment                | Multi-stage image definition, Compose, illustrative Kubernetes/CI                                                                                                                                                   | Production HTTPS/proxy/secret provisioning, full container-stack and Kubernetes acceptance                           |
| Performance               | Client Credentials k6 workload, bounded local token/WebAuthn measurements, CPU sampling and capacity formulas                                                                                                       | Production throughput/SLO goals unverified; representative workloads and deployment pending                          |

## Critical unresolved risks

1. OP logout revokes associated refresh families and pending codes, then asynchronously invalidates opted-in RP sessions
   through durable delivery. Unregistered/unreachable RPs or terminal delivery failures can retain local sessions;
   operators must resolve dead deliveries. JWTs remain valid offline until lifetime/skew expires.
2. Principal locks, snapshot versions and durable tombstones now fence refresh, code exchange, revocation, logout and
   suspension. These guarantees require the authoritative single PostgreSQL writer and application-mediated state
   changes; mixed-version writers and asynchronous active-active regions are unsupported.
3. An absolute default eight-hour family deadline caps refresh generations. Automated cleanup now retains replay/fencing
   state through expiry plus grace and protects deletion with a durable creation floor. Query plans/throughput under
   large production backlogs remain unverified.
4. Revoked OP session keys now fence subsequent browser use and token issuance. Idle/absolute deadline revocation is
   implemented. Owner session APIs and platform revoke-all are implemented. Physical device inventory/UI, direct
   Redis-deletion orchestration and policy-driven MFA/identity-version changes remain incomplete.
5. Scope-protected sample orders are a functional JWT demonstration, not resource-level business authorization.
   Integrate the PDP at every sensitive operation.
6. Administrative machine authority is intentionally separate but is not a complete human-admin workflow with
   phishing-resistant step-up, approval or tamper-aware audit.
7. Framework database state contains tokens; PostgreSQL/Redis/private signing and MFA encryption inputs require strict
   operational custody. Dev Compose lacks authenticated TLS between stores and apps.
8. Mounted JWKs load once; multiple private signing candidates, compromised keys and rolling changes need disciplined
   key operations. Only verifier overlap is tested.
9. Password policy lacks compromise screening. Admin credential creation/reset now enforce Unicode length and BCrypt
   UTF-8 byte bounds. Verification and reset work for trusted email bindings; public signup, self-service email updates,
   lost-MFA recovery and complete account lifecycle remain blockers.
10. Audit coverage lacks consistent actor/context and durable tamper-aware export. Fixed-bound list endpoints and some
    management operations lack optimistic concurrency/idempotency contracts.
11. The local web-client cookie/HTTP setup is for demonstration; production BFF hardening, JDBC custody, schema
    isolation and migration require review.
12. Boot 3.5 compatibility is verified; current vendor support, transitive vulnerabilities and release suitability must
    be reassessed before deployment.
