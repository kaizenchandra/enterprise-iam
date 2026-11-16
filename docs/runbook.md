# Operations and incident response

This repository contains development infrastructure and an illustrative Kubernetes deployment, not an approved
production release.

## Keys

Development keys are generated once to an ignored restrictive file. `kid` is random, RS256 is allowlisted, JWKS excludes
private components. The current key source loads a JWK set at startup. For a controlled rotation, build a set with one
active private key and retiring **public-only** keys; restart the IAM replicas consistently, retain retired public keys
beyond maximum token TTL + skew + cache lifetime. The active private key must be the only signing candidate. No dynamic
KMS/HSM custody or automatic rotation is implemented. Verify new-token kid and old-token validation before retiring
keys. Never replace the file in place on a running JVM and assume it reloads.

For compromise: disable issuance, isolate the signing path, revoke affected authorizations/client secrets, replace the
key, remove the compromised public key from trusted distribution and force downstream cache refresh/restart. Offline
validators may trust previously cached compromised keys until coordinated eviction. Communicate that window explicitly.
Key rotation overlap tests remain outstanding.

## Failures

Database failure stops login, issuance and fresh PDP decisions. Redis failure blocks session-backed operations and
throttled login; existing offline JWT validation can continue. No universal fail-open mode exists. Signing-file failure
prevents startup. Federation/MFA network-provider failures are not implemented adapters; no fallback assurance is
claimed. Audit is local SQL for selected operations; there is no audit outbox/Kafka durability pipeline and no
exhaustive security audit coverage.

Protect Redis/PostgreSQL on private networks using authenticated TLS, least-privilege roles and encrypted backups. Redis
stores browser contexts; PostgreSQL owns session deadlines/revocations. For Redis: use noeviction, persistence,
replication and tested restore. Public health probes reveal only status; keep Prometheus behind authenticated internal
access. Never enable HTTP body or SQL parameter logging. Scrub reverse-proxy query logging of authorization codes and
state. Framework error stack traces require a restricted operator sink.

## Deployment and recovery

Use externally issued HTTPS certificates, a fixed issuer and explicitly trusted proxy boundaries. Set Secure cookies,
disable local bootstrap, provide controlled signing material and MFA encryption inputs, and provision clients through an
approved process. The baseline has no production bootstrap workflow.

Use expand/contract schema migrations, one controlled migration job, backups and rollback testing. Avoid destructive
migrations during mixed-version rollouts. Redis uses Java session serialization; restrict Redis writers and treat
incompatible principal classes as a logout/migration event. Never roll untested serialization changes across a fleet.

Alert on token errors, elevated login failures, replay events, database pool saturation, Redis errors, audit backlog and
key expiry. Micrometer/Prometheus supplies JVM/HTTP/pool metrics; dedicated IAM counters, dashboards and tracing are
still incomplete. Audit records currently lack consistent actor/correlation data and tamper-evident export, which is a
deployment blocker.

## Retention operations

Automatic cleanup defaults to one invocation per minute, 100 candidates per stage, and one day of history/tombstone
retention after absolute expiry. See [retention.md](retention.md) for environment overrides, metrics, lock behavior and
V5 rollout. Drain old writers before migration/activation. Do not reset the durable creation floor or run ad hoc
tombstone deletes. On failures, restore the dependency and let the next bounded invocation resume; no manual token
reconstruction is needed. Monitor failures, skips, last-success time and table growth. Tune only using measured database
capacity. Audit events are outside this cleanup policy.

## Back-channel logout delivery

See [backchannel-logout.md](backchannel-logout.md) for allowed origins, retry/deadline limits, RP schema/session setup,
retention pins and V6 rollout. Inspect `logout_deliveries` status/attempts/last_outcome using a restricted operator
role. Investigate DEAD rather than silently resetting budgets. Pause sending with `iam.backchannel.enabled=false`;
overdue records still become terminal through retention cleanup. Do not drop participant/session rows underneath
delivery records or alter creation floors. Rotate approved endpoint registrations under the administrative API, not
request-supplied destinations. Shared RP session databases and indexed OP Redis require consistent code versions and
protected stores.

## Idle and absolute OP expiry

See [session-expiry.md](session-expiry.md). Drain old writers before V7; legacy sessions become due and users must
reauthenticate. Keep the expiry worker enabled and monitor due unrevoked sessions, expiry failures/skips, audit events
and delivery backlog. Pausing `iam.session.expiry-enabled` stops scheduled propagation but does not allow expired
grants; retention keeps unprocessed session/participant state. Restore dependencies and let the next bounded pass
resume. Do not extend expired deadlines or reset fencing state. Refresh/RP API activity is not OP idle renewal.
PostgreSQL driver socket/connect/cancel timeouts supplement transaction/pool limits; review URL overrides. General
device-session management and direct Redis-delete orchestration remain separate work.

## Session management

Use the [session-management APIs](session-management.md) rather than direct Redis or SQL deletion. Self-service is
owner-only; platform revoke-all ends global OP sessions across organizations. Revoke-all permits a fresh login; suspend
the user separately when access must remain disabled. V8 requires draining old writers to enforce the durable login
cutoff. Keep user cutoff, lifecycle/creation floors and normal retention intact. Inspect attributed
`SESSION_SELF_REVOKED` and `USER_SESSIONS_REVOKED` audit events; RP delivery can still require DEAD recovery. Never
broaden management audiences/scopes through ordinary client registration. These APIs expose session metadata, not
verified physical device identity.

## Web session controls

The portals expose `/sessions`; see [session UI provisioning](session-ui.md). Register the second exact callback and
management scopes for approved confidential clients. Keep management and business tokens in separate server-side
authorized-client entries. Secure cookies default on; disable Secure only for explicit local HTTP execution. For
management 409, reconnect controls through OIDC; for 503, restore the dependency and refresh before retrying an
ambiguous mutation. Current-session revocation signs the local user out and enqueues RP logout. The CI UI scenario uses
isolated schemas and does not certify visual accessibility or production capacity.

## MFA assurance upgrade and incidents

See [MFA assurance](mfa-assurance.md). Drain old writers before V9. Enrolled users' legacy sessions/grants are revoked
and remembered RP logout is queued; do not restore assurance from Redis markers. Monitor MFA_FAILED and recovery-use
audit events and logout delivery backlog. Five failed proofs lock new verification for five minutes across logins.
Existing verified sessions still follow their own lifetime; a proof-attempt lock is not account suspension. Do not clear
counters or replace MFA seeds through ad hoc SQL. Enrollment completion shows codes once, ends previous sessions and
requires fresh login. Password/email recovery and passkeys are implemented in later increments; see their rollout
guides. Lost-all-factors recovery remains a release gate.

## Verification and password recovery

See [account-actions.md](account-actions.md). Configure independent account-delivery encryption secrets, fixed HTTPS
origin and approved SMTP sender/credentials before enabling. STARTTLS and server identity verification default on. Bind
legacy addresses through the platform email API; do not mark guessed addresses verified. SMTP DEAD/lease/queue age
require investigation and new user requests rather than replaying consumed tokens. Pause delivery separately from
maintenance; encrypted payloads expire and are wiped. Keep custody keys consistent across replicas and plan outstanding
envelopes before rotation. Never enable HTTP body, SQL parameter or SMTP debug logging. Reset is not MFA recovery or
account reactivation; use authorized state transitions and existing revocation/retention paths. Mailpit and HTTP
overrides are local-only.

## Passkey operations

See [WebAuthn rollout and recovery](passkeys.md). Keep passkeys disabled during additive V11 migration, drain
incompatible writers, validate the real HTTPS RP ID/origins and then enable consistently. Monitor PASSKEY_REAUTH_FAILED
and credential-change events, challenge-table growth and existing logout backlog. Removal is an owner
current-password/MFA operation that revokes sessions. Password reset preserves keys; explicitly remove a suspected
compromised key. Do not restore deleted key records or lower counters/cutoffs through ad hoc SQL. Disabling the feature
preserves data and does not revoke existing bearer tokens. Lost-all-factors recovery and hardware-attestation
enforcement are not supplied.

## Hardware attestation operations

See [hardware trust rollout and incident behavior](hardware-attestation.md). V12 is additive, but drain older writers
before REQUIRED mode. Provision signed offline FIDO2 metadata, explicit signing/manufacturer roots and current CRLs.
Advance the policy revision for custody/configuration changes; never lower it or delete model compromise tombstones.
Metadata serial replay cannot refresh its age. Monitor attestationPolicy health, metadata refresh/revocation counters
and the existing logout backlog. Accepted model/root withdrawal blocks new hardware assertions; the bounded per-user
sweep revokes existing grants and enqueues logout. Offline JWT lifetimes remain unchanged. Keep password/MFA-based
recovery and owned key removal usable while fixing metadata delivery. Physical-vendor/live-public-MDS interoperability
and production fan-out performance remain unverified.
