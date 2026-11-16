# Durable MFA enforcement

Enrolled users must prove their second factor before OAuth authorization. Previously the browser assurance filter ran
after Spring's authorization endpoint handlers. Redis's `mfa_subject` marker also could not safely bind proof to
persisted grants. This increment moves the gate after CSRF/session activity but before authorization handlers and
records successful proof in the authoritative OP session.

## Boundaries and flows

Password login registers an OP session with no MFA proof. For an enabled authenticator, GET authorization redirects to
`/mfa` before code or consent persistence. Successful OTP/recovery verification rotates the HTTP session ID and uses
Spring's saved-request handler to resume the original authorization request, preserving state, nonce and PKCE challenge.
Existing login request restoration also uses the framework handler. Redis assurance markers never authorize a grant.

`identity_sessions.mfa_verified_at` and `mfa_method` record the proof against the durable OP session. All human grant
saves, including code exchange and refresh, and grant lookups require that proof whenever the user's MFA credential is
enabled. This is defense against in-flight issuance and stale Redis state, not only a browser redirect. Workload grants
remain separate; a browser cookie cannot impose human MFA requirements on a machine's own protocol authentication.
Logout remains CSRF/framework validated and idempotent even with a revoked session. Expiry and revocation always
override proof.

The session-bound workflow acquires the same principal transaction lock as issuance, logout, suspension and retention.
It checks ACTIVE user and eligible session before consuming an OTP/recovery code. Successful proof, one-time consumption
and audit commit together. Concurrent OTP use has one winner. OTP verification and its replay step use the same captured
clock instant through the established library's timestamp overload; crossing a time-step boundary cannot cause the
library and replay guard to use different instants.

No `acr`/`amr` or phishing-resistant assurance claim is issued by this change. Proof is valid only through its OP
session lifetime. Tenant-required enrollment and per-operation freshness/step-up remain separate policies.

## Enrollment and recovery codes

`POST /mfa/enroll` requires an active session, CSRF and current password reauthentication. The pending secret is
encrypted at rest and returned only in the authorized no-store response. An enabled credential cannot be silently
replaced by this endpoint. POST `/mfa/verify` confirms the pending authenticator.

Confirmation atomically enables the credential, creates hashed one-time recovery codes, revokes all previous user
sessions/grants, advances the login cutoff, enqueues RP logout and writes audit. The confirmation response displays
recovery codes once with no-store; the current browser session ends and a fresh password-plus-MFA login is required.
Failed delivery enqueue/audit/persistence rolls activation and token changes back together. The former Redis-backed GET
`/mfa/recovery-codes` retrieval route is removed. Codes are not persisted in Redis or plaintext database rows.

POST `/mfa/recover` consumes a hashed recovery code and records method `recovery` on the eligible current session. It
requires enabled MFA and never disables the authenticator. Reuse fails, including from another fresh login. Recovery
codes are a lower-assurance fallback and not phishing-resistant. Losing both authenticator and recovery codes has no
self-service/helpdesk reset workflow yet; do not bypass this by editing credentials directly.

The existing bounded OTP window remains one time step. Primary DB lockout deadlines use database time; OTP calculation
uses the application clock, so hosts still require synchronized time. Pending-enrollment expiry, removal/reset with
reauthentication and recovery-code reissue workflows are not implemented here. A lost confirmation response can lose the
one-time code display; the authenticator remains usable for a fresh login.

## Attempts, errors and telemetry

Five invalid verifications cause a durable five-minute per-user lock. New password logins cannot reset it. Expired lock
state resets the failure series, and successful verification clears it. Attempts are serialized under the principal
lock. Existing IP throttling and per-browser attempt limits remain complementary; this is not a complete
credential-stuffing or edge-abuse system. Invalid/locked proofs fail generically; transaction/store failure returns
sanitized 503 and no-store without claiming success.

Audit event types are `MFA_ENROLLED`, `MFA_VERIFIED`, `MFA_RECOVERY_USED`, `MFA_FAILED` and migration
`MFA_ASSURANCE_UPGRADE`. They contain user/actor identifiers, not OTPs, seeds or codes. Protect HTTP/SQL logs and
responses; do not enable body tracing for MFA routes. Durable tamper-aware audit export remains incomplete.

## V9 rollout

Drain old writers. Their late filters and Redis-only proof are incompatible with this guarantee. V9 adds session
assurance and user lockout state, and conservatively revokes existing sessions/grants for enrolled users, advances their
login cutoff and enqueues remembered RP logout transactionally. Refresh history, lifecycle tombstones and RP/outbox
dependencies survive. Users without enrolled MFA are unaffected by this migration; enrolled users must sign in and prove
MFA anew. Configure approved outbound origins/registered RP endpoints before activating delivery and preserve
signing-key overlap to verify queued logout tokens, and use the existing retention/creation-floor rules. Never backfill
durable proof from Redis markers. Production-scale migration runtime is unmeasured.

## Verification and remaining work

Run `mvn -f enterprise-iam/pom.xml verify` with Java 21 and Docker. Real HTTP tests cover direct authorization bypass,
forged Redis markers, successful code/refresh after proof, recovery replay across sessions, lockout surviving fresh
login, concurrent OTP consumption, stale proof persistence, enrollment revocation/outbox delivery, injected enqueue
rollback and saved PKCE request continuation. PostgreSQL tests cover a fixed OTP timestamp and V8-to-V9 enrolled-session
migration with preserved history/outbox.

[Account verification/password reset](account-actions.md) and [passkeys](passkeys.md) are implemented in later
increments. Public registration, mandatory tenant MFA and per-operation step-up remain unimplemented. These are still
release gates. Existing JWTs at offline resource servers keep their independent lifetime; this change does not provide
immediate global JWT invalidation or production readiness.

Concurrent MFA verification and local logout are also exercised through HTTP. A logout winner cannot be revived by
verification; session-ID rotation/invalidation tolerates the session already having ended. The packaged session UI
scenario is rerun as an existing-flow regression, not as a passkey/step-up claim.

Executed evidence: final Java 21 Maven verification passed **124 tests, zero failures/errors/skips**. The packaged
session UI regression passed after the protocol changes; subsequent controller-only logout handling was verified through
targeted and full Maven tests. No penetration test, load benchmark, production migration or regulatory assessment was
performed.
