> The authentication UI now lives in Next.js.
> See [the REST migration contract](frontend.md#rest-authentication-ui-migration) for current endpoints and origins.

# Account verification and password recovery

This workflow supports administratively provisioned identities, trusted email bindings, and opt-in public
registration. It does not automatically link accounts. Email possession is verified separately from account state, MFA
and
organization permissions. Legacy users have no recovery address until a platform administrator binds one; migration
never guesses addresses or marks them verified.

## User and administrator flows

The frontend identity login page links to `/account/verify` and `/account/reset`. React forms call
CSRF-protected JSON APIs through `/api/iam`. Requests return the same generic 200 JSON for unknown, ineligible,
throttled-by-address and
eligible addresses. The request transaction does not query the user directory: it durably queues an encrypted request;
eligibility is checked asynchronously. Global resource exhaustion/store failure returns generic 503 rather than
pretending acceptance.

| Endpoint                                                 | Contract                                                                                                                                  |
|----------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| GET `/account/verify`, `/account/reset`                  | JSON account metadata; the frontend owns forms. Use `/session/bootstrap` for CSRF                                                         |
| POST `/account/verify/request`, `/account/reset/request` | JSON `email` with `X-CSRF-TOKEN`; generic accepted response                                                                               |
| POST `/account/verify`                                   | JSON `token` with `X-CSRF-TOKEN`; proves the bound address; pending user becomes ACTIVE                                                   |
| POST `/account/reset`                                    | JSON `token`, `password`, `confirmation` with `X-CSRF-TOKEN`; atomically changes password and revokes sessions                            |
| POST `/api/v1/admin/users/{id}/email`                    | Dedicated platform `iam-admin` audience/`iam.admin` scope and a live persisted grant; JSON `{ "email": "..." }`; 204 on committed binding |

Admin user creation accepts optional `email` in addition to username/password and creates a PENDING_VERIFICATION user.
The user requests verification through the public form. Trusted email binding supports existing users, revokes their old
sessions/grants, advances the login cutoff, invalidates previous action tokens, and queues verification. If the old
address was verified, a durable security notification goes to that old address. A changed binding must be verified
again. Repeating the same binding is a no-op; use the public request form to resend. A pre-binding public cooldown
cannot suppress a fresh trusted-binding verification job.

Only pending or ACTIVE/unverified users receive verification links; only ACTIVE users with verified addresses receive
reset links. Verification cannot reactivate LOCKED, SUSPENDED, DISABLED or DELETED identities. Administrative activation
remains an explicit platform attestation and does not set `email_verified`; it cannot establish a password-recovery
destination. Email changes are platform-admin operations here, not tenant-admin or self-asserted profile changes.
Same-tenant membership and arbitrary request subjects confer no authority. The shared directory uses unique, lowercase
ASCII email bindings; internationalized/quoted-address policy and self-service email changes remain extensions.

No verification/reset operation creates an authenticated session or issues OAuth tokens. After completion, sign in
normally. Existing cookies for the reset identity remain revoked; GET `/login` clears an inactive cookie and renders a
fresh form without reactivating it. MFA credentials, recovery codes, consumed OTP steps and MFA attempt lockout remain
unchanged. Email recovery is never a bypass for a lost MFA device. Initial password provisioning still requires an
approved administrative channel; do not email plaintext passwords.

## Token and browser security

Actions use 32 random bytes from JDK `SecureRandom`, encoded as unpadded base64url. PostgreSQL stores SHA-256 digests,
subject, purpose, user version, expiry and consumption time. The high-entropy bearer is not a password hash or a new
OAuth grant/token format. It has no stateless validation path. Verification expires one hour after the request; reset
expires 15 minutes after the request. Queue delay never extends validity. Fresh issuance supersedes previous unconsumed
links of the same purpose; successful completion invalidates the user's outstanding action tokens.

Consumption locks the principal and rechecks purpose, expiry, consumption, account state, user version and the user
revocation cutoff under the same transaction. Competing consumption has one winner.
Missing/used/wrong-purpose/expired/unavailable links return generic 400; invalid password input does not consume the
token. Passwords require 14–64 Unicode code points and at most 72 UTF-8 bytes before the existing BCrypt encoder is
invoked. Both new-user creation and reset enforce the byte bound. Password compromise screening remains unfinished.

The email link uses a **fragment**, for example `/account/reset#token=...`, so the bearer is not sent in the HTTP URL or
Referer. A small same-origin script transfers it to the form and removes the fragment with `history.replaceState`; users
without JavaScript can paste the token manually. It is never stored in localStorage/sessionStorage. Forms submit the
token only in a POST body with CSRF. GETs and email prefetches cannot consume it. Responses use no-store, no-referrer
and restrictive CSP; no external analytics/assets receive it. Never enable request-body, SQL-parameter or SMTP
transcript logging. Browser extensions, mailbox compromise and phishing remain risks.

Links come only from the configured public origin, never the request Host header or caller-selected redirect. Production
requires HTTPS. There is no client-supplied email delivery target after verification: the worker resolves the address in
the authoritative directory, and immutable/versioned state binds the action. Shared tenant claims are not evidence of
mailbox ownership.

## Atomic reset and stale-write protection

A successful reset updates the adaptive password hash/version, revokes all target sessions and pending OAuth
codes/refresh families, advances the existing durable login cutoff, queues all newly revoked RP sessions for
back-channel logout, cancels outstanding action deliveries and enqueues a credential-change notification. These writes
and `PASSWORD_RESET` audit commit together. Failed enqueue/audit/database work rolls everything back, including
consumption; the link can be retried within its original lifetime.

Login birth stamps captured before reset cannot register a new session afterward. Request jobs queued before a global
revoke/reset cannot mint a fresh action after that cutoff. Suspension and reset share the principal lock and version
checks: either reset commits first and suspension follows, or reset rejects; recovery never restores a suspended
identity. Existing refresh digest/history and session/lifecycle retention horizons remain intact. Other identities are
unaffected.

Already-issued JWTs at offline resource servers retain their independent expiry/skew. Remote logout remains asynchronous
with bounded retries and operator handling of DEAD deliveries. Database commits cannot be made atomic with browser/SMTP
response receipt. If a successful reset response is lost, the token stays consumed; use normal login or request another
link rather than attempting to reconstruct state.

## Durable request and mail delivery

`account_requests` stores encrypted address envelopes. Requests for unknown addresses use the same durable path and are
completed without mail. Admission has a single-primary transaction lock, a 10,000-pending-request cap and a
per-purpose/address one-minute resend interval, in addition to IP throttles. Trusted binding may bypass the public
cooldown once within its privileged transaction, but still observes the queue cap. Completed/expired request envelopes
are wiped.

A bounded worker prepares at most 20 requests per pass in short database transactions, revalidates current user state
under the principal lock, defers busy owners without moving their original expiry or blocking other queued addresses,
and atomically creates token digest plus encrypted mail. Mail payloads include recipient and body and are encrypted with
Spring Security's authenticated encryption using a separate account-delivery custody key. No raw action token is
persisted unencrypted. SMTP runs outside database transactions through Boot-managed Jakarta Mail.

Delivery claims at most 10 messages per pass with `FOR UPDATE SKIP LOCKED`, fresh lease UUIDs and a 30-second lease.
Attempts are capped at six, with randomized increasing retry bounds (maximum five minutes). Stale/expired
acknowledgements cannot overwrite later claims or canceled rows. SMTP failure/lost acknowledgement can resend the
**same** link; it never mints a second token. Successful and terminal deliveries wipe the encrypted envelope.
Deadline/abandoned-attempt cleanup runs even when preparation or SMTP is disabled. Notifications have a one-day delivery
deadline.

SMTP configuration has 2-second connect and 5-second read/write timeouts, required STARTTLS by default, server-identity
checking and disabled mail debug. These are per-I/O transport bounds, not a measured absolute delivery SLO. SMTP
acceptance does not prove inbox receipt. Permanent and transient transport failures share the finite retry budget; DEAD
messages require investigation/reissue. Encryption/decryption failure fails closed; rotate keys only with a plan for
outstanding envelopes. No hot key ring, exactly-once SMTP or guaranteed delivery during outages is claimed.

## Retention and failure behavior

Cleanup processes at most 100 rows per category in a five-second transaction: expire pending requests/mail, wipe
terminal payloads, then remove completed requests/mail after one day, expired token rows after one day and old resend
limits. Mail FKs pin token rows until delivery retention releases them. The resend cleanup rechecks its outer timestamp
predicate so a concurrent fresh request does not lose its cooldown. Token rows cannot be recreated by stale
consumers/acknowledgements; after deletion an old digest is simply unknown. New tokens use fresh cryptographic
randomness, not recycled identifiers.

A PostgreSQL outage returns sanitized 503 and performs no permissive fallback. A Redis outage that prevents CSRF/session
checks denies completion without consuming the action. Store failure after an already-committed operation can make
response receipt ambiguous; successful SQL state is not rolled back by a later cache/network failure. SMTP outage
preserves encrypted delivery until retry/deadline. The synchronous mail health indicator is disabled so a relay outage
does not remove otherwise healthy authentication nodes; alert on mail queue age, attempts and DEAD status instead.
Restarts recover committed jobs and expired leases. Observe `iam.account.delivery{outcome=success|retry|dead}`,
`iam.account.worker.failures`, `iam.account.prepare.skipped`, request age/count, mail status/deadline and audit events
`EMAIL_VERIFIED`, `PASSWORD_RESET`, `ACCOUNT_EMAIL_BOUND`. Audit tamper-aware export and high-volume backlog/SLO
benchmarks remain release gates.

## Configuration and local execution

Account actions default **disabled**. Enabling requires separate `ACCOUNT_ENCRYPTION_PASSWORD` (at least 32 characters;
use a generated high-entropy secret) and `ACCOUNT_ENCRYPTION_SALT` (32 hex characters). `scripts/init-local.sh` adds
missing development inputs without rotating existing keys. SMTP credentials and these inputs must come from a secret
manager in production. Do not commit them or reuse the MFA encryption key.

| Setting                                    | Default / purpose                                                                 |
|--------------------------------------------|-----------------------------------------------------------------------------------|
| `ACCOUNT_ACTIONS_ENABLED`                  | false; explicit feature enable                                                    |
| `ACCOUNT_DELIVERY_ENABLED`                 | true; pause SMTP while maintaining expiry/cleanup                                 |
| `ACCOUNT_PUBLIC_ORIGIN`                    | https://localhost:9000; fixed browser origin with no path/query/fragment/userinfo |
| `ACCOUNT_ALLOW_HTTP`                       | false; only explicit local development override                                   |
| `ACCOUNT_MAIL_FROM`                        | identity@example.invalid; provision an approved real sender for production        |
| `SMTP_HOST`, `SMTP_PORT`                   | localhost, 2525                                                                   |
| `SMTP_USERNAME`, `SMTP_PASSWORD`           | delivery provider credentials                                                     |
| `SMTP_STARTTLS`                            | true; false only for the local sink                                               |
| `iam.account.delay-ms`, `initial-delay-ms` | 5000; bounded maintenance cadence                                                 |

The application scheduler now has four threads for retention, expiry, logout and account delivery. V10 is additive;
legacy addresses stay null/unverified. Deploy schema/new writers before enabling these endpoints/worker across the
fleet, preserve existing login-cutoff and retention rules, and protect backups/outbox keys. Directory/email version
writes must use the approved principal-locked paths. Production migration duration and SMTP TLS/provider
interoperability have not been benchmarked/certified.

For local development after a Java 21 build:

```sh
./scripts/init-local.sh
docker compose --profile mail up -d postgres redis mailpit
```

Load the ignored `.env` in your shell. Run the IAM jar with
`SPRING_PROFILES_ACTIVE=local ACCOUNT_ACTIONS_ENABLED=true ACCOUNT_ALLOW_HTTP=true ACCOUNT_PUBLIC_ORIGIN=http://localhost:9000 SMTP_STARTTLS=false`.
Mailpit captures mail at http://localhost:8025, with SMTP on localhost:2525. For the containerized IAM, use
`docker compose -f docker-compose.yml -f docker-compose.mail.yml --profile mail up -d --build iam mailpit`; the local
override sets the public origin, internal SMTP endpoint and
local HTTP/TLS overrides. Mailpit is loopback-only and development-only; it does not forward mail externally. Its
pinned [release](https://github.com/axllent/mailpit/releases/tag/v1.33.1) was verified.

## Verification

```sh
mvn -f enterprise-iam/pom.xml verify
cd enterprise-iam
python3 tests/frontend_rest_workflow_test.py
```

The Maven HTTP tests use real PostgreSQL/Redis and actual Jakarta Mail SMTP sockets, including lost acknowledgements,
server disconnects, paused databases/Redis, concurrent consumption/claims, lockout/MFA preservation, suspension and
logout enqueue rollback. The packaged scenario requires the local stores/Mailpit and initialized keys. It runs IAM,
resource server, two BFFs and a shared-session peer; it binds an address, reads captured verification/reset mail, checks
replay/old-password rejection and fresh protected-API access, proves distributed logout and preserves another owner.
Only generated application schemas/Redis namespace and spawned Java processes are removed; local captured test mail
remains available for inspection and refers to discarded test state. This is server-rendered HTTP/form evidence, not
JavaScript browser certification or production readiness.

Design references: [Spring Boot mail configuration](https://docs.spring.io/spring-boot/3.5/reference/io/email.html)
and [OWASP recovery guidance](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html). Public
signup, self-service address change, lost-MFA recovery, breached-password screening, human-admin step-up and production
operational validation remain separate work.

Executed evidence: full Java 21 verification passed **144 tests, zero failures/errors/skips**. The final SMTP-outage
health assertion passed in a subsequent targeted server verification. The final packaged Mailpit account scenario also
passed. These are local protocol/functional results; no production mail delivery, STARTTLS-provider conformance,
load/SLO benchmark or deployment approval is claimed.

## Local console + Mailpit verification

Use the committed local mail override to enable account actions and passkeys together, preserve
SMTP delivery encryption, and keep email links on the public IAM origin:

```sh
docker compose -f docker-compose.yml -f docker-compose.mail.yml --profile mail up -d --build iam mailpit
```

Run `scripts/init-local.sh` first if the account encryption inputs are missing. That helper adds
missing inputs without rotating existing credentials. Mailpit UI is http://localhost:8025;
SMTP is localhost:2525 from host applications and mailpit:1025 from IAM's container. Both published
ports bind to loopback. This override is for local testing, not production email delivery.

From the console, provision a user with an email, then visit Account & security → Email verification.
Request a link for that address, open the captured message in Mailpit, follow its verification link,
and submit Verify email. Tokens use URL fragments, are removed from browser history by the account
script, and are single use. Expired/reused links return an actionable form without echoing the token.
After successful verification, the user can sign in from http://localhost:3000/login.

With the console and IAM running:

```sh
python3 tests/frontend_mailpit_test.py
```

The check provisions and logically deletes a unique test identity, captures real SMTP mail using
[Mailpit's v1 API](https://mailpit.axllent.org/docs/api-v1/), validates link origin and fragment
handling, verifies CSRF and replay rejection, and completes console login and UserInfo. Only the
matching test mailbox is read; other mail is neither read nor deleted. Captured test messages remain
in Mailpit for inspection, with their verification tokens already consumed.

## Public registration

Start at `http://localhost:3000/register` or choose Create an account on the login page.
The console redirects to the identity frontend at `http://iam.localhost:3000`. Its forms send
username, email, password and confirmation through the restricted same-origin proxy to IAM JSON APIs.
The proxy does not store credentials; authentication and credential policy remain in IAM.
Usernames use 3–128 ASCII letters/numbers/dots/underscores/hyphens and must start with a
letter or number. Passwords use the existing 14–64 character / 72 UTF-8 byte policy.

`REGISTRATION_ENABLED=true` and `ACCOUNT_ACTIONS_ENABLED=true` are required. Both remain
opt-in outside the local mail override. `ACCOUNT_CONSOLE_ORIGIN=http://localhost:3000`
sets a configured, validated return destination; user-supplied redirect URLs are not accepted.
The Mailpit override enables these options for local testing.

Registration creates a `PENDING_VERIFICATION` identity with no roles or memberships,
and queues email atomically. Duplicate usernames/emails return the same check-inbox page
without changing existing credentials or re-sending attacker-selected credentials. Use the
existing verification resend or password recovery flow for existing accounts. Concurrent
signups have one identity and one initial verification request. A queue failure rolls back
identity creation. Registration is limited to five POST attempts per minute per source IP
in addition to the existing request limits and CSRF protection. Configure trusted proxy
handling before production use; the application does not trust arbitrary forwarding headers.

Verification links expire after one hour and work once. Valid verification activates the
account and offers a link to the configured console login. Unverified accounts cannot log in.
Existing account state, MFA, credential hashing, token consumption and revocation rules apply.
No registration flow can assign administrator or tenant roles.

```sh
python3 tests/frontend_registration_test.py
```

This live HTTP check uses Mailpit SMTP capture and cleans up its own disposable identity.
It verifies signup through the console entry point, duplicate handling, pre-verification login
denial, activation, replay rejection, OIDC/UserInfo and lack of administrator access.
