# Human login update

The frontend now has `/login` with normal and administrator workspace entry points. Both redirect
to IAM's username/password form through Code+PKCE; no browser client credentials or password grant.
The old operator credential exchange is disabled (410). The backend checks a dedicated human
platform-administrator role at token issuance and every admin request; the UI is not the security
boundary. Different signed-in subjects cannot retain one another's admin or delegated grants.

Local credentials: `admin` / root `ADMIN_PASSWORD`, and `employee` / root `DEMO_PASSWORD`. Run the
initializer and restart updated IAM to provision the absent admin. Existing usernames are never
promoted implicitly. V15 is additive; no old checksums are altered. Removing a platform role blocks
already-issued admin tokens on subsequent requests. Machine admin APIs remain for automation;
frontend sessions reject machine administrator subjects. Prior operator-login descriptions below
are historical and superseded by this section.

# Next.js console integration

The repository now includes a Next.js App Router frontend at [frontend/](../frontend/README.md).
It extends the existing Java demonstrations rather than replacing their tested protocol flows.

## User experience

A persistent sidebar separates administration from personal security tools. The overview shows
current first-page directory counts (clearly bounded to 100) and connection state. Directory tables
support search on the current page, deterministic backend pagination, empty/loading/error states,
record actions and a responsive layout. Forms use explicit labels, constraints, helper text and
field types. Destructive actions require review/confirmation; submissions are not automatically
retried. Drawers trap keyboard focus, restore it on close, and support Escape. Reduced-motion
preferences, visible focus rings, a skip link and semantic tables are supported. Recovery/MFA/
passkey flows use the established provider origin and CSRF/reauthentication protections.

## Implemented API coverage

| Console area         | Backend integration                                                                                                                                                                            |
|----------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Users                | Create/list/detail, optimistic username update, activate/suspend/deactivate/logical delete, trusted email binding, revoke-all sessions                                                         |
| Organizations        | Create/list; membership create/list/remove with assignment removal                                                                                                                             |
| Applications         | Register/list machine clients; Basic/private_key_jwt selection; public JWKS; rotate secret; GET/PUT/DELETE authentication-key policy with expected revision; static back-channel configuration |
| Access policies      | Role creation, permission creation, scoped assignment, assignment revocation, policy listing                                                                                                   |
| My sessions          | Separate owner authorization, cursor-based listing and owner session revocation                                                                                                                |
| Authorization check  | Separate enterprise-audience authorization and current-subject PDP decision                                                                                                                    |
| Account & security   | Provider MFA enrollment/verification/recovery, passkey registration/login/removal, password reset and email verification via provider-owned forms; OIDC UserInfo and protected orders API      |
| Protocol integration | Discovery, Code+S256 PKCE, state/nonce/browser binding, verified ID/access tokens and signed back-channel logout                                                                               |

The checked-in operation catalog is generated from implemented `/api/` paths in OpenAPI. A test
compares it with the backend contract, including methods and audience lane; the server uses it as
an allowlist and the UI uses it for forms. Run `python3 scripts/sync-frontend-contracts.py` from the repository root to
regenerate the catalog
and field metadata; use `--check` to detect stale output. Protocol/browser ceremony endpoints intentionally do not
become arbitrary
proxy operations. No browser token storage or backend CORS relaxation is required.

No invented controls are provided for unimplemented PATCH client/policy APIs, arbitrary web-client
registration, SCIM, federation, audit-event listing, metrics history or richer ABAC. The policy
listing contains role/permission rows, not a history of versioned policy documents. Assignment IDs
must come from creation responses because no assignment-list endpoint exists. Roles/permissions
have no dedicated list APIs beyond the policy listing. Protected resources currently require
operator provisioning; the console cannot create them through an absent API.

## Trust boundary and lifecycle

The Next server exchanges operator credentials for an `iam.admin` grant and retains only the token,
subject/client identity and expiration. Redis stores separate `admin`, `app` and `management`
grants behind a random 256-bit browser handle. Redis keys hash handles; no bearer tokens appear in
cookies, URLs, localStorage, sessionStorage, HTML or the status API. The server checks authorization
lane and expiry before proxying. The backend still enforces every scope/audience and domain rule.
Token expiration is explicit; there is no automatic refresh/rotation retry race.

OAuth transactions are five-minute single-use Redis records bound to a separate HttpOnly state
cookie and the console session. Callback verification checks signature, issuer, audience, expiry,
nonce, subject and OP session ID. Different personal subjects cannot occupy the two delegated
lanes concurrently. A successful operator connection rotates the handle and discards prior grants.

Back-channel logout verifies the OP's RS256 JWT, audience, issuer, type, event, freshness and required
claims, then invalidates indexed console sessions. Ended-session tombstones and a second publication
check prevent a racing callback from restoring an already-ended session. Repeated deliveries are
idempotent; Redis failure produces a retryable response. No positive authorization cache exists.
The Java delivery client explicitly uses HTTP/1.1: the Node 26 local Next server rejects Java's
cleartext HTTP/2 upgrade with a closed connection. TLS verification and redirect/timeout policy
remain unchanged.

All mutations require an exact configured Origin, including credential exchange, disconnect and
OAuth initiation. Back-channel delivery is an authenticated server-to-server exception. Proxy
paths/methods and query keys are allowlisted; request bodies are bounded to 64 KiB even without a
Content-Length header. No open URL-fetch facility exists. Upstream errors are reduced to safe
messages. Per-document nonce CSP, frame denial, no-referrer, no-store and nosniff headers are used.
The server never persists operator client secrets; trusted client configuration remains server-only.

## Limits and operations

Redis is a sensitive token store: isolate it, restrict access, use TLS/authentication and deploy unique
namespaces. Sessions have a 30-minute bounded Redis lifetime and each grant its shorter JWT expiry.
Logout index keys expire after one hour; pending callback transactions expire after five minutes.
Disconnected console sessions do not revoke the underlying issued tokens. Existing offline JWT
lifetime and asynchronous logout delivery limits remain the backend's documented guarantees.

The global operator exchange limiter permits 20 attempts/minute per configured namespace. This is
bounded development admission, not a distributed anti-abuse or human-account lockout program.
External per-operator/network admission and production measurements are still required. A shared
Redis outage fails protected operations closed. Standalone Redis is not a production HA claim.
Normal deployments must use trusted HTTPS origins and secure host-only cookies. The permissive
HTTP/localhost settings belong to development only. UI automation, unit and local real-stack results
do not constitute an accessibility certification, penetration test or production readiness claim.

See [run instructions and exact checks](../frontend/README.md) and [capability status](status.md).

## Session lifecycle integration

`/api/auth/status` checks each unexpired grant against IAM's authenticated introspection
endpoint. MFA/passkey changes and administrative revocation therefore remove the console's
connected state before token expiry, even if a logout delivery has not arrived. IAM outages
produce an unavailable state and disable protected controls; they do not delete otherwise-valid
grants. Protected API 401 responses remove only the rejected lane. Compare-and-delete prevents
an old response from removing a newly connected grant. Status requests also refresh on window
focus and visibility changes, with generation checks to discard obsolete responses.

Visit the configured `CONSOLE_ORIGIN` consistently. The console's home and login pages redirect
loopback aliases to that origin before displaying forms; mutation requests still require the
exact configured Origin. The public IAM issuer is used for browser navigation and its server
transport alias is used only for backchannel HTTP requests.

With the local stack and frontend running, execute:

```sh
python3 tests/frontend_human_login_test.py
python3 tests/frontend_mfa_workflow_test.py
```

The second check creates and logically deletes a disposable user and exercises console login,
MFA enrollment/confirmation, recovery login, code renewal, replay rejection, removal,
password-only login afterward, and immediate console invalidation after admin revocation.
These are live HTTP integration checks, not browser rendering or physical-device tests.

Direct sign-in on IAM uses the configured `ACCOUNT_CONSOLE_ORIGIN` when no saved request exists.
The frontend `/auth/continue` page automatically submits the same-origin, CSRF-protected OIDC
start form (with a manual fallback button). IAM SSO then completes the callback and creates a
real console grant. Assigned platform administrators land on Overview; other users land on
their personal workspace. Password, MFA and passkey login share this default destination;
saved OIDC authorization requests retain their original continuation.

Verify with `python3 tests/frontend_direct_login_test.py` against the running local mail stack.

## REST authentication UI migration

IAM no longer renders HTML views. Thymeleaf, JVM templates and provider-side UI JavaScript
are removed. Spring Boot REST controllers return JSON for registration, verification, reset,
MFA and passkey operations. OAuth/OIDC protocol endpoints keep their required browser redirects.
`GET /login` is a navigation redirect to the frontend sign-in screen, not a backend view.
The legacy Spring Security `POST /login` form-processing endpoint remains only for existing
protocol clients; new frontend code uses the JSON session-login endpoint.

Local origins are:

- Console: `http://localhost:3000`
- Identity frontend: `http://iam.localhost:3000`
- IAM protocol/API issuer: `http://iam.localhost:9000`
- Server transport: `http://127.0.0.1:9000`

The frontend identity hostname must match the issuer hostname/RP ID. This keeps existing
`iam.localhost` passkeys usable. The local mail override permits both frontend and legacy
provider origins; it generates new email links pointing to the frontend port. Production needs
HTTPS and corresponding trusted DNS/routing. Configure `AUTH_UI_ORIGIN` in IAM and
`IAM_AUTH_UI_ORIGIN` in Next consistently. Next defaults the identity UI to the issuer hostname
with the console port.

The frontend's `/api/iam/*` proxy accepts only explicitly supported identity operations, only
on the configured identity-UI host. Mutations require that exact Origin, JSON bodies and a
backend-issued CSRF header. It forwards only the `IAM_SESSION` cookie and CSRF token; it never
forwards console cookies or arbitrary bearer credentials. The IAM cookie remains HttpOnly.
Cookies are shared across ports on the same identity hostname, so OAuth navigation and REST
calls use the same Spring Session. No permissive CORS or browser token storage is used.

### JSON endpoints

| Endpoint                                                  | Method | Purpose                                              |
|-----------------------------------------------------------|--------|------------------------------------------------------|
| `/session/bootstrap`                                      | GET    | CSRF token and feature capabilities                  |
| `/session/login`                                          | POST   | Username/password login and trusted continuation URL |
| `/session/logout`                                         | POST   | Revoke current IAM session                           |
| `/account/register`                                       | POST   | Create pending identity and queue verification       |
| `/account/verify/request`, `/account/reset/request`       | POST   | Queue a generic email request                        |
| `/account/verify`, `/account/reset`                       | POST   | Consume one-use token                                |
| `/mfa/settings`                                           | GET    | Authenticator policy/state                           |
| `/mfa/enroll`, `/mfa/verify`, `/mfa/recover`              | POST   | TOTP setup/proof/recovery                            |
| `/mfa/recovery-codes`, `/mfa/remove`                      | POST   | Reauthenticate and update MFA                        |
| `/passkeys`                                               | GET    | List credentials and attestation policy              |
| `/passkeys/register/options`, `/passkeys/register/finish` | POST   | WebAuthn registration                                |
| `/passkeys/login/options`, `/passkeys/login/finish`       | POST   | WebAuthn authentication                              |
| `/passkeys/{id}/remove`                                   | POST   | Owner-scoped removal with reauthentication           |

JSON requests use the existing field names (username, email, password, confirmation, token,
code, recovery). Proof and enrollment endpoints preserve durable locks, expiry, replay rejection,
revocation and audit behavior. Recovery codes are returned once in a no-store JSON response
and held only in component memory until the user leaves. Error responses contain sanitized
Problem Details. API login rotates the session ID and CSRF token before saving the authenticated
security context, and no access token is exposed to frontend authentication components.

Run `python3 tests/frontend_rest_workflow_test.py` with the local Mailpit stack and rebuilt Next
frontend. The older focused frontend test commands delegate to this migrated REST workflow.
This validates live HTTP integration; real device enrollment still requires a supported browser
and authenticator.
