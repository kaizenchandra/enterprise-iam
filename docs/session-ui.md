# Web-client session controls

Open **Manage login sessions** on the portal home page, or visit `/sessions`. On first use the portal redirects through
OIDC with a separate `iam-management` registration. With an eligible existing OP session this uses SSO; otherwise the OP
can require authentication. Successful connection returns to the session list.

The rendered page lists public session UUIDs, creation/last-OP-activity/deadline timestamps, status and a **Current
session** marker. It provides pagination and POST revoke forms. The current-session button explicitly states that it
also signs the user out. Revoked rows have no action. Last activity is OP activity, not continuous activity at an RP,
and these are login sessions rather than verified physical devices.

## Token and identity boundaries

Both OAuth registrations use the same approved confidential client identity, issuer and S256 PKCE, with distinct
callbacks and scopes:

| BFF registration | Scopes                                         | Access-token audience  |
|------------------|------------------------------------------------|------------------------|
| `iam`            | openid, profile, orders.read                   | enterprise-api         |
| `iam-management` | openid, profile, sessions.read, sessions.write | iam-session-management |

The business token remains usable after management authorization. Management access/refresh tokens reside exclusively in
the existing JDBC HTTP session authorized-client repository, alongside the business authorization. They are never model
attributes, HTML fields, URLs, JavaScript variables or browser storage. HTTP calls to the IAM management API originate
at the BFF with the stored access token. The browser has only its HttpOnly, SameSite cookie and CSRF fields. Cookies
default to Secure; `SESSION_COOKIE_SECURE=false` is an explicit local HTTP-only override used by Compose, README local
commands and the isolated test launcher.

The management OIDC user-service hook requires an already authenticated OIDC principal and matching issuer, subject
**and OP sid**. Switching the OP account or OP session cannot silently replace the BFF identity during management
authorization. The framework still validates state, nonce, signature and code/PKCE. The management callback returns only
to the fixed `/sessions` path; no request-selected redirect is accepted.

Management calls load the authorized client directly from the session repository. They deliberately do not invoke
automatic refresh: concurrent BFF requests must not race refresh-token rotation. A missing or near-expired token
initiates a new OIDC authorization. An ineligible token produces a generic reconnect page and removes only the
management authorization. No upstream response body or credential-bearing exception is rendered or logged by the
controller. The business authorized client is retained.

## Browser actions and failures

GET `/sessions` renders data; GET never revokes. POST `/sessions/{UUID}/revoke` uses Spring's CSRF-protected browser
filter chain. Missing CSRF returns 403. UUID parsing occurs before downstream URL construction; the API destination is
fixed from the configured trusted issuer. The browser cannot supply a management token, owner or tenant selector. IAM
independently enforces ownership/current-grant checks; another owner's UUID returns a generic unavailable-session page
with 404.

After a successful delete, the BFF checks management eligibility. If the current OP session was revoked, the grant
becomes ineligible and the BFF invalidates its own HTTP session immediately, redirecting to the public `/signed-out`
page. Existing back-channel delivery invalidates other RPs/shared BFF nodes. A concurrent callback may invalidate the
local session first; missing bindings and RP SID tombstones continue to fence stale saved session state. Other owners
and independent OP sessions remain unaffected.

Successful reads/actions and signed-out/error pages use no-store. Upstream authentication failures show 409 with a safe
reconnect link; upstream absence is 404; transport/store failures are sanitized 503. The management HTTP client uses a
two-second connect timeout and five-second read timeout without following redirects. An ambiguous mutation response does
not claim success: refresh the list before retrying. Existing API idempotency and retention guarantees apply. Offline
business JWTs retain their own expiry; remote logout is asynchronous and finite.

## Provisioning and deployment

Local bootstrap adds the management scopes and `/login/oauth2/code/iam-management` callback to both approved development
portal clients, preserving their existing credential hash and business registrations. This is limited to the local
profile. Production provisioning must approve those scopes and register both exact HTTPS callbacks; the ordinary
client-creation API still cannot grant management or platform administration scopes. Keep RP database access restricted
and encrypted, use authenticated TLS to IAM, protect cookies, and preserve the OP issuer/key and existing RP migration
requirements. No new schema migration is introduced for the UI. Existing V8 rollout constraints still apply.

## Verification

With Java 21 and Docker, build and run the Maven regression suite:

```sh
mvn -f enterprise-iam/pom.xml verify
cd enterprise-iam
./scripts/init-local.sh
docker compose up -d --wait postgres redis
python3 tests/backchannel_stack_test.py --mode ui
```

The standalone UI scenario runs the packaged IAM, resource server, two portals and a shared-session peer on isolated
ports/schemas. It exercises actual code/PKCE callbacks, rendered forms and current markers, separate business/management
grants, missing-CSRF and GET rejection, other-owner isolation, account-switch rejection, concurrent duplicate
revocation, revoked-grant reconnect, individual/current-session revocation and distributed logout. No mocked identity
establishes those results. It advances management eligibility in the test schema only to exercise reconnect. It cleans
up generated schemas, Redis namespace and spawned application processes. Test request timeouts are not performance
measurements.

The CI workflow runs the UI scenario after Maven verification and local-store initialization, then stops the stores.
This is a server-rendered HTTP/form end-to-end test, not a JavaScript browser automation or visual/accessibility
certification. Production scale, formal penetration testing and human-admin UI remain outside this change.

Executed results: the full Java 21 reactor passed 114 tests (zero failures/errors/skips); the 11 client tests passed
again after final login-routing changes. The final packaged five-process UI scenario passed, including account-switch
rejection and concurrent revocation. Compose configuration validated. No remote CI run, image rebuild or production
rollout was performed for this increment.
