# IAM Console — Next.js frontend

A local, responsive Next.js App Router console for the implemented Enterprise IAM backend. It uses
real backend data; disconnected and unavailable states never display invented directory statistics.
See [the full project walkthrough](../help.md) and [API coverage](../docs/frontend.md).

## Identity frontend and REST APIs

Login, registration, email verification/reset, MFA and passkey screens are implemented in Next.js.
The identity UI runs at **http://iam.localhost:3000** and the console at **http://localhost:3000**.
IAM at port 9000 serves JSON APIs and OAuth/OIDC endpoints, not HTML templates.
Use the local mail override to enable registration, Mailpit and passkeys together:

```sh
docker compose -f docker-compose.yml -f docker-compose.mail.yml --profile mail up -d --build iam mailpit
```

Keep `AUTH_UI_ORIGIN` (IAM) and `IAM_AUTH_UI_ORIGIN` (Next) aligned. For the supplied Compose
setup, Next derives the auth UI automatically from the issuer hostname and console port.
Read the [REST integration contract](../docs/frontend.md#rest-authentication-ui-migration).
Verify with `python3 tests/frontend_rest_workflow_test.py` from the repository root.

## Run

Prerequisites: Node 22+, npm, Java 21, Maven and running Docker Compose PostgreSQL/Redis. The tested
Node runtime was 26.13.1. Run the Java commands from the repository root:

```sh
export JAVA_HOME=$(/usr/libexec/java_home -v 21) # macOS
export PATH="$JAVA_HOME/bin:$PATH"
export DOCKER_HOST="$(docker context inspect --format '{{.Endpoints.docker.Host}}')"
mvn -B verify
./scripts/init-local.sh
set -a
. ./.env
set +a
docker compose up -d postgres redis
./scripts/run-local.sh
```

The local bootstrap provisions `next-console`, using `PORTAL_SECRET`, with exact callback
`http://localhost:3000/api/auth/callback` and back-channel endpoint
`http://localhost:3000/api/auth/backchannel`. Restart IAM with the new JAR to provision it. Bootstrap
inserts this client only if absent; changing `.env` does not rotate persisted credentials. Existing
`IAM_BACKCHANNEL_ALLOWED_ORIGINS` overrides must explicitly include `http://localhost:3000`.

In another root terminal, load `.env` and run the protected sample API:

```sh
java -jar sample-resource-server/target/sample-resource-server-0.1.0-SNAPSHOT.jar
```

In `frontend/`:

```sh
npm ci
cp .env.example .env.local
# Edit CONSOLE_CLIENT_SECRET to match root PORTAL_SECRET; keep the file private.
npm run dev
```

Open **http://localhost:3000** (use localhost consistently, not 127.0.0.1 in the browser).
Open **http://localhost:3000/login**. Choose Administrator workspace or My workspace, then
enter your personal username/password on IAM’s secure form:

| Account                   | Username   | Password in root `.env` |
|---------------------------|------------|-------------------------|
| Local administrator       | `admin`    | `ADMIN_PASSWORD`        |
| Normal demonstration user | `employee` | `DEMO_PASSWORD`         |

Run `./scripts/init-local.sh` and restart the updated IAM service to provision an absent local
administrator. Existing accounts/passwords are never overwritten. The platform administrator
role is independent of tenant roles. Choosing the admin entry point does not grant the role.
Machine `ADMIN_SECRET`/`PORTAL_SECRET` values are never browser login credentials. The old
`/api/auth/connect` browser credential-exchange endpoint returns 410. Tokens remain server-side.

For **My sessions** or **Authorization check**, use their sign-in action. IAM handles the employee
login (username `employee`, private `DEMO_PASSWORD`) and any configured MFA/passkeys. The console
requests separate audience-specific grants for personal sessions and business authorization. **Account & security**
links to the provider's protected MFA, passkey, recovery and verification
flows and can call UserInfo/the sample orders API using your delegated authorization.

For a production-mode local preview:

```sh
npm run build
npm start
```

## Verify

When changing the backend OpenAPI contract, regenerate and check the catalog from the repository root:

```sh
python3 scripts/sync-frontend-contracts.py
python3 scripts/sync-frontend-contracts.py --check
```

```sh
npm test
npm run typecheck
npm run build
```

From the repository root, with stores running and ports 3000/9000/9001 free:

```sh
python3 tests/frontend_stack_test.py
# Optional: hold the tested isolated stack for manual inspection; Enter cleans it up.
python3 tests/frontend_stack_test.py --preview
```

The real-stack test creates a temporary database schema and Redis namespaces, launches actual
Next/IAM/resource processes, tests security gates, user lifecycle/version conflicts, membership,
RBAC, client secret rotation, Code+PKCE, UserInfo, resource access, PDP allow/deny, and signed
back-channel logout. It cleans only its own data/processes. No credential/token values are printed.
Run it after a successful Maven and Next build; it does not rebuild automatically. Do not run it
against occupied ports or concurrently with the manual stack.

## Security and deployment boundaries

Tokens live in Redis; browsers get an opaque HttpOnly SameSite=Lax cookie. Mutation routes enforce
an exact configured Origin. The proxy permits only implemented paths/methods and supported query
parameters. It never forwards arbitrary upstream headers or cookies. Errors do not reflect internal
exceptions or credentials. CSP uses per-document script nonces; no third-party fonts/scripts load.

Use HTTPS and `CONSOLE_COOKIE_SECURE=true` outside loopback. Use a private TLS/authenticated Redis
service, a unique `CONSOLE_REDIS_PREFIX` per deployment, private server environment configuration,
trusted TLS routing, external admission/rate limiting and operational monitoring. No credentials
belong in `NEXT_PUBLIC_*` values. The frontend needs server execution; it is not a static export.

For a different origin or production, provision a confidential Code+PKCE client with exact callback
and approved back-channel URLs, and the documented scopes; do not reuse the local profile. The
current backend admin registration API creates machine clients only, so confidential web-client
provisioning needs an operator-controlled backend deployment step. Container localhost differs from
host localhost; the guide above uses host-run apps. No frontend container/production deployment is
claimed.

Disconnect removes this console's Redis session; it does not end the IAM browser session or revoke
all issued tokens. IAM session revocation/provider logout delivers back-channel invalidation to
this console. Access tokens are not silently refreshed or exposed through a browser token viewer.
Credential issuance/rotation shows its one-time secret only in the current response panel. Copying
it places it on the OS clipboard; store it securely. Logical user deletion is not personal-data
erasure. Audit export, human admin federation/SSO, richer policy engines, production SLO/failover
and all outstanding backend capabilities remain separate release work.

## Connect to an already-running Compose backend

Inspect discovery before configuring the frontend. The Compose deployment advertises
`http://iam.localhost:9000`, while host-run Java normally advertises `http://localhost:9000`.
Do not substitute one issuer for the other when validating JWTs. If Node cannot resolve the Compose
name, use these explicit private server settings:

```dotenv
IAM_ISSUER=http://iam.localhost:9000
IAM_TRANSPORT_ORIGIN=http://127.0.0.1:9000
RESOURCE_ORIGIN=http://127.0.0.1:9001
```

JWT verification still requires the exact configured issuer. The transport override controls
connection/JWKS and provider navigation addresses; it does not rewrite issuer claims or bypass
signature checks. Pinning the resource address to IPv4 avoids inadvertently reaching a separate
host JVM listening only on IPv6 port 9001. Provider-origin-bound passkeys require URLs matching
the configured RP ID/origins; use the original provider origin with working host resolution for
those ceremonies. Container-to-host back-channel logout also needs a reachable, approved endpoint;
the local host-run stack's loopback callback cannot be used unchanged inside an IAM container.

To test login/admin workflows on the running stack without stopping any services:

```sh
python3 tests/frontend_live_test.py # run from the repository root
```

It uses a new disposable identity, logically deletes that identity afterward, and retains the
clearly labeled empty verification organization/audit records. Existing users are not edited.
It verifies HTTP redirects and API integration, not rendered browser interactions or Docker
back-channel delivery.

## Local email verification with Mailpit

Start the local mail integration from the repository root:

```sh
docker compose -f docker-compose.yml -f docker-compose.mail.yml --profile mail up -d --build iam mailpit
```

Open Account & security → Email verification and request a link for an address provisioned by
an administrator. Inspect captured mail at http://localhost:8025. Verification links use
http://iam.localhost:9000 and activate the eligible identity once.
See [account action setup and verification](../docs/account-actions.md#local-console--mailpit-verification).
Run `python3 tests/frontend_mailpit_test.py` from the repository root to verify delivery,
CSRF/replay protections, activation, console login and protected identity access.

Public registration is available at http://localhost:3000/register when the local mail
override is enabled. New users must follow their Mailpit verification link before login.
See [registration requirements and tests](../docs/account-actions.md#public-registration).
