# End-to-end project testing

Run commands from the repository root. This is a development IAM baseline; see
[capability status](docs/status.md) for outstanding requirements and production release gates.
Never use real employee credentials in this local demonstration.

## 1. Check prerequisites

Install Java 21, Maven, Docker with Compose, and Python 3. Browser passkey tests additionally need
Node 24+ and recent Chrome (see [passkey setup](docs/passkeys.md)).

```sh
export JAVA_HOME=$(/usr/libexec/java_home -v 21) # macOS; select your JDK 21 on Linux
export PATH="$JAVA_HOME/bin:$PATH"
java -version
mvn -version
docker info
docker compose version
python3 --version
```

Both Java commands must report 21. Start Docker before continuing. Ports 5432 and 6379 must be
available for the local stores; manual apps use 9000, 9001, 8080 and 8081. Packaged tests use
19000/19001/19003/19004 and 18080–18082. Do not terminate unrelated listeners; change the test
portal range with `export IAM_TEST_PORTAL_BASE_PORT=28080` if needed.

For OrbStack or another Docker context whose socket is not `/var/run/docker.sock`, configure
Testcontainers before Maven:

```sh
export DOCKER_HOST="$(docker context inspect --format '{{.Endpoints.docker.Host}}')"
```

## 2. Build and run automated Java verification

```sh
mvn -B verify
```

Expected: all three reactor modules succeed, zero test failures/errors/skips. Tests create isolated
PostgreSQL/Redis containers and apply migrations. This needs Docker access even before starting
Compose. Reports are under each module's `target/surefire-reports`; packaged JARs are under
`target/`. A failed build is a stop condition: do not test an older JAR and treat it as current.

Focused regression for the lifecycle additions:

```sh
mvn -B -pl iam-server -Dtest=StateIntegrationTest,UserStateTest test
```

These exercise actual PostgreSQL state, stale profile versions, deleted-user terminal state,
durable session invalidation, and transactional rollback on audit failure.

## 3. Initialize private local configuration

```sh
./scripts/init-local.sh
set -a
. ./.env
set +a
docker compose up -d postgres redis
docker compose ps
```

Expected: both stores healthy. The initializer creates absent signing keys/secrets and adds absent
account-delivery inputs. It does not rotate stored client/user passwords. Keep `.env` and `secrets/`
private. Do not print or commit them. Existing database identities retain their original credentials.

## 4. Run the isolated packaged application tests

```sh
python3 tests/backchannel_stack_test.py
python3 tests/backchannel_stack_test.py --mode idle
python3 tests/backchannel_stack_test.py --mode absolute
python3 tests/backchannel_stack_test.py --mode ui
python3 tests/backchannel_stack_test.py --mode client-auth
```

Run sequentially. Each command launches real packaged apps with temporary database schemas,
Redis namespaces and ports, checks its assertions, and cleans up its own resources. Expected:
exit status zero. Default tests distributed logout; idle/absolute exercise expiry; UI exercises
owner session management; client-auth tests asymmetric authentication and a bounded comparison.
These tests do not require the manual app processes in the next step.

For optional account/passkey paths:

```sh
docker compose --profile mail up -d mailpit
python3 tests/backchannel_stack_test.py --mode account
python3 tests/backchannel_stack_test.py --mode passkey
python3 tests/passkeys_matrix.py
```

Expected: account verification/reset single-use and expiry assertions pass; virtual browser
registration/login/removal and the virtual authenticator matrix pass. Mailpit's development inbox
is http://localhost:8025. The isolated tests configure their feature flags; enabling features for
the manual stack requires [account settings](docs/account-actions.md) and
[passkey settings](docs/passkeys.md). Virtual devices do not prove physical interoperability.
Use the [operator-assisted physical procedure](docs/physical-passkey-tests.md) for actual hardware.
Hardware attestation and live metadata require separately provisioned trust inputs: follow
[hardware attestation](docs/hardware-attestation.md) and [live MDS](docs/live-mds.md).

## 5. Start the manual application stack

In each of four terminals select Java 21, go to this directory and load `.env` using step 3.
Leave each process running.

Terminal 1:

```sh
./scripts/run-local.sh
```

Terminal 2:

```sh
java -jar sample-resource-server/target/sample-resource-server-0.1.0-SNAPSHOT.jar
```

Terminal 3:

```sh
CLIENT_SECRET="$PORTAL_SECRET" SESSION_COOKIE_SECURE=false java -jar sample-web-client/target/sample-web-client-0.1.0-SNAPSHOT.jar
```

Terminal 4:

```sh
PORT=8081 CLIENT_ID=portal-b CLIENT_SCHEMA=portal_b SESSION_COOKIE=CLIENT_B CLIENT_SECRET="$PORTAL_SECRET" SESSION_COOKIE_SECURE=false java -jar sample-web-client/target/sample-web-client-0.1.0-SNAPSHOT.jar
```

Wait for each app's startup message. Inspect discovery:

```sh
curl --fail --silent http://localhost:9000/.well-known/openid-configuration
curl --fail --silent http://localhost:9000/oauth2/jwks
```

Expected: issuer `http://localhost:9000`, protocol endpoints, and public signing keys only.
Do not mix Compose issuer `http://iam.localhost:9000` with this host-run stack.

## 6. Test browser SSO, authorization and logout

1. Open http://localhost:8080 and sign in as `employee`, using the private `DEMO_PASSWORD` value.
2. Approve requested consent if shown. Confirm the portal displays the signed-in identity.
3. Follow **Protected orders API** and **My identity**. Confirm authenticated responses.
4. Open http://localhost:8081 in the same browser. IAM should reuse its login session; the portal
   obtains separate tokens. Consent may still be required for the second client.
5. Open **Manage login sessions**. Complete its separate authorization if requested; list sessions.
6. Revoke a session and verify that affected portals require authentication again. Owner scope,
   cross-user denial and CSRF checks are automated by UI/Java tests.
7. Sign in to both portals again, then submit the logout form. After asynchronous back-channel
   delivery both participating portal sessions should be invalidated. Unrelated OP sessions remain
   independent. See [logout timing and guarantees](docs/backchannel-logout.md).

JWT resource servers can accept an already-issued token until expiry; logout does not turn offline
JWT validation into an immediate global revocation check.

## 7. Test machine clients and HTTP protocol regressions

In a terminal with `.env` loaded and manual apps running:

```sh
python3 scripts/machine-client.py
python3 tests/protocol_test.py
```

Expected: machine API call succeeds and protocol assertions pass. The suite uses real HTTP.
For `private_key_jwt` provisioning, key overlap/retirement and replay rejection use
[the client authentication guide](docs/private-key-jwt.md); do not paste private keys into logs.

## 8. Exercise administrative lifecycle APIs

Use a development admin access token with audience `iam-admin` and scope `iam.admin`, obtained by
an authorized client. With the local stack running and `.env` loaded:

```sh
ADMIN_TOKEN=$(curl --fail --silent --user "admin-cli:$ADMIN_SECRET" \
  --data 'grant_type=client_credentials&scope=iam.admin' http://localhost:9000/oauth2/token \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
curl --fail --silent -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:9000/api/v1/admin/users
```

Use this Authorization header for each request below, add `Content-Type: application/json` for
JSON bodies, and use `curl -X PATCH`, `-X POST` or `-X DELETE` as appropriate. Do not enable shell
tracing. Run `unset ADMIN_TOKEN` when finished. [OpenAPI](docs/openapi.json) lists request/response contracts. Ordinary
portal
and machine tokens must be denied admin access. Retain the returned ID and numeric version when
creating/listing a disposable user.

- `PATCH /api/v1/admin/users/{id}` accepts `{"username":"new-name","version":0}`. Use the
  actual current version. Expect 200 with the incremented version; retrying a stale version gives 409.
  Email, credentials and state cannot be changed through this profile request.
- `POST /api/v1/admin/users/{id}/deactivate` returns 204 and changes the state to DISABLED,
  revokes grants/sessions and queues participating RP logout. Activation uses the existing
  `/activate` endpoint; a state transition that is not allowed returns 409.
- `DELETE /api/v1/admin/users/{id}` returns 204 and logically deletes the user with revocation.
  The tombstone is retained for security evidence; activation or profile updates then return 409.
  This is not personal-data erasure. Repeated deletion returns 409.
- Missing users return 404, invalid inputs return 400, duplicate names return 409. Audit persistence
  failure rolls back changes. All these routes inherit the existing admin audience/scope gate.

## 9. Check nonfunctional behavior

```sh
python3 tests/backchannel_stack_test.py --mode capacity
```

Expected: bounded 50-request token workload completes without errors/drops and writes aggregate
latencies to `benchmarks/results/token-local.json`. It does not prove the prompt's throughput or
100 ms token SLO. `--mode client-auth` compares Basic and private_key_jwt under bounded load.
See [benchmark methodology](benchmarks/README.md) for k6, profiling and required production evidence.
The Maven suite covers database concurrency, replay, audit/store failures and scheduling;
[status](docs/status.md) distinguishes measured results from deployment claims.
Do not lower hash strength or bypass authorization to improve a benchmark.

## 10. Stop and troubleshoot

Stop manual Java processes with Ctrl-C, then:

```sh
docker compose stop
```

Volumes remain intact. Avoid `down -v` unless deliberately discarding all local data.
Docker socket errors require a running accessible daemon. Testcontainer startup errors may require
pre-pulling PostgreSQL/Redis images. A compiler error about release 21 means Maven selected the wrong
JDK. Connection refused means the expected app/store is not ready. Login failures after editing
`.env` can mean the database still has older secrets. Redirect or issuer errors often mean host and
container URLs were mixed. Secure-cookie problems on HTTP require the local-only portal flag above.
For detailed operations see [runbook](docs/runbook.md).

## 11. Test organization membership and emergency permission removal

Use the admin token from step 8 and a disposable ACTIVE user (activate a newly created user first).
POST `/api/v1/admin/organizations` with `{"name":"membership-test"}` and retain its returned ID.
POST `/api/v1/organizations/{id}/members` with `{"userId":"USER_UUID"}`: expect 201. GET the same
URL with `?page=0`: expect the membership. Repeating the POST returns 409; a portal token must
receive 403. Negative pages and `page=21474837` return 400 rather than overflowing an offset.

Assign a role using the admin role/permission/assignment APIs and confirm a qualifying PDP request
allows the user (PDP caller needs `enterprise-api` audience and `decision.write`, with that user's
subject). DELETE `/api/v1/organizations/{id}/members/{userId}`: expect 204, then a new PDP request
must deny. Repeat DELETE: expect 404. Re-add membership: prior assignments must stay absent.
A separate organization's memberships must be unaffected. This tests PDP permission freshness;
existing offline JWT acceptance follows the separate token expiry guarantees.

Automated database regressions, including concurrent assignment/removal and audit-failure rollback:

```sh
mvn -B -pl iam-server -Dtest=StateIntegrationTest test
mvn -B -pl iam-server '-Dtest=TokenProtocolIntegrationTest#organizationMembershipApiRequiresAdminAndValidatesPages' test
```

The HTTP regression runs through the full server security chain with isolated PostgreSQL/Redis;
it verifies anonymous/ordinary-token denial, admin operations, duplicates and pagination bounds.

See [authorization model](docs/authorization-model.md) for locking, staleness and rollout boundaries.

## 12. Run and test the Next.js frontend

Follow [frontend setup](frontend/README.md) to install dependencies, configure the private server
environment and start the UI at http://localhost:3000. Rebuild/restart IAM first to provision the
local `next-console` confidential client. Keep `localhost` consistent across browser, issuer and
callback configuration. Connect `admin-cli` with the root private `ADMIN_SECRET` for administration;
use the distinct personal sign-in actions for session management and PDP checks.

With backend/frontend artifacts built, stores running and ports 3000/9000/9001 free:

```sh
cd frontend
npm ci
npm test
npm run typecheck
npm run build
cd ..
python3 tests/frontend_stack_test.py
```

Expected: frontend checks pass and the real-stack test reports PASS for management, Code+PKCE,
protected APIs, PDP and distributed logout. It uses an isolated database schema/Redis namespaces,
then stops only its own app processes and removes only its own test data. Add `--preview` to hold
the verified stack for manual desktop/mobile testing; press Enter to clean up.

In the browser, check sidebar keyboard navigation, a directory's search/pagination, row action
menus, drawer focus/Escape, validation, destructive confirmations and one-time secret display.
Resize to a narrow viewport and verify navigation becomes a menu and tables scroll within their
cards. Test disconnected/error/expired states as well as success paths. See [API coverage and
limitations](docs/frontend.md); unsupported backend capabilities are not simulated.

## Troubleshoot PostgreSQL password authentication failures

If startup reports `flywayInitializer` / `RefreshGuard` / `disableServletRegistration` errors
with SQLSTATE `28P01`, the root error is database password authentication. Spring does not
automatically load the repository's `.env` when launching a JAR or from an IDE. Docker Compose
loads `.env` for its own configuration; that does not export it into the Java process.

Use `./scripts/run-local.sh` from the project root. It loads `.env`, selects the local profile and
aligns Spring's datasource URL/username/password properties with the local DB settings. It also
overrides stale `SPRING_DATASOURCE_*` environment settings. It does not change database credentials
or delete data. For an IDE run configuration, supply the same `DB_*` and other required private
environment values, select the local profile, and remove conflicting `SPRING_DATASOURCE_*` or
command-line datasource overrides. Do not put passwords into program arguments or commit them.

If authentication still fails, verify the configured host/port/database and persisted PostgreSQL
role credentials. Changing `POSTGRES_PASSWORD` in Compose does not change a password in an already
initialized PostgreSQL volume. Do not use `docker compose down -v` as a password fix: it destroys
data. Reconcile credentials through an authorized database administrator if they truly differ.

If fixing credentials reveals **Flyway checksum mismatch**, authentication has succeeded and a
separate migration-history problem needs resolution. Restore the exact migration artifacts used
for that database, or review the historical versus current migrations and database state before an
operator-approved repair. Do not disable validation or rewrite checksums simply to start the app.
The local V1–V14 mismatch was subsequently repaired on 2026-11-17 after schema equivalence
verification and a private full backup. Only migration checksums changed; application-table
contents were fingerprinted under write locks and remained identical. IAM then validated all
14 migrations and started successfully. See the guarded maintenance procedure below.

Launcher regression (does not require Docker or real credentials):

```sh
python3 tests/local_launcher_test.py
```

## Guarded local Flyway checksum reconciliation

Use this only for the local Compose `iam` database with Java 21 and the current packaged IAM JAR.
The script requires exactly successful V1–V14 history and identical source/packaged SQL. It migrates
a temporary reference database, compares its complete public schema with the existing one, and
refuses repair if definitions differ. It never replays historical migrations on the existing DB.

```sh
export JAVA_HOME=$(/usr/libexec/java_home -v 21)
# Read-only verification of existing DB; temporary reference DB is created and removed.
python3 scripts/repair-local-flyway.py
# Explicit repair: private full backup/history, write locks, repair, validation and fingerprints.
python3 scripts/repair-local-flyway.py --apply
./scripts/run-local.sh
```

A successful apply stores a full logical SQL backup, original history and a SHA-256 verification
receipt under a unique `secrets/backups/flyway-*` directory (directory 0700, files 0600; excluded
from Git/Docker context). These backups contain sensitive database data; retain them privately.
Do not automatically restore the complete dump over a running database.

The existing-schema comparison confirms structural equivalence, not the provenance or historical
semantics of unavailable older SQL artifacts. The explicitly requested repair changes only
checksum metadata after these checks; it is not an automatic production migration-repair policy.

Verified local repair: V1–V14 validate, schema is at version 14 with no pending migrations, health
and readiness return UP, and discovery serves issuer `http://localhost:9000`. Regression checks:

```sh
python3 tests/flyway_repair_test.py
python3 tests/local_launcher_test.py
```

## Verify the already-running frontend and Compose IAM deployment

The host frontend can connect to the Compose issuer using the explicit issuer/transport settings
in [frontend setup](frontend/README.md#connect-to-an-already-running-compose-backend). On 2026-11-17,
the console at http://localhost:3000 was verified against the running IAM and IPv4 resource server.
The actual HTTP test passed admin lifecycle/membership, Code+PKCE login/SSO, UserInfo, protected
orders, PDP default-deny, owner sessions and console disconnect. Nine frontend tests and the
optimized build also passed. No running backend/resource services were restarted or stopped.

```sh
python3 tests/frontend_live_test.py
```

The test logically deletes its disposable user and leaves its clearly labeled empty organization
and audit evidence. This check does not establish rendered-browser behavior, passkey-origin
compatibility or back-channel delivery across the host/container boundary.

## Human administrator and normal-user login

Open http://localhost:3000/login. Both workspaces use IAM username/password authentication
through Code+S256 PKCE; no password grant or browser machine credentials are used.

- Administrator: username `admin`, password `ADMIN_PASSWORD` in the root private `.env`.
- Normal user: username `employee`, password `DEMO_PASSWORD` in that file.

`./scripts/init-local.sh` generates the separate admin password if absent. Updated local IAM
bootstrap provisions the administrator only if username `admin` is absent, and never promotes an
existing account or rotates its password. V15 adds `platform_administrators`; ordinary tenant
roles never grant platform access. Admin scope issuance and every human admin API request require
current platform membership/ACTIVE state; API requests also require a live grant. Machine admin
clients remain available for authorized automation, but their grants are rejected by the frontend.

Previous frontend instructions that ask for `admin-cli` / `ADMIN_SECRET` are superseded.

```sh
python3 tests/frontend_human_login_test.py
```

This tests human admin login and user lifecycle, normal user login and protected APIs, privilege
removal when switching identities, and denial when a normal user requests admin scope. Password
entry stays on the IAM origin to preserve MFA/passkeys, CSRF, lockout and recovery protections.
