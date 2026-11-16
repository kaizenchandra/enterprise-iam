# Enterprise IAM — executable engineering baseline

Java 21, Spring Boot 3.5.16, Spring Security 6.5.11 and Spring Authorization Server 1.5.8 (Boot BOM managed). This is a
working development baseline, **not a completed enterprise identity product or production-ready deployment**.
See [capability status](docs/status.md) before use.

For a complete step-by-step test walkthrough, see [help.md](help.md).

## Build and run

Requires Java 21, Maven 3.6.3+, Docker Compose and Python 3. Run commands from this directory.

```sh
export JAVA_HOME=$(/usr/libexec/java_home -v 21) # macOS; otherwise select your JDK 21
mvn -B verify # Includes isolated full-server token-lifecycle HTTP tests; Docker must be available
./scripts/init-local.sh
set -a
. ./.env
set +a
docker compose up -d postgres redis
./scripts/run-local.sh
```

In separate shells load `.env` as above, then run:

```sh
java -jar sample-resource-server/target/sample-resource-server-0.1.0-SNAPSHOT.jar
CLIENT_SECRET="$PORTAL_SECRET" SESSION_COOKIE_SECURE=false java -jar sample-web-client/target/sample-web-client-0.1.0-SNAPSHOT.jar
PORT=8081 CLIENT_ID=portal-b CLIENT_SCHEMA=portal_b SESSION_COOKIE=CLIENT_B CLIENT_SECRET="$PORTAL_SECRET" SESSION_COOKIE_SECURE=false java -jar sample-web-client/target/sample-web-client-0.1.0-SNAPSHOT.jar
```

Visit http://localhost:8080. Username `employee`; password is `DEMO_PASSWORD` in your private `.env`.
Visit http://localhost:8081 in the same browser: IAM reuses its session, each portal receives its own authorization code
and tokens. Follow “Protected orders API” and “My identity”. POST logout through the CSRF-protected form. The OP queues
back-channel delivery to both portals; their JDBC sessions are invalidated asynchronously. Separate OP sessions remain
eligible.

```sh
python3 scripts/machine-client.py
python3 tests/protocol_test.py
python3 tests/backchannel_stack_test.py # Isolated packaged-app distributed logout check
```

Migration V4 invalidates legacy grants: drain old writers before upgrading; users/clients must obtain fresh grants. V5
adds safe automatic retention (enabled by default) and requires floor-aware writers; drain older binaries before
deploying it. V6 adds the logout outbox and retention pins; drain old writers before activating it. Review indexed Redis
session migration and fresh namespace/reauthentication requirements
in [back-channel rollout](docs/backchannel-logout.md). V7 adds durable idle/absolute expiry and conservatively expires
legacy sessions; drain old writers and plan reauthentication.
See [session-expiry policy and rollout](docs/session-expiry.md) and [token lifecycle](docs/token-lifecycle.md).

Ports: IAM 9000, resource 9001, clients 8080/8081, PostgreSQL 5432 and Redis 6379. Stop only these services with
`docker compose stop`. Data remains in named volumes. Local bootstrap only inserts absent identities/clients; changing
`.env` does not rotate stored secrets. Use the management API or a fresh isolated database.

## Container demonstration

After generating `.env` and keys, `docker compose up --build` launches all services. Its issuer is
`http://iam.localhost:9000`; the browser must resolve `iam.localhost` to loopback. Compose provides that name
internally. If your browser/OS does not resolve `.localhost`, add a local hosts entry. Host-side tests must set
`IAM_ISSUER=http://iam.localhost:9000` and have the same name resolution. All HTTP, cookie exceptions and local
credentials are development-only. The initializer records your numeric UID/GID; the local IAM container uses them to
read its restrictive key bind mount. Kubernetes uses a mounted Secret instead. Never make the key world-readable.

## Next.js administration console

The new `/login` flow uses personal username/password authentication at IAM. Local credentials
are `admin` / root `ADMIN_PASSWORD` and `employee` / root `DEMO_PASSWORD`; no browser client
credentials are needed. V15 and updated services must be applied first (live rollout pending
approval). See [current rollout status](docs/status.md).

### Console integration

A responsive frontend is available in [frontend/](frontend/README.md). It integrates implemented
management APIs, delegated owner-session/PDP access, provider security flows and signed logout.
See [coverage and security boundaries](docs/frontend.md).

## Documentation

- [Architecture and boundaries](docs/architecture.md)
- [Protocol and client integration](docs/oauth2-oidc.md)
- [Token consistency and logout](docs/token-lifecycle.md)
- [Automated retention and cleanup](docs/retention.md)
- [Distributed back-channel logout](docs/backchannel-logout.md)
- [Authorization](docs/authorization-model.md)
- [Threat model](docs/threat-model.md)
- [Capacity estimates](docs/capacity-planning.md)
- [Runbook and key operations](docs/runbook.md)
- [Verification evidence and limitations](docs/status.md)
- [Implemented API contract](docs/openapi.json)
- [35 failure scenarios](docs/failure-analysis.md)
- [50-question architecture review](docs/architecture-review.md)
- [Sequence diagrams](docs/authentication-flows.md)

Never expose this local profile to an untrusted network. No scale/SLO, conformance, penetration-test or regulatory
claims are made.

For scheduled expiry and back-channel invalidation across both BFFs and a shared-session peer, run
`python3 tests/backchannel_stack_test.py --mode idle` and `--mode absolute` after building and starting the local
stores. See [session-expiry guarantees and test details](docs/session-expiry.md).

Owner-only session listing/deletion and platform-admin revoke-all are available through
the [session-management APIs](docs/session-management.md). V8 introduces public session UUIDs and a durable login
cutoff; drain old writers before upgrading. Self-service uses dedicated management scopes/audience and never grants
access through tenant membership.

The web portal now provides **Manage login sessions** at `/sessions`, using a separate server-side management
authorization. See [UI security, provisioning and end-to-end verification](docs/session-ui.md). Run
`python3 tests/backchannel_stack_test.py --mode ui` after building and starting the local stores. Secure cookies default
on; local HTTP runs must set `SESSION_COOKIE_SECURE=false`.

Enrolled-user MFA now gates authorization and existing grants through durable session proof. V9 requires draining older
writers and fresh MFA login for previously enrolled users. See [MFA assurance and rollout](docs/mfa-assurance.md).
Enrollment confirmation displays recovery codes once and ends old sessions.

Account verification and password recovery are available from the IAM login page. Enable them only after configuring a
trusted email binding, separate account-delivery encryption inputs and SMTP; they default disabled. Run
`./scripts/init-local.sh` to add development inputs and `docker compose --profile mail up -d mailpit` for the local-only
inbox at http://localhost:8025. See [account-action security, setup and tests](docs/account-actions.md). The packaged
test is `python3 tests/backchannel_stack_test.py --mode account` after building and starting the stores/mail sink.

Passkeys are opt-in using Yubico WebAuthn 2.10.1. Enrollment and removal require current-password reauthentication and
configured MFA, then revoke existing sessions; passkey login preserves the TOTP gate.
See [passkey configuration, guarantees and browser tests](docs/passkeys.md) and additive migration V11. Run
`python3 tests/backchannel_stack_test.py --mode passkey` with Node 24+, recent Chrome and the local stores/mail sink.

For the virtual CTAP/platform, USB/RSA and synced-credential matrix, run `python3 tests/passkeys_matrix.py`. Add
`--benchmark` for a bounded 20-login local report; it does not establish physical-device, hardware-attestation or
production capacity. See [verification boundaries](docs/passkeys.md#default-disabled-and-interoperability-verification).

Hardware attestation is opt-in (`PASSKEY_ATTESTATION_MODE=REQUIRED`) with explicit CA roots and signed FIDO2 metadata.
The default OFFLINE source uses provisioned CRLs/bundles. Additive V12 introduces durable policy/metadata high-water
marks and revoked-model/session coordination. Default NONE preserves ordinary passkeys.
Read [hardware trust, provisioning and rollout](docs/hardware-attestation.md) before enabling; physical-device
certification is not claimed.

Optional [live public MDS](docs/live-mds.md) uses bounded isolated verification, durable fetch leases/backoff and
validated peer caches; OFFLINE stays the default.
An [interactive physical-device runner](docs/physical-passkey-tests.md) records operator-assisted evidence without
virtual devices. Bounded local performance workloads are in [benchmarks](benchmarks/README.md); they do not establish
production capacity.

Machine clients can opt into [private_key_jwt](docs/private-key-jwt.md) with provisioned public RS256 keys, durable
replay protection and versioned overlapping rotation. Existing client-secret authentication and BCrypt cost remain
unchanged. A bounded same-driver comparison is available with
`python3 tests/backchannel_stack_test.py --mode client-auth`; see the guide for prerequisites and limitations.
