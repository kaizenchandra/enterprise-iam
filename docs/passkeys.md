> Passkey screens now live at `http://iam.localhost:3000/passkeys` and call IAM REST APIs through the frontend proxy.
> See [REST UI integration](frontend.md#rest-authentication-ui-migration). Existing RP IDs and credential records are
> preserved.

# Passkeys and WebAuthn

This implementation uses Yubico `webauthn-server-core` **2.10.1** with Java 21 and the existing Boot 3.5.16 dependency
management. [Official library documentation](https://developers.yubico.com/java-webauthn-server/)
and [release notes](https://github.com/Yubico/java-webauthn-server/releases) were checked; the selected dependency was
resolved, compiled and exercised using real Chromium virtual-authenticator ceremonies. Spring Security's native
integration was evaluated; direct library integration allows this application's PostgreSQL challenge ledger, principal
locks and revocation transactions to own lifecycle state. This is not an external conformance or hardware certification.

An optional [hardware attestation policy](hardware-attestation.md) is implemented in V12, with
optional [live metadata](live-mds.md) in V13. NONE and the OFFLINE source remain the defaults; passkeys remain disabled
until explicitly enabled.

## Configuration and local execution

Passkeys default disabled. After `mvn verify`, initialize local inputs and load `.env` as in the README. For a host-side
IAM process, add:

```sh
PASSKEYS_ENABLED=true PASSKEY_RP_ID=localhost \
PASSKEY_ORIGINS=http://localhost:3000,http://localhost:9000 PASSKEY_ALLOW_LOCAL_HTTP=true \
SPRING_PROFILES_ACTIVE=local java -jar iam-server/target/iam-server-0.1.0-SNAPSHOT.jar
```

For Compose set `PASSKEYS_ENABLED=true`; the Compose defaults use RP ID `iam.localhost`, origin
`http://iam.localhost:9000`, and an explicitly enabled local HTTP exception. Visit IAM using that hostname. Credentials
for `localhost` and `iam.localhost` are separate. Production requires HTTPS, Secure cookies, the real RP ID and exact
origins including non-default ports. No wildcard or subdomain matching is enabled. This baseline deliberately requires
origin host equal to RP ID. Changing RP ID loses access to old credentials; changing the origin configuration
invalidates pending ceremonies through a configuration fingerprint. Review DNS, proxy forwarding, browser compatibility
and recovery before enabling.

Sign in using the password and existing MFA, then open **Manage passkeys** on the IAM home page. Enter the current
password, complete enrollment using a discoverable credential with user verification, and sign in again. The login page
offers **Sign in with a passkey**. Removal requires the current password and an eligible MFA-assured session. Enrollment
and removal end all existing sessions, including the current one, and queue logout to linked applications. No passwords,
assertion bodies, raw credential IDs or private keys are shown in management lists or logs. Public random UUIDs identify
owned management entries; the page shows the public management identifier and registration time, not device fingerprints
or attestation identity.

The UI uses native browser JSON conversion APIs (`parseCreationOptionsFromJSON`, `parseRequestOptionsFromJSON`,
`toJSON`); older browsers without those APIs must use password login. At most ten credentials are allowed per identity.
Passkey-only account creation, key naming, attestation-based device trust and self-service lost-all-factors recovery are
not implemented.

## Security and correctness

* Yubico verifies WebAuthn challenge, ceremony type, RP ID hash, exact origin, signature, credential/user-handle
  association, presence and required user verification. ES256/RS256 are offered; attestation is NONE. Private keys stay
  with the authenticator. A UV-capable discoverable credential is mandatory. The anonymous options endpoint does not
  accept a username or disclose credential lists.
* PostgreSQL stores only public COSE material, a random credential-management UUID, a globally unique credential ID,
  counters and backup flags. The WebAuthn user handle is the opaque directory UUID rather than an email/username. Synced
  authenticators may use zero signature counters; counter checks cannot prove absence of cloning. Backup flags do not
  establish device trust.
* Two-minute challenges are bound to the initiating HTTP session through SHA-256, purpose and RP configuration. Options
  and nonces are server-generated. Starting another ceremony supersedes the previous one of the same kind for that
  browser. A locked SQL claim makes validation attempts single-use; wrong-browser requests cannot consume the challenge.
  Invalid crypto/ceremony attempts consume it; store failures roll back the claim. After an HTTP/store failure start a
  new ceremony, since login rotates the browser session identifier before validation. There is no automatic assertion
  replay/retry.
* Principal advisory locks serialize enrollment/removal, assertion counter updates, account changes and grant/session
  issuance. Enrollment stores the user version and originating OP session; completion requires that version, a
  still-assured live session and challenge birth later than the persistent user revocation cutoff. Authentication
  rechecks ACTIVE state, cutoff, key ownership and stored key under the same lock. A removal or reset winner prevents a
  prepared assertion from establishing a new session. An authentication winner remains subject to subsequent revocation.
* Enrollment and removal require current-password reauthentication, plus durable MFA assurance if enrolled. Five failed
  password proofs impose a five-minute durable lock, independent of newly started ceremonies. Success clears that
  counter. Primary passkey login creates a fresh SQL session **without MFA proof**; configured TOTP/recovery-code
  verification remains mandatory before protected browser/OAuth operations. User verification is enforced but is not
  mapped to new ACR/AMR claims or treated as a TOTP bypass.
* Key insertion/deletion, user version increment, revocation cutoff, grant/family revocation, back-channel enqueue and
  audit commit together. PostgreSQL failure returns a sanitized 503 and rolls back. Redis/throttle failure fails closed.
  Browser context is saved only after successful database authentication; a later context-write failure cannot mint a
  bearer token, and orphan SQL sessions expire normally. Later revocation fences stale Redis contexts and token
  persistence through existing guards.
* Account verification/password reset neither enroll nor delete keys, clear MFA, nor reset MFA/passkey-attempt lockouts.
  Reset invalidates older assertions via the existing cutoff. A fresh assertion using a retained valid key can still
  authenticate; suspected key compromise requires explicit key removal. Email proof is not authority to remove MFA or a
  passkey. Recovery of all lost factors remains an operator-governed release gate.
* All modifying endpoints require normal Spring CSRF, including anonymous assertion options/finish. Requests are
  session-bound; session ID rotates on login. Finish bodies are bounded at 64 KiB. Auth endpoints use fixed flow
  throttle buckets plus a shared per-IP ceiling. Browser pages have no-store/no-referrer and restrictive self-only CSP.
  No tokens enter browser storage.

## API contracts

See [OpenAPI](openapi.json). All routes use browser cookies and CSRF, not bearer management tokens. `/passkeys` lists
only the current directory identity's keys; organization membership grants no access to another identity's credentials.
Keys belong to a shared-issuer identity, not an individual organization.

| Route                             | Contract                                                                                                                          |
|-----------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| `GET /passkeys`                   | Authenticated/MFA-assured HTML credential management                                                                              |
| `POST /passkeys/register/options` | Current password form; returns ceremony UUID plus library creation options; 401 reauth, 409 capacity                              |
| `POST /passkeys/register/finish`  | JSON `{id, credential}`; library verification, atomic insertion/revocation; returns fixed login redirect                          |
| `POST /passkeys/login/options`    | Anonymous CSRF-bound discoverable assertion options                                                                               |
| `POST /passkeys/login/finish`     | JSON `{id, credential}`; 200 fresh primary session/home or saved local OAuth authorization redirect, 400 invalid/expired/replayed |
| `POST /passkeys/{id}/remove`      | Owned management UUID and current password form; 302 login after atomic removal/revocation; 404 non-owner, 401 failed proof       |

CSRF failures are 403, oversized finish bodies 413, throttling 429 with Retry-After, disabled feature and store
failures 503. Invalid crypto responses do not return verifier details. Management routes with an expired session return
401 or initiate normal login; missing configured MFA redirects to `/mfa`. Successful passkey login restores only a saved
local `/oauth2/authorize` path/query, so an RP-initiated flow resumes without accepting an arbitrary redirect URL.
Native browser cancellation creates no identity proof. A lost enrollment response may leave a registered credential and
revoked session; sign in and inspect the list rather than replaying completion.

## Persistence, retention and rollout

Flyway **V11** is additive and does not revoke existing keys/sessions. Drain old binaries before enabling passkeys:
every writer must preserve revocation cutoff/version/principal-lock semantics. Keep feature disabled through schema
rollout, configure/validate origins, then enable on compatible writers. All nodes need identical RP configuration. Roll
back by disabling the feature while retaining V11 data; do not roll back schema or restore deleted credentials casually.

Every minute a five-second transaction deletes at most 100 challenges expired more than one day. No worker recreates
them; row locking coordinates cleanup with finish. Cleanup never deletes credentials, refresh history, tombstones,
session cutoffs or logout dependencies. Credential removal uses existing revokeUser/retention guarantees; offline access
JWTs remain valid to their independent expiry, and remote RP invalidation is asynchronous with bounded delivery.
See [retention](retention.md) and [back-channel logout](backchannel-logout.md).

Bounded issuance caps live global challenges at 10,000 and supersedes the browser's previous challenge.
Consumed/unexpired rows remain until expiry plus one day; monitor table growth and throttle load before production. The
global creation advisory lock and password hashing inside a principal transaction are conservative baseline choices, not
a high-throughput claim. Database permissions must exclude untrusted writers; direct SQL key insertion or cutoff
rollback bypasses application guarantees.

## Verification

Run from `enterprise-iam/` with Java 21, Docker, Node 24+ and recent Chrome:

```sh
mvn -B verify
docker compose --profile mail up -d --wait postgres redis mailpit
python3 tests/backchannel_stack_test.py --mode passkey
```

`CHROME_BIN` may override the browser binary. The launcher creates isolated schemas, Redis namespace and Chrome profile;
it stops only its own processes and cleans only its generated data. The real CDP virtual authenticator generates
signatures and keys. Tests submit actual enrollment/login/removal forms, a signed assertion from a foreign port, a
UV-downgraded assertion, replay and simultaneous assertion completion. They check owner isolation, CSRF, failed password
removal, password reset retaining keys and MFA, pre-reset/pre-removal assertions, audit-storage rollback, two-client SSO
and distributed logout including a peer RP node. The Maven SQL tests cover expiry/binding, challenge single use,
required UV/discoverability, durable reauth lockout, two simultaneous removals, MFA removal gating, disabled feature and
audit failure rollback. No physical authenticator/browser matrix, external conformance, penetration test, sustained
passkey load/capacity test or production rollout has been performed.

## Default-disabled and interoperability verification

The default-off contract is tested at the real HTTP boundary using the normal application configuration: no login
button, 503 for CSRF-valid anonymous options/finish and authenticated enrollment/list/removal, no SQL challenge/key
writes, and continued ordinary password/OIDC access. The service test also starts ceremonies while enabled and verifies
that a disabled service cannot complete them or consume pending state. This is a static deployment flag, not a
cluster-wide kill switch: old instances must be drained, and existing sessions/JWTs are not revoked merely by disabling
the feature.

`python3 tests/passkeys_matrix.py` repeats the complete browser security/recovery/logout scenario sequentially with
these **virtual**, automatically user-verified devices:

| Profile  | Transport / CTAP | Credential                           | Coverage                                                           |
|----------|------------------|--------------------------------------|--------------------------------------------------------------------|
| platform | internal / 2.0   | ES256, device-bound                  | Default native UI enrollment                                       |
| usb      | USB / 2.1        | RS256, device-bound                  | Native RSA creation forced by narrowing the offered algorithm list |
| synced   | internal / 2.1   | ES256, backup eligible and backed up | Persisted backup flags, full lifecycle                             |

Runs wait for the public throttle window between stacks; they do not reset shared counters or relax runtime limits. Use
`--profile platform|usb|synced` for a targeted rerun. The verifier still retains its registered ES256/RS256 algorithm
allowlist; the RSA test changes only the browser's selection from those offered algorithms. Every profile must pass
origin/UV and invalid-signature rejection, replay, concurrent completion, owner checks, reset preservation,
removal/audit rollback and distributed logout. CDP creates the virtual devices; no real device is enrolled and no
authenticator private key is exported or constructed by the harness. This matrix does not verify Bluetooth/NFC/hybrid
transport, cloud synchronization, a physical security key, biometrics, device PIN UX, Firefox or Safari.

### Physical-device acceptance record

Physical interoperability requires a person with the device to complete its presence/PIN/biometric prompt. No physical
device has been verified in this workspace. For each intended supported combination, record model/firmware, OS/browser
versions, date, RP ID/origin, credential backup category, test outcomes and reviewer. Use dedicated test identities and
test profiles. Do not record private keys, passwords, codes, raw assertions or credential identifiers in shared
evidence.

Test a UV/resident-capable USB key with PIN, a platform authenticator, and the intended synced phone/desktop passkey
ecosystem. On each, exercise enrollment from the rendered form; RP-initiated OIDC and protected API; configured MFA
gate; cancel/retry; duplicate enrollment behavior; exact-origin rejection; password reset preserving keys;
reauthenticated removal and both RP sessions ending. A nonresident/no-UV device must fail enrollment rather than trigger
weaker server policy. Check unsupported JSON-conversion APIs show the password fallback. Validate HTTPS and actual
supported RP hostnames; localhost/virtual success is insufficient. Mark every untested cell **NOT RUN**, with blocked
reason; do not infer vendor/device certification from a browser or transport simulation.

### Original NONE-mode hardware attestation boundary

The tested creation options request `attestation: none`, ES256/RS256 and required UV/discoverability. The RP does not
configure an attestation trust source, store an attestation trust result or enforce hardware provenance. A valid passkey
therefore cannot authorize a hardware-only policy. Backup flags and UV do not establish a hardware manufacturer or
secure-element claim. This is the verified policy, not a hardware-attestation implementation.

If hardware-only enrollment is required, first specify approved authenticator models/AAGUIDs, trusted manufacturer
roots, metadata signature and freshness policy, revoked/status handling, privacy implications and offline/outage
behavior. The [maintained library](https://developers.yubico.com/java-webauthn-server/) supports an optional attestation
trust source and metadata integration. A future hardware policy must enforce a verified trust result server-side, fail
closed for none/self/untrusted/stale metadata and test real trusted/untrusted/revoked certificates and devices.
Requesting direct attestation alone does not enforce that policy. The
later [V12 hardware policy](hardware-attestation.md) implements maintained-library trust validation and durable
revocation using a provisioned offline profile. Physical-vendor tests remain unverified.

### Local performance smoke measurement

`python3 tests/passkeys_matrix.py --benchmark` also performs 20 fresh, real signed assertions against a new isolated
local stack and writes `benchmarks/results/passkeys-local.json`. It uses one active test identity/credential and one
closed-loop virtual authenticator, retains normal CSRF/throttles/session transactions, and records options HTTP,
simulated native assertion, finish HTTP and combined latency percentiles plus achieved wall-clock ceremony rate.
Login-page navigation between iterations is included in wall-clock throughput but excluded from per-ceremony timing.
Browser/CDP/test-client overhead remains included. No request/credential body or secret is written to the report. With
20 samples, p99 is the maximum observation and is not a reliable production tail estimate.

This does not establish production performance. Before a capacity claim, run in an isolated representative deployment
with TLS, intended network/regions, actual directory/credential/session sizes, supported algorithms, real user-device
latency and MFA paths; distinguish those from pure verification CPU. Record offered/achieved rates, dropped work,
errors, p50/p95/p99, CPU/GC, connection pools, DB/Redis wait and transaction latency, lock contention, cleanup/logout
backlog, and resource-server/PDP work separately. Exercise sustained/soak load, key changes, outages and revocation
races. Respect normal public throttles; do not disable them on shared/production endpoints to manufacture throughput.
Token-API SLOs are not WebAuthn human-ceremony SLOs. The global challenge lock and principal serialization require
measurement before scaling claims.

### Malformed RSA signature regression

The USB/RS256 negative test found that a short RSA signature caused the maintained verifier to wrap JCA
`SignatureException` in an unchecked exception. The original path failed closed but returned 500 and logged verifier
details. The service now handles specifically that wrapped signature-validation exception as a rejected ceremony (400),
commits the single-use challenge claim and creates no session. Other runtime/store exceptions still propagate and roll
back. Browser tests use CDP's documented response-override facility to generate the bad UV/signature inputs; no
signature verifier or cryptographic signing is implemented by this project. The CTAP 2.1 negative UV test requests a
discouraged client-side UV option with a cleared UV response bit while the stored server-side requirement remains
REQUIRED, ensuring the server enforces its own saved policy.

### Recorded local result (2026-11-15)

The latest packaged local measurement passed. [Machine-readable result](../benchmarks/results/passkeys-local.json):
Chrome 157.0.8103.79, Node 26.13.1, macOS ARM64, one 256 MiB IAM heap with local PostgreSQL/Redis, 20 ES256 samples, one
active identity/credential, concurrency one, **zero failures**. Wall time was 7.896 seconds and achieved closed-loop
rate was 2.533 ceremonies/second, including between-sample navigation. An initial measurement attempt stopped before
samples because an unrelated port-forward acquired a demo port; it was left untouched. `IAM_TEST_PORTAL_BASE_PORT=28080`
now selects three separate portal ports (default 18080..18082) for the launcher/browser runner. The retry completed
normally; cleanup now attempts SQL even when Redis cleanup fails and preserves the original test exception.

| Observed client timing         |  p50 ms |  p95 ms | p99 / maximum ms |
|--------------------------------|--------:|--------:|-----------------:|
| Options HTTP/CDP               |  23.775 |  57.679 |          180.616 |
| Simulated native assertion/CDP |  49.123 |  57.965 |           61.309 |
| Finish HTTP/CDP                |  61.461 | 134.343 |          220.428 |
| Combined, excluding navigation | 143.488 | 335.342 |          336.071 |

These values are actual local observations, not server-only latency or a production SLO result. Human interaction,
physical devices, real synchronization, TLS/network, large directories, concurrency, sustained offered load, CPU/GC and
pool/lock pressure were not measured. No inference to the master-prompt capacity targets is warranted.

## Console browser origin

The console sends browser authorization and security navigation to `IAM_ISSUER`, while its server
uses `IAM_TRANSPORT_ORIGIN` for token/JWKS/API requests. For Compose, use browser origin
`http://iam.localhost:9000`, RP ID `iam.localhost`, and server transport `http://127.0.0.1:9000`.
Using the transport alias as a browser URL breaks RP ID validation. Local HTTP is permitted only
under the explicit local exception; production requires HTTPS. Browser ceremonies require a current
WebAuthn implementation with JSON option parsing and serialization support. Cancellation/timeouts
leave password sign-in available. An enrolled TOTP requirement is preserved after passkey login.

The account page links to authenticator settings and passkey management. Enrollment/removal
still require reauthentication, revoke sessions, and preserve the other credential types.
Real device enrollment requires the user's browser/OS interaction; automated library integration
checks do not establish hardware interoperability or certification.
