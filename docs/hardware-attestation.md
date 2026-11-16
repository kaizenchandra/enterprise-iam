# Hardware-attested passkeys

Hardware attestation is **opt-in**. `NONE` remains the default and preserves ordinary passkeys, including synced
credentials. `REQUIRED` uses Yubico `webauthn-server-core` and `webauthn-server-attestation` **2.10.1** for registration
verification and signed metadata verification. It requests DIRECT attestation, configures
`allowUntrustedAttestation(false)`, requires a trusted registration result, UV, a nonzero known FIDO2 AAGUID, a
validated certificate path and a device-bound credential (backup eligibility must be false). Signed model metadata must
declare hardware/TEE/secure-element key protection and must not declare software or remote-handle protection; missing
protection fails closed. This is a trusted-publisher declaration validated with attestation, not an independent hardware
laboratory assessment. This is an authentication mechanism, not an assertion that every hardware implementation is
secure or certified. Password login and existing TOTP policy remain separate; no new ACR/AMR/authorization authority is
issued.

V13 adds an opt-in [live public MDS source](live-mds.md) while preserving this OFFLINE profile. The offline URL/catalog
restrictions below do not describe the LIVE worker.

## Supported metadata profile and trust custody

This release consumes **provisioned signed FIDO2 MDS-format bundles**. It does not download the public FIDO Metadata
Service or arbitrary certificate URLs. The optional Yubico module exposes no per-download timeout hook for its
certificate/CRL retrieval, so this integration selects a deliberately offline profile: reject `x5u` and
duplicate/ambiguous JSON header fields, require inline `x5c` (at most eight certificates), reject AIA/CDP retrieval
extensions in that signing chain, and supply CRLs explicitly. JVM network PKIX discovery (OCSP/AIA) must remain
disabled. A public MDS bundle containing unsupported retrieval URLs or UAF/U2F entries without an AAGUID is rejected; it
must not be silently treated as verified. Deploy an approved enterprise metadata publisher/offline provisioning process
for this profile. No public-MDS interoperability or certification is claimed.

The operator supplies two distinct PEM CA bundles:

* **Metadata signing roots** authenticate the signed metadata publisher. Yubico verifies the JWS signature, signing
  certificate PKIX path and CRL revocation with `verifyDownloadsOnly(false)`. Exact configured legal-header matching,
  current certificates/CRLs, positive serial and unexpired `nextUpdate` are mandatory.
* **Authenticator roots** constrain which manufacturer CA certificates may verify attestation. Roots must appear both in
  validated metadata and in this explicit allowlist. Extra roots never bypass metadata/status checks. Core Yubico
  verification checks the ceremony, attestation format/signature and certificate trust. Standard JCA PKIX rechecks
  stored certificate paths against current allowed metadata roots at authentication. An expired attestation leaf/root
  blocks fresh hardware login even if the credential signature is valid; plan device/credential replacement before
  certificate expiry.

Both bundles require 1..32 CA certificates, at most 256 KiB. CRLs are bounded at 1 MiB; signed BLOBs at 5 MiB / 10,000
entries. Every entry needs a unique nonzero FIDO2 AAGUID and recognized, nonempty status reports. Unknown statuses
reject the bundle. REVOKED, RETIRED, attestation/user-key compromise, user-verification bypass and UPDATE_AVAILABLE deny
the model. This conservative profile does not infer firmware patch level or certificate-specific safety; it denies the
entire affected model. Rogue-list references also deny the model because this offline profile does not fetch/interpret
those lists. Future-dated adverse reports are conservatively denied immediately.

Use read-only local/mounted files with controlled ownership. Replace complete files atomically; never expose private
signing keys to IAM. Public root/metadata/CRL files still require integrity protection. The signed snapshot retained in
PostgreSQL is public metadata, not a private key or bearer credential. Attestation paths may identify a
device/manufacturer: management views show only enrollment-attested/revoked labels, never chains or AAGUIDs. Protect
database access/backups and apply identity deletion/retention policy to credential records.

## Configuration and rollout

```sh
PASSKEYS_ENABLED=true
PASSKEY_ATTESTATION_MODE=REQUIRED
PASSKEY_ATTESTATION_POLICY_REVISION=1
PASSKEY_METADATA_FILE=/run/iam-attestation/metadata.jwt
PASSKEY_METADATA_SIGNING_ROOTS_FILE=/run/iam-attestation/metadata-roots.pem
PASSKEY_AUTHENTICATOR_ROOTS_FILE=/run/iam-attestation/authenticator-roots.pem
PASSKEY_METADATA_CRLS_FILE=/run/iam-attestation/metadata.crl.pem
PASSKEY_METADATA_LEGAL_HEADER='<exact publisher legal header reviewed by the operator>'
PASSKEY_METADATA_MAXIMUM_AGE=PT24H
```

For local Compose, an opt-in [read-only mount override](../docker/compose.attestation.yml) uses files named
`metadata.jwt`, `metadata-roots.pem`, `authenticator-roots.pem` and `metadata.crl.pem` in
`PASSKEY_ATTESTATION_DIRECTORY`. Set the revision/legal-header variables, then run
`docker compose -f compose.yml -f docker/compose.attestation.yml config --quiet` before starting it. The override does
not create a missing source directory or supply trust material. In Kubernetes, mount reviewed files read-only through a
controlled Secret/CSI volume, set the same environment variables, and ensure the application UID can read them; large
metadata bundles exceed native Secret/ConfigMap size limits. No production cluster rollout was performed.

Keep the existing exact HTTPS RP ID/origin configuration. Configure the legal header only after reviewing applicable
publisher terms; the application does not accept terms on an operator's behalf. No development roots or keys are
shipped. Do not enable REQUIRED without validated files and a working delivery process.

Flyway **V12** is additive. Drain V11/older writers before enabling this policy: they do not enforce metadata
locks/revisions. The settings fingerprint changes, invalidating pending older ceremonies; existing credentials/sessions
are retained. Legacy unattested keys remain usable in NONE mode and cannot authenticate in REQUIRED mode. Password plus
existing MFA remains available, including owner credential removal during metadata outages. This policy does not itself
require hardware for every possible login method; that would need a separate assurance/login policy.

Provision files consistently to all nodes, deploy compatible writers with the same monotonically increasing policy
revision, wait for accepted metadata/health, then enable traffic. The scheduled refresh runs after one second and every
60 seconds by default (`iam.passkey.attestation.initial-delay-ms` / `refresh-delay-ms`). A required policy with
unavailable metadata returns 503 rather than accepting an unattested credential. The `attestationPolicy` health
component reports mode, accepted serial or a sanitized unavailable reason. Include it explicitly in a deployment's
readiness health group if hardware authentication is a readiness requirement; default Spring readiness grouping is not
changed here.

Every root, CRL, legal-header, maximum-age or mode change requires a **higher policy revision**. Deploy/configure
revisions as a controlled rollout; nodes with a different revision/configuration fail closed. Republishing a lower
revision or inconsistent configuration at the same revision is rejected, including an older NONE publisher trying to
undo REQUIRED. The accepted mode is durable: a NONE node cannot authenticate/enroll passkeys against an accepted
REQUIRED state. A coordinated switch back to NONE needs valid metadata/configuration and a higher revision; it never
erases compromise tombstones or re-enables revoked credential records. Disabling `PASSKEYS_ENABLED` alone is not
token/session revocation.

## Durable freshness and replay rules

The supported PostgreSQL transaction isolation is the existing READ COMMITTED default; deployment changes to isolation
or unfenced direct writers need a separate concurrency review. This is one shared-issuer policy, not a
tenant-admin-editable trust source.

PostgreSQL stores the verified signed BLOB, digest, metadata serial, policy revision/configuration, accepted mode/time,
deadline and current model eligibility. The deadline is the earliest of `nextUpdate` (UTC start of day), signing
certificate expiry, supplied CRL `nextUpdate`, and acceptance plus configured age (positive, at most 24 hours). Database
time anchors acceptance/freshness; JVM/database skew over 30 seconds fails closed. Each node revalidates a changed
signed snapshot before caching it. Configuration files and authoritative database deadline/revision are checked during
use; an in-memory snapshot cannot hide a newer peer publication.

Metadata serials may increase across missed updates. Lower serials and different BLOBs at the same serial are rejected.
Identical serial/digest replay never moves the acceptance time or deadline; repeatedly rereading a file cannot make
stale metadata fresh. A higher policy revision with the same signed BLOB preserves its previous age/deadline. A new
publisher serial is needed when the accepted deadline expires, including an earlier CRL deadline. Serial/revision
high-water marks and model-compromise tombstones are not deleted by authorization/session retention jobs.

On file/delivery/signature outage, the last accepted snapshot can support hardware authentication only while its
authoritative deadline and current root/CRL configuration remain valid. Missing roots/CRLs, stale state, inconsistent
revision or database outage fails closed. Validation happens outside the publication transaction, without network
requests. Invalid candidates never replace valid state. Loss of a new publication response is safe to retry;
serial/digest/revision checks are idempotent.

## Races, revocation and session guarantees

Registration and assertion transactions acquire the shared metadata advisory lock **before** the existing principal
lock. Publication acquires the exclusive metadata lock, writes the snapshot/eligibility and appends compromise-model
tombstones atomically, and never acquires a principal lock. The verified root/status policy therefore cannot change
halfway through a committing ceremony. Enrollment still checks user version, live MFA-assured source session, challenge
binding and revocation cutoff. Challenges remain short-lived and single-use. Invalid proof consumes its claim;
metadata/store failure rolls back. Assertions recheck credential owner, current path/status, user state/cutoff and final
policy eligibility before registering the primary session.

Accepted compromised models remain denied even if a later signed bundle omits their adverse reports. Root withdrawal or
missing model eligibility also blocks new hardware assertions. A bounded sweep processes at most 100 affected users per
poll with five-second per-user transactions and try-locks for busy principals. It marks affected credential records
revoked, calls the existing `revokeUser`, and writes an audit event atomically. That retains refresh history/tombstones,
advances session/login cutoffs, revokes families/codes and enqueues existing back-channel logout deliveries.
Audit/queue/database failure rolls back and the next poll retries. Two workers cannot duplicate the winning change;
stale session/grant writers remain fenced. Removing the bad root need not permanently blacklist an otherwise healthy
model, but a credential already revoked by policy cannot be revived by restoring roots.

New assertions fail immediately after the winning publication; **existing sessions/families are revoked asynchronously
by the bounded sweep**, subject to poll interval, backlog, busy principals and outages. Back-channel delivery adds its
own bounded retry/retention behavior. Already-issued offline JWTs retain their independent lifetime. Expired/unavailable
metadata blocks fresh hardware authentication; it does not mass-delete every existing session or credential. Use
existing administrative revoke-all for emergency account-level action. To require reauthentication when introducing a
stronger login policy, explicitly revoke the relevant pre-policy sessions; not all sessions can be attributed to one
authenticator in this baseline.

## Operations

Monitor `iam.passkey.metadata.refresh_success`, `refresh_failure`, `revocation_failure` and
`iam.passkey.attestation.users_revoked` counters (Prometheus names are normalized by Micrometer), `attestationPolicy`
health, `PASSKEY_MODEL_REVOKED` audit events, and the existing logout backlog. A successful refresh of an unchanged BLOB
is not evidence that its deadline was extended. Alert on repeated validation failures, approaching metadata/CRL
deadlines and a growing affected-user backlog.

For backlog inspection, use the same eligibility/tombstone predicate as `AttestationPolicy.revokeBatch`; do not log
chains or credential IDs. Publication/worker query timeouts are five seconds; SQL/certificate work is bounded by input
limits. Large model feeds/fan-out and policy-lock contention have not been load-tested. Keep clocks synchronized. Do not
lower revisions/serials, delete model tombstones or restore revoked credential rows through ad hoc SQL. Fix the signed
bundle/root/CRL delivery and publish a valid new serial/revision; password recovery does not reset hardware trust
decisions.

## Verification and limits

Run Java 21, Maven, Docker and OpenSSL:

```sh
mvn -B verify
# Focused real-PKI / metadata / concurrency suite:
mvn -pl iam-server -Dtest=AttestationIntegrationTest verify
# Existing unattested/synced browser behavior (local stores, Node and Chrome required):
python3 tests/passkeys_matrix.py
```

Fixtures generate disposable CA/attestation/credential keys at runtime with OpenSSL/JCA. They create real signed packed
registrations/assertions and signed metadata; the production Yubico libraries verify them. No verifier, hash scheme or
token protocol is implemented in test code. Tests cover trusted/none/untrusted paths, software/unspecified-protection
rejection, unsafe statuses, revoked signing certificates, signature tampering, CRL-bounded expiry, outage/rollback,
metadata/policy equivocation, competing revisions, peer caches, global mode enforcement, simultaneous registration,
authentication/publication races, worker idempotency, MFA preservation and owner removal during metadata failure.
Physical manufacturer devices, live/public MDS, TPM/Android/Apple attestation interoperability, FIPS/hardware
certification, penetration testing and production fan-out/SLOs remain unverified. Algorithm and protocol support in a
dependency does not establish this deployment's interoperability.

Design
references: [Yubico attestation integration](https://developers.yubico.com/java-webauthn-server/webauthn-server-attestation/)
and [core library](https://developers.yubico.com/java-webauthn-server/). The library's metadata service does not itself
revoke previously registered credentials; the application sweep supplies that lifecycle integration.

Final verification: the complete Java 21 build passed **191 tests with zero failures, errors or skips**, including
**33** hardware/metadata cases. The final standalone JAR passed the full existing platform/USB-RSA/synced Chrome
virtual-authenticator matrix in NONE mode. That packaged check found and led to fixing a CBOR dependency scope defect
which was invisible on the test classpath. Base Compose plus the opt-in read-only attestation override and OpenAPI JSON
validated. A limited exact-value scan found no generated development secrets in checked source/test/docs files; this was
not a comprehensive secret scan. No physical device, live public MDS, production rollout, security certification or
hardware-policy capacity benchmark was performed.
