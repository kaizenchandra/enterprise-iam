# Live public FIDO metadata

`PASSKEY_METADATA_SOURCE=LIVE` extends the existing optional hardware policy. OFFLINE remains the default, retaining the
V12 signed-file/CRL behavior and its configuration fingerprint. Live retrieval uses the maintained Yubico 2.10.1
signature/PKIX verifier in a disposable JVM. Login, registration and health requests **never fetch metadata or launch
the worker**; they use a locally verified snapshot plus the authoritative database revision/deadline. A new node with no
verified local copy fails closed until scheduled maintenance warms it.

This is live metadata integration, not physical-device certification. Configured manufacturer roots still intersect
signed metadata roots; nothing automatically approves the entire public catalog. Existing hardware/MFA, model-tombstone,
session-cutoff, refresh-history and durable logout rules continue to apply. A source/URL/origin/deadline configuration
change needs a higher policy revision and compatible writers.

## Bounded transport and process lifecycle

The library's URL-based certificate/CRL download implementation has no per-request timeout hooks. The isolated worker
installs a URL handler only in that child JVM; all retrieval, including library-requested CRLs, uses a controlled JDK
HttpClient. The parent server's URL behavior is unchanged.

* Exact allowed origins; default `https://mds.fidoalliance.org` and `https://crl.globalsign.com`. No redirect following,
  URL credentials or fragments. Public-address checks reject local/private/link-local/multicast destinations. The
  explicit loopback option is test-only. DNS is checked before connection, not pinned through the TLS connector: retain
  trusted DNS and enforce infrastructure egress restrictions against rebinding/network compromise.
* Public signing certificates advertise HTTP CRL URLs. Only a host explicitly approved for HTTPS may have that HTTP URL
  upgraded to HTTPS at the same path. CRL authenticity/revocation is checked by PKIX, not inferred from transport
  success. Unapproved certificate URLs fail; `x5u` and ambiguous duplicate JSON headers remain forbidden.
  Legacy/non-FIDO2 catalog entries are filtered out, never promoted to trusted FIDO2 models.
* Two-second connect bound; four-second CRL and eight-second metadata request/body deadlines; at most twelve requests
  and 32 MiB of completed body data per child. Metadata is capped at 16 MiB, individual CRLs at 4 MiB, signing chains at
  eight certificates. Bounded subscribers cancel oversized responses. No automatic HTTP retries.
* One worker slot per application JVM, no unbounded work queue. A 256 MiB child heap and an overall 20-second deadline
  by default (configurable 1..30) bound a stuck library, DNS lookup or transfer. Timeout/interruption kills the owned
  child and releases the slot. IPC input/output is capped at 40 MiB. Only public metadata, roots and CRLs cross the
  pipe; the child environment is cleared and does not inherit database/client credentials. Errors return bounded codes,
  not payloads or keys.

This is **fault/resource isolation, not an OS security sandbox**. The worker has the application's OS identity and
classpath. Harden the container/filesystem, keep dependencies/JDK updated, reserve child memory and restrict egress; do
not claim protection from arbitrary native/JVM compromise. Public-feed parsing and heap behavior must be tested at
deployment sizing.

The signing leaf must carry the exact expected publisher dNSName in its certificate SAN (default: configured endpoint
hostname, optionally `PASSKEY_MDS_SIGNER_NAME`). A valid certificate under a shared public CA for some other domain is
insufficient. Only loopback tests may use a directly pinned self-signed test publisher without DNS SAN.

The worker verifies the original signed BLOB with `verifyDownloadsOnly(false)`, configured signer roots and PKIX
revocation. Only a successful owned process may construct the application's internal verified-result object. The parent
uses a parsing-only library call on that exact verified result; arbitrary files/database rows never enter this parsing
shortcut. Cache misses in LIVE mode return unavailable until maintenance revalidates the signed database snapshot in a
worker. This avoids both trusting a database flag alone and doing certificate networking in login transactions.

## Durable polling, freshness and races

Flyway V13 adds source, signed-CRL retrieval evidence, its digest and a singleton fetch lease/backoff row. One publisher
per shared database may fetch, using a 40-second lease. Other nodes warm from the retained signed BLOB/CRLs without
external requests. The default external poll interval is one hour; maintenance can still run each minute for cache
warm-up and revocation work. An unchanged, locally valid snapshot needs no repeated worker.

HTTP 429/503 Retry-After is parsed as seconds or HTTP date, with conservative fallback. The persisted delay is at least
one hour and bounded at 31 days; an excessive/unusable retry requirement needs operator attention. The application does
not loop to defeat rate limits. A failed or crashed fetch leaves bounded backoff/lease state; a stale lease cannot
publish. The shared metadata lock, policy revision and serial/digest checks still fence competing writers, and evidence
digests invalidate peer caches when CRLs change while the metadata serial stays the same.

LIVE accepts a configured maximum snapshot age up to 31 days because public MDS serials may remain unchanged across
daily CRL renewal. Choose this explicitly against the publisher's signed cadence; the unchanged default is 24 hours. The
accepted deadline remains bounded by signed `nextUpdate`, signing-certificate validity, current verified CRL deadlines,
and the **original acceptance time plus maximum age**. Source OFFLINE still cannot extend a replayed snapshot's
deadline.

A successful HTTPS metadata retrieval of the same signed BLOB, or an authenticated 304/429 whose ETag matches its
subsequently verified serial, may renew only the CRL-limited portion of the LIVE deadline. It does not move original
acceptance time, bypass signature validation, erase adverse-model tombstones, or pass signed/maximum-age limits. An
outage or unconfirmed cache fallback never extends the previous deadline. Once stale, new hardware authentication fails
closed. Existing sessions/families retain the documented bounded revocation/sweep behavior; offline JWTs retain their
own expiry.

Publisher transitions keep metadata serial high-water marks: an older/different feed cannot reset them by changing URL
or roots. If moving to a source with a lower sequence space, plan a separately reviewed migration/issuer boundary rather
than deleting high-water state.

## Configuration and trust roots

Continue the exact HTTPS RP ID/origins and manufacturer allowlist from [hardware attestation](hardware-attestation.md).
Example opt-in settings:

```sh
PASSKEYS_ENABLED=true
PASSKEY_ATTESTATION_MODE=REQUIRED
PASSKEY_METADATA_SOURCE=LIVE
PASSKEY_ATTESTATION_POLICY_REVISION=2
PASSKEY_MDS_URL=https://mds.fidoalliance.org/
PASSKEY_MDS_SIGNER_NAME=mds.fidoalliance.org
PASSKEY_MDS_ORIGINS=https://mds.fidoalliance.org,https://crl.globalsign.com
PASSKEY_MDS_TIMEOUT_SECONDS=20
PASSKEY_METADATA_SIGNING_ROOTS_FILE=/run/iam-attestation/metadata-roots.pem
PASSKEY_AUTHENTICATOR_ROOTS_FILE=/run/iam-attestation/authenticator-roots.pem
PASSKEY_METADATA_MAXIMUM_AGE=P31D
PASSKEY_METADATA_LEGAL_HEADER='<reviewed exact publisher legal header>'
# Optional initial downloaded candidate; still fully validated by the worker:
PASSKEY_METADATA_FILE=/run/iam-attestation/metadata.jwt
```

Review publisher terms before configuring the legal header. Root and optional seed files require trusted provisioning.
The current Yubico 2.10.1 public-MDS root is GlobalSign R46 with DER SHA-256
`4fa3126d8d3a11d1c4855a4f807cbad6cf919d3a5a88b03bea2c6372d93c40c9`; verify against current official library
documentation before provisioning/rotation. Do not substitute an arbitrary downloaded certificate or turn off PKIX to
make an outage pass. LIVE retrieves signer CRLs; it does not require the OFFLINE CRL file. It does not auto-import
manufacturer certificates from the metadata catalog.

Drain older writers before enabling LIVE. V13 is additive and leaves existing OFFLINE policy fingerprints/behavior
intact. All LIVE nodes need the same roots, mode, revision and retrieval configuration. A source/policy mismatch fails
closed. Keep external-fetch backoff separate from the existing per-user revocation sweep and delivery retries. Monitor
metadata refresh/revocation metrics, `attestationPolicy` health, fetch lease/next-fetch time, evidence deadline and
logout backlog. A valid CRL refresh is not proof of a new metadata serial.

An opt-in [Compose override](../docker/compose.live-mds.yml) mounts reviewed public trust files read-only. Ensure
process memory reserves both server and worker heaps/native memory. The existing Kubernetes template still needs
deployment-specific volumes, egress policy and readiness grouping; no cluster was deployed here.

## Read-only external probe and evidence

After Java 21 `mvn verify`, run the packaged probe from this directory with a reviewed signer root:

```sh
PASSKEY_METADATA_LEGAL_HEADER='<reviewed exact header>' \
java -Xmx512m -Dloader.main=com.example.iam.server.passkey.LiveMdsProbe \
  -cp iam-server/target/iam-server-0.1.0-SNAPSHOT.jar \
  org.springframework.boot.loader.launch.PropertiesLauncher \
  /path/to/metadata-roots.pem benchmarks/results/live-mds-probe.json
```

`PASSKEY_MDS_SEED_FILE` may name a previously downloaded candidate when the endpoint is rate-limited. That candidate is
not trusted until signature/PKIX/CRLs verify. An optional third argument supplies a separately reviewed
manufacturer-root bundle; without it the probe uses signer roots for statistics, so eligible device count will normally
be zero. The probe never publishes database trust, registers a device or grants a token. It is a single operator
diagnostic, not a replacement fleet poller; respect upstream backoff between runs.

The actual public feed retrieved on 2026-11-15 was 11,148,970 bytes, serial 301, with signed nextUpdate 2026-12-01. A
packaged read-only validation passed with three CRLs: 537 entries / 365 FIDO2 models. Java requests observed HTTP 429,
so the successful run validated the earlier downloaded seed with live CRLs (`retrieved=false`); it did not claim a fresh
successful Java BLOB fetch. [Recorded probe](../benchmarks/results/live-mds-probe.json) reports 8,054.453 ms for that
one run and zero approved manufacturer models. This is control-plane verification timing, not authentication latency or
production throughput.

## Verification commands and pending evidence

```sh
mvn -B verify
mvn -pl iam-server -Dtest=LiveMetadataIntegrationTest verify
# With the LIVE environment and reviewed public trust files above:
python3 tests/backchannel_stack_test.py --mode mds
```

The controlled suite uses real signed metadata/CRLs and actual worker processes with local HTTP endpoints: valid proof,
cache warm-up without login networking, outage/expiry, signature corruption, revoked models, redirect/size limits,
deadline and interruption cleanup, private-origin rejection, rate backoff, lease fencing, legacy filtering and CRL
renewal across peers. The optional two-node packaged probe uses isolated schemas and records readiness with 256 MiB
server heaps. To respect upstream backoff while testing large real data, `PASSKEY_MDS_TEST_CATALOGUE_FILE` may serve the
previously downloaded public signed candidate through a loopback-only test mirror; that mode still validates its real
signing identity and CRLs and is labeled as a mirror in the report, not a fresh public BLOB fetch. Controlled fixtures
do not establish vendor device behavior; live evidence does not approve all public models.

See [physical-device runner](physical-passkey-tests.md) for operator-assisted interoperability,
and [performance workloads](../benchmarks/README.md). Physical devices and a representative isolated deployment are
needed before physical-vendor or production-capacity claims. No FIDO certification, penetration-test completion or
production readiness is claimed.

References: [Yubico metadata integration](https://developers.yubico.com/java-webauthn-server/webauthn-server-attestation/)
and [public FIDO metadata endpoint](https://mds.fidoalliance.org/).
