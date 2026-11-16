# Reproducible benchmark entry point

Run `MACHINE_SECRET=... RATE=100 k6 run benchmarks/token.js` against an isolated deployment. Increase RATE to 1000,
10000, 100000 only with an approved capacity environment. The script enforces a bounded VU pool and five-second timeout.
Record offered rate, achieved throughput, dropped iterations, errors, latency distribution, CPU/heap/GC, signature time,
PostgreSQL pool/wait/commit latency and Redis latency. Never print token bodies.

No production-capacity benchmark has been executed. A functional test duration is not a benchmark. Login, local JWT
validation, remote introspection and PDP decision workloads need separate scripts and fixtures; do not extrapolate one
from another. The supplied k6 script is only the Client Credentials workload. Bounded local measurements are recorded
below.

A bounded WebAuthn local measurement is available with `python3 tests/passkeys_matrix.py --benchmark` after building and
starting the local stores/mail sink. It writes `results/passkeys-local.json` using real browser-generated signatures and
one virtual authenticator. It is 20 closed-loop samples with CDP/HTTP overhead, not a saturation, physical-device or
production-capacity test. See [method and limitations](../docs/passkeys.md#local-performance-smoke-measurement).

Latest actual virtual measurement: 20/20 successful ES256 logins, client/CDP combined p50/p95/p99
143.488/335.342/336.071 ms, achieved closed-loop rate 2.533 ceremonies/second. The token target is not a user-device
ceremony target. Set `IAM_TEST_PORTAL_BASE_PORT=28080` for alternate local portal ports when the default range is
occupied; no unrelated listener is terminated.

## Bounded local token workload

After `mvn verify` and starting the local PostgreSQL/Redis stores, run
`python3 tests/backchannel_stack_test.py --mode capacity`. It uses isolated schemas and five packaged JVMs, then offers
exactly 50 Client Credentials requests at 5 requests/second for 10 seconds, with at most eight in flight and a
three-second HTTP timeout. Three warmups are excluded. Dropped work/errors are recorded and fail the smoke run; no
token/credential bodies are printed. The fixed-loopback-only helper writes `results/token-local.json` with
offered/attempted/achieved work, scheduling lag, status counts and p50/p95/p99. This is not WebAuthn/MFA, local JWT
validation or remote PDP throughput.

A 50-sample p99 is the observed maximum; host CPU contention, HTTP, a tiny directory and one client identity are not a
production environment. Client-secret BCrypt validation, signing and SQL work are included. Do not extrapolate this
workload to the master-prompt scale targets or lower hash/authorization controls to manufacture an SLO pass.

Actual local result on 2026-11-15: [unprofiled report](results/token-local.json), 50/50 successes, zero errors/drops,
offered 5 requests/second, achieved 4.953 requests/second, p50/p95/p99 **283.272/523.868/616.833 ms**. This does not
meet the 100 ms token target in this environment. The server heap was 256 MiB on Darwin arm64 with 11 logical host CPUs
and same-host database/Redis/JVMs. It is neither a saturation test nor production capacity evidence.

`python3 tests/backchannel_stack_test.py --mode capacity-profile` repeats that bounded workload with `cpu-only.jfc`. It
enables only CPU execution sampling, disables environment/property/JVM-argument events and deletes raw recording/event
JSON after exporting aggregate categories. The separate [profiled report](results/token-local-profiled.json) completed
50/50; its timings include sampling overhead and must not replace the unprofiled
series. [CPU sample summary](results/token-cpu-profile.json): 1,203 of 1,211 measured HTTP executor samples (99.34%)
contained BCrypt client authentication. This is sampled CPU attribution, not a wall-time decomposition. GC/pool wait,
realistic asymmetric client authentication and representative staging workloads still require measurement. Preserve
password/secret verification cost; do not reduce it to manufacture a latency pass.

## Live metadata control-plane evidence

[Read-only probe](results/live-mds-probe.json) records one actual public-snapshot signature/PKIX/CRL validation: serial
301, 11,148,970 bytes, 537 entries, 365 FIDO2 models, three CRLs, 8,054.453 ms including worker startup/network. Direct
Java metadata retrieval returned 429; the candidate came from an earlier download and was verified with live CRLs. This
is control-plane work, not login/token API latency or sustained throughput.
The [two-node packaged report](results/live-mds-stack.json) records both nodes ready at 256 MiB server heaps, using a
loopback mirror of that public signed candidate, real HTTPS signer CRLs and a 256 MiB worker heap. Neither probe
approved a manufacturer model. See [live MDS method](../docs/live-mds.md).

## Before a production claim

Use an explicitly isolated representative deployment: realistic identity/client/session cardinality, credential
algorithms and key custody, TLS/network, database topology, resource requests/limits, replica counts and region
placement. Preserve rate limits and security policy. Run separate offered-rate and soak scenarios for password+MFA,
WebAuthn user/device latency, code exchange, refresh/replay, Client Credentials, local JWT validation, introspection,
PDP and metadata publication. Capture offered/achieved throughput, dropped work, errors, p50/p95/p99, signing/credential
CPU, JVM/GC, SQL/Redis latency/pool waits, policy-lock contention, cleanup/logout backlog, rotation/outage recovery and
revocation staleness. A probe, virtual authenticator or small local smoke is not enterprise production evidence. No
production endpoint is targeted by these local tools.

## Same-driver client authentication comparison

`IAM_TEST_PORTAL_BASE_PORT=28080 python3 tests/backchannel_stack_test.py --mode client-auth` starts the isolated
packaged stack, registers an in-memory generated development RSA public key through the authenticated administration API
and measures 50 Basic requests followed by 50 `private_key_jwt` requests. Both use the same Java 21 HTTP driver,
`order-service` identity, scope, issuer, server signing configuration, stores and 5 requests/second / 8-in-flight
limits. Three warmups per method are excluded; the asymmetric timing includes fresh assertion signing and the durable
single-use replay commit. BCrypt remains cost 12. The private key stays in the workload process's memory; no
credentials/assertions/token responses are exported.

Aggregate reports go to `results/token-auth-comparison.json`. Sequential order, warm caches and shared-host contention
can affect comparisons. A p99 from 50 requests is the observed maximum, not a reliable tail estimate. This does not
measure TLS, production key custody, realistic data, saturation, soak, peak capacity, regional consistency or human
login. See [assertion security and operations](../docs/private-key-jwt.md).

Actual 2026-11-15 result: [same-driver comparison](results/token-auth-comparison.json), Java 21.0.13.0.3, macOS arm64,
11 logical host CPUs, 256 MiB IAM heap. Each method completed 50/50 with zero errors or dropped requests.

| Authentication                    |  p50 ms |  p95 ms | p99 / maximum ms | Achieved successes/second |
|-----------------------------------|--------:|--------:|-----------------:|--------------------------:|
| client_secret_basic, BCrypt 12    | 318.733 | 491.285 |          583.593 |                     4.939 |
| private_key_jwt, RSA 2048 / RS256 |  23.209 |  48.615 |           61.981 |                     5.087 |

Elapsed time runs from the first scheduled request through the final completion; the 50 arrivals span 9.8 seconds, so
the small asymmetric series can show an achieved rate slightly above the configured five arrivals/second. This is not
capacity headroom. The observed asymmetric maximum was below 100 ms in this small workload; it does not verify the
production p99 target. Do not compare this series directly to the earlier Python-driver timing series as if the
drivers/environments were identical. No hash cost, replay persistence, PKCE, audience/scope, key-rotation or
commit-before-response control was disabled.
