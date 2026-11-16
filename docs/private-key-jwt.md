# Asymmetric OAuth client authentication

The Java 21 / Boot 3.5.16 / Spring Authorization Server 1.5.8 baseline now supports `private_key_jwt` alongside existing
`client_secret_basic`. This is a client authentication method, not a custom grant: Authorization Code/PKCE, Client
Credentials and refresh still use their existing grant providers, scopes, audiences, lifecycle fences and
commit-before-response transaction. Human password hashing stays BCrypt cost 12. JWT access tokens remain bearer tokens;
asymmetric client authentication does not make them sender-constrained.

Spring's maintained `JwtClientAssertionAuthenticationProvider` owns protocol authentication and confidential-client PKCE
checks. A configured decoder uses Spring/Nimbus signature verification against administrator-provisioned public keys,
with no remote JWKS request or key cache that can outlive a rotation. The supported provisioning profile deliberately
uses inline public JWKS rather than `jwks_uri`. Remote discovery, automatic vendor key import, `client_secret_jwt`,
mTLS, workload federation and KMS-backed demonstration signing are not added by this increment.

## Assertion profile

POST form fields to `/oauth2/token`:

```
grant_type=client_credentials
scope=orders.read
client_id=<registered-client>
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
client_assertion=<signed-JWT>
```

Use a fresh signed assertion per request; never put it in a URL or log it. Do not combine it with Basic Authorization or
a `client_secret` field. The assertion profile requires:

* `alg=RS256`, `typ=JWT`, exact registered `kid`. Provision one to three unique public RSA keys, 2048..4096 bits,
  exponent 65537, `alg=RS256`, `use=sig`, and optional `key_ops=["verify"]`. No private parameters, remote/certificate
  references, symmetric keys or unapproved algorithms.
* `iss` and `sub` both equal the registered `client_id`. The signature key must belong to that client's active policy; a
  key/header supplied by the assertion cannot establish trust.
* Exactly one `aud`, the configured issuer plus the endpoint path. For example `https://identity.example/oauth2/token`.
  Introspection and revocation need fresh assertions addressed to `/oauth2/introspect` and `/oauth2/revoke`
  respectively. Issuer-only or cross-endpoint audiences are rejected by this profile.
* Required NumericDate `iat` and `exp`, `exp > iat`, maximum 60-second lifetime. Clients should use 30 seconds. Clock
  allowance is five seconds; future/stale issuance is rejected. Optional `nbf` must lie between `iat` and `exp` and pass
  time validation. Keep server/database clocks synchronized.
* Required unpredictable `jti`, 16..128 URL-safe alphanumeric, underscore or hyphen characters; UUIDs are suitable.
  Every successfully authenticated assertion is single-use across nodes and endpoints. A fresh assertion is required
  after an ambiguous/lost response.
* Maximum 8 KiB compact assertion, strict duplicate JSON rejection, no JOSE `jwk`, `jku`, `x5u`, `x5c` or `crit`.
  Signature checking alone does not authenticate an assertion with invalid claims.

Invalid assertions produce OAuth `invalid_client` without token material. Invalid scope/grant behavior still comes from
the maintained framework. Existing resource servers continue enforcing signature, issuer, audience, time, token type and
scopes; no validation is relaxed to improve timings.

## Registration, migration and rotation

All management paths require the existing platform administration bearer audience `iam-admin` and scope `iam.admin`.
Ordinary application and organization identities cannot administer keys. This is shared-issuer/platform administration,
not tenant-controlled trust.

New machine client: `POST /api/v1/admin/clients` with `clientId`, restricted `scopes`,
`clientAuthenticationMethod: "private_key_jwt"`, and a public `jwks: {"keys":[...]}`. Response is 201 with client ID
only; the IAM server never generates or returns a client private key or secret. Omitting the authentication method
retains existing secret registration and its one-time authorized secret response. A private-only client cannot use the
secret-rotation API or disable its sole authentication method.

To migrate an existing secret client without disabling its current method:

1. `GET /api/v1/admin/clients/{clientId}/authentication-keys` to obtain revision (zero if unconfigured).
2. `PUT` the same path with `{"expectedRevision":0,"jwks":{"keys":[<public-key>]}}`. It adds `private_key_jwt` and
   preserves Basic, scopes, redirects and existing settings. Response includes the next revision and enabled state,
   never private material.
3. Deploy the client signer using the private key held in its own protected keystore/KMS; switch to fresh assertions.
   Possession of the old secret remains an authentication path while Basic is retained; plan its separate operational
   retirement.
4. Rotate using a full replacement set `[old,new]` with the current expected revision. Move clients to the new `kid`,
   then replace with `[new]`. Overlap is explicit and operator-controlled. No old key survives in a decoder cache.
   Reusing a `kid` with a different public key also takes effect without restarting the server, although distinct IDs
   are clearer operationally.

`DELETE .../authentication-keys?expectedRevision=N` disables assertions only when another client authentication method
remains. The revision tombstone persists; stale publishers cannot restore it with an old revision. Conflicting updates
return 409; missing clients return 404; malformed/untrusted key documents return 400. Re-read and review conflicts
instead of automatically retrying stale policy. Public JWKS is returned as a JSON-encoded string by GET; secret hashes
and private keys are never included.

Token/revocation requests hold a shared registered-client row lock through their enclosing transaction's commit. Key
replacement, secret rotation and back-channel configuration use the same row's exclusive lock. Distinct assertions can
authenticate concurrently; a rotation waits for an earlier issuance, then subsequent requests observe the committed
policy. Retiring a key does not recall a response already committed, revoke already-issued JWTs, or revoke all grants.
Use existing grant/session revocation procedures as appropriate; access JWT lifetime/revocation limits remain unchanged.
Direct database/old-writer changes that ignore these locks are outside the supported management contract.

Client assertion keys are separate from the Authorization Server's access/ID-token signing keys published by
`/oauth2/jwks`. A compromised client key requires immediate replacement without overlap; retaining a compromised key for
a convenience overlap leaves it usable. Review retained Basic credentials too. Changing client trust alone cannot
immediately invalidate existing self-contained access JWTs; apply the documented resource/revocation controls and
lifetime bounds.

## Replay state, failure behavior and retention

V14 adds versioned public-key policies and hashed assertion IDs. The replay claim is an atomic PostgreSQL insert with a
unique external-client-ID/JTI key. Replay rows do not cascade when a registry record is deleted, so recreating an
external client ID cannot erase a consumed assertion within its acceptance window. It commits in a bounded independent
transaction **before** a successful token response, so issuance/audit/commit failure cannot make a consumed assertion
reusable. No raw assertion or private key is persisted. A failed cryptographic or claim check cannot fill replay
storage. Replay-store/key-policy/database outage fails closed; no process-local fallback admits assertions.

The claim statement checks authoritative database time again, then rechecks after the insert has acquired any
conflicting locks. A request that waited beyond expiry rolls back its claim; a pre-wait predicate alone is insufficient.
Replay evidence is retained through `exp + 5 seconds`; bounded cleanup deletes only older rows with `SKIP LOCKED`. A
delayed writer cannot claim an expired assertion even if cleanup already removed its row. The default per-node cleanup
batch is 1,000 each minute; configure `iam.client-assertion.cleanup-batch-size` (1..10,000) and
`iam.client-assertion.cleanup-delay-ms` for measured traffic and database capacity. Cleanup can run concurrently across
nodes. This default is a development baseline, not 100,000 token requests/second capacity; monitor expiry backlog and
provision maintenance appropriately. An expired row left during an outage prevents reuse conservatively and consumes
storage; it cannot authorize a request.

Independent replay commits need an additional pooled connection while an issuance transaction holds its connection.
Pools, request admission and timeouts must be sized together; saturation fails closed after bounded waits, and no
throughput claim is made at pool exhaustion. The default pool remains 20, acquisition two seconds, assertion transaction
three seconds, protocol transaction ten seconds. Do not solve pool pressure by dropping replay durability or permitting
stale keys.

Metrics include `iam.client.assertion{outcome=accepted|rejected}`, cleaned rows and cleanup failures.
`CLIENT_ASSERTION_KEYS_CHANGED` is audited atomically with policy changes. Invalid signatures/claims and framework
client authentication failures are distinct from replay claims; the counter is not a count of every invalid-client
attempt. Do not add credential/assertion/JTI payloads to logging or tracing.

## Verification and bounded comparison

Drain older assertion readers and direct registry writers before enabling a client; only compatible nodes may serve that
issuer. V14 is additive. From `enterprise-iam/`, with Java 21 and local Docker available:

```sh
mvn -B verify
# Focused actual HTTP / PostgreSQL / Redis suite:
mvn -pl iam-server -Dtest=PrivateKeyClientIntegrationTest verify
# Build artifacts, initialize .env and start local stores as in README first:
IAM_TEST_PORTAL_BASE_PORT=28080 python3 tests/backchannel_stack_test.py --mode client-auth
```

The comparison uses temporary schemas/Redis namespace, packaged IAM/resource/BFF applications and an in-memory generated
development RSA key. It provisions only the public key through the authenticated management API. The same Java HTTP
driver, client identity, scopes, signing configuration and stores run 50 Basic requests then 50 assertion requests at
five requests/second, at most eight in flight, with three excluded warmups per method and three-second requests.
Assertion signing and durable replay commits are included in timing. No private key, reusable credential, assertion or
access token is exported. Only aggregate results go to `benchmarks/results/token-auth-comparison.json`. Failure and
dropped work make the run fail. This is a bounded local comparison, not a production or saturation benchmark; ordering
and warm-cache effects remain limitations.

See [performance evidence](../benchmarks/README.md) and [current verification status](status.md) for executed results.
Physical devices and live MDS are unrelated to machine-client assertion signing; the prior passkey and logout guarantees
still need their regression evidence.

References: [Spring 1.5.8 provider](https://docs.spring.io/spring-authorization-server/reference/api/java/org/springframework/security/oauth2/server/authorization/authentication/JwtClientAssertionAuthenticationProvider.html), [Spring 1.5.8 default validator source](https://github.com/spring-projects/spring-authorization-server/blob/1.5.8/oauth2-authorization-server/src/main/java/org/springframework/security/oauth2/server/authorization/authentication/JwtClientAssertionDecoderFactory.java), [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html)
and [OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html). Application lifetime, endpoint binding, durable
replay and provisioning restrictions strengthen the supported local profile; they are not claims that the framework
alone supplies those guarantees.
