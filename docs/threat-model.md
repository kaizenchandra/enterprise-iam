# STRIDE security review

Trust boundaries: untrusted browser to BFF/OP, BFF to token endpoint, bearer to RS, service caller to PDP, operator to
PAP, app to PostgreSQL/Redis, key custodian to signing process. Attackers can send arbitrary requests, steal
browser/token material, control client inputs, replay responses, race requests and cause dependency outages;
database/key operator compromise is a separate high-impact threat.

| Surface               | STRIDE threats                               | Implemented controls                                                                                                                                                           | Detection/test                                                              | Residual / missing controls                                                                           |
|-----------------------|----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------|
| Login                 | Spoofing, disclosure, DoS                    | BCrypt 12, generic login failure, CSRF, Redis throttling                                                                                                                       | Password success/invalid protocol paths; load tests absent                  | Distributed stuffing, account enumeration timing, breached-password screening, notifications          |
| MFA                   | Spoofing, replay, elevation                  | Library TOTP, AES-GCM secret storage, confirm-before-enable, row-locked step, hashed one-time recovery                                                                         | PostgreSQL MFA tests                                                        | Phishing, recovery workflow, mandatory enrollment/step-up and AMR/ACR absent                          |
| Account recovery      | Spoofing, replay, elevation, disclosure, DoS | Trusted email binding, random purpose-bound digest tokens, version/cutoff/principal locking, atomic session revocation, encrypted bounded mail outbox, CSRF and fragment links | HTTP/SMTP replay, lost-ack, outage, race and packaged Mailpit tests         | Mailbox compromise/phishing, lost-MFA recovery, production mail/key custody and timing/load review    |
| Authorization request | Tampering, code interception, CSRF           | Framework state/code checks, exact redirect, PKCE S256 policy                                                                                                                  | Real HTTP PKCE, redirect and code-replay tests                              | Mobile/public-client interoperability, authorization request DoS                                      |
| Token endpoint        | Spoofing, substitution, DoS                  | Confidential client auth, registered scopes, short TTL, audience separation                                                                                                    | Client/invalid-scope tests                                                  | Per-client endpoint throttles, asymmetric auth, key custody                                           |
| Refresh               | Replay, tampering, repudiation               | Digest history, authenticated-client binding, family lock, replay audit                                                                                                        | Concurrent/reused token HTTP tests                                          | Lost refresh response forces login; primary-writer dependence and network delivery ambiguity remain   |
| Session               | Fixation, hijacking, CSRF                    | Framework ID rotation, HttpOnly, Secure default, SameSite, CSRF, timeouts                                                                                                      | Functional login, real logout/CSRF/SSO and shared-node invalidation tests   | Store custody, explicit fixation attack coverage, front-channel logout and terminal delivery recovery |
| Back-channel logout   | Spoofing, replay, SSRF, DoS, stale writes    | Signed issuer/audience/SID profile, receipt/tombstone fencing, allowlisted origins, bounded leased retries and retention                                                       | HTTP replay/outage/race tests; five-process packaged-app scenario           | Trusted DNS/egress, terminal delivery recovery, external interoperability and load unverified         |
| Session expiry        | Replay, stale-write elevation, DoS           | Durable deadlines, browser-only renewal after CSRF, principal-locked revocation/enqueue, retention pins                                                                        | Elapsed deadline, outage, concurrency, rollback and stale-cookie HTTP tests | Worker backlog/large sessions, OP activity differs from RP activity, independent offline JWT lifetime |
| PDP                   | IDOR/BOLA, cross-tenant elevation            | Trusted token subject, database resource tenant and membership, default deny                                                                                                   | Tenant/suspension DB tests                                                  | Business PEP integration, SoD, versioning, bounded decision audit                                     |
| PAP/admin             | Elevation, insider misuse, repudiation       | Dedicated audience/scope and constrained ordinary clients                                                                                                                      | Nonadmin API rejection                                                      | Human step-up, dual approval, complete audit and version preconditions                                |
| Federation            | Spoofing, SSRF, assertion tampering          | Disabled                                                                                                                                                                       | No claim                                                                    | Trusted metadata egress, subject linking, signature/audience validation required                      |
| Keys                  | Disclosure, algorithm/key confusion          | External ignored keys, public JWKS, RS256 allowlist, kid                                                                                                                       | Local JWKS rotation and invalid token tests                                 | KMS/HSM, automated rotation/compromise drills                                                         |
| Dependencies          | Supply-chain elevation                       | BOM version alignment                                                                                                                                                          | Compile and tests                                                           | SBOM review, CVE scans, reproducible pinning and signed artifacts                                     |

Do not log request bodies, Authorization headers, OTPs, authorization codes, reset tokens or key material. Reverse-proxy
query logs must be scrubbed. BCrypt uses library salts; password policy currently validates 14–64 characters, with no
periodic forced rotation. Unicode byte length versus BCrypt's 72-byte limit must be explicitly handled before broader
password input support. No penetration test, ZAP scan, OIDC conformance certification or regulatory assessment has been
performed.

Cross-reference the 35 scenarios in [failure-analysis.md](failure-analysis.md). Abuse cases not covered by executed
tests remain open, including XSS/CSP review, MFA bypass penetration testing, trusted-proxy configuration, SSRF
federation tests, administrative insider controls and dependency scanning.

The [durable MFA assurance increment](mfa-assurance.md) fixes late-filter authorization bypass, ignores Redis-only
markers, gates persisted grants, adds per-user attempt lockout, and couples enrollment to revocation/outbox. TOTP replay
tracking uses the same instant as library verification. See later [account actions](account-actions.md)
and [passkeys](passkeys.md) for implemented recovery and WebAuthn controls. Lost-all-factors reset remains a release
gate.

The [V12 hardware attestation policy](hardware-attestation.md) adds separate signing/manufacturer trust roots and CRLs,
real signed metadata verification, bounded freshness, monotonic serial/revision state, ambiguous-header and
retrieval-URL rejection, and durable model compromise decisions. Metadata publishers are a new administrative trust
boundary. Shared/exclusive policy locks prevent a ceremony racing publication from committing under mixed trust state;
principal locks retain cutoff/refresh/session invariants. Root withdrawal or compromise blocks new hardware assertions
and queues existing session/grant revocation through the bounded sweep. A stale NONE node cannot bypass the accepted
REQUIRED state. Residual risks include the accepted metadata freshness window, asynchronous worker/back-channel/JWT
revocation, offline file delivery failure, trusted publisher compromise, unverified physical-vendor behavior and
unmeasured fan-out. No attestation-based application permission or new ACR/AMR authority is introduced.
