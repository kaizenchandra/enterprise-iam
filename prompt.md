# MASTER PROMPT: Design and Develop a Production-Grade Enterprise Centralized Authentication and Authorization Service Using Java 21, Spring Boot, OAuth 2.0, and OpenID Connect

## 1. ROLE AND ENGINEERING RESPONSIBILITIES

Act as a **Principal Software Engineer, Distinguished Identity and Access Management (IAM) Architect, Enterprise
Solution Architect, Java 21 Expert, Spring Security Architect, Application Security Engineer, Distributed Systems
Architect, Cloud Security Architect, and Site Reliability Engineer** with 15+ years of experience designing secure
enterprise identity platforms.

Your task is to **design, develop, test, security-harden, benchmark, document, and deploy a centralized enterprise
Authentication and Authorization Platform** using Java 21, Spring Boot, Spring Security, OAuth 2.0, and OpenID Connect.

The platform should be comparable in architectural capability to enterprise identity solutions such as Keycloak, Okta,
Microsoft Entra ID, and Auth0, without attempting to reproduce every proprietary feature.

Treat this as a real enterprise engineering project, not a theoretical system design exercise.

### Your responsibilities

1. Functional and non-functional requirements
2. High-Level Design (HLD)
3. Low-Level Design (LLD)
4. OAuth 2.0 Authorization Server
5. OpenID Connect Provider
6. Identity and user lifecycle management
7. Authentication mechanisms
8. Single Sign-On and Single Logout
9. Multi-Factor Authentication
10. Passwordless authentication and passkeys
11. Access and refresh token lifecycle
12. JWT signing and JWKS management
13. Centralized authorization
14. RBAC, ABAC, and policy-based authorization
15. Service-to-service authentication
16. Identity federation and enterprise SSO
17. Client application registration
18. Session management
19. Token revocation and introspection
20. Audit logging and security monitoring
21. Threat modeling and security hardening
22. High availability and fault tolerance
23. Horizontal scalability
24. Automated tests and security verification
25. Performance benchmarking
26. Docker and Kubernetes deployment
27. Functional administration and demonstration clients
28. Complete source code and operational documentation

**Do not stop after HLD, LLD, pseudocode, architecture diagrams, or illustrative examples. Deliver a working,
maintainable, secure, tested implementation using established security libraries and protocols.**

### Mandatory engineering principles

- Use Java 21 and verified compatible Spring Boot and Spring Security releases.
- Use the maintained Spring Authorization Server capabilities available for the selected Spring ecosystem version.
- Verify compatibility against official documentation rather than assuming historical dependency versions.
- Follow existing repository instructions, dependency management, and coding conventions.
- Apply SOLID, DDD, Clean Architecture, and Hexagonal Architecture pragmatically.
- Apply Defense in Depth, Least Privilege, Secure by Default, Zero Trust, and Fail Secure principles.
- Use standards-compliant OAuth2/OIDC implementations.
- Never invent cryptographic algorithms, password hashing schemes, authentication protocols, or token formats.
- Never store plaintext passwords, raw recovery codes, private keys, access tokens, or sensitive credentials in
  unrestricted logs.
- Protect against account enumeration, replay attacks, credential stuffing, token theft, privilege escalation, and
  authorization bypass.
- Use bounded retries, timeouts, connection pools, queues, and resource limits.
- Address concurrency, idempotency, transaction boundaries, race conditions, and distributed failures.
- Clearly separate authentication, authorization, identity lifecycle, and business-domain permissions.
- Never claim regulatory compliance, security certification, penetration-test completion, or production readiness
  without supporting evidence.
- Make routine engineering decisions independently and document significant architectural trade-offs.

---

# PART A — PROJECT OBJECTIVE

## 2. PRIMARY OBJECTIVE

Build a centralized Identity and Access Management platform that provides secure authentication, authorization, token
issuance, session management, and identity federation for multiple enterprise applications and microservices.

The platform must support:

- Enterprise user authentication
- OAuth 2.0 authorization
- OpenID Connect identity
- Single Sign-On
- Single Logout with documented limitations
- Multi-Factor Authentication
- Passkeys/WebAuthn
- Password-based authentication where permitted
- Authorization Code with PKCE
- Client Credentials
- Refresh tokens and rotation
- JWT access tokens
- Opaque tokens where justified
- Token introspection
- Token revocation
- JWKS key discovery
- Role-based authorization
- Attribute-based authorization
- Fine-grained resource permissions
- Service-to-service identity
- Tenant/organization-aware access
- Identity federation
- Audit logging
- Administrative lifecycle management

### Example enterprise scenario

An organization operates:

- Customer Portal
- Employee Portal
- Banking Application
- Order Management Service
- Payment Service
- Reporting Service
- API Gateway

All applications use the centralized IAM platform.

Example authentication flow:

1. An employee opens the Employee Portal.
2. The portal redirects the user to the centralized OIDC Provider.
3. The Authorization Server validates the client, redirect URI, scope, and request.
4. The user authenticates using an approved mechanism.
5. The platform evaluates whether MFA or step-up authentication is required.
6. The user completes MFA.
7. The platform establishes an authenticated identity session.
8. An authorization code is issued.
9. The client exchanges the code using PKCE.
10. The Authorization Server issues appropriately scoped tokens.
11. The client calls a protected backend API.
12. The Resource Server validates the token's signature, issuer, audience, expiry, and applicable claims.
13. The backend evaluates authorization policy for the requested operation.
14. Access is granted or denied.
15. Audit events are recorded without exposing sensitive token or credential material.
16. Refresh token rotation and session revocation follow the documented security model.

The system must recover safely from token replay, key rotation, concurrent refresh requests, identity-provider outages,
and infrastructure failures.

---

# PART B — AUTHENTICATION AND AUTHORIZATION FOUNDATIONS

## 3. DEFINE CORE SECURITY CONCEPTS

Clearly distinguish:

### Authentication — AuthN

Verifies the identity of a user, client, workload, or device.

### Authorization — AuthZ

Determines whether an authenticated identity may perform a specific action on a resource.

### Identity Provider — IdP

Authenticates identities and provides identity assertions.

### Authorization Server — AS

Issues OAuth2 tokens and processes authorization requests.

### OpenID Provider — OP

Provides OIDC identity functionality.

### Resource Server — RS

Protects APIs and validates access tokens.

### Policy Decision Point — PDP

Evaluates authorization policies.

### Policy Enforcement Point — PEP

Enforces authorization decisions.

### Policy Administration Point — PAP

Manages authorization policies.

### Policy Information Point — PIP

Supplies relevant attributes and authorization context.

Explain these components and responsibilities without unnecessarily combining them into one large service.

---

# PART C — OAUTH 2.0 AND OIDC PROTOCOL DESIGN

## 4. OAUTH 2.0 SUPPORT

Implement supported OAuth 2.0 flows using maintained framework capabilities.

### Required grant types

1. Authorization Code with PKCE
2. Client Credentials
3. Refresh Token

Evaluate extension flows only where appropriate, including Device Authorization Grant and Token Exchange.

Explicitly avoid:

- Implicit Grant for new applications
- Resource Owner Password Credentials Grant for new applications
- Unnecessary custom OAuth grants

Use the applicable current OAuth security best practices.

### Protocol endpoints

Implement applicable standards-based endpoints such as:

- `/oauth2/authorize`
- `/oauth2/token`
- `/oauth2/jwks`
- `/oauth2/revoke`
- `/oauth2/introspect`
- `/oauth2/device_authorization` if supported and selected
- `/oauth2/device_verification` if supported and selected

Use the configured authorization-server framework endpoints rather than manually reimplementing protocol handlers.

Verify the actual endpoint configuration for the selected framework version.

---

## 5. OPENID CONNECT PROVIDER

Implement standards-compliant OIDC support.

Required capabilities:

- Discovery metadata
- ID tokens
- UserInfo endpoint
- Standard identity claims
- Subject identifiers
- OIDC scopes
- Authentication context where supported
- Session and logout behavior

Expose applicable endpoints such as:

- `/.well-known/openid-configuration`
- `/userinfo`
- OIDC logout endpoint supported by the chosen framework

Evaluate:

- Pairwise subject identifiers
- Public subject identifiers
- Authentication context class references
- Authentication method references
- RP-Initiated Logout
- Front-channel and back-channel logout

Do not claim support for an OIDC feature unless its protocol and interoperability requirements are implemented and
tested.

---

## 6. AUTHORIZATION CODE WITH PKCE

Implement a complete Authorization Code + PKCE flow.

Security requirements:

- Authorization code is short-lived and single-use.
- Exact registered redirect URI validation.
- PKCE S256 enforcement for supported public clients.
- Appropriate PKCE requirements for confidential clients.
- Secure state handling.
- OIDC nonce validation where applicable.
- Authorization code bound to the correct client and redirect URI.
- CSRF protection.
- Prevention of authorization code replay.
- No tokens in browser URL fragments for the chosen architecture.
- Secure handling of login sessions.

Provide sequence diagrams for browser, mobile, and confidential web clients.

---

# PART D — IDENTITY MANAGEMENT

## 7. USER LIFECYCLE

Implement:

- User registration
- Identity verification
- User activation
- Account suspension
- Account lockout
- Password recovery
- Credential reset
- Profile updates
- Email verification
- Device/session management
- Account deactivation
- Account deletion
- Administrative access review

Define user states:

- PENDING_VERIFICATION
- ACTIVE
- LOCKED
- SUSPENDED
- DISABLED
- DELETED

Use explicit state transitions.

Do not allow account state changes to bypass required security checks.

---

## 8. CREDENTIAL MANAGEMENT

If password authentication is supported, implement:

- Strong password hashing using an approved adaptive algorithm
- Salted password storage
- Password policy
- Password reset with single-use tokens
- Reset-token expiration
- Password compromise screening where available
- Credential change notifications
- Secure account recovery

Evaluate Argon2id, scrypt, or BCrypt according to platform compatibility, operational requirements, and current
recommendations.

Never implement custom password hashing.

Avoid periodic password rotation requirements without a justified security or regulatory need.

Treat password-reset and account-recovery paths as security-sensitive operations.

---

# PART E — MULTI-FACTOR AUTHENTICATION

## 9. MFA CAPABILITIES

Support:

- TOTP authenticator applications
- WebAuthn/passkeys
- Recovery codes
- Configurable MFA enrollment
- MFA removal with reauthentication
- MFA policy enforcement
- Step-up authentication

Evaluate SMS/email OTP only as lower-assurance fallback mechanisms with explicit risks.

### Required MFA security

- TOTP secret protected at rest.
- OTP replay prevention within the chosen validation window.
- Time drift tolerance bounded.
- Enrollment confirmation.
- Recovery-code hashing and one-time consumption.
- Rate limiting.
- Failed-attempt monitoring.
- Secure MFA reset/recovery.

Do not treat all MFA methods as phishing-resistant.

---

## 10. WEBAUTHN AND PASSKEYS

Evaluate WebAuthn-based passwordless authentication.

Implement using maintained, standards-compliant libraries.

Address:

- Registration ceremony
- Authentication ceremony
- Challenge generation
- Challenge expiration
- RP ID
- Origin validation
- Credential public keys
- Signature verification
- User verification
- Credential lifecycle
- Device loss and recovery

Do not implement WebAuthn cryptographic verification manually.

Clearly distinguish a completed WebAuthn integration from a demonstration-only adapter.

---

# PART F — SINGLE SIGN-ON AND LOGOUT

## 11. ENTERPRISE SSO

Implement OIDC-based SSO across multiple registered applications.

Demonstrate:

1. User authenticates with Application A.
2. Authorization Server establishes a secure session.
3. User opens Application B.
4. Application B initiates an OIDC authorization request.
5. The Authorization Server reuses the eligible authenticated session.
6. Application B receives its own tokens through the correct OAuth flow.

Do not share access tokens directly between unrelated applications as an SSO shortcut.

Define session validity, authentication freshness, consent, and MFA requirements.

---

## 12. SINGLE LOGOUT

Evaluate:

- Local application logout
- Identity-provider logout
- RP-Initiated Logout
- Back-channel logout
- Front-channel logout
- Session revocation
- Refresh-token invalidation

Explain that terminating the Authorization Server session does not automatically invalidate already-issued
self-contained JWT access tokens.

Document the trade-offs between short token lifetimes, introspection, revocation lists, and resource-server
coordination.

Implement the supported logout strategy and test it.

---

# PART G — TOKEN DESIGN AND LIFECYCLE

## 13. ACCESS TOKENS

Evaluate:

### JWT access tokens

Advantages:

- Local signature validation
- Reduced dependency on the Authorization Server for every request
- Horizontal scalability

Trade-offs:

- Revocation latency
- Claim staleness
- Token exposure
- Key lifecycle management

### Opaque access tokens

Advantages:

- Centralized introspection
- Flexible revocation
- Less client-visible claim content

Trade-offs:

- Introspection latency
- Higher dependency availability requirements
- Caching complexity

Implement one default strategy and support the other where requirements justify it.

---

## 14. JWT SECURITY

Use standard JWT/JWS libraries integrated with Spring Security.

Define:

- Issuer (`iss`)
- Subject (`sub`)
- Audience (`aud`)
- Expiration (`exp`)
- Issued-at (`iat`)
- Not-before (`nbf`) where relevant
- Token identifier (`jti`) where relevant
- Scope
- Authorized party/client identity where applicable
- Tenant/organization claims where justified

### Mandatory validation

Resource Servers must validate:

- Trusted issuer
- Signature
- Allowed algorithm
- Appropriate signing key
- Expiration
- Audience
- Token type and applicable claim semantics
- Scope/authority
- Clock skew within a bounded window

Do not treat successful signature verification alone as sufficient authorization.

Do not put passwords, private secrets, or unnecessary sensitive user data into JWT claims.

---

## 15. REFRESH TOKEN ROTATION

Implement:

- Secure refresh-token issuance
- Appropriate binding to client/session
- Rotation
- Token family tracking
- Replay detection
- Revocation
- Expiration
- Concurrent refresh handling
- Session logout integration

### Critical scenario

1. Client receives refresh token R1.
2. Client refreshes and receives R2.
3. R1 is reused.
4. Platform detects reuse according to its configured rotation semantics.
5. Affected token family/session is revoked or otherwise handled safely.

Distinguish malicious replay from legitimate concurrent refresh races.

Use durable transactional state where necessary.

Do not assume a stateless JWT refresh token alone provides safe rotation and replay detection.

---

## 16. TOKEN REVOCATION

Support:

- Refresh-token revocation
- Client revocation
- Session revocation
- User disablement
- Token introspection
- Access-token revocation strategy

Explain which revocation guarantees are immediate and which are bounded by token lifetime or cache freshness.

Use short-lived access tokens where appropriate.

Avoid promising immediate global JWT invalidation without a concrete enforcement mechanism.

---

# PART H — CRYPTOGRAPHIC KEY MANAGEMENT

## 17. JWKS AND KEY ROTATION

Implement:

- Managed signing keys
- Public JWKS endpoint
- Key identifiers (`kid`)
- Algorithm allowlist
- Key rotation
- Key overlap periods
- Retired-key handling
- Emergency key compromise response

Evaluate RSA and elliptic-curve signing algorithms according to interoperability and current security recommendations.

Prefer KMS/HSM integration for production signing-key custody where supported.

Do not commit private keys to Git repositories.

Use development-only keys for local execution.

### Required tests

- Old valid tokens remain verifiable during a supported rotation overlap.
- New tokens use the active signing key.
- Retired keys are removed according to policy.
- Unknown key IDs fail safely.
- Key compromise procedures can revoke or retire affected credentials.

---

# PART I — CENTRALIZED AUTHORIZATION

## 18. AUTHORIZATION ARCHITECTURE

Design a centralized policy management and decision capability.

Compare:

1. RBAC — Role-Based Access Control
2. ABAC — Attribute-Based Access Control
3. ReBAC — Relationship-Based Access Control
4. PBAC — Policy-Based Access Control

Implement **RBAC with resource-scoped permissions** as the initial baseline.

Add ABAC where justified.

Do not implement a custom general-purpose authorization language unless required.

Evaluate established policy engines such as OPA, Cedar-compatible systems, or relationship authorization solutions where
appropriate.

---

## 19. AUTHORIZATION COMPONENTS

Design:

- Policy Enforcement Point (PEP)
- Policy Decision Point (PDP)
- Policy Administration Point (PAP)
- Policy Information Point (PIP)

Define:

- Subject
- Action
- Resource
- Context
- Decision
- Policy version
- Reason code

Example decision request:

```json
{
  "subject": {
    "id": "user-123",
    "tenantId": "tenant-456"
  },
  "action": "payment:approve",
  "resource": {
    "type": "payment",
    "id": "payment-789"
  },
  "context": {
    "authenticationLevel": "mfa"
  }
}
```

Example response:

```json
{
  "decision": "DENY",
  "reasonCode": "INSUFFICIENT_PERMISSION",
  "policyVersion": "v12"
}
```

Never trust caller-supplied identity, tenant membership, resource ownership, or authentication strength without
validating their provenance.

---

## 20. RBAC IMPLEMENTATION

Implement:

- Roles
- Permissions
- Role assignments
- Permission inheritance where justified
- Role revocation
- Resource-level authorization
- Separation of duties
- Administrative role management

Example roles:

- PLATFORM_ADMIN
- ORGANIZATION_ADMIN
- SECURITY_ADMIN
- AUDITOR
- APPLICATION_USER

Avoid granting broad administrative access through ordinary application roles.

---

## 21. ATTRIBUTE-BASED AUTHORIZATION

Support selected policies using attributes such as:

- User department
- Tenant
- Resource owner
- Resource classification
- Authentication assurance
- Device trust
- Time
- Requested operation
- Transaction amount

Example:

A payment approval requires:

- Permission to approve payments
- Same organization as the resource
- Sufficient authentication assurance
- Approval limit not exceeded
- Separation-of-duties constraints satisfied

Define the authoritative source and freshness of each attribute.

Do not use self-asserted request attributes to grant sensitive permissions.

---

## 22. POLICY EVALUATION AND CACHING

Implement:

- Default deny
- Policy versioning
- Policy validation
- Deterministic evaluation
- Audit events
- Decision caching where safe
- Cache invalidation
- Emergency revocation

Define the maximum acceptable authorization staleness.

High-risk actions must not rely on stale authorization decisions beyond their permitted risk window.

Differentiate policy decision caching from identity/session caching.

---

# PART J — MULTI-TENANT IDENTITY AND AUTHORIZATION

## 23. ORGANIZATION AND TENANT SUPPORT

Support:

- Organizations
- Organization membership
- Tenant-scoped users
- Multiple organization memberships
- Organization administrators
- Tenant-aware roles
- Application-specific permissions
- Tenant-specific authentication policies

Define whether the Authorization Server is shared across tenants or partitioned by realm/issuer.

Compare:

- Shared issuer with tenant claims
- Separate issuer per tenant
- Dedicated enterprise identity deployment

Do not assume a tenant claim alone establishes resource ownership.

Implement tenant membership validation and resource-level isolation.

---

# PART K — IDENTITY FEDERATION

## 24. ENTERPRISE FEDERATION

Evaluate:

- OIDC federation
- SAML 2.0 federation
- Enterprise identity-provider integration
- Just-in-time user provisioning
- Account linking
- Domain-based discovery

Use established federation libraries or broker integrations.

Do not implement SAML signature validation or XML security from scratch.

Define:

- Trusted issuer configuration
- Audience validation
- Signing-key/certificate handling
- Attribute mapping
- Subject mapping
- Account linking security
- Federation logout behavior
- IdP outage policy

Treat SAML federation as an explicitly scoped extension if a suitable library/provider integration is unavailable.

---

## 25. SCIM PROVISIONING

Evaluate SCIM 2.0 for enterprise user and group provisioning.

Support where implemented:

- User provisioning
- Group provisioning
- Deprovisioning
- Attribute mapping
- Idempotent updates
- Pagination
- Synchronization
- Authorization of provisioning clients

Ensure deprovisioned identities lose access according to documented token/session revocation guarantees.

Do not claim SCIM compliance unless the supported operations and conformance behavior have been verified.

---

# PART L — MACHINE-TO-MACHINE SECURITY

## 26. SERVICE-TO-SERVICE AUTHENTICATION

Implement OAuth 2.0 Client Credentials for confidential machine clients.

Support:

- Registered service identities
- Client authentication
- Scoped access tokens
- Audience restrictions
- Client revocation
- Credential rotation
- Service authorization

Evaluate:

- Client Secret authentication
- Private Key JWT
- Mutual TLS client authentication
- Workload identity federation

Prefer asymmetric client authentication or workload identity for higher-assurance environments where justified.

Never reuse human user tokens as a generic machine identity mechanism.

---

## 27. ZERO TRUST ARCHITECTURE

Apply:

- Explicit verification
- Least privilege
- Short-lived credentials
- Workload identity
- Authenticated service communication
- Continuous authorization where appropriate
- Service-specific audiences
- Strong identity boundaries
- No implicit trust based solely on network location

Explain the responsibilities of:

- API Gateway
- Service Mesh
- Authorization Server
- Resource Server
- Central Authorization Service

Do not assume API Gateway authentication alone protects internal service endpoints.

---

# PART M — SESSION MANAGEMENT

## 28. SESSION SECURITY

Implement:

- Secure session creation
- Session expiration
- Idle timeout
- Absolute timeout
- Session invalidation
- Concurrent session policies
- Device/session inspection
- Session revocation
- Secure cookie handling

Use:

- HttpOnly cookies
- Secure cookies
- Appropriate SameSite policy
- CSRF protection where applicable
- Session identifier rotation after authentication

Store session data in a suitable durable or distributed store according to availability requirements.

Avoid putting access tokens into browser localStorage by default for sensitive enterprise applications.

Evaluate a Backend-for-Frontend (BFF) architecture for browser-based clients.

---

# PART N — DATABASE DESIGN

## 29. POSTGRESQL DATA MODEL

Use PostgreSQL as the authoritative persistence layer.

Design tables as needed for:

- users
- user_credentials
- user_profiles
- organizations
- organization_memberships
- roles
- permissions
- role_permissions
- user_role_assignments
- registered_clients
- oauth2_authorizations
- oauth2_consents
- user_sessions
- refresh_token_families
- mfa_credentials
- webauthn_credentials
- password_reset_requests
- recovery_codes
- signing_key_metadata
- authorization_policies
- policy_versions
- security_audit_events
- outbox_events

Use framework-provided authorization persistence schemas where appropriate.

Do not invent unnecessary parallel stores for data already managed correctly by Spring Authorization Server.

Define:

- Primary keys
- Foreign keys
- Unique constraints
- Indexes
- Credential hashing
- Encryption
- Data retention
- Optimistic locking
- Session expiration
- Token cleanup
- Audit timestamps
- Migration strategy

Implement Flyway migrations.

---

# PART O — HIGH-LEVEL SYSTEM DESIGN

## 30. ARCHITECTURE OPTIONS

Compare:

### Option A — Unified IAM Modular Application

One Spring Boot application implements:

- Identity
- Authentication
- Authorization Server
- OIDC Provider
- Client Management
- Authorization Policy
- Administration

### Option B — Separate Authentication and Authorization Workloads

Separate:

- Identity/Authorization Server
- Authorization Decision Service
- User/Client Administration
- Audit/Event Processing

### Option C — Enterprise IAM Platform

Shared identity control plane with independently scalable:

- Login/Authorization endpoints
- Token endpoints
- JWKS/discovery endpoints
- Authorization decision services
- Administration workflows

Evaluate:

- Availability
- Security boundaries
- Operational complexity
- Fault isolation
- Performance
- Deployment independence
- Key management
- Maintenance cost

**Choose a modular baseline while allowing independent scaling of high-volume authorization decisions when justified.**

Do not create arbitrary microservices for every IAM responsibility.

---

## 31. REFERENCE ARCHITECTURE

Consider:

1. Web/Mobile Clients
2. API Gateway
3. Spring Authorization Server
4. OpenID Connect Provider
5. Authentication Engine
6. MFA/WebAuthn Integration
7. User Directory
8. Client Registry
9. Session Manager
10. Token Service
11. JWKS/Key Manager
12. Authorization PDP
13. Policy Administration
14. PostgreSQL
15. Redis
16. Kafka where justified
17. Audit/Security Monitoring
18. Resource Servers
19. Kubernetes/Cloud Infrastructure

Provide Mermaid diagrams for:

- Overall HLD
- Authorization Code + PKCE
- Client Credentials
- SSO
- MFA
- Token refresh
- Refresh-token replay
- Token revocation
- JWKS rotation
- Centralized authorization
- Identity federation
- Session logout
- Service-to-service authentication

Clearly identify trust boundaries.

---

# PART P — CAPACITY PLANNING

## 32. TARGET SCALE AND SLOS

Treat these as design goals requiring verification.

| Dimension                            | Target                                                               |
|--------------------------------------|----------------------------------------------------------------------|
| Registered identities                | 100 million                                                          |
| Enterprise organizations             | 100,000                                                              |
| Registered applications              | 100,000                                                              |
| Concurrent authenticated sessions    | 10 million                                                           |
| Peak login attempts                  | 10,000/sec                                                           |
| Peak token requests                  | 100,000/sec                                                          |
| Authorization decisions              | 1 million/sec scale-out target                                       |
| Resource-server local JWT validation | Independently scalable                                               |
| Availability                         | 99.99% target                                                        |
| Token API latency                    | p99 below 100 ms within a region, excluding external IdP/MFA latency |
| Authorization decision latency       | p99 below 10 ms for a supported local/cached workload                |
| Deployment                           | Multi-AZ, multi-region extension                                     |
| Audit                                | Durable and tamper-aware                                             |

Distinguish:

- Login throughput
- Token issuance throughput
- JWT validation throughput
- Remote authorization decisions
- Concurrent sessions
- Identity directory size

Estimate:

1. User storage
2. Session storage
3. Token state storage
4. PostgreSQL QPS
5. Redis memory
6. Token signing CPU
7. JWKS traffic
8. Authorization cache load
9. Audit event throughput
10. Database connections
11. Application instance count
12. Regional replication overhead

Do not invent measured vendor performance.

---

# PART Q — SECURITY THREAT MODEL

## 33. THREAT MODELING

Perform STRIDE-based threat modeling for:

- Login
- MFA enrollment
- Account recovery
- OAuth authorization
- Token exchange
- Refresh tokens
- Session management
- Authorization decisions
- Administrative APIs
- Federation
- Key management

Analyze:

- Spoofing
- Tampering
- Repudiation
- Information disclosure
- Denial of service
- Elevation of privilege

Document trust boundaries, attacker capabilities, mitigations, and residual risks.

---

## 34. COMMON SECURITY ATTACKS

Design controls against:

1. Credential stuffing
2. Password spraying
3. Brute-force login
4. Account enumeration
5. Phishing
6. Session fixation
7. Session hijacking
8. CSRF
9. XSS-related token theft
10. OAuth redirect URI manipulation
11. Authorization code interception
12. Authorization code replay
13. PKCE downgrade or omission
14. Token substitution
15. JWT algorithm confusion
16. JWT key confusion
17. JWT audience confusion
18. Refresh-token replay
19. Token leakage through logs
20. Privilege escalation
21. IDOR/BOLA
22. Cross-tenant authorization bypass
23. MFA bypass
24. Account recovery abuse
25. Open redirect vulnerabilities
26. SSRF in federation metadata retrieval
27. Signing-key compromise
28. Dependency compromise
29. Insider administrative misuse
30. Authentication/authorization denial of service

For each, provide prevention, detection, test strategy, and residual risk.

Use current OWASP and applicable IETF/OIDC security recommendations.

---

# PART R — RESILIENCE AND HIGH AVAILABILITY

## 35. FAILURE HANDLING

Analyze:

- PostgreSQL outage
- Redis outage
- Authorization Server instance crash
- Login-session store failure
- Signing-key service outage
- External IdP outage
- MFA service outage
- Token introspection timeout
- JWKS refresh failure
- Authorization PDP outage
- Kafka outage
- Key rotation failure
- Clock skew
- Network partition
- Regional outage

Define which operations fail closed and which can continue using previously validated state.

For example:

- New token issuance must not proceed without required authentication and signing-key guarantees.
- Resource Servers may continue validating eligible existing JWTs while trusted cached keys remain valid.
- Sensitive authorization operations may require fresh policy decisions and fail closed during policy-service outages.

Avoid implementing a universal fail-open policy.

---

## 36. CACHING AND PERFORMANCE

Use Redis where justified for:

- Sessions
- Authentication flow state
- Rate limiting
- Selected authorization decision caches
- Revocation metadata
- Login throttling

Define:

- Cache keys
- TTL
- Eviction
- Revocation behavior
- Cache invalidation
- Replay safety
- Cache outage fallback

Do not cache raw passwords, unencrypted secrets, or reusable plaintext credentials.

Explain the consistency/security trade-offs of caching authorization decisions.

---

# PART S — TECHNOLOGY STACK

## 37. JAVA 21 + SPRING BOOT STACK

Use the following baseline.

| Component              | Technology                                                            |
|------------------------|-----------------------------------------------------------------------|
| Language               | Java 21                                                               |
| Framework              | Spring Boot, verified compatible release                              |
| Authentication         | Spring Security                                                       |
| Authorization Server   | Spring Authorization Server capabilities in selected Spring ecosystem |
| Identity Protocol      | OpenID Connect                                                        |
| Authorization Protocol | OAuth 2.0                                                             |
| Token Format           | JWT/JWS or opaque access tokens                                       |
| Token validation       | Spring Security OAuth2 Resource Server                                |
| Key management         | KMS/HSM adapter where justified                                       |
| Persistence            | PostgreSQL                                                            |
| Data access            | Spring Data JDBC/JPA as justified                                     |
| Database migration     | Flyway                                                                |
| Distributed state      | Redis                                                                 |
| Event processing       | Kafka where justified                                                 |
| Federation             | Established OIDC/SAML integrations                                    |
| WebAuthn               | Maintained WebAuthn library                                           |
| Observability          | Micrometer/OpenTelemetry                                              |
| Unit tests             | JUnit 5/Mockito                                                       |
| Integration tests      | Testcontainers                                                        |
| Security testing       | OWASP ZAP and protocol/security tests                                 |
| Performance            | k6/Gatling                                                            |
| Containers             | Docker                                                                |
| Orchestration          | Kubernetes                                                            |
| Monitoring             | Prometheus/Grafana                                                    |

Verify dependencies and exact supported protocol features against current official documentation.

Do not mix incompatible Spring Security and Spring Authorization Server versions.

---

# PART T — SOURCE CODE ORGANIZATION

## 38. PROJECT STRUCTURE

Create a focused Maven project.

Suggested structure:

```text
enterprise-iam/
├── pom.xml
├── README.md
├── docs/
│   ├── architecture.md
│   ├── oauth2-oidc.md
│   ├── authentication-flows.md
│   ├── authorization-model.md
│   ├── token-lifecycle.md
│   ├── key-management.md
│   ├── threat-model.md
│   ├── capacity-planning.md
│   ├── security-hardening.md
│   ├── runbook.md
│   └── decisions/
├── iam-server/
│   └── src/
│       ├── main/
│       │   ├── java/com/example/iam/
│       │   │   ├── identity/
│       │   │   ├── authentication/
│       │   │   ├── authorization/
│       │   │   ├── oauth2/
│       │   │   ├── oidc/
│       │   │   ├── client/
│       │   │   ├── session/
│       │   │   ├── token/
│       │   │   ├── mfa/
│       │   │   ├── federation/
│       │   │   ├── tenant/
│       │   │   ├── audit/
│       │   │   ├── security/
│       │   │   └── infrastructure/
│       │   └── resources/
│       │       ├── application.yml
│       │       └── db/migration/
│       └── test/
├── sample-resource-server/
├── sample-web-client/
├── iam-admin-portal/
├── benchmarks/
├── docker/
├── helm/
└── .github/workflows/
```

Split components into deployables only where there is a real isolation, reuse, or scaling requirement.

Avoid excessive modules or custom protocol layers.

---

# PART U — ADMINISTRATION APIS

## 39. REQUIRED MANAGEMENT APIS

Implement secure versioned administration APIs.

### Users

- `POST /api/v1/admin/users`
- `GET /api/v1/admin/users`
- `GET /api/v1/admin/users/{userId}`
- `PATCH /api/v1/admin/users/{userId}`
- `POST /api/v1/admin/users/{userId}/suspend`
- `POST /api/v1/admin/users/{userId}/activate`

### Organizations

- `POST /api/v1/admin/organizations`
- `GET /api/v1/admin/organizations`
- `POST /api/v1/organizations/{id}/members`

### OAuth clients

- `POST /api/v1/admin/clients`
- `GET /api/v1/admin/clients`
- `PATCH /api/v1/admin/clients/{clientId}`
- `POST /api/v1/admin/clients/{clientId}/rotate-credentials`

### Roles and permissions

- `POST /api/v1/admin/roles`
- `POST /api/v1/admin/permissions`
- `POST /api/v1/admin/role-assignments`
- `DELETE /api/v1/admin/role-assignments/{id}`

### Sessions

- `GET /api/v1/users/me/sessions`
- `DELETE /api/v1/users/me/sessions/{sessionId}`
- `POST /api/v1/admin/users/{userId}/revoke-sessions`

### Authorization

- `POST /api/v1/authorization/decisions`
- `GET /api/v1/admin/policies`
- `POST /api/v1/admin/policies`
- `PATCH /api/v1/admin/policies/{policyId}`

For every API define:

- Authentication
- Authorization
- Input validation
- Idempotency where required
- HTTP status codes
- Error contracts
- Pagination
- Audit requirements
- OpenAPI specification

Use RFC 9457 Problem Details where appropriate.

Do not expose secret values in ordinary client registration responses after their initial authorized issuance.

---

# PART V — FUNCTIONAL DEMONSTRATION

## 40. REQUIRED DEMO APPLICATIONS

Implement a functional demonstration consisting of:

### Application A — IAM Server

Provides OAuth2/OIDC authentication and token services.

### Application B — Web Client

Demonstrates:

- Login
- Logout
- Authorization Code + PKCE
- Session handling
- MFA
- User profile
- Protected API calls

### Application C — Resource Server

Demonstrates:

- JWT validation
- Scope checking
- Audience validation
- Role-based authorization
- Resource-level permission checks

### Application D — Machine Client

Demonstrates:

- Client Credentials
- Service-to-service token acquisition
- Scoped API access
- Invalid-client and insufficient-scope handling

### Application E — IAM Administration Portal

Supports:

- Users
- Organizations
- Registered clients
- Roles
- Permissions
- Sessions
- Security audit history

Provide an end-to-end scenario showing SSO across two distinct client applications.

Do not substitute static UI mockups for functional authentication flows.

---

# PART W — AUTOMATED TESTING

## 41. UNIT TESTS

Cover:

- User lifecycle
- Credential validation
- Role evaluation
- Permission evaluation
- Token claim customization
- Session policy
- MFA validation
- Refresh-token state transitions
- Policy decision rules
- Organization membership

---

## 42. OAUTH2/OIDC INTEGRATION TESTS

Verify:

- Discovery document
- JWKS endpoint
- Authorization Code + PKCE
- Client Credentials
- ID token validation
- UserInfo
- Refresh token rotation
- Token revocation
- Token introspection
- Invalid redirect URI rejection
- Expired authorization code rejection
- Code reuse rejection
- Invalid scope handling
- Invalid client authentication
- Audience restrictions

Test actual standards-based protocol interactions.

Do not use only mocked security contexts to establish protocol correctness.

---

## 43. SECURITY TESTS

Verify:

- Credential stuffing controls
- Account lockout/rate limits
- Password reset replay
- MFA bypass prevention
- Session fixation prevention
- CSRF handling
- JWT signature validation
- JWT algorithm restrictions
- Issuer validation
- Audience validation
- Expired token rejection
- Unknown signing-key rejection
- Refresh-token replay detection
- Privilege escalation prevention
- Cross-tenant access rejection
- Administrative authorization
- Unauthorized client registration rejection

Use security scanning as complementary evidence, not as a substitute for integration tests or human review.

---

## 44. CONCURRENCY TESTS

Specifically test:

- Concurrent refresh-token use
- Multiple token revocation requests
- Concurrent password resets
- Simultaneous MFA verification
- Session invalidation races
- User suspension during token issuance
- Policy update during authorization decisions
- Signing-key rotation during token validation
- Concurrent OAuth client registration

Ensure database constraints and transaction semantics enforce critical invariants.

---

## 45. FAILURE TESTS

Simulate:

- Database outage
- Redis outage
- Signing-key provider outage
- External IdP timeout
- Network partition
- Authorization service outage
- Token introspection failure
- Lost HTTP response
- Duplicate administrative request
- Rolling deployment with mixed versions

Document which tests were executed and which remain unverified.

---

# PART X — PERFORMANCE ENGINEERING

## 46. LOAD TESTING

Create reproducible workloads for:

### Authentication

- 100 logins/sec
- 1,000 logins/sec
- 10,000 logins/sec

### Token issuance

- 1,000 requests/sec
- 10,000 requests/sec
- 100,000 requests/sec

### Authorization decisions

- 10,000 decisions/sec
- 100,000 decisions/sec
- 1 million decisions/sec as a scale target

### Resource-server JWT validation

Benchmark local verification separately from remote introspection.

Measure:

- Offered and achieved throughput
- p50/p95/p99 latency
- Authentication failure rate
- Token issuance failures
- Password hash CPU cost
- Signing CPU cost
- Database latency
- Redis latency
- Session storage
- JWT validation latency
- Authorization cache hit rate
- Key rotation impact
- JVM CPU/heap/GC
- Error rates

Never fabricate results.

Clearly distinguish performance of local JWT verification from centralized remote authorization decisions.

---

# PART Y — MULTI-REGION ARCHITECTURE

## 47. GLOBAL IAM DEPLOYMENT

Compare:

1. Single-region multi-AZ
2. Active-passive multi-region
3. Regionally distributed token validation
4. Globally active-active authorization servers

Evaluate:

- Issuer consistency
- Signing-key distribution
- Session replication
- Refresh-token consistency
- Revocation propagation
- Clock skew
- User directory replication
- Region failover
- Data residency
- RPO/RTO

Do not claim strict globally consistent token rotation or revocation using asynchronous replication alone.

Define authoritative token-family/session ownership where needed.

---

# PART Z — DEPLOYMENT AND OPERATIONS

## 48. DOCKER AND KUBERNETES

Provide:

- Multi-stage Dockerfile
- Docker Compose
- PostgreSQL
- Redis
- IAM server
- Sample Resource Server
- Demo client
- Administration portal
- Kubernetes manifests or Helm
- ConfigMaps
- Secret references
- Resource requests/limits
- HPA
- PodDisruptionBudget
- Readiness/liveness probes
- Graceful shutdown
- Rolling deployment
- CI/CD workflow

Use local development-only test identities and keys.

Never ship development signing keys or default credentials as production configuration.

Ensure local execution demonstrates a complete standards-based login and protected API flow.

---

# PART AA — OBSERVABILITY AND SECURITY MONITORING

## 49. METRICS AND ALERTING

Expose:

- Login attempts
- Login failures
- MFA challenges
- MFA failures
- Token issuance throughput
- Token issuance errors
- Refresh-token replay detection
- Revocations
- Active sessions
- Authorization denials
- Invalid token attempts
- Client authentication failures
- Signing-key rotation state
- JWKS requests
- Database latency
- Redis latency
- External IdP failures
- Security audit backlog

Provide:

- Micrometer metrics
- Prometheus
- Grafana dashboards
- OpenTelemetry tracing
- Structured security audit events
- SLO definitions
- Alert thresholds
- Operational runbooks

Do not include raw passwords, OTP codes, access tokens, refresh tokens, authorization codes, or private signing keys in
telemetry.

Use controlled identifiers and privacy-aware logging.

---

# PART AB — REQUIRED PRODUCTION FAILURE ANALYSIS

## 50. ANALYZE THESE 35 SCENARIOS

1. User submits valid credentials while PostgreSQL is unavailable.
2. Two requests attempt refresh-token rotation simultaneously.
3. A rotated refresh token is reused.
4. Access token is stolen.
5. User logs out while access token remains valid.
6. User is suspended while an existing JWT is active.
7. Authorization policy is revoked while a cache entry remains valid.
8. Signing key rotates during token validation.
9. Signing key is compromised.
10. Resource Server cannot reach JWKS endpoint.
11. Resource Server receives an unknown `kid`.
12. OAuth authorization code is reused.
13. PKCE verifier is invalid.
14. Redirect URI is manipulated.
15. Client requests unauthorized scopes.
16. Client secret is compromised.
17. Machine client attempts another service's audience.
18. MFA enrollment is interrupted.
19. MFA recovery is abused.
20. Password reset token is replayed.
21. User account is targeted by credential stuffing.
22. Login session is fixed or hijacked.
23. Tenant administrator attempts platform-admin operations.
24. User from Tenant A requests Tenant B's resource.
25. Identity provider federation becomes unavailable.
26. External identity assertion contains unexpected claims.
27. Redis session store becomes unavailable.
28. Audit event publishing fails.
29. Authorization PDP becomes unavailable.
30. Token introspection times out.
31. Two administrators change the same role assignments.
32. User is removed from an organization while a session remains active.
33. OAuth client credentials rotate during active requests.
34. Regional outage occurs during authentication.
35. Rolling deployment introduces incompatible session or token persistence changes.

For every scenario provide:

- Failure/attack mechanism
- Security impact
- Data integrity impact
- User-visible behavior
- Detection signals
- Prevention
- Recovery
- Automated test
- Residual risk

---

# PART AC — END-TO-END IMPLEMENTATION PLAN

## 51. DEVELOPMENT PHASES

Execute the project incrementally.

### Phase 1 — Requirements and Security Architecture

Define identity boundaries, OAuth2/OIDC features, authentication assurance, authorization model, trust boundaries, SLOs,
and threat model.

### Phase 2 — Authorization Server Foundation

Implement Spring Authorization Server configuration, registered clients, protocol endpoints, database persistence,
signing keys, and discovery.

### Phase 3 — Identity and Authentication

Implement user management, credential handling, account lifecycle, login, account recovery, and security protections.

### Phase 4 — OIDC and SSO

Implement OIDC identity capabilities, login sessions, Authorization Code + PKCE, SSO, and supported logout behavior.

### Phase 5 — MFA and Passkeys

Implement TOTP and recovery codes. Add WebAuthn/passkeys using a verified maintained integration.

### Phase 6 — Token Lifecycle

Implement JWT validation, refresh-token rotation, replay detection, revocation, introspection, token lifetime policies,
and key rotation.

### Phase 7 — Centralized Authorization

Implement roles, permissions, scoped policies, PDP, PEP integration, policy management, and secure decision caching.

### Phase 8 — Machine Identity

Implement Client Credentials, service authentication, audience restrictions, and machine-client demonstration.

### Phase 9 — Federation and Enterprise Identity

Implement supported OIDC federation and evaluate SAML/SCIM extensions based on verified library capabilities.

### Phase 10 — Functional Demonstration

Implement a web client, Resource Server, machine client, and administration portal.

### Phase 11 — Security Hardening

Implement threat mitigations, brute-force protection, session protections, security events, rate limits, and
authorization enforcement.

### Phase 12 — Reliability and Observability

Implement bounded retries, failure behavior, metrics, tracing, audit logs, alarms, and recovery procedures.

### Phase 13 — Deployment

Implement Docker Compose, Kubernetes/Helm, CI/CD, secure configuration, and key-management integration points.

### Phase 14 — Verification and Performance

Run protocol, unit, integration, concurrency, security, failure, and load tests. Fix discovered defects.

### Phase 15 — Final Security Architecture Review

Review protocol conformance, identity lifecycle, token security, authorization correctness, attack resistance,
operational reliability, and production risks.

For every phase:

- Implement actual source files.
- Maintain a working build.
- Run applicable tests.
- Fix meaningful failures.
- Preserve unrelated code.
- Document significant design decisions.
- Clearly state verified functionality.
- Identify unresolved security risks.

If repository and command execution tools are available, implement and verify directly.

If unavailable, provide complete source files, paths, and reproducible commands without claiming execution.

---

# PART AD — REQUIRED DELIVERABLES

## 52. COMPLETE PROJECT OUTPUTS

### Deliverable 1 — Requirements

- Functional requirements
- Non-functional requirements
- Security invariants
- Authentication assurance requirements
- Threat model
- Acceptance criteria

### Deliverable 2 — High-Level Design

- Architecture diagrams
- Trust boundaries
- Authentication and authorization flows
- SSO architecture
- Capacity planning
- Multi-region strategy

### Deliverable 3 — Low-Level Design

- Domain model
- UML diagrams
- Sequence diagrams
- Token lifecycle
- Session state machine
- Database schema
- Authorization policy model
- API contracts

### Deliverable 4 — Complete IAM Backend

- Java 21 Spring Boot source
- OAuth2 Authorization Server
- OIDC Provider
- Identity management
- Client registration
- Authentication
- MFA
- Token issuance
- Refresh-token rotation
- Revocation
- JWKS/key rotation
- Centralized authorization
- RBAC/ABAC
- Session management
- Security audit

### Deliverable 5 — Functional Applications

- Web client
- Resource Server
- Machine client
- Administration portal
- SSO demonstration

### Deliverable 6 — Automated Tests

- Unit tests
- OAuth2/OIDC integration tests
- Security tests
- Concurrency tests
- Failure recovery tests
- Authorization isolation tests

### Deliverable 7 — Infrastructure

- Dockerfile
- Docker Compose
- Kubernetes/Helm
- CI/CD
- Monitoring
- Secure configuration examples

### Deliverable 8 — Performance

- Load-test scripts
- Actual results where measured
- Capacity estimates
- Bottleneck analysis
- Scaling recommendations

### Deliverable 9 — Documentation

- README
- Architecture Decision Records
- OAuth2/OIDC protocol guide
- Client integration guide
- Resource Server integration guide
- Token lifecycle
- Signing-key management
- Security threat model
- Authorization policy guide
- Deployment guide
- Incident response runbook
- Known limitations

---

# PART AE — MANDATORY ARCHITECTURE REVIEW

## 53. ANSWER THESE 50 QUESTIONS

1. How would you design a centralized enterprise IAM platform?
2. What is the difference between authentication and authorization?
3. What is the difference between OAuth2 and OpenID Connect?
4. What are Authorization Servers and Resource Servers?
5. How does Authorization Code with PKCE work?
6. Why is the Implicit Grant discouraged?
7. Why should the Password Grant not be used for new applications?
8. How does OpenID Connect SSO work?
9. How is OIDC different from SAML?
10. How does RP-Initiated Logout work?
11. What happens to JWTs after logout?
12. How do you design secure login sessions?
13. What is session fixation?
14. How do you prevent CSRF during login/authorization flows?
15. How should passwords be hashed?
16. How do you prevent credential stuffing?
17. How does TOTP MFA work?
18. What makes WebAuthn phishing-resistant?
19. How do you securely recover an account after MFA device loss?
20. What is the difference between JWT access tokens and opaque tokens?
21. Which JWT claims must a Resource Server validate?
22. Why is signature validation not sufficient?
23. How does JWKS discovery work?
24. How does signing-key rotation work?
25. What happens when a signing key is compromised?
26. How does refresh-token rotation work?
27. How do you detect refresh-token replay?
28. How do you revoke JWT access tokens?
29. How do token introspection and revocation differ?
30. How do you implement OAuth2 Client Credentials securely?
31. When should private_key_jwt or mTLS be used?
32. How do you prevent token audience confusion?
33. What is the difference between RBAC and ABAC?
34. How do you design centralized authorization with PDP and PEP?
35. How do you enforce resource-level permissions?
36. How do you prevent privilege escalation?
37. How do you secure multi-tenant authorization?
38. How do you handle cached authorization decisions?
39. How do you propagate revocation across microservices?
40. How do you integrate enterprise identity federation?
41. What are the security risks of account linking?
42. How does SCIM user provisioning work?
43. How do you design secure administrative APIs?
44. How do you audit privileged operations?
45. What happens when the Authorization Server is unavailable?
46. How can Resource Servers continue validating JWTs during an outage?
47. How do you scale authorization decisions to one million per second?
48. How do you design multi-region IAM without token replay races?
49. How do you test OAuth2/OIDC protocol and authorization security?
50. What evidence is required before enterprise production deployment?

For every question provide:

- Architectural reasoning
- Protocol behavior
- Security implications
- Correctness guarantees
- Implementation considerations
- Failure scenarios
- Trade-offs

---

# PART AF — DEFINITION OF DONE

## 54. ACCEPTANCE CRITERIA

The implementation is complete only when:

- Java 21 project builds successfully.
- Spring Authorization Server starts.
- OAuth2 discovery and supported protocol endpoints function.
- Authorization Code + PKCE works.
- Client Credentials works.
- OIDC discovery and ID token issuance work.
- UserInfo works where required.
- Client registration and management are secured.
- Passwords are protected with an approved adaptive hashing scheme.
- Account recovery has replay and expiration protections.
- MFA enrollment and verification work.
- Supported SSO flow works across two client applications.
- Logout behavior matches documented guarantees.
- JWT access tokens are signed and validated correctly.
- Resource Servers enforce issuer, audience, expiry, and scopes.
- Refresh-token rotation and replay handling are verified.
- Token revocation and introspection behave according to their documented model.
- Signing-key rotation is tested.
- RBAC and resource authorization work.
- Cross-tenant authorization is prevented.
- Service-to-service Client Credentials flow works.
- Sensitive credentials and tokens are not exposed in logs.
- Critical security tests pass.
- Docker Compose starts the IAM platform and demo clients.
- Kubernetes configuration is provided.
- Security metrics and audit events are functional.
- Benchmark scripts are reproducible.
- Performance claims are verified or marked untested.
- Known security limitations and remaining production risks are documented.

Do not declare production readiness merely because an OAuth2 login succeeds in a development environment.

---

# FINAL EXECUTION INSTRUCTIONS

Build a **real, enterprise-grade Centralized Authentication and Authorization Platform using Java 21, Spring Boot,
Spring Security, OAuth 2.0, and OpenID Connect**.

Prioritize:

1. **Identity security:** Secure authentication, MFA, credential handling, and account recovery.
2. **Protocol correctness:** Standards-compliant OAuth2 and OIDC behavior.
3. **Token security:** Correct issuance, validation, rotation, expiry, revocation, and signing-key management.
4. **Authorization correctness:** Least privilege, default deny, and resource-level access control.
5. **Zero Trust:** Explicit verification across clients, gateways, Resource Servers, and internal services.
6. **Tenant isolation:** No cross-organization privilege escalation.
7. **Reliability:** Predictable behavior during outages, key rotation, and token/session races.
8. **Scalability:** Horizontal token-service scaling and efficient authorization decisions.
9. **Maintainability:** Established frameworks, clear boundaries, and minimal custom security logic.
10. **Observability:** Security auditability without exposing credentials.
11. **Reproducibility:** Runnable source, functional clients, automated tests, infrastructure, and documentation.

Begin with a concise architectural assessment.

Select the OAuth2/OIDC protocol scope, token model, authorization model, identity storage strategy, and deployment
architecture.

Then implement the complete project phase by phase.

Use available development tools to create files, compile code, run tests, validate security behavior, and fix defects.

At completion report:

- Implemented functionality
- Architecture and security decisions
- Supported OAuth2/OIDC features
- Authentication and authorization guarantees
- Source structure and important files
- Exact build and run commands
- Tests actually executed
- Security checks actually performed
- Performance measurements actually obtained
- Known limitations
- Remaining security and production risks

**Do not stop after HLD or LLD. Deliver the complete centralized IAM system end to end, including Authorization Server,
OIDC Provider, authentication, MFA, token management, policy-based authorization, demonstration clients, automated
security tests, and deployment infrastructure.**