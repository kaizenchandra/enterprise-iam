# OAuth/OIDC protocol and integration

Official compatibility sources checked during implementation:

- https://docs.spring.io/spring-boot/3.5/system-requirements.html
- https://docs.spring.io/spring-boot/3.5/appendix/dependency-versions/coordinates.html
- https://docs.spring.io/spring-authorization-server/reference/configuration-model.html
- https://docs.spring.io/spring-authorization-server/reference/core-model-components.html
- https://spring.io/blog/2026/06/09/spring-authorization-server-releases-2026-06/
- https://github.com/wstrange/GoogleAuth

The Boot BOM resolves Authorization Server 1.5.8 and Security 6.5.11; individual Spring versions are not overridden.
Boot 3.5 supports Java 21. Select a currently supported vendor/release and reassess vulnerabilities before deployment;
compatibility alone does not establish ongoing support.

Enabled: authorization code with required PKCE, confidential client credentials, rotating refresh tokens and OIDC.
Framework endpoints: `/oauth2/authorize`, `/oauth2/token`, `/oauth2/jwks`, `/oauth2/introspect`, `/oauth2/revoke`,
`/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`, `/userinfo`, `/connect/logout`. Device
and token exchange grants are not registered. Implicit and password grants are not registered. Dynamic OIDC client
registration is disabled. Management client registration currently creates constrained machine clients only.

The two portals explicitly add S256 PKCE, use framework state/nonce and ID-token handling, retain tokens on the server,
and use exact pre-registered callback URIs. They are distinct confidential registrations. Public mobile clients and
browser-only clients need additional registration policy and interoperability tests; they are not claimed as completed
demos. A mobile app should use the system browser, S256, verified app/universal links and OS-protected refresh storage.
Avoid embedded webviews.

JWT access tokens use RS256, five-minute TTL, issuer, subject, audience and scope. The resource server explicitly checks
issuer, RS256, signature, time validity, `at+jwt`, `enterprise-api` audience and `orders.read`. IAM administration
checks `iam-admin` and `iam.admin`. ID tokens are for client identity processing, never API authorization.

Opaque tokens are available in the framework but not configured or verified here. Introspection supports
framework-maintained active token state. Offline JWT validation intentionally does not consult introspection on each
call.

Only public subjects are configured. Pairwise subjects, authenticated dynamic registration, ACR/AMR claim semantics,
front-channel logout, federation, SAML and SCIM are unimplemented. Do not infer support from a dependency alone.

## API conventions

Implemented admin users create/list/get/activate/suspend, organizations create/list, machine clients create/list/rotate,
roles, permissions and role assignments; authorization decisions are separate. All admin routes require a JWT with the
administrative audience and scope. Only the local bootstrap creates the `admin-cli` identity. Ordinary client
registration cannot request `iam.admin`.

JSON Bean Validation rejects invalid payloads; SQL constraints enforce uniqueness/FKs. Create returns 201, lists return
200, assignment delete returns 204, unknown selected resources return 404, illegal user transitions and constraint
conflicts return 409. Spring MVC Problem Details handles supported errors; security-filter errors are not a complete RFC
9457 contract. User listing uses 100-row pages; other lists currently have a fixed 100-row bound. Idempotency keys and
complete optimistic management concurrency contracts remain open. Do not automatically retry creates after uncertain
responses.
