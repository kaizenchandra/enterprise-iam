# Token and session consistency

## Absolute lifetime

`iam.refresh-family-lifetime` defaults to `PT8H`, configurable with `REFRESH_FAMILY_LIFETIME`. The deadline starts when
an authorization is first persisted, including authorization-code/consent state. It never slides during refresh. Each
persisted refresh token's expiration is the earlier of its framework-configured expiry and this deadline. PostgreSQL
`clock_timestamp()` is the authoritative time; an authorization at or beyond its deadline is unavailable for lookup and
cannot be saved as active.

Access JWTs still have their independently configured short lifetime. Neither family expiry nor logout instantly
invalidates a self-contained JWT at an offline resource server. Framework validators also permit bounded clock skew.
Authorization codes retain their short framework lifetime and single-use checks.

## Authoritative lifecycle fencing

Spring JDBC remains the token store. `authorization_lifecycle` adds only authorization identity, client/subject/session
binding, creation/deadline, revision and revocation tombstone. It contains no reusable token. The version is persisted
as a string attribute in the framework authorization record to preserve its serialization allowlist.

All saves, removals, session revocations and user suspension/revocation coordinate through a PostgreSQL transaction
advisory lock on the principal. Saves additionally lock the lifecycle row and compare the snapshot revision. A stale
issuance cannot overwrite a newer generation or recreate revoked/deleted OAuth state. Tombstones survive deletion of the
framework record until the retention horizon. Their eventual deletion atomically advances a durable creation-time floor;
persisted snapshots remain version-fenced. See [automated retention](retention.md). Invalidation of an access/refresh
token conservatively revokes the whole authorization family, even when revocation read an earlier generation. Repeated
revocation is idempotent, including after suspension.

`AdminController` acquires the same principal lock before changing user state and revoking sessions/authorizations in
the same transaction. After suspension commits, a stale code exchange or refresh cannot persist a valid authorization.
Reactivation does not reactivate old grants or sessions. Use these application paths; direct database updates bypass
orchestration.

The current lock granularity serializes a principal's persistence and refresh work. This favors correctness over maximum
single-principal throughput, including hot machine identities. It requires a single authoritative PostgreSQL writer. No
globally active-active or async-replica consistency guarantee is claimed.

## Refresh and revocation

`RefreshGuard` runs after client authentication inside the protocol transaction. Only a history entry owned by that
client can acquire the corresponding principal lock and trigger replay handling. A stale generation revokes the family
and returns `invalid_grant`. Strict concurrent refresh semantics remain: one can succeed, the loser revokes the family.
Clients must single-flight refresh and reauthenticate after an ambiguous/lost response.

`RevocationAuthorizationService` is a view used exclusively by Spring's standard revocation provider. If a submitted
refresh token was rotated away, digest history resolves its current family. The provider still validates authenticated
client ownership before invalidation. This closes the race where revocation arrives just after rotation and would
otherwise silently miss R1 while R2 survives. Refresh and introspection do not use this historical lookup. Unknown-token
revocation remains a successful no-op; another client cannot revoke the family.

## Commit before response

`ProtocolTransactionFilter` encloses `/oauth2/token` and `/oauth2/revoke` processing in a bounded transaction and
buffers response bodies. Successful token bodies are released only after commit. A transaction/commit failure discards
the body and returns HTTP 503 `temporarily_unavailable` with `Cache-Control: no-store`. Initial authorization saves
commit before the framework sends its redirect.

Issuance may commit just before revocation and its HTTP response may arrive later. That ordering does not promise a
still-usable refresh token upon response receipt: clients must handle rejection. An access JWT from that earlier
issuance can still validate offline until expiry. Transactions cannot make network delivery atomic with a database
commit.

Client Credentials grants use `client:<clientId>` subjects and persisted principals, so a client ID equal to a directory
UUID cannot impersonate that user in the PDP or be revoked by user-wide lifecycle operations. They never inherit OP
browser-session bindings, even if a token request carries an OP cookie.

## OP session binding and logout

A server-controlled session correlation key is explicitly registered at successful login and links grants from multiple
clients sharing one OP browser session. It survives MFA session-ID rotation and is replaced on a fresh password login.
Session registration/authorization saves share the principal lock with logout. Even logout before a first grant creates
a session tombstone, fencing an in-flight authorization.

- CSRF-protected IAM `POST /logout` revokes all grants and pending codes belonging to that OP session, then invalidates
  the browser session.
- Validated RP-Initiated Logout uses the framework's `logoutResponseHandler` extension: revoke the hinted/current OP
  session before delegating to Spring's default logout success handler. Invalid hints/redirects never reach this hook.
  See [Spring's endpoint documentation](https://docs.spring.io/spring-authorization-server/reference/protocol-endpoints.html).
- Other OP sessions for the same user remain eligible. Opted-in RP sessions are invalidated after back-channel delivery;
  unregistered/unreachable RPs can retain local state. Existing access JWTs can still work until expiry, but refresh
  tokens from the logged-out OP session are rejected.
- A revoked correlation key fences a stale Redis session on subsequent browser requests and on authorization
  persistence. A new login creates a fresh eligible session and resets prior MFA assurance.

Back-channel logout now delivers asynchronously to opted-in RPs with durable retries and client JDBC-session
invalidation; see [back-channel delivery](backchannel-logout.md). Idle and absolute OP expiry now revoke linked grants
and enqueue back-channel logout; see [durable session expiry](session-expiry.md). Front-channel logout, orchestration
for arbitrary direct Redis deletion, remain unimplemented; owner-session UI is implemented (session-ui.md). RP-local
logout without OP logout does not revoke an OP family.

## Storage and rollout

Migration V4 deliberately invalidates preexisting framework authorizations. Their OP-session bindings and absolute
deadlines cannot be reconstructed safely. Users/clients must obtain fresh grants; offline JWTs are not retroactively
invalidated. Directory, registered clients and consents remain. Stop/drain old writers before migration and deploy the
new version together; mixed old/new persistence writers are unsupported. Because workload subject semantics now use a
namespace, allow the maximum previous access-token TTL plus validator skew to elapse before reopening resource
decisions, or perform coordinated old-key retirement/cache eviction. Database invalidation alone cannot fence old
offline JWTs. This is tested from a seeded V3 schema.

Framework authorization rows contain reusable token material: protect database roles, encryption/backups and query logs.
Refresh history contains only SHA-256 digests. A scheduled bounded worker now removes expired grants and purges
history/tombstones after the configured post-expiry grace. It preserves replay detection through the family horizon and
advances the creation floor atomically with tombstone deletion. V5 requires draining old writers;
see [retention configuration and safety proof](retention.md). Large-backlog performance and audit retention remain
separate release gates.

V8 adds [owner-scoped session management](session-management.md). User-wide revocation advances a persistent login birth
cutoff before ending sessions; pre-cutoff registrations cannot revive access after session GC. Only newly revoked
sessions enqueue, including when earlier delivery rows have already been purged. Offline JWT behavior is unchanged.
