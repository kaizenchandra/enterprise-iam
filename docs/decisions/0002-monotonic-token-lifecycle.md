# ADR 0002: absolute deadlines and monotonic revocation

Accepted for the next development increment.

The initial refresh-only advisory lock allowed framework revocation and suspension to race stale saves. Rotated-token
revocation could also return a successful no-op after the framework replaced the submitted generation. The initial HTTP
transaction could publish a token before commit.

Add durable versioned lifecycle rows and revocation tombstones beside the framework store. Enforce a fixed eight-hour
default authorization/family deadline. Serialize lifecycle writes and refresh processing per principal at the PostgreSQL
primary; reject stale active saves and let revocation conservatively invalidate the whole family. Keep historical
refresh resolution private to the framework revocation provider's persistence view.

Bind human authorizations to a server-controlled OP session key, fence session logout durably, and invoke revocation
only after local CSRF or OIDC framework validation. Buffer token/revocation responses until commit. Existing
self-contained JWTs retain their offline lifetime. Workload grants never inherit browser sessions; workload subjects and
persisted principals use a `client:` namespace to prevent collisions with directory UUIDs.

Consequences: hot principals serialize; database transactions include token endpoint processing; transaction and
connection limits remain important. Migration V4 invalidates legacy grants, so drain old writers and plan
reauthentication. ADR 0003 adds bounded automated retention with a creation-time floor; multi-region ownership remains
future work. These are correctness measures for the single-writer baseline, not a claim of complete enterprise
readiness.
