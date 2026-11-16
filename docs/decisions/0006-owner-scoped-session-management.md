# ADR 0006: owner-scoped session APIs and global revoke-all

Status: accepted for the development baseline.

OP sessions span applications and organizations. Treating a tenant claim or organization role as authority to revoke a
shared session would allow cross-organization impact. Self-service therefore resolves owners exclusively from a live
human OAuth authorization, under the principal lock. A separate audience and approved scopes isolate these bearer APIs
from ordinary business tokens. Public UUIDs expose neither cookies nor OIDC session identifiers. Tenant administrators
have no global session authority; platform revoke-all retains the dedicated administrative scope/audience and
current-grant check.

Use the existing transactional revocation/outbox path, preserving replay retention and creation floors. Only newly
revoked sessions enqueue, so repeated commands after delivery retention cannot reconstruct a delivered outbox entry. A
persistent per-user login birth cutoff fences delayed password-login registration across revoke-all and session GC.
Deterministically ordered actor/target locks avoid lock-order cycles. New audit attribution contains actor and public
target identifiers but no credentials.

Consequences: revoked/expired management JWTs cannot use these APIs even while offline business validators would still
accept their signatures. Current-session deletion makes that management token unusable. Revoke-all allows fresh login
afterward and is not account suspension. Shared sessions cannot be partially revoked for one tenant; that requires a
different session model. Device fingerprinting, management UI, human-admin step-up and production fan-out performance
are outside this increment. V8 requires draining old writers that ignore the login cutoff.
See [API contracts and guarantees](../session-management.md).
