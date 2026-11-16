# Authorization model

RBAC maps users to roles and roles to named permissions. Assignments are scoped to an organization and optionally a
resource. ABAC checks authoritative current user state, membership and resource organization. PDP always derives subject
from the authenticated JWT. The caller selects the requested tenant/action/resource, but those values confer no rights.

`DecisionController` executes a single joined query and returns ALLOW only on an exact qualifying grant. Unknown
subjects, absent membership, inactive state, wrong tenants and missing resources return DENY. It has no positive
decision cache; authorization freshness is the current primary-database statement snapshot. Concurrent role changes may
be ordered before or after that snapshot. No linearizable guarantee with downstream business commits is claimed. A
future high-risk payment operation must authorize and commit using an authoritative transaction/fenced policy version,
with separation of duties and approval limits from trusted records.

The current policyVersion `database-current` is a diagnostic marker, not versioned policy history. Versioning, approval
workflows, SoD, limit ABAC and a business-resource PEP integration remain unimplemented. Never send self-asserted
assurance, ownership or payment amounts to gain access. OPA/Cedar could serve richer deterministic policies;
relationship engines suit document sharing graphs. Introducing one now would add a second policy datastore without a
demonstrated requirement.

Do not cache high-risk ALLOW decisions. Lower-risk future caches should bind subject, organization, action, resource and
policy/membership version, use a documented short TTL, subscribe to invalidation and fail closed when fresh decisions
are required. Identity/session caching is distinct from authorization-result caching.

## Membership administration and audited RBAC mutations

Platform administrators (`iam-admin` audience and `iam.admin` scope) can POST/GET
`/api/v1/organizations/{id}/members` and DELETE
`/api/v1/organizations/{id}/members/{userId}`. An ordinary tenant member has no such authority.
Creation requires an existing ACTIVE user and organization; duplicates return 409. Deletion removes
all that user's role assignments in that organization before removing membership. Rejoining never
restores those assignments. Other tenants are unaffected. Missing targets return 404.

Membership add/remove and role assignment/revocation take the same organization row lock, so competing
writes within an organization serialize. Assignment foreign keys additionally prevent orphan grants.
Membership creation holds a user row share lock while checking state. A subsequent suspension can
still occur; the PDP checks current user state independently. Mutation locks are transaction-scoped;
callers must use the Spring-managed controllers, not invoke methods outside a transaction.

Role creation, permission creation, assignment and assignment revocation now require a successful
security audit insert in their transaction, as do membership changes. An unavailable audit table
rolls back the mutation. Events retain the existing event-type/subject format: actor identity,
organization context and an external tamper-evident audit pipeline remain follow-up work.

User, organization, policy and membership lists accept a zero-based `page`, return at most 100 rows,
and reject negative or overflowing offsets. Page order is deterministic, but offset pagination is
not a snapshot across concurrent writes. Organization mutation serialization is conservative; hot
tenants need measured contention/admission limits before a production scale claim.

There is no authorization-result cache: after removal commits, a newly acquired PDP statement
snapshot cannot authorize using removed membership/assignments. An in-flight decision may precede
the commit. The resource-server demo validates JWTs independently and does not automatically call
this PDP; business PEP integration and atomic authorization/business commits remain outstanding.

Before mixed-version rollout, drain older admin writers that do not acquire these organization locks.
No schema migration is required. Rollback must preserve the newer locking/audit guarantees or stop
admin mutations; older binaries do not provide these guarantees.
