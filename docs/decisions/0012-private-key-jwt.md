# ADR 0012: Provisioned asymmetric client keys and durable assertion replay claims

Accepted. Keep the maintained Spring Authorization Server grant/client providers and Nimbus signature verification. Add
`private_key_jwt` with provisioned public RS256 JWKS, exact identity/endpoint audiences, short lifetimes and hashed
durable JTI claims. Preserve Basic client authentication and BCrypt cost 12. No custom signing or verification primitive
is introduced.

Use explicit public-key registration rather than a remote `jwks_uri`. This bounds request work, avoids token-path
networking/SSRF and makes rotation authoritative at database commit. The trade-off is operational key provisioning
rather than automatic discovery. Support explicit old/new overlap with at most three keys, expected-revision updates and
retained disable tombstones. Share-lock registered clients during issuance; exclusive-lock the same row for supported
admin mutations. Do not retain unversioned decoder caches.

Commit replay claims independently of grant issuance. A lost response or later transaction failure consumes the
assertion; clients must sign a fresh request. This adds a durable write and a second pooled connection but avoids
rollback-based replay. Scope records to the external client ID without cascading registry deletion, preserving live
evidence on recreation. Cleanup uses authoritative expiration/time, bounded batches and SKIP LOCKED; a post-insert time
check closes the lock-wait gap after the initial predicate. Delayed claims cannot resurrect expired assertions.
Multi-region asynchronous replication is insufficient for global single-use: keep one authoritative regional
writer/store or use a synchronously fenced ownership design.

Measure Basic and asymmetric methods with the same bounded local Java driver and unchanged server controls. CPU samples
from the prior increment motivate this work; they do not predict the new result. Key custody, representative
cardinalities, TLS, sustained load, pool saturation and regional failure remain production acceptance work.

See [protocol, operations and verification](../private-key-jwt.md).
