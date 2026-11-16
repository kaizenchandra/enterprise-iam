# ADR 0009: Library WebAuthn with durable ceremonies and conservative MFA policy

Accepted. Use Yubico webauthn-server-core 2.10.1 for all WebAuthn protocol/cryptographic validation, compiled on Java 21
with the existing Boot BOM. Store public credentials and single-use browser-bound challenges in PostgreSQL. Use exact RP
origins, required discoverability/user verification, ES256/RS256 and no attestation trust policy.

Direct library ceremonies integrate with the existing principal locks, durable MFA proof, user-version/cutoff fences,
audit and revokeUser transaction. Redis-only challenges or filter-local authentication success would not preserve those
race guarantees. Spring's maintained native WebAuthn integration remains a future alternative if its
persistence/lifecycle hooks can enforce the same invariants.

A verified passkey replaces the password step but does not silently clear configured TOTP. Current-password
reauthentication and any enrolled MFA guard enrollment/removal; both changes revoke existing sessions/grants and enqueue
durable logout. Email/password recovery preserves public keys and MFA while advancing the login cutoff. Password-only
credential removal and passkey-only recovery would weaken the existing account-recovery model.

Trade-offs: feature is opt-in, older browser JSON APIs require password fallback, changing RP ID affects credential
usability, synced key counters provide limited clone detection, and no attestation-backed hardware assurance or new
ACR/AMR contract is claimed. A global issuance cap/lock is a bounded baseline rather than evidence for the throughput
targets. See [implementation, verification and rollout](../passkeys.md).
