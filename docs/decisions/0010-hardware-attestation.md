# ADR 0010: Explicit attestation policy with durable offline metadata

Accepted. Keep ordinary passkeys in default NONE mode. REQUIRED uses maintained Yubico 2.10.1 trust-source/metadata
verification, configured signing and manufacturer roots, provisioned CRLs and signed FIDO2 MDS-format snapshots.
Manufacturer roots intersect metadata roots; untrusted/self/none/synced credentials cannot satisfy this profile. This
does not add application authorization authority or remove existing TOTP requirements.

Choose a restricted offline provisioning profile because the library downloader can follow certificate/CRL URLs without
per-request timeout hooks. Reject remote certificate retrieval and unsupported metadata rather than embedding an
unbounded downloader in login or silently skipping signature/CRL validation. Live/public MDS and physical-vendor
interoperability require separate work/evidence. This is an operationally narrower integration with an explicit delivery
responsibility.

Persist metadata serial/digest, policy revision/configuration/mode, bounded freshness and model eligibility.
Shared/exclusive advisory locks coordinate publication and ceremonies; existing principal locks fence user/session/grant
changes. Never extend a replayed snapshot's age or let old roots/mode republish at an older revision. Accepted
compromise-model tombstones are permanent until a separately reviewed remediation; trust-root withdrawal revokes
affected keys without automatically blacklisting every model forever.

Recheck stored attestation at login and use a bounded per-principal revocation sweep for existing credentials/sessions,
preserving audit, refresh history, tombstones and durable back-channel logout. New assertions stop at publication;
existing grants/session/JWT revocation retain their documented asynchronous/lifetime limits. Do not hold the exclusive
metadata lock while acquiring principal locks. Preserve password/MFA recovery and allow owned key removal during
metadata failure.

See [contracts, rollout, verification and limitations](../hardware-attestation.md).
