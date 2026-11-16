# ADR 0008: purpose-bound account actions and durable mail

Status: accepted for the development baseline.

Use the shared directory's trusted email binding, not caller-provided user IDs or new delivery addresses, for account
verification and password recovery. Public requests take an asynchronous encrypted queue path without synchronous
directory lookup. Do not introduce public signup or email-based federation linking in this increment. Platform email
binding checks a live administrative grant, revokes old sessions/action tokens and requires fresh mailbox proof; admin
activation alone never proves email possession.

Generate 256-bit opaque action secrets with JDK SecureRandom, store only digests plus
purpose/version/deadline/consumption, and retain raw delivery material only inside separately encrypted request/mail
envelopes. Consume under the existing principal lock and version/cutoff checks. Password reset updates the hash and
atomically revokes sessions/grants, fences old logins, queues logout and a security notification. It never disables MFA,
clears its lockout, regenerates recovery codes or logs a user in.

Use Boot-managed Jakarta Mail with bounded per-I/O timeouts and required production STARTTLS/server identity checking.
PostgreSQL leases, attempt budgets and fenced acknowledgements support restart-safe at-least-once mail; SMTP can
duplicate or lose acknowledgements, so retries reuse the same one-time secret. Expiry and retention progress
independently of enabled delivery. A trusted binding can bypass a pre-existing public cooldown to avoid suppressing its
fresh verification request, while still observing global queue bounds.

Browser links use fragments and same-origin script/manual form entry to avoid query/Referer leakage; CSRF protects POST
completion. Fixed configured origins, no-store/no-referrer/CSP and generic request responses reduce exposure. V10 adds
nullable unverified legacy email fields and action/outbox state. Full production mail/key operations, timing analysis,
self-service email change, public signup and lost-MFA recovery remain separate gates.
See [account-action contracts and evidence](../account-actions.md).
