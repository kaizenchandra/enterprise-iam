# ADR 0007: durable MFA assurance at protocol boundaries

Status: accepted for the development baseline.

A browser-only gate placed after the framework authorization endpoint cannot enforce MFA before code issuance. Redis
session markers also cannot establish authorization persistence assurance. Move the gate ahead of protocol authorization
handlers and require current durable OP-session proof on human grant lookup/save whenever MFA is enabled. Client
Credentials and validated logout use their protocol paths independently.

Serialize session proof, OTP/recovery consumption, per-user attempts and enrollment with the existing principal lock.
Keep expiry/revocation stronger than assurance. Enrollment confirmation revokes previous grants/sessions and enqueues
back-channel logout atomically; show recovery codes once in the authorized no-store response and require fresh login.
Use one timestamp for library OTP verification and replay tracking. Resume authorization using Spring's saved-request
handler rather than reconstructing OAuth requests.

V9 cannot attest legacy Redis assurance: drain old writers, revoke enrolled users' legacy grants/sessions and enqueue
their remembered RP logout while retaining history/tombstones. No ACR/AMR, phishing resistance, mandatory tenant
enrollment or step-up claim follows merely from this change. Account verification/password-reset delivery, MFA
removal/reset and passkeys remain separate work. See [controls, tests and rollout](../mfa-assurance.md).
