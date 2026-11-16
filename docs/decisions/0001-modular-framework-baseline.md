# ADR 0001: modular framework baseline

Accepted for development: Boot BOM-managed Spring stack, framework OAuth/OIDC handlers, JDBC OAuth persistence and
PostgreSQL advisory locks for strict refresh replay semantics. Redis supplies shared browser state. JWT access tokens
permit independently scalable local validation with a five-minute revocation delay. No authorization positive cache is
introduced before freshness and invalidation requirements are established.

Alternatives: opaque tokens trade revocation immediacy for availability/latency dependencies; arbitrary IAM
microservices add failure boundaries; custom grant handlers add protocol risk. None are needed for this baseline. Strict
refresh replay trades security simplicity for reauthentication during legitimate races or lost responses. A home-region
writer is mandatory for each family.
