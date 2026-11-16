# Capacity estimates — no measured scale claims

All figures are assumptions for initial sizing. Measure row widths, amplification, password hash cost, signatures and
connection occupancy before purchasing capacity.

| Dimension            | Calculation / implication                                                                                                                                        |
|----------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 100M identities      | Assume 2 KiB base + indexes each: about 200 GB before replicas, audit and bloat; at 3 copies about 600 GB                                                        |
| 10M sessions         | Assume 2 KiB per serialized session: 20 GB payload, budget 2–3x for Redis overhead/replicas: 40–60 GB                                                            |
| Refresh history      | At 100K refresh/s and 8h retention: 2.88B generations; at 150B each ~432 GB before indexes; absolute family lifetime required for bounded cleanup                |
| Token state          | Assume 2 KiB/authorization; 100K new authorizations/s with 5m retention ~60 GB, before refresh-lived families                                                    |
| PostgreSQL QPS       | Token issue requires reads and durable writes; 100K/s cannot be assumed on one primary. Separate grants, batch audit, partition retention and measure contention |
| Signing CPU          | If measured signing cost is c milliseconds, cores needed >= throughput*c/1000/utilization; c is unmeasured                                                       |
| Password CPU         | 10K password logins/s at measured h milliseconds costs >=10*h cores before headroom; BCrypt cost 12 must be calibrated                                           |
| JWKS                 | Public keys are cacheable; request demand is number of RS instances / refresh interval plus misses, not one fetch per token                                      |
| PDP 1M/s             | Current remote SQL join per request is not validated for this goal; use partitioned snapshots and local PEP evaluation where freshness permits                   |
| Audit                | 100K events/s at 500B =50 MB/s, 4.32 TB/day before replicas/indexes; retention and downstream backpressure essential                                             |
| Connections          | 20 per IAM pod, reserve DB headroom; cap pods and use a transaction pooler before scaling beyond DB connection budget                                            |
| Instances            | N >= peak throughput / verified per-instance sustainable throughput, with AZ-loss and rollout reserve; per-instance value unmeasured                             |
| Regional replication | Audit/state write bandwidth plus WAL amplification and cross-region latency; asynchronous RPO is nonzero                                                         |

99.99% permits roughly 4.32 minutes downtime in a 30-day month. Error budgets must include dependency failures. Token
p99 <100ms and PDP p99 <10ms are unverified targets. Local RS verification is a distinct benchmark, not a proxy for
central issuance or PDP capacity.
