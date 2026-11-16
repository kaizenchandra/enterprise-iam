# ADR 0011: Bounded live metadata worker and durable fleet polling

Accepted. Preserve OFFLINE as the default and its existing fingerprint/age semantics. LIVE uses the original signed
public MDS BLOB, maintained Yubico signature/PKIX checks and explicit manufacturer roots. Legacy entries are excluded
from FIDO2 eligibility rather than causing rejection of the whole public catalog. Do not implicitly trust every root in
a verified catalog.

Use a disposable JVM with a controlled URL handler/JDK HttpClient because the maintained downloader does not expose
per-download deadlines for its certificate/CRL URLs. Bound body sizes, origins, requests, heap, parent deadline and
cancellation. The parent clears child environment variables and treats the helper as a fault boundary, not an OS
security sandbox. Never launch network verification from login/health transactions; background validation prewarms a
local immutable snapshot. A cold or inconsistent node fails closed.

V13 adds durable fleet fetch leasing/backoff, retained signed CRL evidence and evidence digests. Only one publisher
fetches externally; peers can validate the retained signed snapshot offline. Preserve metadata serial/digest and
policy-revision high-water marks. A successful live confirmation may renew current CRL evidence without changing the
snapshot's original acceptance time, signed nextUpdate or maximum age. Unconfirmed outage fallback cannot slide the
deadline. Evidence changes invalidate peer caches even if the BLOB serial is unchanged.

Permit an explicit maximum age up to 31 days only for LIVE, reflecting signed public metadata cadence; OFFLINE remains
capped at 24 hours. Honor bounded Retry-After and never use aggressive retries to bypass rate limiting. Read-only probes
cannot approve devices or publish production state. Physical device interaction and representative load environments
remain separate acceptance evidence.

See [configuration, live evidence and verification](../live-mds.md).
