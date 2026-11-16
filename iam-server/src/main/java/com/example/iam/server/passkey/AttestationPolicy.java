package com.example.iam.server.passkey;

import com.example.iam.server.token.TrackedAuthorizationService;
import com.yubico.webauthn.attestation.AttestationTrustSource;
import com.yubico.webauthn.data.ByteArray;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.cert.CRL;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * Durable cross-node metadata high-water mark, policy lock and bounded revoked-model sweep.
 */
@Component
public class AttestationPolicy implements AttestationTrustSource, org.springframework.boot.actuate.health.HealthIndicator {
    final boolean required;
    final JdbcTemplate db;
    final TransactionTemplate tx;
    final TrackedAuthorizationService grants;
    final String blobFile, signerFile, rootFile, crlFile, legal;
    final Duration maximumAge;
    final Clock clock;
    final long revision;
    final String source;
    final LiveMdsClient live;
    private volatile Cached cache;
    private volatile io.micrometer.core.instrument.MeterRegistry meters;

    @org.springframework.beans.factory.annotation.Autowired
    public AttestationPolicy(JdbcTemplate db, PlatformTransactionManager manager, TrackedAuthorizationService grants,
                             @Value("${iam.passkey.attestation.mode:NONE}") String mode,
                             @Value("${iam.passkey.attestation.metadata-file:}") String blobFile,
                             @Value("${iam.passkey.attestation.signing-roots-file:}") String signerFile,
                             @Value("${iam.passkey.attestation.authenticator-roots-file:}") String rootFile,
                             @Value("${iam.passkey.attestation.crls-file:}") String crlFile,
                             @Value("${iam.passkey.attestation.legal-header:}") String legal,
                             @Value("${iam.passkey.attestation.maximum-age:PT24H}") Duration age,
                             @Value("${iam.passkey.attestation.policy-revision:1}") long revision,
                             @Value("${iam.passkey.attestation.source:OFFLINE}") String source, LiveMdsClient live) {
        this(db, manager, grants, mode, blobFile, signerFile, rootFile, crlFile, legal, age, Clock.systemUTC(), revision, source, live);
    }

    AttestationPolicy(JdbcTemplate source, PlatformTransactionManager manager, TrackedAuthorizationService grants, String mode, String blobFile, String signerFile, String rootFile, String crlFile, String legal, Duration age, Clock clock) {
        this(source, manager, grants, mode, blobFile, signerFile, rootFile, crlFile, legal, age, clock, 1);
    }

    AttestationPolicy(JdbcTemplate datasource, PlatformTransactionManager manager, TrackedAuthorizationService grants, String mode, String blobFile, String signerFile, String rootFile, String crlFile, String legal, Duration age, Clock clock, long revision) {
        this(datasource, manager, grants, mode, blobFile, signerFile, rootFile, crlFile, legal, age, clock, revision, "OFFLINE", null);
    }

    AttestationPolicy(JdbcTemplate datasource, PlatformTransactionManager manager, TrackedAuthorizationService grants, String mode, String blobFile, String signerFile, String rootFile, String crlFile, String legal, Duration age, Clock clock, long revision, String source, LiveMdsClient live) {
        if (!Set.of("OFFLINE", "LIVE").contains(source) || source.equals("LIVE") && live == null)
            throw new IllegalArgumentException("Invalid metadata source");
        this.source = source;
        this.live = live;
        this.revision = revision;
        if (revision < 1) throw new IllegalArgumentException("Invalid policy revision");
        if (!Set.of("NONE", "REQUIRED").contains(mode) || age.isNegative() || age.isZero() || age.compareTo(Duration.ofDays(source.equals("LIVE") ? 31 : 1)) > 0)
            throw new IllegalArgumentException("Invalid attestation policy");
        required = mode.equals("REQUIRED");
        this.blobFile = blobFile;
        this.signerFile = signerFile;
        this.rootFile = rootFile;
        this.crlFile = crlFile;
        this.legal = legal;
        maximumAge = age;
        this.clock = clock;
        this.grants = grants;
        if (required && (source.equals("OFFLINE") && (blobFile.isBlank() || crlFile.isBlank()) || signerFile.isBlank() || rootFile.isBlank() || legal.isBlank()))
            throw new IllegalArgumentException("Required attestation custody inputs missing");
        db = datasource == null ? null : new JdbcTemplate(Objects.requireNonNull(datasource.getDataSource()));
        if (db != null) db.setQueryTimeout(5);
        tx = manager == null ? null : new TransactionTemplate(manager);
        if (tx != null) tx.setTimeout(5);
    }

    static AttestationPolicy none() {
        return new AttestationPolicy(null, null, null, "NONE", "", "", "", "", "", Duration.ofHours(24), Clock.systemUTC());
    }

    private static ResponseStatusException unavailable() {
        return new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Attestation metadata unavailable");
    }

    static UUID uuid(ByteArray bytes) {
        var b = java.nio.ByteBuffer.wrap(bytes.getBytes());
        if (b.remaining() != 16) throw new IllegalArgumentException("Invalid AAGUID");
        return new UUID(b.getLong(), b.getLong());
    }

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    void metrics(io.micrometer.core.instrument.MeterRegistry registry) {
        meters = registry;
    }

    private void metric(String name) {
        var registry = meters;
        if (registry != null) registry.counter(name).increment();
    }

    @Override
    public org.springframework.boot.actuate.health.Health health() {
        try {
            if (!enforced() && blobFile.isBlank() && source.equals("OFFLINE"))
                return org.springframework.boot.actuate.health.Health.up().withDetail("mode", "NONE").build();
            var bundle = current();
            return org.springframework.boot.actuate.health.Health.up().withDetail("mode", required ? "REQUIRED" : "NONE").withDetail("serial", bundle.blob.getPayload().getNo()).build();
        } catch (RuntimeException unavailable) {
            return org.springframework.boot.actuate.health.Health.down().withDetail("reason", "attestation_metadata_unavailable").build();
        }
    }

    private Inputs inputs() throws Exception {
        var signers = AttestationBundle.certificates(Path.of(signerFile));
        var roots = AttestationBundle.certificates(Path.of(rootFile));
        var hashes = new TreeSet<String>();
        for (var cert : signers) hashes.add("signer:" + Base64.getEncoder().encodeToString(cert.getEncoded()));
        for (var cert : roots) hashes.add("authenticator:" + Base64.getEncoder().encodeToString(cert.getEncoded()));
        Collection<CRL> crls = (source.equals("LIVE") || crlFile.isBlank()) ? List.of() : CertificateFactory.getInstance("X.509").generateCRLs(new java.io.ByteArrayInputStream(AttestationBundle.read(Path.of(crlFile), 1048576))).stream().map(c -> (CRL) c).toList();
        for (var crl : crls) hashes.add("crl:" + Base64.getEncoder().encodeToString(((X509CRL) crl).getEncoded()));
        return new Inputs(signers, roots, crls, TrackedAuthorizationService.digest(hashes + ":" + legal + ":" + maximumAge + ":" + revision + ":" + required + ":" + (source.equals("LIVE") ? "LIVE:" + live.identity() : "offline-fido2-hardware-v1")));
    }

    /**
     * Must run before taking any principal lock. Exclusive publishers never acquire principal locks.
     */
    void guard() {
        if (db != null) db.queryForList("select pg_advisory_xact_lock_shared(hashtextextended('passkey-metadata',0))");
        if (enforced()) current();
    }

    private boolean enforced() {
        return required || db != null && !db.queryForList("select id from passkey_metadata_state where id=1 and required").isEmpty();
    }

    private AttestationBundle current() {
        try {
            var rows = db.queryForList("select *,clock_timestamp()<expires_at as fresh,clock_timestamp() as checked_at from passkey_metadata_state where id=1");
            if (rows.isEmpty() || !Boolean.TRUE.equals(rows.getFirst().get("fresh"))) throw unavailable();
            var row = rows.getFirst();
            checkClock(((java.sql.Timestamp) row.get("checked_at")).toInstant());
            var in = inputs();
            String digest = row.get("digest").toString();
            if (((Number) row.get("policy_revision")).longValue() != revision || !in.configuration.equals(row.get("configuration")))
                throw unavailable();
            var cached = cache;
            if (cached != null && cached.configuration.equals(in.configuration) && cached.digest.equals(digest) && (!source.equals("LIVE") || cached.evidence.equals(row.get("evidence_digest"))))
                return cached.bundle;
            if (source.equals("LIVE"))
                throw unavailable(); // asynchronous worker prewarms; never retrieve inside login transactions
            var bundle = new AttestationBundle(row.get("blob").toString(), in.signers, in.roots, in.crls, legal, clock);
            if (!bundle.digest.equals(digest)) throw unavailable();
            cache = new Cached(in.configuration, digest, bundle, row.get("evidence_digest").toString());
            return bundle;
        } catch (org.springframework.dao.DataAccessException e) {
            throw e;
        } catch (Exception invalid) {
            throw unavailable();
        }
    }

    private void checkClock(Instant databaseNow) {
        if (Duration.between(databaseNow, clock.instant()).abs().compareTo(Duration.ofSeconds(30)) > 0)
            throw unavailable();
    }

    @Override
    public TrustRootsResult findTrustRoots(List<X509Certificate> chain, Optional<ByteArray> aaguid) {
        var bundle = current();
        if (aaguid.isEmpty() || denied(uuid(aaguid.get())))
            return TrustRootsResult.builder().trustRoots(Set.of()).build();
        return bundle.findTrustRoots(chain, aaguid);
    }

    private boolean denied(UUID model) {
        return db.queryForObject("select count(*) from passkey_revoked_models where aaguid=?", Integer.class, model) > 0;
    }

    boolean eligible(UUID model, String chain) {
        if (model == null) return !required;
        var bundle = current();
        if (denied(model)) return false;
        try {
            return bundle.eligible(model, AttestationBundle.chain(chain), clock.instant());
        } catch (Exception malformed) {
            return false;
        }
    }

    /**
     * Validates outside the database transaction; only a verified immutable bundle may publish.
     */
    public void refresh() throws Exception {
        var in = inputs();
        LiveMdsClient.Verified proof;
        UUID lease = null;
        if (source.equals("LIVE")) {
            var old = db.queryForList("select blob,retrieval_cache from passkey_metadata_state where id=1 and source='LIVE'");
            UUID attempt = UUID.randomUUID();
            var claimed = db.queryForList("update passkey_mds_fetch_state set lease_id=?,lease_until=clock_timestamp()+interval '40 seconds',next_fetch_at=clock_timestamp()+interval '1 hour' where id=1 and next_fetch_at<=clock_timestamp() and (lease_until is null or lease_until<clock_timestamp()) returning id", attempt);
            if (!claimed.isEmpty()) lease = attempt;
            if (lease == null) {
                try {
                    if (cache != null) {
                        current();
                        return;
                    }
                } catch (ResponseStatusException unavailable) {/* warm or revalidate retained state */}
                if (old.isEmpty()) throw unavailable();
            }
            String seed = old.isEmpty() ? (blobFile.isBlank() ? null : new String(AttestationBundle.read(Path.of(blobFile), MdsVerifierWorker.BLOB_LIMIT), StandardCharsets.UTF_8).strip()) : old.getFirst().get("blob").toString();
            try {
                proof = live.verify(in.signers, legal, seed, old.isEmpty() ? null : old.getFirst().get("retrieval_cache").toString(), lease != null);
            } catch (Exception failed) {
                if (lease != null)
                    db.update("update passkey_mds_fetch_state set lease_id=null,lease_until=null,next_fetch_at=greatest(next_fetch_at,clock_timestamp()+(? * interval '1 second')) where id=1 and lease_id=?", Math.max(3600, live.retryAfter), lease);
                throw failed;
            }
        } else proof = null;
        String jwt = proof == null ? new String(AttestationBundle.read(Path.of(blobFile), 5242880), StandardCharsets.UTF_8).strip() : proof.jwt;
        var bundle = new AttestationBundle(jwt, in.signers, in.roots, in.crls, legal, clock, proof);
        String retrievalCache = proof == null ? "{}" : AttestationBundle.JSON.writeValueAsString(new TreeMap<>(proof.downloads));
        final UUID publicationLease = lease;
        try {
            tx.executeWithoutResult(status -> {
                db.queryForList("select pg_advisory_xact_lock(hashtextextended('passkey-metadata',0))");
                if (publicationLease != null && db.queryForList("select id from passkey_mds_fetch_state where id=1 and lease_id=? and lease_until>clock_timestamp() for update", publicationLease).isEmpty())
                    throw new IllegalArgumentException("Stale metadata fetch lease");
                var rows = db.queryForList("select * from passkey_metadata_state where id=1");
                Instant accepted = db.queryForObject("select clock_timestamp()", java.sql.Timestamp.class).toInstant();
                checkClock(accepted);
                Instant expires = bundle.expires.isBefore(accepted.plus(maximumAge)) ? bundle.expires : accepted.plus(maximumAge);
                if (!expires.isAfter(accepted))
                    throw new IllegalArgumentException("Expired metadata at database clock");
                if (!rows.isEmpty()) {
                    var old = rows.getFirst();
                    long previousRevision = ((Number) old.get("policy_revision")).longValue();
                    if (revision < previousRevision || revision == previousRevision && !in.configuration.equals(old.get("configuration")))
                        throw new IllegalArgumentException("Stale or inconsistent attestation policy revision");
                    int serial = ((Number) old.get("serial")).intValue();
                    if (bundle.blob.getPayload().getNo() < serial || bundle.blob.getPayload().getNo() == serial && !bundle.digest.equals(old.get("digest")))
                        throw new IllegalArgumentException("Metadata rollback or equivocation");
                    if (bundle.blob.getPayload().getNo() == serial && revision == previousRevision && proof == null)
                        return;
                    if (bundle.blob.getPayload().getNo() == serial) {
                        accepted = ((java.sql.Timestamp) old.get("accepted_at")).toInstant();
                        Instant oldExpiry = ((java.sql.Timestamp) old.get("expires_at")).toInstant();
                        if (proof == null || !(proof.retrieved || proof.confirmed)) {
                            if (oldExpiry.isBefore(expires)) expires = oldExpiry;
                        } else {
                            Instant originalAge = accepted.plus(maximumAge);
                            if (originalAge.isBefore(expires)) expires = originalAge;
                        }
                    }
                }
                db.update("delete from passkey_model_eligibility");
                for (var model : bundle.models.entrySet())
                    db.update("insert into passkey_model_eligibility(aaguid,eligible) values (?,?)", model.getKey(), model.getValue());
                for (var model : bundle.revoked)
                    db.update("insert into passkey_revoked_models(aaguid,first_serial) values (?,?) on conflict do nothing", model, bundle.blob.getPayload().getNo());
                db.update("insert into passkey_metadata_state(id,serial,digest,configuration,policy_revision,required,source,retrieval_cache,evidence_digest,blob,accepted_at,expires_at) values (1,?,?,?,?,?,?,?,?,?,?,?) on conflict(id) do update set serial=excluded.serial,digest=excluded.digest,configuration=excluded.configuration,policy_revision=excluded.policy_revision,required=excluded.required,source=excluded.source,retrieval_cache=excluded.retrieval_cache,evidence_digest=excluded.evidence_digest,blob=excluded.blob,accepted_at=excluded.accepted_at,expires_at=excluded.expires_at", bundle.blob.getPayload().getNo(), bundle.digest, in.configuration, revision, required, source, retrievalCache, TrackedAuthorizationService.digest(retrievalCache), jwt, java.sql.Timestamp.from(accepted), java.sql.Timestamp.from(expires));
            });
            cache = new Cached(in.configuration, bundle.digest, bundle, TrackedAuthorizationService.digest(retrievalCache));
        } finally {
            if (publicationLease != null)
                db.update("update passkey_mds_fetch_state set lease_id=null,lease_until=null,next_fetch_at=greatest(next_fetch_at,clock_timestamp()+(? * interval '1 second')) where id=1 and lease_id=?", Math.max(3600, live.retryAfter), publicationLease);
        }
    }

    public int revokeBatch() {
        var users = db.queryForList("select distinct c.user_id from passkey_credentials c left join passkey_model_eligibility m on m.aaguid=c.attestation_aaguid where c.attestation_aaguid is not null and c.attestation_revoked_at is null and (not coalesce(m.eligible,false) or exists(select 1 from passkey_revoked_models r where r.aaguid=c.attestation_aaguid)) limit 100", String.class);
        int count = 0;
        for (var user : users) {
            Boolean changed = tx.execute(status -> {
                guardReadOnly();
                if (db.queryForList("select pg_try_advisory_xact_lock(hashtextextended(?,0)) as locked", "principal:" + user).stream().noneMatch(r -> Boolean.TRUE.equals(r.get("locked"))))
                    return false;
                // Use the same principal namespace as grant issuance (lockPrincipal also guards namespace changes).
                grants.lockPrincipal(user);
                int updated = db.update("update passkey_credentials c set attestation_revoked_at=clock_timestamp() where c.user_id=? and c.attestation_revoked_at is null and c.attestation_aaguid is not null and (not coalesce((select m.eligible from passkey_model_eligibility m where m.aaguid=c.attestation_aaguid),false) or exists(select 1 from passkey_revoked_models r where r.aaguid=c.attestation_aaguid))", user);
                if (updated == 0) return false;
                grants.revokeUser(user);
                db.update("insert into security_audit_events(id,event_type,subject_id,actor_id) values (?,'PASSKEY_MODEL_REVOKED',?,'metadata-policy')", UUID.randomUUID().toString(), user);
                return true;
            });
            if (Boolean.TRUE.equals(changed)) {
                count++;
                metric("iam.passkey.attestation.users_revoked");
            }
        }
        return count;
    }

    private void guardReadOnly() {
        db.queryForList("select pg_advisory_xact_lock_shared(hashtextextended('passkey-metadata',0))");
    }

    @Scheduled(fixedDelayString = "${iam.passkey.attestation.refresh-delay-ms:60000}", initialDelayString = "${iam.passkey.attestation.initial-delay-ms:1000}")
    public void maintenance() {
        if (!blobFile.isBlank() || source.equals("LIVE")) try {
            refresh();
            metric("iam.passkey.metadata.refresh_success");
        } catch (Exception unavailable) {
            metric("iam.passkey.metadata.refresh_failure");
        }
        try {
            revokeBatch();
        } catch (org.springframework.dao.DataAccessException |
                 org.springframework.transaction.TransactionException unavailable) {
            metric("iam.passkey.metadata.revocation_failure");
        }
    }

    private record Cached(String configuration, String digest, AttestationBundle bundle, String evidence) {
    }

    private record Inputs(Set<X509Certificate> signers, Set<X509Certificate> roots, Collection<CRL> crls,
                          String configuration) {
    }
}
