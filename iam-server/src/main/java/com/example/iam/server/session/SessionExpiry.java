package com.example.iam.server.session;

import com.example.iam.server.token.TrackedAuthorizationService;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Durable expiry does not depend on Redis notifications, availability or retained session objects.
 */
@Component
public class SessionExpiry {
    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(SessionExpiry.class);
    private final JdbcTemplate db;
    private final TransactionTemplate tx;
    private final TrackedAuthorizationService authorizations;
    private final MeterRegistry meters;
    private final boolean enabled;
    private final int batch;

    public SessionExpiry(JdbcTemplate db, PlatformTransactionManager manager, TrackedAuthorizationService authorizations,
                         MeterRegistry meters, @Value("${iam.session.expiry-enabled:true}") boolean enabled,
                         @Value("${iam.session.expiry-batch-size:100}") int batch) {
        if (batch < 1 || batch > 1000) throw new IllegalArgumentException("Session expiry batch must be 1..1000");
        this.db = new JdbcTemplate(java.util.Objects.requireNonNull(db.getDataSource()));
        this.db.setQueryTimeout(5);
        tx = new TransactionTemplate(manager);
        tx.setTimeout(5);
        tx.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.authorizations = authorizations;
        this.meters = meters;
        this.enabled = enabled;
        this.batch = batch;
    }

    @Scheduled(fixedDelayString = "${iam.session.expiry-fixed-delay-ms:5000}", initialDelayString = "${iam.session.expiry-initial-delay-ms:5000}")
    public void scheduled() {
        if (!enabled) return;
        try {
            runBatch();
        } catch (RuntimeException e) {
            LOG.warn("Session expiry batch failed ({})", e.getClass().getSimpleName());
        }
    }

    public int runBatch() {
        var timer = Timer.start(meters);
        int expired = 0;
        try {
            var candidates = db.queryForList("""
                    select id,principal_name from identity_sessions
                    where revoked_at is null and least(expires_at,idle_expires_at)<=clock_timestamp()
                    order by least(expires_at,idle_expires_at),id limit ?
                    """, batch);
            for (var candidate : candidates) {
                String reason = tx.execute(status -> {
                    String principal = candidate.get("principal_name").toString();
                    boolean locked = Boolean.TRUE.equals(db.queryForObject(
                            "select pg_try_advisory_xact_lock(hashtextextended(?,0))", Boolean.class, "principal:" + principal));
                    if (!locked) {
                        meters.counter("iam.session.expiry.skipped", "reason", "principal_busy").increment();
                        return null;
                    }
                    return authorizations.expireSessionIfDue(candidate.get("id").toString(), principal);
                });
                if (reason != null) {
                    expired++;
                    meters.counter("iam.session.expired", "reason", reason).increment();
                }
            }
            return expired;
        } catch (RuntimeException e) {
            meters.counter("iam.session.expiry.failures").increment();
            throw e;
        } finally {
            timer.stop(meters.timer("iam.session.expiry.duration"));
        }
    }
}
