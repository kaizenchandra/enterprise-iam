package com.example.iam.server.client;

import com.example.iam.server.token.TrackedAuthorizationService;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.Timestamp;
import java.time.Instant;

@Service
public class ClientAssertionReplayStore {
    private final JdbcTemplate db;
    private final TransactionTemplate tx;
    private final MeterRegistry meters;
    private final int batchSize;

    public ClientAssertionReplayStore(JdbcTemplate db, PlatformTransactionManager manager, MeterRegistry meters) {
        this(db, manager, meters, 1000);
    }

    @org.springframework.beans.factory.annotation.Autowired
    public ClientAssertionReplayStore(JdbcTemplate db, PlatformTransactionManager manager, MeterRegistry meters,
                                      @org.springframework.beans.factory.annotation.Value("${iam.client-assertion.cleanup-batch-size:1000}") int batchSize) {
        if (batchSize < 1 || batchSize > 10000)
            throw new IllegalArgumentException("Assertion cleanup batch must be 1..10000");
        this.batchSize = batchSize;
        this.db = db;
        this.meters = meters;
        tx = new TransactionTemplate(manager);
        tx.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        tx.setTimeout(3);
    }

    public boolean claim(String clientId, String jti, Instant issued, Instant expires) {
        if (jti == null || !jti.matches("[A-Za-z0-9_-]{16,128}") || issued == null || expires == null
                || !expires.isAfter(issued) || expires.isAfter(issued.plusSeconds(60))) return false;
        // Recheck authoritative time in the same statement as the claim; cleanup cannot resurrect an expired assertion.
        boolean claimed = Boolean.TRUE.equals(tx.execute(status -> {
            int inserted = db.update("""
                            insert into client_assertion_replays(client_id,jti_hash,expires_at)
                            select ?,?,? where ? > clock_timestamp()-interval '5 seconds'
                              and ? <= clock_timestamp()+interval '5 seconds' and ? >= clock_timestamp()-interval '65 seconds'
                            on conflict do nothing
                            """, clientId, TrackedAuthorizationService.digest(jti), Timestamp.from(expires.plusSeconds(5)),
                    Timestamp.from(expires), Timestamp.from(issued), Timestamp.from(issued));
            if (inserted != 1) return false;
            // INSERT may wait on a unique-index/trigger lock after evaluating WHERE. Cleanup must not admit that stale writer.
            Instant now = db.queryForObject("select clock_timestamp()", Timestamp.class).toInstant();
            if (!expires.plusSeconds(5).isAfter(now) || issued.isAfter(now.plusSeconds(5)) || issued.isBefore(now.minusSeconds(65))) {
                status.setRollbackOnly();
                return false;
            }
            return true;
        }));
        meters.counter("iam.client.assertion", "outcome", claimed ? "accepted" : "rejected").increment();
        return claimed;
    }

    public int cleanup() {
        int count = tx.execute(status -> db.update("""
                with old as(select client_id,jti_hash from client_assertion_replays where expires_at<clock_timestamp()
                  order by expires_at limit ? for update skip locked)
                delete from client_assertion_replays r using old where r.client_id=old.client_id and r.jti_hash=old.jti_hash
                """, batchSize));
        meters.counter("iam.client.assertion.cleaned").increment(count);
        return count;
    }
}
