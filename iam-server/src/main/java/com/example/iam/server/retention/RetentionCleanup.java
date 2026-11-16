package com.example.iam.server.retention;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Small independent transactions, nonblocking principal locks and a durable GC floor.
 * No request/thread, history row or session can recreate deleted lifecycle state.
 */
@Service
public class RetentionCleanup {
    private final JdbcTemplate db;
    private final TransactionTemplate tx;
    private final RetentionProperties properties;
    private final MeterRegistry meters;
    private final AtomicLong lastSuccess = new AtomicLong();

    public RetentionCleanup(JdbcTemplate db, PlatformTransactionManager manager,
                            RetentionProperties properties, MeterRegistry meters) {
        this.db = new JdbcTemplate(java.util.Objects.requireNonNull(db.getDataSource()));
        this.db.setQueryTimeout(5);
        this.properties = properties;
        this.meters = meters;
        tx = new TransactionTemplate(manager);
        tx.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        tx.setTimeout(5);
        meters.gauge("iam.retention.last.success.epoch.seconds", lastSuccess);
    }

    public Result runBatch() {
        var sample = Timer.start(meters);
        try {
            Instant now = db.queryForObject("select clock_timestamp()", Timestamp.class).toInstant();
            Timestamp cutoff = Timestamp.from(now.minus(properties.afterExpiry()));
            int grants = 0, history = 0, orphans = 0, lifecycles = 0, sessions = 0;
            int expiredDeliveries = tx.execute(status -> db.update("""
                    with overdue as(select id from logout_deliveries where status in ('PENDING','INFLIGHT') and deadline<=clock_timestamp()
                      order by deadline,id limit ? for update skip locked)
                    update logout_deliveries d set status='DEAD',completed_at=clock_timestamp(),lease_id=null,lease_until=null,last_outcome='DEADLINE'
                    from overdue where d.id=overdue.id
                    """, properties.batchSize()));
            if (expiredDeliveries > 0)
                meters.counter("iam.logout.delivery", "outcome", "dead").increment(expiredDeliveries);
            int deliveries = count("logout_deliveries", tx.execute(status -> db.update("""
                    with old as (select id from logout_deliveries where status in ('SUCCEEDED','DEAD') and completed_at<=?
                      order by completed_at,id limit ? for update skip locked)
                    delete from logout_deliveries d using old where d.id=old.id
                    """, cutoff, properties.batchSize())));
            for (var candidate : candidates("""
                    select a.id,a.principal_name from authorization_lifecycle a
                    where (a.grant_expires_at<=clock_timestamp() or a.expires_at<=clock_timestamp() or a.revoked_at is not null)
                      and exists(select 1 from oauth2_authorization o where o.id=a.id)
                    order by a.grant_expires_at,a.id limit ?
                    """, properties.batchSize()))
                grants += count("grants", tx.execute(status -> retireGrant(candidate)));
            for (var candidate : candidates("""
                    select h.token_hash as id,a.principal_name from authorization_lifecycle a
                    join refresh_history h on h.authorization_id=a.id where a.expires_at<=?
                    order by a.expires_at,a.id,h.token_hash limit ?
                    """, cutoff, properties.batchSize()))
                history += count("history", tx.execute(status -> purgeHistory(candidate, cutoff)));
            for (String hash : db.queryForList("""
                    select h.token_hash from refresh_history h where h.created_at<=?
                      and not exists(select 1 from authorization_lifecycle a where a.id=h.authorization_id)
                    order by h.created_at,h.token_hash limit ?
                    """, String.class, cutoff, properties.batchSize()))
                orphans += count("orphan_history", tx.execute(status -> purgeOrphan(hash, cutoff)));
            for (var candidate : candidates("""
                    select a.id,a.principal_name from authorization_lifecycle a where a.expires_at<=?
                      and not exists(select 1 from oauth2_authorization o where o.id=a.id)
                      and not exists(select 1 from refresh_history h where h.authorization_id=a.id)
                      and not exists(select 1 from logout_deliveries d join oidc_rp_sessions r on r.id=d.rp_session_id where r.session_id=a.session_id)
                    order by a.expires_at,a.id limit ?
                    """, cutoff, properties.batchSize()))
                lifecycles += count("lifecycles", tx.execute(status -> purgeLifecycle(candidate, cutoff)));
            int participants = 0;
            for (var candidate : candidates("""
                    select r.id,s.principal_name from oidc_rp_sessions r join identity_sessions s on s.id=r.session_id
                    where s.revoked_at is not null and s.expires_at<=? and not exists(select 1 from authorization_lifecycle a where a.session_id=s.id)
                      and not exists(select 1 from logout_deliveries d where d.rp_session_id=r.id)
                    order by s.expires_at,r.id limit ?
                    """, cutoff, properties.batchSize()))
                participants += count("logout_participants", tx.execute(status -> {
                    if (!principal(candidate)) return 0;
                    return db.update("""
                            delete from oidc_rp_sessions r using identity_sessions s where r.id=? and s.id=r.session_id and s.revoked_at is not null and s.expires_at<=?
                              and not exists(select 1 from authorization_lifecycle a where a.session_id=s.id)
                              and not exists(select 1 from logout_deliveries d where d.rp_session_id=r.id)
                            """, candidate.id(), cutoff);
                }));
            for (var candidate : candidates("""
                    select s.id,s.principal_name from identity_sessions s where s.revoked_at is not null and s.expires_at<=?
                      and not exists(select 1 from authorization_lifecycle a where a.session_id=s.id)
                      and not exists(select 1 from oidc_rp_sessions r where r.session_id=s.id)
                      and not exists(select 1 from logout_deliveries d join oidc_rp_sessions r on r.id=d.rp_session_id where r.session_id=s.id)
                    order by s.expires_at,s.id limit ?
                    """, cutoff, properties.batchSize()))
                sessions += count("sessions", tx.execute(status -> purgeSession(candidate, cutoff)));
            lastSuccess.set(Instant.now().getEpochSecond());
            return new Result(grants, history, orphans, lifecycles, sessions, deliveries, participants, expiredDeliveries);
        } catch (RuntimeException e) {
            meters.counter("iam.retention.failures").increment();
            throw e;
        } finally {
            sample.stop(meters.timer("iam.retention.duration"));
        }
    }

    private List<Candidate> candidates(String sql, Object... parameters) {
        return db.query(sql, (rs, row) -> new Candidate(rs.getString("id"), rs.getString("principal_name")), parameters);
    }

    private int count(String kind, int count) {
        meters.counter("iam.retention.deleted", "kind", kind).increment(count);
        return count;
    }

    private boolean principal(Candidate candidate) {
        boolean locked = Boolean.TRUE.equals(db.queryForObject("select pg_try_advisory_xact_lock(hashtextextended(?,0))",
                Boolean.class, "principal:" + candidate.principal()));
        if (!locked) meters.counter("iam.retention.skipped", "reason", "principal_busy").increment();
        return locked;
    }

    private boolean floor() {
        // Writers checking the floor use FOR SHARE. Never wait while holding a GC floor lock.
        boolean locked = !db.queryForList("select singleton from authorization_retention_state where singleton=true for update skip locked").isEmpty();
        if (!locked) meters.counter("iam.retention.skipped", "reason", "floor_busy").increment();
        return locked;
    }

    private int retireGrant(Candidate candidate) {
        if (!principal(candidate)) return 0;
        int deleted = db.update("""
                delete from oauth2_authorization o using authorization_lifecycle a
                where o.id=? and a.id=o.id and
                  (a.grant_expires_at<=clock_timestamp() or a.expires_at<=clock_timestamp() or a.revoked_at is not null)
                """, candidate.id());
        if (deleted > 0) db.update("""
                update authorization_lifecycle set revoked_at=coalesce(revoked_at,clock_timestamp()),revision=revision+1 where id=?
                """, candidate.id());
        return deleted;
    }

    private int purgeHistory(Candidate candidate, Timestamp cutoff) {
        if (!principal(candidate)) return 0;
        return db.update("""
                delete from refresh_history h using authorization_lifecycle a
                where h.token_hash=? and a.id=h.authorization_id and a.expires_at<=?
                """, candidate.id(), cutoff);
    }

    private int purgeOrphan(String hash, Timestamp cutoff) {
        if (db.queryForList("select token_hash from refresh_history where token_hash=? for update skip locked", hash).isEmpty())
            return 0;
        return db.update("""
                delete from refresh_history h where h.token_hash=? and h.created_at<=?
                  and not exists(select 1 from authorization_lifecycle a where a.id=h.authorization_id)
                """, hash, cutoff);
    }

    private int purgeLifecycle(Candidate candidate, Timestamp cutoff) {
        if (!floor() || !principal(candidate)) return 0;
        var rows = db.queryForList("""
                select created_at from authorization_lifecycle a where a.id=? and a.expires_at<=?
                  and not exists(select 1 from oauth2_authorization o where o.id=a.id)
                  and not exists(select 1 from refresh_history h where h.authorization_id=a.id)
                      and not exists(select 1 from logout_deliveries d join oidc_rp_sessions r on r.id=d.rp_session_id where r.session_id=a.session_id) for update
                """, candidate.id(), cutoff);
        if (rows.isEmpty()) return 0;
        advanceFloor("authorization_lifecycle", candidate.id());
        return db.update("delete from authorization_lifecycle where id=?", candidate.id());
    }

    private int purgeSession(Candidate candidate, Timestamp cutoff) {
        if (!floor() || !principal(candidate)) return 0;
        var rows = db.queryForList("""
                select created_at from identity_sessions s where s.id=? and s.revoked_at is not null and s.expires_at<=?
                  and not exists(select 1 from authorization_lifecycle a where a.session_id=s.id)
                      and not exists(select 1 from oidc_rp_sessions r where r.session_id=s.id)
                      and not exists(select 1 from logout_deliveries d join oidc_rp_sessions r on r.id=d.rp_session_id where r.session_id=s.id) for update
                """, candidate.id(), cutoff);
        if (rows.isEmpty()) return 0;
        advanceFloor("identity_sessions", candidate.id());
        return db.update("delete from identity_sessions where id=?", candidate.id());
    }

    private void advanceFloor(String table, String id) {
        // Table is an internal constant, never a caller-controlled identifier.
        db.update("update authorization_retention_state set initial_not_before=greatest(initial_not_before,"
                + "(select created_at+interval '1 minute' from " + table + " where id=?)) where singleton=true", id);
    }

    private record Candidate(String id, String principal) {
    }

    public record Result(int grants, int history, int orphanHistory, int lifecycles, int sessions, int deliveries,
                         int participants, int expiredDeliveries) {
    }
}
