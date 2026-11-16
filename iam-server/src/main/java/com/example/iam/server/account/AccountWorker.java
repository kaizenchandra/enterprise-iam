package com.example.iam.server.account;

import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.Timestamp;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

@Component
public class AccountWorker {
    private final JdbcTemplate db;
    private final TransactionTemplate tx;
    private final AccountSettings settings;
    private final AccountActions actions;
    private final JavaMailSender mail;
    private final MeterRegistry meters;

    public AccountWorker(JdbcTemplate db, PlatformTransactionManager manager, AccountSettings settings, AccountActions actions, JavaMailSender mail, MeterRegistry meters) {
        this.db = new JdbcTemplate(Objects.requireNonNull(db.getDataSource()));
        this.db.setQueryTimeout(5);
        tx = new TransactionTemplate(manager);
        tx.setTimeout(5);
        this.settings = settings;
        this.actions = actions;
        this.mail = mail;
        this.meters = meters;
    }

    @Scheduled(fixedDelayString = "${iam.account.delay-ms:5000}", initialDelayString = "${iam.account.initial-delay-ms:5000}")
    public void scheduled() {
        try {
            runBatch();
        } catch (RuntimeException failure) {
            meters.counter("iam.account.worker.failures").increment();
            org.slf4j.LoggerFactory.getLogger(getClass()).warn("Account maintenance failed ({})", failure.getClass().getSimpleName());
        }
    }

    public void runBatch() {
        cleanup();
        if (!settings.enabled) return;
        for (int i = 0; i < 20; i++) if (!prepare()) break;
        if (!settings.deliveryEnabled) return;
        for (int i = 0; i < 10; i++) {
            var attempt = claim();
            if (attempt == null) break;
            boolean sent = false;
            try {
                boolean eligible = attempt.hash() == null || Boolean.TRUE.equals(db.queryForObject("""
                        select exists(select 1 from account_action_tokens t join users u on u.id=t.user_id where t.token_hash=? and t.consumed_at is null
                          and t.expires_at>clock_timestamp() and t.created_at>u.sessions_not_before and t.user_version=u.version
                          and ((t.kind='RESET' and u.state='ACTIVE' and u.email_verified) or (t.kind='VERIFY' and u.state in ('PENDING_VERIFICATION','ACTIVE') and not u.email_verified)))
                        """, Boolean.class, attempt.hash()));
                if (!eligible) {
                    finish(attempt, false, false);
                    continue;
                }
                var content = settings.open(attempt.envelope());
                var message = new SimpleMailMessage();
                message.setFrom(settings.from);
                message.setTo(content.email());
                message.setSubject("Identity account security");
                message.setText(content.body());
                mail.send(message);
                sent = true;
            } catch (RuntimeException failure) {/* Do not log messages, recipients, SMTP bodies or exception text. */}
            finish(attempt, sent, !sent);
        }
    }

    public boolean prepare() {
        return Boolean.TRUE.equals(tx.execute(status -> {
            var rows = db.queryForList("select * from account_requests where completed_at is null and expires_at>clock_timestamp() and next_attempt_at<=clock_timestamp() order by created_at,id limit 1 for update skip locked");
            if (rows.isEmpty()) return false;
            var row = rows.getFirst();
            String email = settings.open(row.get("envelope").toString()).email();
            var users = db.queryForList("select id from users where email=?", email);
            if (!users.isEmpty()) {
                String user = users.getFirst().get("id").toString();
                if (!Boolean.TRUE.equals(db.queryForObject("select pg_try_advisory_xact_lock(hashtextextended(?,0))", Boolean.class, "principal:" + user))) {
                    db.update("update account_requests set next_attempt_at=clock_timestamp()+interval '1 second' where id=?", row.get("id"));
                    meters.counter("iam.account.prepare.skipped").increment();
                    return true;
                }
                String kind = row.get("kind").toString();
                var eligible = db.queryForList("""
                        select version from users where id=? and email=? and ? > sessions_not_before
                         and ((?='VERIFY' and state in ('PENDING_VERIFICATION','ACTIVE') and not email_verified) or (?='RESET' and state='ACTIVE' and email_verified)) for update
                        """, user, email, row.get("created_at"), kind, kind);
                if (!eligible.isEmpty())
                    actions.issue(user, ((Number) eligible.getFirst().get("version")).longValue(), email, kind, ((Timestamp) row.get("created_at")).toInstant());
            }
            db.update("update account_requests set completed_at=clock_timestamp(),envelope=null where id=?", row.get("id"));
            return true;
        }));
    }

    public Attempt claim() {
        return tx.execute(status -> {
            var rows = db.queryForList("""
                    select * from account_mail where attempts<6 and deadline>clock_timestamp() and
                     ((status='PENDING' and next_attempt_at<=clock_timestamp()) or (status='INFLIGHT' and lease_until<=clock_timestamp()))
                    order by next_attempt_at,id limit 1 for update skip locked
                    """);
            if (rows.isEmpty()) return null;
            var row = rows.getFirst();
            UUID id = (UUID) row.get("id"), lease = UUID.randomUUID();
            db.update("update account_mail set status='INFLIGHT',attempts=attempts+1,lease_id=?,lease_until=clock_timestamp()+interval '30 seconds' where id=?", lease, id);
            return new Attempt(id, lease, (String) row.get("token_hash"), (String) row.get("envelope"), ((Number) row.get("attempts")).intValue() + 1);
        });
    }

    public boolean finish(Attempt a, boolean success, boolean retry) {
        return Boolean.TRUE.equals(tx.execute(status -> {
            boolean terminal = success || !retry || a.attempts() >= 6;
            long delay = ThreadLocalRandom.current().nextLong(1000L, Math.min(300000L, 2000L << a.attempts()));
            int updated = db.update("""
                    update account_mail set status=?,envelope=case when ? then null else envelope end,lease_id=null,lease_until=null,
                     completed_at=case when ? then clock_timestamp() else null end,next_attempt_at=clock_timestamp()+?*interval '1 millisecond'
                    where id=? and status='INFLIGHT' and lease_id=? and lease_until>clock_timestamp()
                    """, success ? "SUCCEEDED" : terminal ? "DEAD" : "PENDING", terminal, terminal, delay, a.id(), a.lease());
            if (updated == 1)
                meters.counter("iam.account.delivery", "outcome", success ? "success" : terminal ? "dead" : "retry").increment();
            return updated == 1;
        }));
    }

    public void cleanup() {
        tx.executeWithoutResult(status -> {
            db.update("""
                    with old as(select id from account_requests where completed_at is null and expires_at<=clock_timestamp() order by expires_at limit 100 for update skip locked)
                    update account_requests r set completed_at=clock_timestamp(),envelope=null from old where r.id=old.id
                    """);
            db.update("""
                    with old as(select id from account_mail where status in ('PENDING','INFLIGHT') and (deadline<=clock_timestamp() or attempts>=6 and (status='PENDING' or lease_until<=clock_timestamp())) order by deadline limit 100 for update skip locked)
                    update account_mail m set status='DEAD',envelope=null,lease_id=null,lease_until=null,completed_at=clock_timestamp() from old where m.id=old.id
                    """);
            db.update("delete from account_mail where id in (select id from account_mail where completed_at<clock_timestamp()-interval '1 day' limit 100)");
            db.update("delete from account_requests where id in (select id from account_requests where completed_at<clock_timestamp()-interval '1 day' limit 100)");
            db.update("delete from account_action_tokens where token_hash in (select t.token_hash from account_action_tokens t where t.expires_at<clock_timestamp()-interval '1 day' and not exists(select 1 from account_mail m where m.token_hash=t.token_hash) limit 100)");
            db.update("delete from account_request_limits where requested_at<clock_timestamp()-interval '1 day' and address_hash in (select address_hash from account_request_limits where requested_at<clock_timestamp()-interval '1 day' limit 100)");
        });
    }

    public record Attempt(UUID id, UUID lease, String hash, String envelope, int attempts) {
    }
}
