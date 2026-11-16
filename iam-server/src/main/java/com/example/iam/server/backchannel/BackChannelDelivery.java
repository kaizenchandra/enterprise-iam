package com.example.iam.server.backchannel;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

@Component
public class BackChannelDelivery {
    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(BackChannelDelivery.class);
    private final JdbcTemplate db;
    private final TransactionTemplate tx;
    private final BackChannelPolicy policy;
    private final RegisteredClientRepository clients;
    private final JwtEncoder encoder;
    private final String issuer;
    private final MeterRegistry meters;
    private final boolean enabled;
    private final int batch, maxAttempts;
    private final HttpClient http = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofSeconds(1)).followRedirects(HttpClient.Redirect.NEVER).build();

    public BackChannelDelivery(JdbcTemplate db, PlatformTransactionManager manager, BackChannelPolicy policy,
                               RegisteredClientRepository clients, JWKSource<SecurityContext> keys, MeterRegistry meters,
                               @Value("${iam.issuer}") String issuer, @Value("${iam.backchannel.enabled:true}") boolean enabled,
                               @Value("${iam.backchannel.batch-size:10}") int batch, @Value("${iam.backchannel.max-attempts:8}") int maxAttempts) {
        if (batch < 1 || batch > 100 || maxAttempts < 1 || maxAttempts > 20)
            throw new IllegalArgumentException("Invalid back-channel limits");
        this.db = new JdbcTemplate(Objects.requireNonNull(db.getDataSource()));
        this.db.setQueryTimeout(5);
        tx = new TransactionTemplate(manager);
        tx.setTimeout(5);
        this.policy = policy;
        this.clients = clients;
        encoder = new NimbusJwtEncoder(keys);
        this.meters = meters;
        this.issuer = issuer;
        this.enabled = enabled;
        this.batch = batch;
        this.maxAttempts = maxAttempts;
    }

    @Scheduled(fixedDelayString = "${iam.backchannel.fixed-delay-ms:1000}", initialDelayString = "${iam.backchannel.initial-delay-ms:1000}")
    public void scheduled() {
        if (enabled) try {
            runBatch();
        } catch (RuntimeException e) {
            meters.counter("iam.logout.worker.failures").increment();
            LOG.warn("Logout delivery batch failed ({})", e.getClass().getSimpleName());
        }
    }

    public int runBatch() {
        // Expired leases at the attempt cap must become terminal, not remain stuck INFLIGHT.
        int exhausted = tx.execute(status -> db.update("""
                with dead as (select id from logout_deliveries where status in ('PENDING','INFLIGHT')
                  and (deadline<=clock_timestamp() or (attempts>=? and (status='PENDING' or lease_until<=clock_timestamp())))
                  order by deadline,id limit ? for update skip locked)
                update logout_deliveries d set status='DEAD',completed_at=clock_timestamp(),lease_id=null,lease_until=null,last_outcome='EXHAUSTED'
                from dead where d.id=dead.id
                """, maxAttempts, batch));
        if (exhausted > 0) meters.counter("iam.logout.delivery", "outcome", "dead").increment(exhausted);
        int delivered = 0;
        for (int i = 0; i < batch; i++) {
            Attempt attempt = claim();
            if (attempt == null) break;
            String outcome;
            boolean success = false, retry = false;
            try {
                var client = clients.findById(attempt.registeredClientId());
                if (client == null || !attempt.endpoint().equals(client.getClientSettings().getSetting(BackChannelSessions.URI_SETTING)))
                    throw new IllegalArgumentException("Registration changed");
                URI endpoint = policy.validate(attempt.endpoint());
                var claims = JwtClaimsSet.builder().issuer(issuer).subject(attempt.subject()).audience(List.of(attempt.clientId()))
                        .issuedAt(attempt.issuedAt()).expiresAt(attempt.issuedAt().plusSeconds(120)).id(attempt.lease())
                        .claim("sid", attempt.sid()).claim("events", Map.of("http://schemas.openid.net/event/backchannel-logout", Map.of())).build();
                String token = encoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).type("logout+jwt").build(), claims)).getTokenValue();
                var request = HttpRequest.newBuilder(endpoint).timeout(Duration.ofSeconds(3)).header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString("logout_token=" + URLEncoder.encode(token, StandardCharsets.UTF_8))).build();
                var response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
                int code;
                // Never wait for an unbounded/malicious response body after the status headers.
                try (var ignored = response.body()) {
                    code = response.statusCode();
                }
                success = code == 200 || code == 204;
                retry = code == 408 || code == 429 || code >= 500;
                outcome = "HTTP_" + code;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return delivered;
            } catch (IllegalArgumentException e) {
                outcome = "CONFIGURATION";
            } catch (Exception e) {
                outcome = "TRANSIENT";
                retry = true;
            }
            if (finish(attempt, success, retry, outcome) && success) delivered++;
        }
        return delivered;
    }

    public Attempt claim() {
        return tx.execute(status -> {
            var rows = db.queryForList("""
                    select d.id from logout_deliveries d where d.attempts<? and d.deadline>clock_timestamp()
                      and ((d.status='PENDING' and d.next_attempt_at<=clock_timestamp()) or (d.status='INFLIGHT' and d.lease_until<=clock_timestamp()))
                    order by d.next_attempt_at,d.id limit 1 for update skip locked
                    """, maxAttempts);
            if (rows.isEmpty()) return null;
            String id = rows.getFirst().get("id").toString(), lease = UUID.randomUUID().toString();
            db.update("update logout_deliveries set status='INFLIGHT',attempts=attempts+1,lease_id=?,claimed_at=clock_timestamp(),lease_until=clock_timestamp()+interval '30 seconds' where id=?", lease, id);
            return db.queryForObject("""
                    select d.*,r.client_id,r.registered_client_id,r.subject,r.sid,r.endpoint from logout_deliveries d
                    join oidc_rp_sessions r on r.id=d.rp_session_id where d.id=?
                    """, (rs, n) -> new Attempt(id, lease, rs.getString("client_id"), rs.getString("registered_client_id"), rs.getString("subject"), rs.getString("sid"), rs.getString("endpoint"), rs.getTimestamp("claimed_at").toInstant(), rs.getInt("attempts")), id);
        });
    }

    public boolean finish(Attempt a, boolean success, boolean retry, String outcome) {
        return Boolean.TRUE.equals(tx.execute(status -> {
            long delay = Math.min(300_000L, 2000L << Math.min(a.attempts() - 1, 8));
            delay = ThreadLocalRandom.current().nextLong(Math.max(1, delay / 2), delay + 1);
            boolean terminal = success || !retry || a.attempts() >= maxAttempts;
            int changed = db.update("""
                    update logout_deliveries set status=?,last_outcome=?,lease_id=null,lease_until=null,
                      completed_at=case when ? then clock_timestamp() else null end,
                      next_attempt_at=clock_timestamp()+(? * interval '1 millisecond')
                    where id=? and status='INFLIGHT' and lease_id=? and lease_until>clock_timestamp()
                    """, success ? "SUCCEEDED" : terminal ? "DEAD" : "PENDING", outcome, terminal, delay, a.id(), a.lease());
            if (changed > 0)
                meters.counter("iam.logout.delivery", "outcome", success ? "success" : terminal ? "dead" : "retry").increment();
            return changed > 0;
        }));
    }

    public record Attempt(String id, String lease, String clientId, String registeredClientId, String subject,
                          String sid, String endpoint, Instant issuedAt, int attempts) {
    }
}
