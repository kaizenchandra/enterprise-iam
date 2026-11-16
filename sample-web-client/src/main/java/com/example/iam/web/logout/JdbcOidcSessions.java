package com.example.iam.web.logout;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionInformation;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionRegistry;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Spring owns protocol parsing/signature validation; JDBC owns atomic invalidation and replay state.
 */
@Component
public class JdbcOidcSessions implements OidcSessionRegistry, LogoutHandler {
    private static final String EVENT = "http://schemas.openid.net/event/backchannel-logout";
    private final JdbcTemplate db;
    private final TransactionTemplate tx;
    private final String issuer, client;

    public JdbcOidcSessions(JdbcTemplate db, PlatformTransactionManager manager, ClientRegistrationRepository clients) {
        this.db = new JdbcTemplate(Objects.requireNonNull(db.getDataSource()));
        this.db.setQueryTimeout(5);
        tx = new TransactionTemplate(manager);
        tx.setTimeout(5);
        var registration = Objects.requireNonNull(clients.findByRegistrationId("iam"));
        issuer = registration.getProviderDetails().getIssuerUri();
        client = registration.getClientId();
    }

    private Instant now() {
        return db.queryForObject("select clock_timestamp()", Timestamp.class).toInstant();
    }

    private void lock() {
        db.queryForList("select pg_advisory_xact_lock(hashtextextended(?,0))", "rp:" + issuer + ":" + client);
    }

    private void require(boolean valid) {
        if (!valid) throw new OAuth2AuthenticationException("invalid_logout_token");
    }

    private String hash(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void saveSessionInformation(OidcSessionInformation information) {
        var user = information.getPrincipal();
        var token = user.getIdToken();
        tx.executeWithoutResult(status -> {
            lock();
            Instant time = now();
            String sid = token.getClaimAsString("sid");
            require(issuer.equals(user.getIssuer().toString()) && user.getAudience().contains(client) && sid != null && !sid.isBlank());
            require(token.getIssuedAt() != null && token.getIssuedAt().isAfter(time.minusSeconds(300)) && !token.getIssuedAt().isAfter(time.plusSeconds(30)));
            db.update("insert into rp_creation_floor(issuer,client_id) values (?,?) on conflict do nothing", issuer, client);
            Instant floor = db.queryForObject("select not_before from rp_creation_floor where issuer=? and client_id=?", Timestamp.class, issuer, client).toInstant();
            require(token.getIssuedAt().isAfter(floor));
            require(db.queryForObject("select count(*) from rp_revoked_sids where issuer=? and client_id=? and sid=?", Integer.class, issuer, client, sid) == 0);
            db.update("""
                    insert into rp_bindings(session_id,issuer,client_id,subject,sid) values (?,?,?,?,?)
                    on conflict(session_id) do update set issuer=excluded.issuer,client_id=excluded.client_id,subject=excluded.subject,sid=excluded.sid
                    """, information.getSessionId(), issuer, client, user.getSubject(), sid);
        });
    }

    public boolean valid(String session) {
        return Boolean.TRUE.equals(db.queryForObject("""
                select exists(select 1 from rp_bindings b where b.session_id=? and b.issuer=? and b.client_id=? and b.expires_at>clock_timestamp()
                  and not exists(select 1 from rp_revoked_sids r where r.issuer=b.issuer and r.client_id=b.client_id and r.sid=b.sid))
                """, Boolean.class, session, issuer, client));
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, org.springframework.security.core.Authentication authentication) {
        try {
            require(authentication.isAuthenticated() && authentication.getPrincipal() instanceof OidcLogoutToken);
            var token = (OidcLogoutToken) authentication.getPrincipal();
            // Extra deployment-profile checks supplement Spring's native signature/issuer/audience/events validation.
            var header = com.nimbusds.jwt.SignedJWT.parse(token.getTokenValue()).getHeader();
            require("RS256".equals(header.getAlgorithm().getName()) && header.getType() != null && "logout+jwt".equals(header.getType().toString()));
            accept(token);
            response.setHeader("Cache-Control", "no-store");
            response.setStatus(200);
        } catch (OAuth2AuthenticationException | java.text.ParseException e) {
            response.setStatus(400);
            response.setHeader("Cache-Control", "no-store");
        } catch (org.springframework.dao.DataAccessException | org.springframework.transaction.TransactionException e) {
            response.setStatus(503);
            response.setHeader("Cache-Control", "no-store");
        }
    }

    public void accept(OidcLogoutToken token) {
        tx.executeWithoutResult(status -> {
            lock();
            Instant time = now();
            String sid = token.getSessionId();
            // In Security 6.5, OidcLogoutToken#getExpiresAt is Instant.MAX; validate the signed exp claim.
            Instant expiry = token.getClaimAsInstant("exp");
            require(issuer.equals(token.getIssuer().toString()) && token.getAudience().equals(List.of(client)));
            require(token.getIssuedAt() != null && expiry != null && !token.getIssuedAt().isAfter(time.plusSeconds(30))
                    && token.getIssuedAt().isAfter(time.minusSeconds(120)) && expiry.isAfter(time)
                    && !expiry.isAfter(token.getIssuedAt().plusSeconds(120)));
            require(token.getId() != null && !token.getId().isBlank() && token.getId().length() <= 100 && sid != null && !sid.isBlank() && sid.length() <= 256);
            require(!token.getClaims().containsKey("nonce") && token.getEvents() != null && token.getEvents().get(EVENT) instanceof Map);
            String digest = hash(token.getTokenValue());
            var receipts = db.queryForList("select fingerprint from rp_logout_receipts where issuer=? and client_id=? and jti=?", issuer, client, token.getId());
            if (!receipts.isEmpty()) {
                require(digest.equals(receipts.getFirst().get("fingerprint")));
                return;
            }
            if (token.getSubject() != null)
                require(db.queryForObject("select count(*) from rp_bindings where issuer=? and client_id=? and sid=? and subject<>?", Integer.class, issuer, client, sid, token.getSubject()) == 0);
            // Keep the tombstone even for an unknown sid: logout may arrive before the login callback.
            db.update("insert into rp_revoked_sids(issuer,client_id,sid) values (?,?,?) on conflict do nothing", issuer, client, sid);
            db.update("""
                    delete from SPRING_SESSION s where s.SESSION_ID in
                      (select b.session_id from rp_bindings b where b.issuer=? and b.client_id=? and b.sid=?)
                    """, issuer, client, sid);
            db.update("delete from rp_bindings where issuer=? and client_id=? and sid=?", issuer, client, sid);
            db.update("insert into rp_logout_receipts(issuer,client_id,jti,fingerprint,expires_at) values (?,?,?,?,?)", issuer, client, token.getId(), digest, Timestamp.from(expiry.plusSeconds(30)));
        });
    }

    @Override
    public OidcSessionInformation removeSessionInformation(String session) {
        db.update("delete from rp_bindings where session_id=? and issuer=? and client_id=?", session, issuer, client);
        return null;
    }

    @Override
    public Iterable<OidcSessionInformation> removeSessionInformation(OidcLogoutToken token) {
        accept(token);
        return List.of();
    }

    @Scheduled(fixedDelayString = "${client.logout.cleanup-delay-ms:60000}", initialDelayString = "${client.logout.cleanup-delay-ms:60000}")
    public void cleanup() {
        try {
            tx.executeWithoutResult(status -> {
                lock();
                db.update("""
                        with old as(select issuer,client_id,jti from rp_logout_receipts where issuer=? and client_id=? and expires_at<=clock_timestamp() limit 100)
                        delete from rp_logout_receipts r using old where r.issuer=old.issuer and r.client_id=old.client_id and r.jti=old.jti
                        """, issuer, client);
                var old = db.queryForList("select sid,revoked_at from rp_revoked_sids where issuer=? and client_id=? and revoked_at<=clock_timestamp()-interval '1 day' order by revoked_at limit 100", issuer, client);
                db.update("insert into rp_creation_floor(issuer,client_id) values (?,?) on conflict do nothing", issuer, client);
                for (var row : old) {
                    db.update("update rp_creation_floor set not_before=greatest(not_before,(select revoked_at+interval '30 seconds' from rp_revoked_sids where issuer=? and client_id=? and sid=?)) where issuer=? and client_id=?", issuer, client, row.get("sid"), issuer, client);
                    db.update("delete from rp_revoked_sids where issuer=? and client_id=? and sid=?", issuer, client, row.get("sid"));
                }
                db.update("with old as(select session_id from rp_bindings where issuer=? and client_id=? and expires_at<=clock_timestamp() limit 100) delete from rp_bindings b using old where b.session_id=old.session_id", issuer, client);
            });
        } catch (RuntimeException e) {
            org.slf4j.LoggerFactory.getLogger(getClass()).warn("RP logout cleanup failed ({})", e.getClass().getSimpleName());
        }
    }
}
