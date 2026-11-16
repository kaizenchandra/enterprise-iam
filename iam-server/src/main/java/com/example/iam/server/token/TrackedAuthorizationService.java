package com.example.iam.server.token;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * Framework persistence plus monotonic lifecycle fencing; never a parallel token store.
 */
public class TrackedAuthorizationService implements OAuth2AuthorizationService {
    public static final String REVISION = "iam.lifecycle.revision";
    public static final String SESSION = "iam.lifecycle.session";
    private final JdbcOAuth2AuthorizationService delegate;
    private final JdbcTemplate db;
    private final RegisteredClientRepository clients;
    private final TransactionTemplate tx;
    private final Duration familyLifetime;
    private final com.example.iam.server.session.SessionLifetime sessionLifetime;
    private final com.example.iam.server.backchannel.BackChannelSessions backchannel;
    @org.springframework.beans.factory.annotation.Value("${iam.mfa.required:false}")
    private boolean mfaRequired;

    public TrackedAuthorizationService(JdbcTemplate db, RegisteredClientRepository clients,
                                       PlatformTransactionManager transactions, Duration familyLifetime) {
        this(db, clients, transactions, familyLifetime, com.example.iam.server.session.SessionLifetime.defaults());
    }

    public TrackedAuthorizationService(JdbcTemplate db, RegisteredClientRepository clients,
                                       PlatformTransactionManager transactions, Duration familyLifetime,
                                       com.example.iam.server.session.SessionLifetime sessionLifetime) {
        this.sessionLifetime = java.util.Objects.requireNonNull(sessionLifetime);
        if (familyLifetime.isNegative() || familyLifetime.isZero()) {
            throw new IllegalArgumentException("Family lifetime must be positive");
        }
        this.db = db;
        this.clients = clients;
        this.backchannel = new com.example.iam.server.backchannel.BackChannelSessions(db, clients);
        this.delegate = new JdbcOAuth2AuthorizationService(db, clients);
        this.tx = new TransactionTemplate(transactions);
        this.tx.setTimeout(10);
        this.familyLifetime = familyLifetime;
    }

    public static String digest(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private <T> T transaction(Supplier<T> action) {
        // A protocol envelope owns the transaction when present. Avoid marking it rollback-only
        // when a provider catches a deliberately rejected stale save and emits invalid_grant.
        return TransactionSynchronizationManager.isActualTransactionActive()
                ? action.get() : tx.execute(status -> action.get());
    }

    public void lockPrincipal(String principal) {
        if (!TransactionSynchronizationManager.isActualTransactionActive())
            throw new IllegalStateException("Principal locks require a transaction");
        db.queryForList("select pg_advisory_xact_lock(hashtextextended(?,0))", "principal:" + principal);
    }

    public Instant now() {
        return db.queryForObject("select clock_timestamp()", Timestamp.class).toInstant();
    }

    private String browserSession(String principal) {
        if (!(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes)) {
            return null;
        }
        HttpServletRequest request = attributes.getRequest();
        var authentication = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || !principal.equals(authentication.getName())) {
            return null;
        }
        var session = request.getSession(false);
        if (session == null) return null;
        String id;
        synchronized (session) {
            id = (String) session.getAttribute(SESSION);
            if (id == null) {
                id = digest(session.getId()).substring(0, 32);
                session.setAttribute(SESSION, id);
            }
        }
        return id;
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        transaction(() -> {
            String principal = authorization.getPrincipalName();
            if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(authorization.getAuthorizationGrantType())) {
                var client = clients.findById(authorization.getRegisteredClientId());
                if (client == null) throw invalidGrant();
                principal = "client:" + client.getClientId();
            }
            lockPrincipal(principal);
            // Suspension and token persistence use the same principal lock and transaction.
            if (!invalidatedTokens(authorization) && !AuthorizationGrantType.CLIENT_CREDENTIALS.equals(authorization.getAuthorizationGrantType())) {
                var users = db.queryForList("select state from users where id=?", principal);
                if (users.isEmpty() || !"ACTIVE".equals(users.getFirst().get("state"))) throw invalidGrant();
            }
            Instant time = now();
            var rows = db.queryForList("select * from authorization_lifecycle where id=? for update", authorization.getId());
            String sessionId;
            long revision;
            Instant deadline;
            if (rows.isEmpty()) {
                // A saved lifecycle version must never recreate a deleted lifecycle record.
                if (authorization.getAttribute(REVISION) != null) throw invalidGrant();
                checkBirth(initialBirth(authorization), time);
                sessionId = AuthorizationGrantType.CLIENT_CREDENTIALS.equals(authorization.getAuthorizationGrantType())
                        ? null : browserSession(principal);
                if (sessionId == null && !AuthorizationGrantType.CLIENT_CREDENTIALS.equals(authorization.getAuthorizationGrantType()))
                    throw invalidGrant();
                if (sessionId != null && (!sessionCanAuthorize(sessionId, principal) || !sessionAssured(sessionId, principal)))
                    throw invalidGrant();
                deadline = time.plus(familyLifetime);
                revision = 0;
                db.update("""
                                insert into authorization_lifecycle(id,principal_name,client_id,session_id,created_at,expires_at,grant_expires_at,revision)
                                values (?,?,?,?,?,?,?,0)
                                """, authorization.getId(), principal, authorization.getRegisteredClientId(), sessionId,
                        Timestamp.from(time), Timestamp.from(deadline), Timestamp.from(deadline));
            } else {
                var row = rows.getFirst();
                if (!principal.equals(row.get("principal_name"))
                        || !authorization.getRegisteredClientId().equals(row.get("client_id"))) throw invalidGrant();
                // Revocation remains idempotent across generation changes, expiry and prior revocation.
                if (invalidatedTokens(authorization)) {
                    revokeLocked(authorization.getId());
                    return null;
                }
                if (row.get("revoked_at") != null) throw invalidGrant();
                deadline = db.queryForObject("select expires_at from authorization_lifecycle where id=?", Timestamp.class, authorization.getId()).toInstant();
                Instant grantExpiry = db.queryForObject("select grant_expires_at from authorization_lifecycle where id=?", Timestamp.class, authorization.getId()).toInstant();
                if (!time.isBefore(deadline) || !time.isBefore(grantExpiry)) throw invalidGrant();
                sessionId = (String) row.get("session_id");
                revision = ((Number) row.get("revision")).longValue();
                String expected = authorization.getAttribute(REVISION);
                if (expected == null || !Long.toString(revision).equals(expected)) throw invalidGrant();
            }
            if (sessionId != null && (!sessionActive(sessionId, principal)
                    || (rows.isEmpty() && !sessionCanAuthorize(sessionId, principal)))) throw invalidGrant();
            if (sessionId != null && !sessionAssured(sessionId, principal)) throw invalidGrant();
            var builder = OAuth2Authorization.from(authorization).principalName(principal)
                    .attribute(REVISION, Long.toString(revision + 1));
            if (sessionId != null) builder.attribute(SESSION, sessionId);
            if (authorization.getRefreshToken() != null) {
                var token = authorization.getRefreshToken();
                Instant expiry = token.getToken().getExpiresAt();
                if (expiry == null || expiry.isAfter(deadline)) expiry = deadline;
                builder.token(new OAuth2RefreshToken(token.getToken().getTokenValue(),
                        token.getToken().getIssuedAt(), expiry), metadata -> metadata.putAll(token.getMetadata()));
            }
            var saved = builder.build();
            Instant grantExpiry = grantExpiry(saved, deadline);
            if (!time.isBefore(grantExpiry)) throw invalidGrant();
            backchannel.remember(saved, sessionId);
            delegate.save(saved);
            db.update("update authorization_lifecycle set revision=?,grant_expires_at=? where id=?", revision + 1, Timestamp.from(grantExpiry), authorization.getId());
            if (authorization.getRefreshToken() != null) {
                db.update("""
                                insert into refresh_history(token_hash,authorization_id,client_id) values (?,?,?)
                                on conflict (token_hash) do nothing
                                """, digest(authorization.getRefreshToken().getToken().getTokenValue()),
                        authorization.getId(), authorization.getRegisteredClientId());
            }
            return null;
        });
    }

    private Instant initialBirth(OAuth2Authorization authorization) {
        OAuth2AuthorizationRequest request = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
        if (request != null && request.getAdditionalParameters().get(AuthorizationBirthConverter.BIRTH) instanceof String birth) {
            try {
                return Instant.parse(birth);
            } catch (java.time.format.DateTimeParseException ignored) {
                throw invalidGrant();
            }
        }
        if (authorization.getToken(OAuth2AuthorizationCode.class) != null)
            return authorization.getToken(OAuth2AuthorizationCode.class).getToken().getIssuedAt();
        if (authorization.getAccessToken() != null) return authorization.getAccessToken().getToken().getIssuedAt();
        throw invalidGrant();
    }

    private void checkBirth(Instant birth, Instant time) {
        // Shared floor lock and cleanup's exclusive floor lock make check + insert atomic with GC.
        Instant floor = db.queryForObject("select initial_not_before from authorization_retention_state where singleton=true for share", Timestamp.class).toInstant();
        if (birth == null || !birth.isAfter(floor) || birth.isAfter(time.plusSeconds(60))) throw invalidGrant();
    }

    private Instant grantExpiry(OAuth2Authorization authorization, Instant deadline) {
        Instant latest = null;
        for (Class<? extends OAuth2Token> type : java.util.List.of(OAuth2AuthorizationCode.class,
                OAuth2AccessToken.class, OAuth2RefreshToken.class, org.springframework.security.oauth2.core.oidc.OidcIdToken.class)) {
            var token = authorization.getToken(type);
            if (token != null && !token.isInvalidated() && token.getToken().getExpiresAt() != null) {
                Instant expiry = token.getToken().getExpiresAt();
                if (latest == null || expiry.isAfter(latest)) latest = expiry;
            }
        }
        // Pending consent has no issued token; its state is bounded by the family deadline.
        return latest == null || latest.isAfter(deadline) ? deadline : latest;
    }

    public void registerSession(String session, String principal, Instant birth) {
        transaction(() -> {
            lockPrincipal(principal);
            Instant time = now();
            checkBirth(birth, time);
            if (!Boolean.TRUE.equals(db.queryForObject("select state='ACTIVE' and ? > sessions_not_before from users where id=?",
                    Boolean.class, Timestamp.from(birth), principal))) throw invalidGrant();
            db.update("""
                            insert into identity_sessions(id,principal_name,created_at,expires_at,idle_expires_at,idle_timeout_seconds)
                            values (?,?,?,?,?,?) on conflict do nothing
                            """, session, principal, Timestamp.from(time), Timestamp.from(time.plus(sessionLifetime.absoluteTimeout())),
                    Timestamp.from(time.plus(sessionLifetime.idleTimeout())), sessionLifetime.idleTimeout().toSeconds());
            if (!sessionCanAuthorize(session, principal)) throw invalidGrant();
            return null;
        });
    }

    private boolean sessionCanAuthorize(String session, String principal) {
        return Boolean.TRUE.equals(db.queryForObject("""
                select exists(select 1 from identity_sessions where id=? and principal_name=? and revoked_at is null and expires_at>clock_timestamp() and idle_expires_at>clock_timestamp())
                """, Boolean.class, session, principal));
    }

    public boolean sessionAssured(String session, String principal) {
        return Boolean.TRUE.equals(db.queryForObject("""
                select exists(select 1 from identity_sessions s where s.id=? and s.principal_name=?
                  and s.revoked_at is null and least(s.expires_at,s.idle_expires_at)>clock_timestamp()
                  and (s.mfa_verified_at is not null or (not ? and not exists(select 1 from mfa_credentials m where m.user_id=s.principal_name and m.enabled))))
                """, Boolean.class, session, principal, mfaRequired));
    }

    private boolean invalidatedTokens(OAuth2Authorization authorization) {
        return (authorization.getRefreshToken() != null && authorization.getRefreshToken().isInvalidated())
                || (authorization.getAccessToken() != null && authorization.getAccessToken().isInvalidated());
    }

    public boolean sessionActive(String session, String principal) {
        return sessionCanAuthorize(session, principal);
    }

    public boolean sessionRevoked(String session, String principal) {
        return Boolean.TRUE.equals(db.queryForObject("""
                select not exists(select 1 from identity_sessions where id=? and principal_name=? and revoked_at is null and expires_at>clock_timestamp() and idle_expires_at>clock_timestamp())
                """, Boolean.class, session, principal));
    }

    private void revokeLocked(String id) {
        db.update("update authorization_lifecycle set revoked_at=coalesce(revoked_at,clock_timestamp()),revision=revision+1 where id=?", id);
        db.update("delete from oauth2_authorization where id=?", id);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        transaction(() -> {
            lockPrincipal(authorization.getPrincipalName());
            // remove may race a previously read authorization; tombstone survives all stale saves.
            revokeLocked(authorization.getId());
            return null;
        });
    }

    /**
     * A browser heartbeat never extends a deadline that has already passed.
     */
    public boolean touchSession(String session, String principal) {
        return transaction(() -> {
            lockPrincipal(principal);
            int updated = db.update("""
                    update identity_sessions s set last_seen_at=greatest(last_seen_at,clock_timestamp()),idle_expires_at=least(expires_at,
                        greatest(idle_expires_at,clock_timestamp()+idle_timeout_seconds*interval '1 second'))
                    where id=? and principal_name=? and revoked_at is null
                      and expires_at>clock_timestamp() and idle_expires_at>clock_timestamp()
                      and exists(select 1 from users u where u.id=s.principal_name and u.state='ACTIVE')
                    """, session, principal);
            if (updated == 1) return true;
            expireSessionIfDue(session, principal);
            return false;
        });
    }

    /**
     * Returns the expiry reason only for the transaction that wins revocation.
     */
    public String expireSessionIfDue(String session, String principal) {
        return transaction(() -> {
            lockPrincipal(principal);
            var rows = db.queryForList("""
                    select case when expires_at<=idle_expires_at then 'ABSOLUTE' else 'IDLE' end as reason
                    from identity_sessions where id=? and principal_name=? and revoked_at is null
                      and least(expires_at,idle_expires_at)<=clock_timestamp() for update
                    """, session, principal);
            if (rows.isEmpty()) return null;
            String reason = rows.getFirst().get("reason").toString();
            db.update("update identity_sessions set revoked_at=clock_timestamp() where id=?", session);
            revokeSessionGrants(session, principal);
            db.update("insert into security_audit_events(id,event_type,subject_id) values (?,?,?)",
                    UUID.randomUUID().toString(), "SESSION_" + reason + "_EXPIRED", principal);
            return reason;
        });
    }

    private void revokeSessionGrants(String session, String principal) {
        backchannel.enqueueSession(session, principal);
        db.update("""
                update authorization_lifecycle set revoked_at=clock_timestamp(),revision=revision+1
                where session_id=? and principal_name=? and revoked_at is null
                """, session, principal);
        db.update("""
                delete from oauth2_authorization o using authorization_lifecycle a
                where o.id=a.id and a.session_id=? and a.principal_name=?
                """, session, principal);
    }

    public void revokeSession(String session, String principal) {
        transaction(() -> {
            lockPrincipal(principal);
            int changed = db.update("""
                    insert into identity_sessions(id,principal_name,revoked_at) values (?,?,clock_timestamp())
                    on conflict(id) do update set revoked_at=excluded.revoked_at
                    where identity_sessions.principal_name=excluded.principal_name and identity_sessions.revoked_at is null
                    """, session, principal);
            if (changed == 0) return null;
            revokeSessionGrants(session, principal);
            db.update("insert into security_audit_events(id,event_type,subject_id) values (?,'SESSION_REVOKED',?)", UUID.randomUUID().toString(), principal);
            return null;
        });
    }

    public void revokeUser(String principal) {
        transaction(() -> {
            lockPrincipal(principal);
            db.update("update users set sessions_not_before=greatest(sessions_not_before,clock_timestamp()) where id=?", principal);
            var sessions = db.queryForList("select id from identity_sessions where principal_name=? and revoked_at is null for update", principal);
            db.update("update identity_sessions set revoked_at=clock_timestamp() where principal_name=? and revoked_at is null", principal);
            for (var session : sessions) backchannel.enqueueSession(session.get("id").toString(), principal);
            db.update("update authorization_lifecycle set revoked_at=clock_timestamp(),revision=revision+1 where principal_name=? and revoked_at is null", principal);
            db.update("delete from oauth2_authorization where principal_name=?", principal);
            return null;
        });
    }

    private OAuth2Authorization eligible(OAuth2Authorization authorization) {
        if (authorization == null) return null;
        Boolean active = db.queryForObject("""
                select exists(select 1 from authorization_lifecycle a
                  left join identity_sessions s on s.id=a.session_id
                  where a.id=? and a.revoked_at is null and a.expires_at>clock_timestamp() and a.grant_expires_at>clock_timestamp()
                  and (a.session_id is null or (s.id is not null and s.revoked_at is null
                    and s.expires_at>clock_timestamp() and s.idle_expires_at>clock_timestamp()
                    and (s.mfa_verified_at is not null or not exists(select 1 from mfa_credentials m where m.user_id=s.principal_name and m.enabled)))))
                """, Boolean.class, authorization.getId());
        return Boolean.TRUE.equals(active) ? authorization : null;
    }

    @Override
    public OAuth2Authorization findById(String id) {
        return eligible(delegate.findById(id));
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType type) {
        return eligible(delegate.findByToken(token, type));
    }

    private OAuth2AuthenticationException invalidGrant() {
        return new OAuth2AuthenticationException(new OAuth2Error("invalid_grant"));
    }
}
