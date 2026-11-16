package com.example.iam.server.session;

import com.example.iam.server.token.TrackedAuthorizationService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * OP sessions are global identities: tenant roles never authorize global session administration.
 */
@RestController
public class SessionManagementController {
    private final JdbcTemplate db;
    private final TrackedAuthorizationService authorizations;

    public SessionManagementController(JdbcTemplate db, TrackedAuthorizationService authorizations) {
        this.db = new JdbcTemplate(Objects.requireNonNull(db.getDataSource()));
        this.db.setQueryTimeout(5);
        this.authorizations = authorizations;
    }

    private void locks(String... subjects) {
        Arrays.stream(subjects).distinct().sorted().forEach(authorizations::lockPrincipal);
    }

    private String live(JwtAuthenticationToken identity, boolean human) {
        var grant = authorizations.findByToken(identity.getToken().getTokenValue(), OAuth2TokenType.ACCESS_TOKEN);
        if (grant == null || !identity.getName().equals(grant.getPrincipalName()))
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        if (human && (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(grant.getAuthorizationGrantType())
                || !Boolean.TRUE.equals(db.queryForObject("select exists(select 1 from users where id=? and state='ACTIVE')", Boolean.class, identity.getName()))))
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        String session = grant.getAttribute(TrackedAuthorizationService.SESSION);
        if (human && session == null) throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        return session;
    }

    @GetMapping("/api/v1/users/me/sessions")
    @Transactional(timeout = 10)
    public Page list(JwtAuthenticationToken identity, @RequestParam(defaultValue = "50") @Min(1) @Max(100) int limit,
                     @RequestParam(required = false) UUID after, HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        locks(identity.getName());
        String current = live(identity, true);
        var rows = db.query("""
                        select *, case when revoked_at is not null then 'REVOKED'
                          when least(expires_at,idle_expires_at)<=clock_timestamp() then 'EXPIRED' else 'ACTIVE' end as status
                        from identity_sessions where principal_name=? and (?::uuid is null or management_id>?::uuid)
                        order by management_id limit ?
                        """, (rs, n) -> new SessionView(rs.getObject("management_id", UUID.class), rs.getTimestamp("created_at").toInstant(),
                        rs.getTimestamp("last_seen_at").toInstant(), rs.getTimestamp("idle_expires_at").toInstant(),
                        rs.getTimestamp("expires_at").toInstant(), rs.getString("status"), rs.getString("id").equals(current)),
                identity.getName(), after, after, limit + 1);
        boolean more = rows.size() > limit;
        var items = List.copyOf(rows.subList(0, Math.min(rows.size(), limit)));
        return new Page(items, more ? items.getLast().id() : null);
    }

    @DeleteMapping("/api/v1/users/me/sessions/{sessionId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Transactional(timeout = 10)
    public void revoke(JwtAuthenticationToken identity, @PathVariable UUID sessionId, HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        locks(identity.getName());
        live(identity, true);
        var rows = db.queryForList("select id,revoked_at from identity_sessions where management_id=? and principal_name=? for update", sessionId, identity.getName());
        if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        if (rows.getFirst().get("revoked_at") != null) return;
        authorizations.revokeSession(rows.getFirst().get("id").toString(), identity.getName());
        audit("SESSION_SELF_REVOKED", identity.getName(), identity.getName(), sessionId);
    }

    @PostMapping("/api/v1/admin/users/{userId}/revoke-sessions")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Transactional(timeout = 10)
    public void revokeAll(JwtAuthenticationToken identity, @PathVariable UUID userId, HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        String target = userId.toString();
        locks(identity.getName(), target);
        live(identity, false);
        if (!Boolean.TRUE.equals(db.queryForObject("select exists(select 1 from users where id=?)", Boolean.class, target)))
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        authorizations.revokeUser(target);
        audit("USER_SESSIONS_REVOKED", identity.getName(), target, null);
    }

    private void audit(String type, String actor, String target, UUID session) {
        db.update("insert into security_audit_events(id,event_type,subject_id,actor_id,target_session_id) values (?,?,?,?,?)",
                UUID.randomUUID().toString(), type, target, actor, session);
    }

    public record SessionView(UUID id, Instant createdAt, Instant lastSeenAt, Instant idleExpiresAt,
                              Instant absoluteExpiresAt, String status, boolean current) {
    }

    public record Page(List<SessionView> items, UUID nextCursor) {
    }
}
