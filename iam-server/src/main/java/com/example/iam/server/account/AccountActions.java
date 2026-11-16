package com.example.iam.server.account;

import com.example.iam.server.token.TrackedAuthorizationService;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Base64;
import java.util.Set;
import java.util.UUID;

@Service
public class AccountActions {
    private static final SecureRandom RANDOM = new SecureRandom();
    private final JdbcTemplate db;
    private final AccountSettings settings;
    private final PasswordEncoder passwords;
    private final TrackedAuthorizationService grants;

    public AccountActions(JdbcTemplate db, AccountSettings settings, PasswordEncoder passwords, TrackedAuthorizationService grants) {
        this.db = db;
        this.settings = settings;
        this.passwords = passwords;
        this.grants = grants;
    }

    public static void password(String password) {
        if (password == null || password.codePointCount(0, password.length()) < 14 || password.codePointCount(0, password.length()) > 64 || password.getBytes(StandardCharsets.UTF_8).length > 72)
            throw new IllegalArgumentException("Password must be 14..64 characters and at most 72 UTF-8 bytes");
    }

    private void enabled() {
        if (!settings.enabled) throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE);
    }

    @Transactional(timeout = 10)
    public void request(String email, String kind) {
        enqueue(email, kind, false);
    }

    private void enqueue(String email, String kind, boolean trustedBinding) {
        enabled();
        email = AccountSettings.email(email);
        if (!Set.of("VERIFY", "RESET").contains(kind)) throw new IllegalArgumentException("Invalid purpose");
        // No user lookup in this public transaction: unknown and eligible addresses take the same path.
        db.queryForList("select pg_advisory_xact_lock(hashtextextended('account-requests',0))");
        if (db.queryForObject("select count(*) from account_requests where completed_at is null", Integer.class) >= 10000)
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE);
        String hash = TrackedAuthorizationService.digest(kind + ":" + email);
        int accepted = db.update("""
                insert into account_request_limits(address_hash) values (?) on conflict(address_hash) do update
                set requested_at=clock_timestamp() where ? or account_request_limits.requested_at<clock_timestamp()-interval '1 minute'
                """, hash, trustedBinding);
        if (accepted == 1)
            db.update("insert into account_requests(id,kind,envelope) values (?,?,?)", UUID.randomUUID(), kind, settings.seal(email, ""));
    }

    @Transactional(timeout = 10)
    public boolean consume(String token, String kind, String password) {
        enabled();
        if ("RESET".equals(kind)) password(password);
        if (token == null || !token.matches("[A-Za-z0-9_-]{43}")) return false;
        String hash = TrackedAuthorizationService.digest(token);
        var owner = db.queryForList("select user_id from account_action_tokens where token_hash=? and kind=?", hash, kind);
        if (owner.isEmpty()) return false;
        String user = owner.getFirst().get("user_id").toString();
        grants.lockPrincipal(user);
        var rows = db.queryForList("""
                select t.user_id from account_action_tokens t join users u on u.id=t.user_id where t.token_hash=? and t.kind=?
                and t.consumed_at is null and t.expires_at>clock_timestamp() and t.created_at>u.sessions_not_before and t.user_version=u.version
                and ((t.kind='VERIFY' and u.state in ('PENDING_VERIFICATION','ACTIVE') and not u.email_verified)
                  or (t.kind='RESET' and u.state='ACTIVE' and u.email_verified)) for update of t,u
                """, hash, kind);
        if (rows.isEmpty()) return false;
        if ("VERIFY".equals(kind))
            db.update("update users set email_verified=true,state='ACTIVE',version=version+1 where id=?", user);
        else if ("RESET".equals(kind)) {
            db.update("update users set password_hash=?,version=version+1 where id=?", passwords.encode(password), user);
            grants.revokeUser(user);
            String email = db.queryForObject("select email from users where id=?", String.class, user);
            db.update("insert into account_mail(id,envelope,deadline) values (?,?,clock_timestamp()+interval '1 day')", UUID.randomUUID(), settings.seal(email, "Your password was changed. Existing sessions were revoked. If this was unexpected, contact your identity administrator."));
        } else throw new IllegalArgumentException("Invalid purpose");
        db.update("update account_action_tokens set consumed_at=coalesce(consumed_at,clock_timestamp()) where user_id=?", user);
        db.update("update account_mail set status='DEAD',envelope=null,lease_id=null,lease_until=null,completed_at=clock_timestamp() where token_hash in (select token_hash from account_action_tokens where user_id=?) and status in ('PENDING','INFLIGHT')", user);
        db.update("insert into security_audit_events(id,event_type,subject_id,actor_id) values (?,?,?,?)", UUID.randomUUID().toString(), "VERIFY".equals(kind) ? "EMAIL_VERIFIED" : "PASSWORD_RESET", user, user);
        return true;
    }

    @Transactional(timeout = 10)
    public void bindEmail(String user, String email, org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken actor) {
        enabled();
        email = AccountSettings.email(email);
        if (email == null) throw new IllegalArgumentException("Email required");
        java.util.stream.Stream.of(user, actor.getName()).distinct().sorted().forEach(grants::lockPrincipal);
        var grant = grants.findByToken(actor.getToken().getTokenValue(), org.springframework.security.oauth2.server.authorization.OAuth2TokenType.ACCESS_TOKEN);
        if (grant == null || !actor.getName().equals(grant.getPrincipalName()))
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        var rows = db.queryForList("select email,email_verified,state from users where id=? for update", user);
        if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        var row = rows.getFirst();
        if ("DELETED".equals(row.get("state"))) throw new ResponseStatusException(HttpStatus.CONFLICT);
        if (email.equals(row.get("email"))) return;
        if (Boolean.TRUE.equals(row.get("email_verified")))
            db.update("insert into account_mail(id,envelope,deadline) values (?,?,clock_timestamp()+interval '1 day')", UUID.randomUUID(), settings.seal(row.get("email").toString(), "Your account email was changed by an administrator. Contact your identity administrator if this was unexpected."));
        db.update("update users set email=?,email_verified=false,version=version+1 where id=?", email, user);
        grants.revokeUser(user);
        db.update("update account_action_tokens set consumed_at=coalesce(consumed_at,clock_timestamp()) where user_id=?", user);
        db.update("update account_mail set status='DEAD',envelope=null,lease_id=null,lease_until=null,completed_at=clock_timestamp() where token_hash in (select token_hash from account_action_tokens where user_id=?) and status in ('PENDING','INFLIGHT')", user);
        db.update("insert into security_audit_events(id,event_type,subject_id,actor_id) values (?,'ACCOUNT_EMAIL_BOUND',?,?)", UUID.randomUUID().toString(), user, actor.getName());
        enqueue(email, "VERIFY", true);
    }

    // Called only by the bounded worker transaction after principal lock + user revalidation.
    public void issue(String user, long version, String email, String kind, Instant birth) {
        db.update("update account_action_tokens set consumed_at=coalesce(consumed_at,clock_timestamp()) where user_id=? and kind=?", user, kind);
        db.update("update account_mail set status='DEAD',envelope=null,lease_id=null,lease_until=null,completed_at=clock_timestamp() where token_hash in (select token_hash from account_action_tokens where user_id=? and kind=?) and status in ('PENDING','INFLIGHT')", user, kind);
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes), hash = TrackedAuthorizationService.digest(token);
        Instant expiry = birth.plusSeconds("VERIFY".equals(kind) ? 3600 : 900);
        db.update("insert into account_action_tokens(token_hash,user_id,kind,user_version,expires_at) values (?,?,?,?,?)", hash, user, kind, version, Timestamp.from(expiry));
        String link = settings.origin + ("VERIFY".equals(kind) ? "/account/verify" : "/account/reset") + "#token=" + token;
        db.update("insert into account_mail(id,token_hash,envelope,deadline) values (?,?,?,?)", UUID.randomUUID(), hash, settings.seal(email, ("VERIFY".equals(kind) ? "Verify your account" : "Reset your password") + ":\n" + link + "\nThis link expires and works once. Ignore it if you did not request it."), Timestamp.from(expiry));
    }
}
