package com.example.iam.server.mfa;

import com.example.iam.server.token.TrackedAuthorizationService;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.UUID;

@Service
public class MfaSessionService {
    private final JdbcTemplate db;
    private final MfaService mfa;
    private final TrackedAuthorizationService grants;
    private final PasswordEncoder passwords;

    public MfaSessionService(JdbcTemplate db, MfaService mfa, TrackedAuthorizationService grants, PasswordEncoder passwords) {
        this.db = db;
        this.mfa = mfa;
        this.grants = grants;
        this.passwords = passwords;
    }

    private void active(String user, String session) {
        grants.lockPrincipal(user);
        if (session == null || !grants.sessionActive(session, user) || !"ACTIVE".equals(db.queryForObject("select state from users where id=?", String.class, user)))
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
    }

    @Transactional(timeout = 10)
    public String enroll(String user, String session, String password) {
        active(user, session);
        if (mfa.enabled(user)) throw new ResponseStatusException(HttpStatus.CONFLICT, "Already enrolled");
        String hash = db.queryForObject("select password_hash from users where id=?", String.class, user);
        if (!passwords.matches(password, hash)) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        String secret = mfa.enroll(user);
        db.update("update mfa_credentials set enrollment_session=? where user_id=?", session, user);
        return secret;
    }

    @Transactional(timeout = 10)
    public Verified verify(String user, String session, String code, boolean recovery) {
        active(user, session);
        if (Boolean.TRUE.equals(db.queryForObject("select mfa_locked_until>clock_timestamp() from users where id=?", Boolean.class, user)))
            return new Verified(false, false, List.of());
        boolean enabled = mfa.enabled(user);
        if (!enabled && !Boolean.TRUE.equals(db.queryForObject("select exists(select 1 from mfa_credentials where user_id=? and (enrollment_session is null or enrollment_session=?) and enrollment_expires_at>clock_timestamp())", Boolean.class, user, session)))
            return new Verified(false, false, List.of());
        if (recovery && !enabled) return new Verified(false, false, List.of());
        boolean valid = recovery ? mfa.recover(user, code) : mfa.verify(user, code);
        if (!valid) {
            db.update("update users set mfa_failed_attempts=case when mfa_locked_until<=clock_timestamp() then 1 else mfa_failed_attempts+1 end,mfa_locked_until=case when mfa_locked_until<=clock_timestamp() then null when mfa_failed_attempts>=4 then clock_timestamp()+interval '5 minutes' else null end where id=?", user);
            audit(user, "MFA_FAILED");
            return new Verified(false, false, List.of());
        }
        db.update("update users set mfa_failed_attempts=0,mfa_locked_until=null where id=?", user);
        if (!enabled) {
            var codes = mfa.recoveryCodes(user);
            grants.revokeUser(user);
            audit(user, "MFA_ENROLLED");
            return new Verified(true, true, codes);
        }
        db.update("update identity_sessions set mfa_verified_at=clock_timestamp(),mfa_method=? where id=? and principal_name=?", recovery ? "recovery" : "otp", session, user);
        audit(user, recovery ? "MFA_RECOVERY_USED" : "MFA_VERIFIED");
        return new Verified(true, false, List.of());
    }

    private void audit(String user, String type) {
        db.update("insert into security_audit_events(id,event_type,subject_id,actor_id) values (?,?,?,?)", UUID.randomUUID().toString(), type, user, user);
    }

    public boolean enabled(String user) {
        return mfa.enabled(user);
    }

    public boolean required() {
        return mfa.required();
    }

    @Transactional(timeout = 10)
    public List<String> manage(String user, String session, String password, String code, boolean recovery, boolean remove) {
        active(user, session);
        if (remove && mfa.required()) throw new ResponseStatusException(HttpStatus.FORBIDDEN, "MFA is required");
        if (!mfa.enabled(user)) throw new ResponseStatusException(HttpStatus.CONFLICT, "MFA is not enrolled");
        String hash = db.queryForObject("select password_hash from users where id=?", String.class, user);
        if (!passwords.matches(password, hash)) {
            audit(user, "MFA_REAUTH_FAILED");
            return null;
        }
        if (!verify(user, session, code, recovery).accepted()) return null;
        List<String> codes = List.of();
        if (remove) {
            db.update("delete from recovery_codes where user_id=?", user);
            db.update("delete from mfa_credentials where user_id=?", user);
        } else codes = mfa.recoveryCodes(user);
        grants.revokeUser(user);
        audit(user, remove ? "MFA_REMOVED" : "MFA_RECOVERY_RENEWED");
        return codes;
    }

    public record Verified(boolean accepted, boolean enrolled, List<String> recoveryCodes) {
    }
}
