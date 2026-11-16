package com.example.iam.server.mfa;

import com.example.iam.server.token.TrackedAuthorizationService;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
public class MfaService {
    private final JdbcTemplate db;
    private final TextEncryptor encryption;
    private final java.time.Clock clock;
    private final GoogleAuthenticator otp = new GoogleAuthenticator(new GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder().setWindowSize(1).build());
    @Value("${iam.mfa.required:false}")
    private boolean required;
    @org.springframework.beans.factory.annotation.Autowired
    public MfaService(JdbcTemplate db, @Value("${MFA_ENCRYPTION_PASSWORD}") String password, @Value("${MFA_ENCRYPTION_SALT}") String salt) {
        this(db, password, salt, java.time.Clock.systemUTC());
    }

    public MfaService(JdbcTemplate db, String password, String salt, java.time.Clock clock) {
        this.db = db;
        this.clock = clock;
        encryption = Encryptors.delux(password, salt);
    }

    public boolean required() {
        return required;
    }

    public boolean enabled(String id) {
        return Boolean.TRUE.equals(db.queryForObject("select exists(select 1 from mfa_credentials where user_id=? and enabled=true)", Boolean.class, id));
    }

    @Transactional
    public String enroll(String id) {
        db.queryForList("select id from users where id=? for update", id);
        if (enabled(id)) throw new IllegalStateException("Already enrolled");
        String key = otp.createCredentials().getKey();
        db.update("insert into mfa_credentials(user_id,secret_encrypted,enrollment_expires_at) values (?,?,clock_timestamp()+interval '10 minutes') on conflict(user_id) do update set secret_encrypted=excluded.secret_encrypted,last_step=-1,enrollment_expires_at=excluded.enrollment_expires_at,enrollment_session=null", id, encryption.encrypt(key));
        return key;
    }

    @Transactional
    public boolean verify(String id, String code) {
        var rows = db.queryForList("select secret_encrypted,last_step from mfa_credentials where user_id=? and (enabled or enrollment_expires_at>clock_timestamp()) for update", id);
        if (rows.isEmpty() || !code.matches("[0-9]{6}")) return false;
        long instant = clock.millis(), step = instant / 30000;
        if (((Number) rows.getFirst().get("last_step")).longValue() >= step) return false;
        if (!otp.authorize(encryption.decrypt(rows.getFirst().get("secret_encrypted").toString()), Integer.parseInt(code), instant))
            return false;
        db.update("update mfa_credentials set last_step=?,enabled=true where user_id=?", step, id);
        return true;
    }

    @Transactional
    public List<String> recoveryCodes(String id) {
        db.update("delete from recovery_codes where user_id=?", id);
        var result = new ArrayList<String>();
        for (int i = 0; i < 10; i++) {
            String code = UUID.randomUUID().toString();
            result.add(code);
            db.update("insert into recovery_codes(user_id,code_hash) values (?,?)", id, TrackedAuthorizationService.digest(code));
        }
        return result;
    }

    @Transactional
    public boolean recover(String id, String code) {
        return db.update("delete from recovery_codes where user_id=? and code_hash=?", id, TrackedAuthorizationService.digest(code)) == 1;
    }
}
