package com.example.iam.server.account;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.net.URI;
import java.util.UUID;

@Service
public class RegistrationService {
    private final JdbcTemplate db;
    private final PasswordEncoder passwords;
    private final AccountActions actions;
    private final AccountSettings accounts;
    private final boolean registrationEnabled;
    private final String signInUrl;

    public RegistrationService(JdbcTemplate db, PasswordEncoder passwords, AccountActions actions,
                               AccountSettings accounts,
                               @Value("${iam.account.registration-enabled:false}") boolean enabled,
                               @Value("${iam.account.console-origin:}") String consoleOrigin) {
        this.db = db;
        this.passwords = passwords;
        this.actions = actions;
        this.accounts = accounts;
        this.registrationEnabled = enabled;
        if (!consoleOrigin.isBlank()) {
            URI url = URI.create(consoleOrigin);
            if (url.getHost() == null || url.getUserInfo() != null || url.getQuery() != null || url.getFragment() != null
                    || !url.getPath().isEmpty() || !("https".equals(url.getScheme()) || accounts.origin.startsWith("http:")
                    && "http".equals(url.getScheme()) && java.util.Set.of("localhost", "127.0.0.1").contains(url.getHost())))
                throw new IllegalArgumentException("Invalid console origin");
        }
        this.signInUrl = consoleOrigin.isBlank() ? "/login" : consoleOrigin + "/login";
    }

    public boolean enabled() {
        return registrationEnabled && accounts.enabled;
    }

    public String signInUrl() {
        return signInUrl;
    }

    public String consoleEntry() {
        return signInUrl.equals("/login") ? "/" : signInUrl.substring(0, signInUrl.length() - 6) + "/auth/continue";
    }

    @Transactional(timeout = 10)
    public void register(String username, String email, String password, String confirmation) {
        if (!enabled()) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        if (username == null || !username.matches("[A-Za-z0-9][A-Za-z0-9._-]{2,127}"))
            throw new IllegalArgumentException("Invalid username");
        email = AccountSettings.email(email);
        if (email == null) throw new IllegalArgumentException("Email required");
        AccountActions.password(password);
        if (!password.equals(confirmation)) throw new IllegalArgumentException("Passwords do not match");
        // Hash before the conflict-safe insert so duplicates take the same expensive path.
        String hash = passwords.encode(password), id = UUID.randomUUID().toString();
        int inserted = db.update("insert into users(id,username,password_hash,state,email) values (?,?,?,'PENDING_VERIFICATION',?) on conflict do nothing",
                id, username, hash, email);
        if (inserted == 1) {
            actions.request(email, "VERIFY");
            db.update("insert into security_audit_events(id,event_type,subject_id) values (?,'USER_REGISTERED',?)", UUID.randomUUID().toString(), id);
        }
    }
}
