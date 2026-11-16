package com.example.iam.server;

import com.example.iam.server.passkey.PasskeyRepository;
import com.example.iam.server.passkey.PasskeyService;
import com.example.iam.server.passkey.PasskeySettings;
import com.example.iam.server.token.TrackedAuthorizationService;
import com.yubico.webauthn.data.*;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

@Testcontainers
class PasskeyStateIntegrationTest {
    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:17-alpine");
    static final String PASSWORD = "test-only-strong-passphrase";
    static JdbcTemplate db;
    static TransactionTemplate tx;
    static PasskeyService service;
    static TrackedAuthorizationService grants;
    static PasskeyRepository repository;
    String user, session, binding;

    @BeforeAll
    static void setup() {
        var ds = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(ds).load().migrate();
        db = new JdbcTemplate(ds);
        var manager = new DataSourceTransactionManager(ds);
        tx = new TransactionTemplate(manager);
        repository = new PasskeyRepository(db);
        grants = new TrackedAuthorizationService(db, new JdbcRegisteredClientRepository(db), manager, Duration.ofHours(8));
        service = new PasskeyService(db, new PasskeySettings(repository, true, "localhost", "http://localhost:19000", true), new BCryptPasswordEncoder(12), grants);
    }

    @BeforeEach
    void identity() {
        db.execute("truncate passkey_challenges,passkey_credentials,users,identity_sessions cascade");
        db.update("update authorization_retention_state set initial_not_before='1970-01-01'");
        user = UUID.randomUUID().toString();
        session = UUID.randomUUID().toString();
        binding = TrackedAuthorizationService.digest(UUID.randomUUID().toString());
        db.update("insert into users(id,username,password_hash,state) values (?,?,?,'ACTIVE')", user, user, new BCryptPasswordEncoder(12).encode(PASSWORD));
        grants.registerSession(session, user, grants.now());
    }

    @Test
    void originsAreExactAndLocalHttpIsExplicit() {
        assertThrows(IllegalArgumentException.class, () -> new PasskeySettings(repository, true, "example.com", "http://example.com", true));
        assertThrows(IllegalArgumentException.class, () -> new PasskeySettings(repository, true, "localhost", "http://other.localhost:9000", true));
        assertThrows(IllegalArgumentException.class, () -> new PasskeySettings(repository, true, "localhost", "http://localhost:19000", false));
        assertThrows(IllegalArgumentException.class, () -> new PasskeySettings(repository, true, "localhost", "https://localhost:9000/path", false));
        var valid = new PasskeySettings(repository, true, "example.com", "https://example.com", false);
        assertFalse(valid.relyingParty.isAllowOriginPort());
        assertFalse(valid.relyingParty.isAllowOriginSubdomain());
    }

    @Test
    void registrationRequiresReauthenticationAndProducesRequiredUvResidentOptions() throws Exception {
        assertNull(tx.execute(status -> service.registerStart(user, session, binding, "wrong")));
        var start = tx.execute(status -> service.registerStart(user, session, binding, PASSWORD));
        assertNotNull(start);
        var options = PublicKeyCredentialCreationOptions.fromJson(db.queryForObject("select options from passkey_challenges where id=?", String.class, start.id()));
        assertEquals(UserVerificationRequirement.REQUIRED, options.getAuthenticatorSelection().orElseThrow().getUserVerification().orElseThrow());
        assertEquals(ResidentKeyRequirement.REQUIRED, options.getAuthenticatorSelection().orElseThrow().getResidentKey().orElseThrow());
        assertTrue(options.getChallenge().getBytes().length >= 32);
        assertEquals(AttestationConveyancePreference.NONE, options.getAttestation());
        assertEquals(Set.of(PublicKeyCredentialParameters.ES256, PublicKeyCredentialParameters.RS256), new HashSet<>(options.getPubKeyCredParams()));
    }

    @Test
    void malformedRegistrationIsSpentButWrongBrowserDoesNotConsumeIt() {
        var start = tx.execute(status -> service.registerStart(user, session, binding, PASSWORD));
        assertEquals(Boolean.FALSE, tx.execute(status -> service.registerFinish(user, TrackedAuthorizationService.digest("other"), start.id(), "{}")));
        assertNull(db.queryForObject("select consumed_at from passkey_challenges where id=?", java.sql.Timestamp.class, start.id()));
        assertEquals(Boolean.FALSE, tx.execute(status -> service.registerFinish(user, binding, start.id(), "{}")));
        assertNotNull(db.queryForObject("select consumed_at from passkey_challenges where id=?", java.sql.Timestamp.class, start.id()));
        assertEquals(Boolean.FALSE, tx.execute(status -> service.registerFinish(user, binding, start.id(), "{}")));
    }

    @Test
    void anonymousOptionsDoNotEnumerateUsersAndOlderOptionsAreSuperseded() throws Exception {
        var first = tx.execute(status -> service.authenticateStart(binding));
        var second = tx.execute(status -> service.authenticateStart(binding));
        assertFalse(second.options().contains(user));
        assertFalse(second.options().contains("allowCredentials"));
        assertNotNull(db.queryForObject("select consumed_at from passkey_challenges where id=?", java.sql.Timestamp.class, first.id()));
        assertNull(tx.execute(status -> service.authenticateFinish(binding, first.id(), "{}", "unused-session")));
    }

    @Test
    void durableReauthenticationLockCannotBeResetByNewCeremonies() {
        for (int i = 0; i < 5; i++)
            assertNull(tx.execute(status -> service.registerStart(user, session, binding, "wrong")));
        assertNull(tx.execute(status -> service.registerStart(user, session, binding, PASSWORD)));
        db.update("update users set passkey_reauth_locked_until=clock_timestamp()-interval '1 second' where id=?", user);
        assertNotNull(tx.execute(status -> service.registerStart(user, session, binding, PASSWORD)));
    }

    @Test
    void expirationAndCleanupNeverRecreateChallenges() {
        var start = tx.execute(status -> service.authenticateStart(binding));
        db.update("update passkey_challenges set expires_at=clock_timestamp()-interval '2 days' where id=?", start.id());
        assertNull(tx.execute(status -> service.authenticateFinish(binding, start.id(), "{}", "unused-session")));
        service.cleanup();
        assertEquals(0, db.queryForObject("select count(*) from passkey_challenges", Integer.class));
        assertNull(tx.execute(status -> service.authenticateFinish(binding, start.id(), "{}", "unused-session")));
    }

    @Test
    void concurrentMalformedFinishDoesNotProduceProofOrSession() throws Exception {
        var start = tx.execute(status -> service.authenticateStart(binding));
        try (var pool = Executors.newFixedThreadPool(2)) {
            var barrier = new CyclicBarrier(2);
            var a = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return tx.execute(status -> service.authenticateFinish(binding, start.id(), "{}", "session-a"));
            });
            var b = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return tx.execute(status -> service.authenticateFinish(binding, start.id(), "{}", "session-b"));
            });
            assertNull(a.get(10, TimeUnit.SECONDS));
            assertNull(b.get(10, TimeUnit.SECONDS));
        }
        assertEquals(1, db.queryForObject("select count(*) from passkey_challenges where consumed_at is not null", Integer.class));
        assertEquals(1, db.queryForObject("select count(*) from identity_sessions", Integer.class));
    }

    private UUID credential() {
        UUID id = UUID.randomUUID();
        db.update("insert into passkey_credentials(id,user_id,credential_id,public_key_cose,signature_count,backup_eligible,backed_up) values (?,?,?, 'AQ',0,false,false)", id, user, UUID.randomUUID().toString());
        return id;
    }

    @Test
    void removalIsOwnerScopedAndCannotBypassMfa() {
        UUID id = credential();
        String other = UUID.randomUUID().toString();
        db.update("insert into users(id,username,password_hash,state) values (?,?,?,'ACTIVE')", other, other, new BCryptPasswordEncoder(12).encode(PASSWORD));
        grants.registerSession("other-session", other, grants.now());
        var denied = assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> tx.execute(status -> service.remove(other, "other-session", id, PASSWORD)));
        assertEquals(404, denied.getStatusCode().value());
        db.update("insert into mfa_credentials(user_id,secret_encrypted,enabled) values (?,'not-used',true)", user);
        var mfa = assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> tx.execute(status -> service.remove(user, session, id, PASSWORD)));
        assertEquals(401, mfa.getStatusCode().value());
        assertEquals(1, db.queryForObject("select count(*) from passkey_credentials where id=?", Integer.class, id));
    }

    @Test
    void auditFailureRollsBackRemovalAndRevocation() {
        UUID id = credential();
        db.execute("create function passkey_test_fail() returns trigger language plpgsql as $$begin if new.event_type='PASSKEY_REMOVED' then raise exception 'simulated audit outage'; end if;return new;end$$");
        db.execute("create trigger passkey_test_failure before insert on security_audit_events for each row execute function passkey_test_fail()");
        try {
            assertThrows(org.springframework.dao.DataAccessException.class, () -> tx.execute(status -> service.remove(user, session, id, PASSWORD)));
        } finally {
            db.execute("drop trigger passkey_test_failure on security_audit_events");
            db.execute("drop function passkey_test_fail()");
        }
        assertEquals(1, db.queryForObject("select count(*) from passkey_credentials where id=?", Integer.class, id));
        assertFalse(grants.sessionRevoked(session, user));
        assertEquals(Boolean.TRUE, tx.execute(status -> service.remove(user, session, id, PASSWORD)));
        assertTrue(grants.sessionRevoked(session, user));
    }

    @Test
    void concurrentRemovalHasOneWinnerAndRevokesBothSessions() throws Exception {
        UUID id = credential();
        String second = UUID.randomUUID().toString();
        grants.registerSession(second, user, grants.now());
        try (var pool = Executors.newFixedThreadPool(2)) {
            var barrier = new CyclicBarrier(2);
            java.util.function.Function<String, Boolean> remove = sid -> {
                try {
                    return tx.execute(status -> service.remove(user, sid, id, PASSWORD));
                } catch (org.springframework.web.server.ResponseStatusException e) {
                    assertEquals(401, e.getStatusCode().value());
                    return false;
                }
            };
            var a = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return remove.apply(session);
            });
            var b = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return remove.apply(second);
            });
            assertNotEquals(a.get(10, TimeUnit.SECONDS), b.get(10, TimeUnit.SECONDS));
        }
        assertTrue(grants.sessionRevoked(session, user));
        assertTrue(grants.sessionRevoked(second, user));
        assertEquals(0, db.queryForObject("select count(*) from passkey_credentials", Integer.class));
        assertEquals(1, db.queryForObject("select count(*) from security_audit_events where subject_id=? and event_type='PASSKEY_REMOVED'", Integer.class, user));
    }

    @Test
    void disabledFeatureNeverChangesCredentials() {
        var disabled = new PasskeyService(db, new PasskeySettings(repository, false, "localhost", "https://localhost:9000", false), new BCryptPasswordEncoder(12), grants);
        UUID id = credential();
        var pending = tx.execute(status -> service.authenticateStart(binding));
        var registration = tx.execute(status -> service.registerStart(user, session, binding, PASSWORD));
        assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> tx.execute(status -> disabled.authenticateFinish(binding, pending.id(), "{}", "not-issued")));
        assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> tx.execute(status -> disabled.registerFinish(user, binding, registration.id(), "{}")));
        assertEquals(0, db.queryForObject("select count(*) from passkey_challenges where consumed_at is not null", Integer.class));
        assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> tx.execute(status -> disabled.authenticateStart(binding)));
        assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> tx.execute(status -> disabled.registerStart(user, session, binding, PASSWORD)));
        assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> tx.execute(status -> disabled.remove(user, session, id, PASSWORD)));
        assertEquals(1, db.queryForObject("select count(*) from passkey_credentials", Integer.class));
    }
}
