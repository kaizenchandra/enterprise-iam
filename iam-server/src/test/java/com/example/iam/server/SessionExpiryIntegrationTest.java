package com.example.iam.server;

import com.example.iam.server.retention.RetentionCleanup;
import com.example.iam.server.retention.RetentionProperties;
import com.example.iam.server.session.SessionExpiry;
import com.example.iam.server.session.SessionLifetime;
import com.example.iam.server.token.TrackedAuthorizationService;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

@Testcontainers
class SessionExpiryIntegrationTest {
    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:17-alpine");
    static JdbcTemplate db;
    static DataSourceTransactionManager manager;
    static TrackedAuthorizationService service;
    static RegisteredClient client;
    static JdbcRegisteredClientRepository clients;
    String user;
    SimpleMeterRegistry meters;
    SessionExpiry expiry;
    RetentionCleanup retention;

    @BeforeAll
    static void database() {
        var source = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(source).load().migrate();
        db = new JdbcTemplate(source);
        manager = new DataSourceTransactionManager(source);
        clients = new JdbcRegisteredClientRepository(db);
        client = RegisteredClient.withId("session-client").clientId("session-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("https://client.example/callback").scope("openid")
                .clientSettings(ClientSettings.builder().setting("backchannel_logout_uri", "https://client.example/logout").build()).build();
        clients.save(client);
        service = new TrackedAuthorizationService(db, clients, manager, Duration.ofHours(8));
    }

    @BeforeEach
    void fixture() {
        db.execute("truncate oauth2_authorization,refresh_history,authorization_lifecycle,identity_sessions,users cascade");
        db.update("update authorization_retention_state set initial_not_before='1970-01-01T00:00:00Z'");
        db.update("delete from security_audit_events");
        user = UUID.randomUUID().toString();
        db.update("insert into users(id,username,password_hash,state) values (?,?,?,'ACTIVE')", user, user, "test-only");
        meters = new SimpleMeterRegistry();
        expiry = worker(100);
        retention = new RetentionCleanup(db, manager, new RetentionProperties(true, 100, Duration.ofDays(1)), meters);
    }

    SessionExpiry worker(int batch) {
        return new SessionExpiry(db, manager, service, meters, true, batch);
    }

    OAuth2Authorization grant(MockHttpSession session) {
        String key = TrackedAuthorizationService.digest(session.getId()).substring(0, 32);
        if (session.getAttribute(TrackedAuthorizationService.SESSION) == null) {
            service.registerSession(key, user, service.now());
            session.setAttribute(TrackedAuthorizationService.SESSION, key);
        }
        var request = new MockHttpServletRequest();
        request.setSession(session);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated(user, "unused", List.of()));
        try {
            Instant now = service.now();
            var claims = new HashMap<String, Object>(Map.of("iss", "https://issuer.example", "sub", user, "aud", new ArrayList<>(List.of(client.getClientId())), "sid", key));
            var a = OAuth2Authorization.withRegisteredClient(client).principalName(user)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .token(new OAuth2AuthorizationCode(UUID.randomUUID().toString(), now, now.plusSeconds(60)))
                    .token(new OAuth2RefreshToken(UUID.randomUUID().toString(), now, now.plusSeconds(3600)))
                    .token(new OidcIdToken(UUID.randomUUID().toString(), now, now.plusSeconds(300),
                            claims), metadata -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claims))
                    .build();
            service.save(a);
            return service.findById(a.getId());
        } finally {
            RequestContextHolder.resetRequestAttributes();
            SecurityContextHolder.clearContext();
        }
    }

    String session(OAuth2Authorization grant) {
        return grant.getAttribute(TrackedAuthorizationService.SESSION);
    }

    void due(String session, boolean absolute) {
        db.update(absolute ? "update identity_sessions set expires_at=clock_timestamp()-interval '2 seconds' where id=?"
                : "update identity_sessions set idle_expires_at=clock_timestamp()-interval '2 seconds' where id=?", session);
    }

    OAuth2Authorization rotate(OAuth2Authorization grant) {
        return OAuth2Authorization.from(grant).token(new OAuth2RefreshToken(UUID.randomUUID().toString(), service.now(), service.now().plusSeconds(3600))).build();
    }

    int count(String table) {
        return db.queryForObject("select count(*) from " + table, Integer.class);
    }

    @Test
    void idleExpiryRevokesAllSessionFamiliesAndEnqueuesOnceWithoutTouchingOtherSession() {
        var browser = new MockHttpSession();
        var a = grant(browser);
        var b = grant(browser);
        var independent = grant(new MockHttpSession());
        due(session(a), false);
        assertNull(service.findByToken(a.getRefreshToken().getToken().getTokenValue(), OAuth2TokenType.REFRESH_TOKEN));
        assertThrows(OAuth2AuthenticationException.class, () -> service.save(rotate(a)));
        assertEquals(1, expiry.runBatch());
        assertEquals(0, expiry.runBatch());
        assertEquals(1, count("logout_deliveries"));
        assertEquals(1, count("oauth2_authorization"));
        assertNull(service.findById(a.getId()));
        assertNull(service.findById(b.getId()));
        assertNotNull(service.findById(independent.getId()));
        assertEquals(1, db.queryForObject("select count(*) from security_audit_events where event_type='SESSION_IDLE_EXPIRED'", Integer.class));
        assertEquals(2, db.queryForObject("select count(*) from refresh_history where authorization_id in (?,?)", Integer.class, a.getId(), b.getId()));
        assertFalse(service.touchSession(session(a), user));
    }

    @Test
    void absoluteExpiryCannotBeExtendedByBrowserActivityOrRefresh() {
        var a = grant(new MockHttpSession());
        String key = session(a);
        db.update("update identity_sessions set expires_at=clock_timestamp()+interval '10 minutes',idle_expires_at=clock_timestamp()+interval '1 minute' where id=?", key);
        var end = db.queryForObject("select expires_at from identity_sessions where id=?", Timestamp.class, key);
        assertTrue(service.touchSession(key, user));
        assertEquals(end, db.queryForObject("select idle_expires_at from identity_sessions where id=?", Timestamp.class, key));
        due(key, true);
        assertFalse(service.touchSession(key, user));
        assertEquals(0, expiry.runBatch());
        assertEquals(1, count("logout_deliveries"));
        assertEquals(0, count("oauth2_authorization"));
        assertEquals(1, db.queryForObject("select count(*) from security_audit_events where event_type='SESSION_ABSOLUTE_EXPIRED'", Integer.class));
        assertThrows(OAuth2AuthenticationException.class, () -> service.save(rotate(a)));
    }

    @Test
    void heartbeatsAreMonotonicAndRegistrationDoesNotResetExistingDeadlines() throws Exception {
        var a = grant(new MockHttpSession());
        String key = session(a);
        db.update("update identity_sessions set idle_expires_at=clock_timestamp()+interval '1 minute' where id=?", key);
        var absolute = db.queryForObject("select expires_at from identity_sessions where id=?", Timestamp.class, key);
        try (var pool = Executors.newFixedThreadPool(2)) {
            var barrier = new CyclicBarrier(2);
            var a1 = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return service.touchSession(key, user);
            });
            var a2 = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return service.touchSession(key, user);
            });
            assertTrue(a1.get(10, TimeUnit.SECONDS));
            assertTrue(a2.get(10, TimeUnit.SECONDS));
        }
        var idle = db.queryForObject("select idle_expires_at from identity_sessions where id=?", Timestamp.class, key);
        assertTrue(idle.toInstant().isAfter(service.now().plusSeconds(1100)));
        service.registerSession(key, user, service.now());
        assertEquals(idle, db.queryForObject("select idle_expires_at from identity_sessions where id=?", Timestamp.class, key));
        assertEquals(absolute, db.queryForObject("select expires_at from identity_sessions where id=?", Timestamp.class, key));
    }

    @Test
    void twoExpiryWorkersAndExpiredHeartbeatHaveSingleDurableWinner() throws Exception {
        var a = grant(new MockHttpSession());
        String key = session(a);
        due(key, false);
        try (var pool = Executors.newFixedThreadPool(3)) {
            var barrier = new CyclicBarrier(3);
            var a1 = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return expiry.runBatch();
            });
            var a2 = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return worker(100).runBatch();
            });
            var touch = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return service.touchSession(key, user);
            });
            assertTrue(a1.get(10, TimeUnit.SECONDS) + a2.get(10, TimeUnit.SECONDS) <= 1);
            assertFalse(touch.get(10, TimeUnit.SECONDS));
        }
        assertEquals(1, count("logout_deliveries"));
        assertEquals(0, count("oauth2_authorization"));
        assertEquals(1, db.queryForObject("select count(*) from security_audit_events where event_type='SESSION_IDLE_EXPIRED'", Integer.class));
    }

    @Test
    void expiryRacingRefreshSnapshotAndNewGrantCannotResurrectSession() throws Exception {
        var browser = new MockHttpSession();
        var a = grant(browser);
        due(session(a), false);
        try (var pool = Executors.newFixedThreadPool(3)) {
            var barrier = new CyclicBarrier(3);
            var sweep = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return expiry.runBatch();
            });
            var refresh = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                assertThrows(OAuth2AuthenticationException.class, () -> service.save(rotate(a)));
                return null;
            });
            var issue = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                assertThrows(OAuth2AuthenticationException.class, () -> grant(browser));
                return null;
            });
            sweep.get(10, TimeUnit.SECONDS);
            refresh.get(10, TimeUnit.SECONDS);
            issue.get(10, TimeUnit.SECONDS);
        }
        // A nonblocking worker may skip a principal while issuance holds its lock; the next pass completes it.
        expiry.runBatch();
        assertEquals(0, count("oauth2_authorization"));
        assertEquals(1, count("logout_deliveries"));
    }

    @Test
    void busyPrincipalsAreSkippedAndWorkRemainsBounded() throws Exception {
        var a = grant(new MockHttpSession());
        grant(new MockHttpSession());
        db.update("update identity_sessions set idle_expires_at=clock_timestamp()-interval '2 seconds'");
        var locked = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        try (var pool = Executors.newSingleThreadExecutor()) {
            var holder = pool.submit(() -> new TransactionTemplate(manager).executeWithoutResult(status -> {
                service.lockPrincipal(user);
                locked.countDown();
                try {
                    assertTrue(release.await(10, TimeUnit.SECONDS));
                } catch (InterruptedException e) {
                    throw new IllegalStateException(e);
                }
            }));
            assertTrue(locked.await(5, TimeUnit.SECONDS));
            try {
                assertEquals(0, worker(1).runBatch());
                assertEquals(0, count("logout_deliveries"));
            } finally {
                release.countDown();
            }
            holder.get(10, TimeUnit.SECONDS);
        }
        assertEquals(1, worker(1).runBatch());
        assertEquals(1, worker(1).runBatch());
        assertEquals(0, worker(1).runBatch());
        assertNull(service.findById(a.getId()));
        assertEquals(2, count("logout_deliveries"));
    }

    @Test
    void enqueueFailureRollsBackExpiryAndRetryCompletesWithoutLosingReplayHistory() {
        var a = grant(new MockHttpSession());
        due(session(a), false);
        db.execute("create function reject_expiry_enqueue() returns trigger language plpgsql as $$ begin raise exception 'injected delivery outage'; end $$");
        db.execute("create trigger reject_expiry_enqueue before insert on logout_deliveries for each row execute function reject_expiry_enqueue()");
        try {
            assertThrows(org.springframework.dao.DataAccessException.class, () -> expiry.runBatch());
            assertEquals(1, count("oauth2_authorization"));
            assertEquals(1, count("refresh_history"));
            assertEquals(0, count("logout_deliveries"));
            assertNull(db.queryForObject("select revoked_at from identity_sessions where id=?", Timestamp.class, session(a)));
            assertNull(service.findById(a.getId()));
            assertThrows(OAuth2AuthenticationException.class, () -> service.save(rotate(a)));
        } finally {
            db.execute("drop trigger reject_expiry_enqueue on logout_deliveries");
            db.execute("drop function reject_expiry_enqueue()");
        }
        assertEquals(1, expiry.runBatch());
        assertEquals(0, count("oauth2_authorization"));
        assertEquals(1, count("refresh_history"));
    }

    @Test
    void retentionCannotPurgeUnprocessedExpiryOrItsParticipants() {
        var a = grant(new MockHttpSession());
        String key = session(a);
        db.update("update identity_sessions set created_at=clock_timestamp()-interval '5 days',expires_at=clock_timestamp()-interval '4 days',idle_expires_at=clock_timestamp()-interval '4 days' where id=?", key);
        db.update("update authorization_lifecycle set created_at=clock_timestamp()-interval '5 days',expires_at=clock_timestamp()-interval '4 days',grant_expires_at=clock_timestamp()-interval '4 days' where id=?", a.getId());
        retention.runBatch();
        assertEquals(0, count("authorization_lifecycle"));
        assertEquals(1, count("oidc_rp_sessions"));
        assertEquals(1, count("identity_sessions"));
        assertEquals(1, expiry.runBatch());
        assertEquals(1, count("logout_deliveries"));
        retention.runBatch();
        assertEquals(1, count("identity_sessions"));
        db.update("update logout_deliveries set status='SUCCEEDED',completed_at=clock_timestamp()-interval '2 days'");
        retention.runBatch();
        assertEquals(0, count("identity_sessions"));
        assertEquals(0, count("oidc_rp_sessions"));
        assertThrows(OAuth2AuthenticationException.class, () -> service.registerSession(key, user, service.now().minus(Duration.ofDays(5))));
    }

    @Test
    void expiryRacingRetentionAndLogoutNeverLosesParticipantsOrRecreatesState() throws Exception {
        var a = grant(new MockHttpSession());
        String key = session(a);
        due(key, false);
        try (var pool = Executors.newFixedThreadPool(3)) {
            var barrier = new CyclicBarrier(3);
            var sweep = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return retention.runBatch();
            });
            var expire = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return expiry.runBatch();
            });
            var logout = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                service.revokeSession(key, user);
                return null;
            });
            sweep.get(10, TimeUnit.SECONDS);
            expire.get(10, TimeUnit.SECONDS);
            logout.get(10, TimeUnit.SECONDS);
        }
        assertEquals(1, count("logout_deliveries"));
        assertEquals(1, count("identity_sessions"));
        assertEquals(0, count("oauth2_authorization"));
        assertThrows(OAuth2AuthenticationException.class, () -> service.save(rotate(a)));
    }

    @Test
    void invalidLifetimeAndWorkerBoundsAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> new SessionLifetime(Duration.ZERO, Duration.ofHours(1)));
        assertThrows(IllegalArgumentException.class, () -> new SessionLifetime(Duration.ofMinutes(20), Duration.ofMinutes(10)));
        assertThrows(IllegalArgumentException.class, () -> new SessionLifetime(Duration.ofNanos(1), Duration.ofHours(1)));
        assertThrows(IllegalArgumentException.class, () -> worker(0));
        assertThrows(IllegalArgumentException.class, () -> worker(1001));
    }

    @Test
    void versionSevenEndsLegacyIdleSessionsWithoutLosingGrantsParticipantsOrOutbox() {
        String schema = "session_expiry_upgrade";
        String url = POSTGRES.getJdbcUrl() + (POSTGRES.getJdbcUrl().contains("?") ? "&" : "?") + "currentSchema=" + schema;
        var source = new DriverManagerDataSource(url, POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(source).schemas(schema).defaultSchema(schema).target("6").load().migrate();
        var legacy = new JdbcTemplate(source);
        var registrations = new JdbcRegisteredClientRepository(legacy);
        registrations.save(client);
        legacy.update("insert into users(id,username,password_hash,state) values (?,?,?,'ACTIVE')", user, user, "test-only");
        String key = UUID.randomUUID().toString(), participant = UUID.randomUUID().toString();
        Instant now = service.now();
        legacy.update("insert into identity_sessions(id,principal_name) values (?,?)", key, user);
        var a = OAuth2Authorization.withRegisteredClient(client).principalName(user).authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .attribute(TrackedAuthorizationService.SESSION, key).attribute(TrackedAuthorizationService.REVISION, "1")
                .token(new OAuth2RefreshToken("legacy-refresh-test", now, now.plusSeconds(3600))).build();
        new JdbcOAuth2AuthorizationService(legacy, registrations).save(a);
        legacy.update("insert into authorization_lifecycle(id,principal_name,client_id,session_id,created_at,expires_at,grant_expires_at,revision) values (?,?,?,?,?,?,?,1)",
                a.getId(), user, client.getId(), key, Timestamp.from(now), Timestamp.from(now.plusSeconds(28800)), Timestamp.from(now.plusSeconds(3600)));
        legacy.update("insert into refresh_history(token_hash,authorization_id,client_id) values (?,?,?)", TrackedAuthorizationService.digest("legacy-refresh-test"), a.getId(), client.getId());
        legacy.update("insert into oidc_rp_sessions(id,session_id,registered_client_id,client_id,subject,sid,endpoint) values (?,?,?,?,?,?,?)",
                participant, key, client.getId(), client.getClientId(), user, "legacy-sid", "https://client.example/logout");
        legacy.update("insert into logout_deliveries(id,rp_session_id) values (?,?)", "legacy-delivery", participant);
        Flyway.configure().dataSource(source).schemas(schema).defaultSchema(schema).load().migrate();
        var legacyManager = new DataSourceTransactionManager(source);
        var upgraded = new TrackedAuthorizationService(legacy, registrations, legacyManager, Duration.ofHours(8));
        assertNull(upgraded.findById(a.getId()));
        assertEquals(1, legacy.queryForObject("select count(*) from oauth2_authorization", Integer.class));
        assertEquals(1, new SessionExpiry(legacy, legacyManager, upgraded, meters, true, 100).runBatch());
        assertEquals(0, legacy.queryForObject("select count(*) from oauth2_authorization", Integer.class));
        assertEquals(1, legacy.queryForObject("select count(*) from refresh_history", Integer.class));
        assertEquals("legacy-delivery", legacy.queryForObject("select id from logout_deliveries", String.class));
        assertEquals(1, legacy.queryForObject("select count(*) from oidc_rp_sessions", Integer.class));
        assertFalse(upgraded.touchSession(key, user));
    }

    MockHttpSession shortSession(long idleSeconds, long absoluteSeconds) {
        var browser = new MockHttpSession();
        String key = TrackedAuthorizationService.digest(browser.getId()).substring(0, 32);
        var shortPolicy = new TrackedAuthorizationService(db, clients, manager, Duration.ofHours(8),
                new SessionLifetime(Duration.ofSeconds(idleSeconds), Duration.ofSeconds(absoluteSeconds)));
        shortPolicy.registerSession(key, user, service.now());
        browser.setAttribute(TrackedAuthorizationService.SESSION, key);
        return browser;
    }

    @Test
    void configuredIdleTimeoutActuallyExpiresWithoutRedisEventOrTraffic() {
        var a = grant(shortSession(1, 10));
        org.awaitility.Awaitility.await().atMost(Duration.ofSeconds(5)).until(() -> {
            expiry.runBatch();
            return !service.sessionActive(session(a), user);
        });
        expiry.runBatch();
        assertEquals(1, count("logout_deliveries"));
        assertEquals(0, count("oauth2_authorization"));
        assertEquals(1, db.queryForObject("select count(*) from security_audit_events where event_type='SESSION_IDLE_EXPIRED'", Integer.class));
    }

    @Test
    void configuredAbsoluteTimeoutActuallyExpiresDespiteRepeatedHeartbeats() {
        var a = grant(shortSession(1, 3));
        org.awaitility.Awaitility.await().pollInterval(Duration.ofMillis(100)).atMost(Duration.ofSeconds(6))
                .until(() -> !service.touchSession(session(a), user));
        assertEquals(1, count("logout_deliveries"));
        assertEquals(0, count("oauth2_authorization"));
        assertEquals(1, db.queryForObject("select count(*) from security_audit_events where event_type='SESSION_ABSOLUTE_EXPIRED'", Integer.class));
    }

    @Test
    void revokeAllLoginCutoffSurvivesSessionAndDeliveryRetention() {
        var a = grant(new MockHttpSession());
        Instant before = service.now();
        service.revokeUser(user);
        db.update("update identity_sessions set created_at=clock_timestamp()-interval '5 days',expires_at=clock_timestamp()-interval '4 days' where id=?", session(a));
        db.update("update authorization_lifecycle set created_at=clock_timestamp()-interval '5 days',expires_at=clock_timestamp()-interval '4 days',grant_expires_at=clock_timestamp()-interval '4 days' where id=?", a.getId());
        db.update("update logout_deliveries set status='SUCCEEDED',completed_at=clock_timestamp()-interval '2 days'");
        retention.runBatch();
        assertEquals(0, count("identity_sessions"));
        assertEquals(0, count("authorization_lifecycle"));
        assertThrows(OAuth2AuthenticationException.class, () -> service.registerSession(UUID.randomUUID().toString(), user, before));
        assertDoesNotThrow(() -> service.registerSession(UUID.randomUUID().toString(), user, service.now()));
    }

    @Test
    void revokeAllRacingDelayedSessionRegistrationLeavesNoEligibleOldLogin() throws Exception {
        Instant birth = service.now();
        String key = UUID.randomUUID().toString();
        try (var pool = Executors.newFixedThreadPool(2)) {
            var barrier = new CyclicBarrier(2);
            var login = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                try {
                    service.registerSession(key, user, birth);
                } catch (OAuth2AuthenticationException expected) {
                }
                return null;
            });
            var revoke = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                service.revokeUser(user);
                return null;
            });
            login.get(10, TimeUnit.SECONDS);
            revoke.get(10, TimeUnit.SECONDS);
        }
        assertFalse(service.sessionActive(key, user));
        assertThrows(OAuth2AuthenticationException.class, () -> service.registerSession(key, user, birth));
    }

}
