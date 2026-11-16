package com.example.iam.server;

import com.example.iam.server.retention.RetentionCleanup;
import com.example.iam.server.retention.RetentionProperties;
import com.example.iam.server.token.AuthorizationBirthConverter;
import com.example.iam.server.token.RefreshGuard;
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
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.*;

@Testcontainers
class RetentionIntegrationTest {
    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:17-alpine");
    static JdbcTemplate db;
    static DataSourceTransactionManager manager;
    static TrackedAuthorizationService service;
    static JdbcOAuth2AuthorizationService raw;
    static RegisteredClient client;
    static TransactionTemplate tx;
    String user;
    MockHttpSession session;
    SimpleMeterRegistry meters;
    RetentionCleanup cleanup;

    @BeforeAll
    static void database() {
        var ds = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(ds).load().migrate();
        db = new JdbcTemplate(ds);
        manager = new DataSourceTransactionManager(ds);
        tx = new TransactionTemplate(manager);
        var clients = new JdbcRegisteredClientRepository(db);
        client = RegisteredClient.withId("registered-retention-client").clientId("retention-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("https://client.example/callback").scope("openid").build();
        clients.save(client);
        service = new TrackedAuthorizationService(db, clients, manager, Duration.ofHours(8));
        raw = new JdbcOAuth2AuthorizationService(db, clients);
    }

    @BeforeEach
    void fixture() {
        db.execute("truncate oauth2_authorization,refresh_history,authorization_lifecycle,identity_sessions,users cascade");
        db.update("update authorization_retention_state set initial_not_before='1970-01-01T00:00:00Z'");
        user = UUID.randomUUID().toString();
        db.update("insert into users(id,username,password_hash,state) values (?,?,?,'ACTIVE')", user, user, "test-only");
        session = new MockHttpSession();
        String key = TrackedAuthorizationService.digest(session.getId()).substring(0, 32);
        service.registerSession(key, user, service.now());
        session.setAttribute(TrackedAuthorizationService.SESSION, key);
        meters = new SimpleMeterRegistry();
        cleanup = worker(100);
    }

    RetentionCleanup worker(int batch) {
        return new RetentionCleanup(db, manager, new RetentionProperties(true, batch, Duration.ofDays(1)), meters);
    }

    <T> T browser(Supplier<T> action) {
        var request = new MockHttpServletRequest();
        request.setSession(session);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated(user, "unused", List.of()));
        try {
            return action.get();
        } finally {
            RequestContextHolder.resetRequestAttributes();
            SecurityContextHolder.clearContext();
        }
    }

    OAuth2Authorization live() {
        return browser(() -> {
            var now = service.now();
            var a = OAuth2Authorization.withRegisteredClient(client).principalName(user)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .token(new OAuth2AuthorizationCode(UUID.randomUUID().toString(), now, now.plusSeconds(60)))
                    .token(new OAuth2RefreshToken(UUID.randomUUID().toString(), now, now.plusSeconds(3600))).build();
            service.save(a);
            return service.findById(a.getId());
        });
    }

    OAuth2Authorization rotated(OAuth2Authorization a) {
        return OAuth2Authorization.from(a).token(new OAuth2RefreshToken(UUID.randomUUID().toString(),
                service.now(), service.now().plusSeconds(3600))).build();
    }

    Old old(boolean history) {
        Instant birth = service.now().minus(Duration.ofHours(50)), end = birth.plus(Duration.ofHours(8));
        // Long-lived token models an unversioned initial object retained past its family lifetime.
        var initial = OAuth2Authorization.withRegisteredClient(client).principalName("client:retention-client")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .token(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, UUID.randomUUID().toString(), birth, service.now().plusSeconds(3600))).build();
        var saved = OAuth2Authorization.from(initial).attribute(TrackedAuthorizationService.REVISION, "1").build();
        raw.save(saved);
        db.update("""
                insert into authorization_lifecycle(id,principal_name,client_id,created_at,expires_at,grant_expires_at,revision)
                values (?,?,?,?,?,?,1)
                """, initial.getId(), initial.getPrincipalName(), client.getId(), Timestamp.from(birth), Timestamp.from(end), Timestamp.from(end));
        if (history) history(initial.getId(), "old-token-" + UUID.randomUUID(), birth);
        return new Old(initial, saved);
    }

    void history(String family, String token, Instant born) {
        db.update("insert into refresh_history(token_hash,authorization_id,client_id,created_at) values (?,?,?,?)",
                TrackedAuthorizationService.digest(token), family, client.getId(), Timestamp.from(born));
    }

    int count(String table) {
        return db.queryForObject("select count(*) from " + table, Integer.class);
    }

    Instant floor() {
        return db.queryForObject("select initial_not_before from authorization_retention_state", Timestamp.class).toInstant();
    }

    @Test
    void expiredMaterialAndHistoryArePurgedWithMonotonicStaleSaveFence() {
        var old = old(true);
        var originalFloor = floor();
        var result = cleanup.runBatch();
        assertEquals(1, result.grants());
        assertEquals(1, result.history());
        assertEquals(1, result.lifecycles());
        assertEquals(0, count("oauth2_authorization"));
        assertEquals(0, count("refresh_history"));
        assertEquals(0, count("authorization_lifecycle"));
        assertTrue(floor().isAfter(originalFloor));
        assertThrows(OAuth2AuthenticationException.class, () -> service.save(old.initial()));
        assertThrows(OAuth2AuthenticationException.class, () -> service.save(old.snapshot()));
        assertEquals(new RetentionCleanup.Result(0, 0, 0, 0, 0, 0, 0, 0), cleanup.runBatch());
        assertNotNull(live()); // The global fence must not prevent fresh grants.
    }

    @Test
    void rawExpiryRetiresGrantButGraceKeepsFamilyHistory() {
        var live = live();
        db.update("update authorization_lifecycle set grant_expires_at=clock_timestamp()-interval '1 second' where id=?", live.getId());
        var result = cleanup.runBatch();
        assertEquals(1, result.grants());
        assertEquals(0, result.history());
        assertEquals(0, result.lifecycles());
        assertEquals(1, count("refresh_history"));
        assertEquals(1, count("authorization_lifecycle"));
        assertThrows(OAuth2AuthenticationException.class, () -> service.save(rotated(live)));
    }

    @Test
    void activeFamilyKeepsEveryGenerationAndReplayStillRevokesAfterConcurrentCleanup() throws Exception {
        var first = live();
        String oldToken = first.getRefreshToken().getToken().getTokenValue();
        db.update("update refresh_history set created_at=clock_timestamp()-interval '90 days'");
        try (var pool = Executors.newFixedThreadPool(2)) {
            var barrier = new CyclicBarrier(2);
            var rotate = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                service.save(rotated(first));
                return null;
            });
            var sweep = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return cleanup.runBatch();
            });
            rotate.get(10, TimeUnit.SECONDS);
            assertEquals(0, sweep.get(10, TimeUnit.SECONDS).history());
        }
        assertEquals(2, count("refresh_history"));
        var request = new MockHttpServletRequest("POST", "/oauth2/token");
        request.setParameter("grant_type", "refresh_token");
        request.setParameter("refresh_token", oldToken);
        var response = new MockHttpServletResponse();
        SecurityContextHolder.getContext().setAuthentication(new OAuth2ClientAuthenticationToken(client, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, "test-only"));
        try {
            tx.executeWithoutResult(status -> {
                try {
                    new RefreshGuard(db, service).doFilter(request, response, (req, res) -> fail("Replay reached token grant provider"));
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            });
        } finally {
            SecurityContextHolder.clearContext();
        }
        assertEquals(400, response.getStatus());
        assertNull(service.findById(first.getId()));
    }

    @Test
    void historyWorkIsRowBoundedAndFamilyCannotBePurgedAheadOfHistory() {
        var old = old(false);
        for (int i = 0; i < 7; i++)
            history(old.initial().getId(), "historical-" + i, service.now().minus(Duration.ofDays(3)));
        var small = worker(2);
        var first = small.runBatch();
        assertEquals(2, first.history());
        assertEquals(0, first.lifecycles());
        assertEquals(5, count("refresh_history"));
        for (int i = 0; i < 3; i++) small.runBatch();
        assertEquals(0, count("refresh_history"));
        assertEquals(0, count("authorization_lifecycle"));
    }

    @Test
    void orphanHistoryFromLegacyInvalidationIsBoundedAndRetainsRecentRows() {
        for (int i = 0; i < 5; i++) history("legacy-orphan", "legacy-" + i, service.now().minus(Duration.ofDays(3)));
        history("recent-orphan", "recent", service.now());
        assertEquals(2, worker(2).runBatch().orphanHistory());
        assertEquals(4, count("refresh_history"));
        cleanup.runBatch();
        assertEquals(1, count("refresh_history"));
    }

    @Test
    void busyPrincipalIsSkippedWithoutWaitingThenNextBatchDrainsIt() throws Exception {
        old(true);
        var locked = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        try (var pool = Executors.newSingleThreadExecutor()) {
            var holder = pool.submit(() -> tx.executeWithoutResult(status -> {
                service.lockPrincipal("client:retention-client");
                locked.countDown();
                try {
                    assertTrue(release.await(10, TimeUnit.SECONDS));
                } catch (InterruptedException e) {
                    throw new IllegalStateException(e);
                }
            }));
            assertTrue(locked.await(5, TimeUnit.SECONDS));
            try {
                assertEquals(new RetentionCleanup.Result(0, 0, 0, 0, 0, 0, 0, 0), cleanup.runBatch());
                assertEquals(1, count("oauth2_authorization"));
            } finally {
                release.countDown();
            }
            holder.get(10, TimeUnit.SECONDS);
        }
        assertEquals(1, cleanup.runBatch().lifecycles());
    }

    @Test
    void concurrentWorkersAreIdempotentAndNeverDoubleCountDeletion() throws Exception {
        for (int i = 0; i < 5; i++) old(true);
        RetentionCleanup.Result a, b;
        try (var pool = Executors.newFixedThreadPool(2)) {
            var barrier = new CyclicBarrier(2);
            var first = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return cleanup.runBatch();
            });
            var second = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return worker(100).runBatch();
            });
            a = first.get(15, TimeUnit.SECONDS);
            b = second.get(15, TimeUnit.SECONDS);
        }
        var rest = cleanup.runBatch();
        assertEquals(5, a.grants() + b.grants() + rest.grants());
        assertEquals(5, a.history() + b.history() + rest.history());
        assertEquals(5, a.lifecycles() + b.lifecycles() + rest.lifecycles());
        assertEquals(0, count("oauth2_authorization"));
        assertEquals(0, count("refresh_history"));
        assertEquals(0, count("authorization_lifecycle"));
    }

    @Test
    void cleanupRacingStaleIssuanceAndRevocationCannotResurrectDeletedFamily() throws Exception {
        var old = old(true);
        try (var pool = Executors.newFixedThreadPool(3)) {
            var barrier = new CyclicBarrier(3);
            var sweep = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return cleanup.runBatch();
            });
            var stale = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                assertThrows(OAuth2AuthenticationException.class, () -> service.save(old.initial()));
                return null;
            });
            var revoke = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                service.remove(old.snapshot());
                return null;
            });
            sweep.get(15, TimeUnit.SECONDS);
            stale.get(15, TimeUnit.SECONDS);
            revoke.get(15, TimeUnit.SECONDS);
        }
        cleanup.runBatch();
        assertEquals(0, count("oauth2_authorization"));
        assertEquals(0, count("authorization_lifecycle"));
        assertThrows(OAuth2AuthenticationException.class, () -> service.save(old.initial()));
    }

    @Test
    void sessionTombstoneDeletionDoesNotAllowRedisOrDelayedLoginResurrection() {
        String key = (String) session.getAttribute(TrackedAuthorizationService.SESSION);
        Instant birth = service.now().minus(Duration.ofDays(3));
        service.revokeSession(key, user);
        db.update("update identity_sessions set created_at=?,expires_at=? where id=?", Timestamp.from(birth), Timestamp.from(birth.plusSeconds(28800)), key);
        assertEquals(1, cleanup.runBatch().sessions());
        assertTrue(service.sessionRevoked(key, user));
        assertThrows(OAuth2AuthenticationException.class, () -> browser(() -> {
            live();
            return null;
        }));
        assertThrows(OAuth2AuthenticationException.class, () -> service.registerSession(key, user, birth));
        assertDoesNotThrow(() -> service.registerSession(UUID.randomUUID().toString(), user, service.now()));
    }

    @Test
    void expiredSessionWithReferencedFamilyIsKeptAndMissingSessionFailsClosed() {
        var live = live();
        String key = live.getAttribute(TrackedAuthorizationService.SESSION);
        Instant birth = service.now().minus(Duration.ofDays(3));
        db.update("update identity_sessions set created_at=?,expires_at=? where id=?", Timestamp.from(birth), Timestamp.from(birth.plusSeconds(28800)), key);
        assertEquals(0, cleanup.runBatch().sessions());
        assertNull(service.findById(live.getId()));
        assertTrue(service.sessionRevoked(key, user));
    }

    @Test
    void pendingConsentBirthStampCannotBeReusedAfterTombstonePurge() {
        Instant birth = service.now().minus(Duration.ofHours(50)), end = birth.plusSeconds(28800);
        var pending = OAuth2Authorization.withRegisteredClient(client).principalName(user)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .attribute(OAuth2AuthorizationRequest.class.getName(), OAuth2AuthorizationRequest.authorizationCode()
                        .authorizationUri("https://issuer.example/oauth2/authorize").clientId(client.getClientId())
                        .additionalParameters(new HashMap<>(Map.of(AuthorizationBirthConverter.BIRTH, birth.toString()))).build()).build();
        raw.save(OAuth2Authorization.from(pending).attribute(TrackedAuthorizationService.REVISION, "1").build());
        db.update("""
                insert into authorization_lifecycle(id,principal_name,client_id,session_id,created_at,expires_at,grant_expires_at,revision)
                values (?,?,?,?,?,?,?,1)
                """, pending.getId(), user, client.getId(), session.getAttribute(TrackedAuthorizationService.SESSION), Timestamp.from(birth), Timestamp.from(end), Timestamp.from(end));
        assertEquals(1, cleanup.runBatch().lifecycles());
        assertThrows(OAuth2AuthenticationException.class, () -> browser(() -> {
            service.save(pending);
            return null;
        }));
    }

    @Test
    void floorAdvancementAndTombstoneDeleteRollBackTogetherOnFailure() {
        var old = old(false);
        Instant floor = floor();
        db.execute("create function reject_retention_delete() returns trigger language plpgsql as $$ begin raise exception 'injected cleanup failure'; end $$");
        db.execute("create trigger reject_retention_delete before delete on authorization_lifecycle for each row execute function reject_retention_delete()");
        try {
            assertThrows(org.springframework.dao.DataAccessException.class, () -> cleanup.runBatch());
            assertEquals(floor, floor());
            assertEquals(1, count("authorization_lifecycle"));
            assertEquals(1, meters.counter("iam.retention.failures").count());
        } finally {
            db.execute("drop trigger reject_retention_delete on authorization_lifecycle");
            db.execute("drop function reject_retention_delete()");
        }
        assertEquals(1, cleanup.runBatch().lifecycles());
        assertTrue(floor().isAfter(floor));
        assertThrows(OAuth2AuthenticationException.class, () -> service.save(old.initial()));
    }

    @Test
    void unsafeRetentionSettingsAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> new RetentionProperties(true, 0, Duration.ofDays(1)));
        assertThrows(IllegalArgumentException.class, () -> new RetentionProperties(true, 1001, Duration.ofDays(1)));
        assertThrows(IllegalArgumentException.class, () -> new RetentionProperties(true, 100, Duration.ofSeconds(60)));
    }

    @Test
    void sharedCreationFenceMakesCleanupSkipRatherThanBlockAndFreshIssuanceSurvives() throws Exception {
        var old = old(false);
        service.remove(old.snapshot());
        var locked = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        try (var pool = Executors.newSingleThreadExecutor()) {
            var reader = pool.submit(() -> tx.executeWithoutResult(status -> {
                db.queryForList("select initial_not_before from authorization_retention_state for share");
                locked.countDown();
                try {
                    assertTrue(release.await(10, TimeUnit.SECONDS));
                } catch (InterruptedException e) {
                    throw new IllegalStateException(e);
                }
            }));
            assertTrue(locked.await(5, TimeUnit.SECONDS));
            try {
                assertEquals(0, cleanup.runBatch().lifecycles());
                assertEquals(1, count("authorization_lifecycle"));
            } finally {
                release.countDown();
            }
            reader.get(10, TimeUnit.SECONDS);
        }
        assertEquals(1, cleanup.runBatch().lifecycles());
        assertNotNull(live());
    }

    @Test
    void freshIssuanceRacingGarbageCollectionIsNotRejectedOrDeleted() throws Exception {
        old(false);
        var now = service.now();
        var fresh = OAuth2Authorization.withRegisteredClient(client).principalName("client:retention-client")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .token(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, UUID.randomUUID().toString(), now, now.plusSeconds(300))).build();
        try (var pool = Executors.newFixedThreadPool(2)) {
            var barrier = new CyclicBarrier(2);
            var sweep = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return cleanup.runBatch();
            });
            var issue = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                service.save(fresh);
                return null;
            });
            sweep.get(15, TimeUnit.SECONDS);
            issue.get(15, TimeUnit.SECONDS);
        }
        cleanup.runBatch();
        assertNotNull(service.findById(fresh.getId()));
        assertEquals(1, count("oauth2_authorization"));
    }

    @Test
    void versionFivePreservesActiveVersionFourGrantsAndConservativelyBackfillsExpiry() {
        String schema = "retention_upgrade";
        String url = POSTGRES.getJdbcUrl() + (POSTGRES.getJdbcUrl().contains("?") ? "&" : "?") + "currentSchema=" + schema;
        var source = new DriverManagerDataSource(url, POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(source).schemas(schema).defaultSchema(schema).target("4").load().migrate();
        var legacyDb = new JdbcTemplate(source);
        var legacyClients = new JdbcRegisteredClientRepository(legacyDb);
        legacyClients.save(client);
        legacyDb.update("insert into users(id,username,password_hash,state) values (?,?,?,'ACTIVE')", user, user, "test-only");
        String key = UUID.randomUUID().toString();
        legacyDb.update("insert into identity_sessions(id,principal_name) values (?,?)", key, user);
        String revoked = UUID.randomUUID().toString();
        legacyDb.update("insert into identity_sessions(id,principal_name,revoked_at) values (?,?,clock_timestamp())", revoked, user);
        Instant birth = service.now(), deadline = birth.plusSeconds(28800);
        String token = UUID.randomUUID().toString();
        var saved = OAuth2Authorization.withRegisteredClient(client).principalName(user).authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .attribute(TrackedAuthorizationService.REVISION, "1").attribute(TrackedAuthorizationService.SESSION, key)
                .token(new OAuth2RefreshToken(token, birth, birth.plusSeconds(3600))).build();
        new JdbcOAuth2AuthorizationService(legacyDb, legacyClients).save(saved);
        legacyDb.update("insert into authorization_lifecycle(id,principal_name,client_id,session_id,created_at,expires_at,revision) values (?,?,?,?,?,?,1)",
                saved.getId(), user, client.getId(), key, Timestamp.from(birth), Timestamp.from(deadline));
        legacyDb.update("insert into refresh_history(token_hash,authorization_id,client_id) values (?,?,?)", TrackedAuthorizationService.digest(token), saved.getId(), client.getId());
        Flyway.configure().dataSource(source).schemas(schema).defaultSchema(schema).load().migrate();
        var upgraded = new TrackedAuthorizationService(legacyDb, legacyClients, new DataSourceTransactionManager(source), Duration.ofHours(8));
        // V5 preserves the grant, but V7 deliberately expires legacy sessions whose idle age is unknown.
        assertNotNull(new JdbcOAuth2AuthorizationService(legacyDb, legacyClients).findById(saved.getId()));
        var found = upgraded.findByToken(token, OAuth2TokenType.REFRESH_TOKEN);
        assertNull(found);
        assertEquals(Timestamp.from(deadline), legacyDb.queryForObject("select grant_expires_at from authorization_lifecycle where id=?", Timestamp.class, saved.getId()));
        assertEquals(1, legacyDb.queryForObject("select count(*) from refresh_history", Integer.class));
        assertTrue(upgraded.sessionRevoked(revoked, user));
        var maintenance = new RetentionCleanup(legacyDb, new DataSourceTransactionManager(source), new RetentionProperties(true, 100, Duration.ofDays(1)), new SimpleMeterRegistry());
        assertEquals(new RetentionCleanup.Result(0, 0, 0, 0, 0, 0, 0, 0), maintenance.runBatch());
        var expiry = new com.example.iam.server.session.SessionExpiry(legacyDb, new DataSourceTransactionManager(source), upgraded, new SimpleMeterRegistry(), true, 100);
        assertEquals(1, expiry.runBatch());
        assertNull(upgraded.findById(saved.getId()));
    }

    record Old(OAuth2Authorization initial, OAuth2Authorization snapshot) {
    }

}
