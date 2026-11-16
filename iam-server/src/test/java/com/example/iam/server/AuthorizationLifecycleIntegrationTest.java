package com.example.iam.server;

import com.example.iam.server.token.TrackedAuthorizationService;
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
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.*;

@Testcontainers
class AuthorizationLifecycleIntegrationTest {
    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:17-alpine");
    static JdbcTemplate db;
    static TrackedAuthorizationService service;
    static TransactionTemplate tx;
    static RegisteredClient client;
    String user;

    @BeforeAll
    static void database() {
        var ds = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(ds).load().migrate();
        db = new JdbcTemplate(ds);
        var manager = new DataSourceTransactionManager(ds);
        tx = new TransactionTemplate(manager);
        var clients = new JdbcRegisteredClientRepository(db);
        client = RegisteredClient.withId(UUID.randomUUID().toString()).clientId("test-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("https://client.example/callback").scope("openid").build();
        clients.save(client);
        service = new TrackedAuthorizationService(db, clients, manager, Duration.ofHours(8));
    }

    @BeforeEach
    void identity() {
        user = UUID.randomUUID().toString();
        db.update("insert into users(id,username,password_hash,state) values (?,?,?,'ACTIVE')", user, user, "test-only");
    }

    private <T> T browser(MockHttpSession session, Supplier<T> action) {
        if (session.getAttribute(TrackedAuthorizationService.SESSION) == null) {
            String key = TrackedAuthorizationService.digest(session.getId()).substring(0, 32);
            service.registerSession(key, user, service.now());
            session.setAttribute(TrackedAuthorizationService.SESSION, key);
        }
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

    private OAuth2Authorization grant(MockHttpSession session) {
        return browser(session, () -> {
            Instant now = Instant.now();
            var authorization = OAuth2Authorization.withRegisteredClient(client).principalName(user)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizedScopes(new HashSet<>(Set.of("openid")))
                    .token(new OAuth2AuthorizationCode(UUID.randomUUID().toString(), now, now.plusSeconds(60)))
                    .token(new OAuth2RefreshToken(UUID.randomUUID().toString(), now, now.plus(Duration.ofDays(1))))
                    .build();
            service.save(authorization);
            return service.findById(authorization.getId());
        });
    }

    private OAuth2Authorization rotate(OAuth2Authorization previous) {
        return OAuth2Authorization.from(previous).token(new OAuth2RefreshToken(UUID.randomUUID().toString(),
                Instant.now(), Instant.now().plus(Duration.ofDays(1)))).build();
    }

    @Test
    void deadlineIsAbsoluteAndRotatedTokenIsClamped() {
        var original = grant(new MockHttpSession());
        var deadline = db.queryForObject("select expires_at from authorization_lifecycle where id=?", java.sql.Timestamp.class, original.getId());
        service.save(rotate(original));
        var current = service.findById(original.getId());
        assertEquals(deadline, db.queryForObject("select expires_at from authorization_lifecycle where id=?", java.sql.Timestamp.class, original.getId()));
        assertEquals(deadline.toInstant(), current.getRefreshToken().getToken().getExpiresAt());
        db.update("update authorization_lifecycle set created_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour' where id=?", original.getId());
        assertNull(service.findByToken(current.getRefreshToken().getToken().getTokenValue(), OAuth2TokenType.REFRESH_TOKEN));
        assertThrows(OAuth2AuthenticationException.class, () -> service.save(rotate(current)));
    }

    @Test
    void staleIssuanceCannotResurrectRemovedAuthorization() throws Exception {
        var snapshot = grant(new MockHttpSession());
        var removed = new CountDownLatch(1);
        try (var pool = Executors.newFixedThreadPool(2)) {
            var revoke = pool.submit(() -> {
                service.remove(snapshot);
                removed.countDown();
            });
            var issue = pool.submit(() -> {
                assertTrue(removed.await(5, TimeUnit.SECONDS));
                assertThrows(OAuth2AuthenticationException.class, () -> service.save(rotate(snapshot)));
                return null;
            });
            revoke.get(10, TimeUnit.SECONDS);
            issue.get(10, TimeUnit.SECONDS);
        }
        assertNull(service.findById(snapshot.getId()));
        assertEquals(0, db.queryForObject("select count(*) from oauth2_authorization where id=?", Integer.class, snapshot.getId()));
    }

    @Test
    void twoStaleIssuanceSnapshotsHaveOnlyOneWinner() throws Exception {
        var snapshot = grant(new MockHttpSession());
        var barrier = new CyclicBarrier(2);
        Callable<Boolean> save = () -> {
            barrier.await(5, TimeUnit.SECONDS);
            try {
                service.save(rotate(snapshot));
                return true;
            } catch (OAuth2AuthenticationException rejected) {
                return false;
            }
        };
        try (var pool = Executors.newFixedThreadPool(2)) {
            var first = pool.submit(save);
            var second = pool.submit(save);
            assertNotEquals(first.get(10, TimeUnit.SECONDS), second.get(10, TimeUnit.SECONDS));
        }
    }

    @Test
    void staleRevocationStillRevokesTheLatestGeneration() {
        var snapshot = grant(new MockHttpSession());
        service.save(rotate(snapshot));
        var invalidated = OAuth2Authorization.from(snapshot).token(snapshot.getRefreshToken().getToken(),
                metadata -> metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true)).build();
        service.save(invalidated);
        assertNull(service.findById(snapshot.getId()));
        assertThrows(OAuth2AuthenticationException.class, () -> service.save(rotate(snapshot)));
    }

    @Test
    void logoutRevokesAllGrantsInOnlyThatSession() {
        var sameSession = new MockHttpSession();
        var first = grant(sameSession);
        var second = grant(sameSession);
        var separate = grant(new MockHttpSession());
        service.revokeSession(first.getAttribute(TrackedAuthorizationService.SESSION), user);
        assertNull(service.findById(first.getId()));
        assertNull(service.findById(second.getId()));
        assertNotNull(service.findById(separate.getId()));
        assertThrows(OAuth2AuthenticationException.class, () -> service.save(rotate(first)));
        assertThrows(OAuth2AuthenticationException.class, () -> grant(sameSession));
    }

    @Test
    void logoutBeforeFirstGrantPreventsInflightAuthorization() {
        var session = new MockHttpSession();
        service.revokeSession(TrackedAuthorizationService.digest(session.getId()).substring(0, 32), user);
        assertThrows(OAuth2AuthenticationException.class, () -> grant(session));
    }

    @Test
    void suspensionFencesInflightIssuanceAndReactivationDoesNotRestoreOldGrants() {
        var snapshot = grant(new MockHttpSession());
        tx.executeWithoutResult(status -> {
            service.lockPrincipal(user);
            db.update("update users set state='SUSPENDED' where id=?", user);
            service.revokeUser(user);
        });
        assertThrows(OAuth2AuthenticationException.class, () -> service.save(rotate(snapshot)));
        db.update("update users set state='ACTIVE' where id=?", user);
        assertThrows(OAuth2AuthenticationException.class, () -> service.save(rotate(snapshot)));
        assertNull(service.findById(snapshot.getId()));
    }

    @Test
    void revocationRemainsIdempotentAfterSuspension() {
        var snapshot = grant(new MockHttpSession());
        tx.executeWithoutResult(status -> {
            service.lockPrincipal(user);
            db.update("update users set state='SUSPENDED' where id=?", user);
            service.revokeUser(user);
        });
        var invalidated = OAuth2Authorization.from(snapshot).token(snapshot.getRefreshToken().getToken(),
                metadata -> metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true)).build();
        assertDoesNotThrow(() -> service.save(invalidated));
        assertNull(service.findById(snapshot.getId()));
    }

    @Test
    void versionFourUpgradeInvalidatesLegacyGrantsButKeepsDirectoryAndClients() {
        String schema = "upgrade_test";
        String url = POSTGRES.getJdbcUrl() + (POSTGRES.getJdbcUrl().contains("?") ? "&" : "?") + "currentSchema=" + schema;
        var source = new DriverManagerDataSource(url, POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(source).schemas(schema).defaultSchema(schema).target("3").load().migrate();
        var legacyDb = new JdbcTemplate(source);
        var legacyClients = new JdbcRegisteredClientRepository(legacyDb);
        legacyClients.save(client);
        legacyDb.update("insert into users(id,username,password_hash,state) values (?,?,?,'ACTIVE')", user, user, "test-only");
        var raw = new JdbcOAuth2AuthorizationService(legacyDb, legacyClients);
        var legacy = OAuth2Authorization.withRegisteredClient(client).principalName(user)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .token(new OAuth2AuthorizationCode("legacy-test-code", Instant.now(), Instant.now().plusSeconds(60))).build();
        raw.save(legacy);
        assertNotNull(raw.findById(legacy.getId()));
        Flyway.configure().dataSource(source).schemas(schema).defaultSchema(schema).load().migrate();
        assertNull(raw.findById(legacy.getId()));
        assertEquals(1, legacyDb.queryForObject("select count(*) from users", Integer.class));
        assertNotNull(legacyClients.findById(client.getId()));
    }

}
