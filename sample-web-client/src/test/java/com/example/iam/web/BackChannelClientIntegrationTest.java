package com.example.iam.web;

import com.example.iam.web.logout.JdbcOidcSessions;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionInformation;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.session.jdbc.JdbcIndexedSessionRepository;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"CLIENT_SECRET=test-only", "CLIENT_SCHEMA=public", "client.logout.cleanup-delay-ms=3600000"})
@org.springframework.test.annotation.DirtiesContext(classMode = org.springframework.test.annotation.DirtiesContext.ClassMode.AFTER_CLASS)
@Import(BackChannelClientIntegrationTest.Clients.class)
class BackChannelClientIntegrationTest {
    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:17-alpine");
    static final AtomicReference<JWKSet> KEYS = new AtomicReference<>();
    static final AtomicBoolean UNAVAILABLE = new AtomicBoolean();
    static final RSAKey KEY = key("first"), SECOND = key("second");
    static final com.sun.net.httpserver.HttpServer ISSUER = issuer();
    static final String EVENT = "http://schemas.openid.net/event/backchannel-logout";
    final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).followRedirects(HttpClient.Redirect.NEVER).build();
    @LocalServerPort
    int port;
    @Autowired
    JdbcTemplate db;
    @Autowired
    JdbcIndexedSessionRepository repository;
    @Autowired
    JdbcOidcSessions sessions;
    String subject, sid;

    static RSAKey key(String id) {
        try {
            return new RSAKeyGenerator(2048).keyID(id).generate();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static com.sun.net.httpserver.HttpServer issuer() {
        try {
            var server = com.sun.net.httpserver.HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            KEYS.set(new JWKSet(KEY.toPublicJWK()));
            server.createContext("/jwks", exchange -> {
                if (UNAVAILABLE.get()) {
                    exchange.sendResponseHeaders(503, -1);
                    exchange.close();
                    return;
                }
                byte[] body = KEYS.get().toString().getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, body.length);
                try (var out = exchange.getResponseBody()) {
                    out.write(body);
                }
            });
            server.start();
            return server;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String issuerUri() {
        return "http://127.0.0.1:" + ISSUER.getAddress().getPort();
    }

    @AfterAll
    static void stopIssuer() {
        ISSUER.stop(0);
    }

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry properties) {
        properties.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        properties.add("spring.datasource.username", POSTGRES::getUsername);
        properties.add("spring.datasource.password", POSTGRES::getPassword);
    }

    @BeforeEach
    void setup() {
        UNAVAILABLE.set(false);
        KEYS.set(new JWKSet(List.of(KEY.toPublicJWK(), SECOND.toPublicJWK())));
        db.execute("truncate rp_bindings,rp_logout_receipts,rp_revoked_sids,rp_creation_floor,SPRING_SESSION cascade");
        subject = UUID.randomUUID().toString();
        sid = UUID.randomUUID().toString();
    }

    OidcUser user(String sid, Instant issued) {
        return new DefaultOidcUser(List.of(new SimpleGrantedAuthority("OIDC_USER")),
                new OidcIdToken("internal-test-id-token", issued, issued.plusSeconds(300), Map.of("iss", issuerUri(), "sub", subject, "aud", List.of("rp-test"), "sid", sid)));
    }

    @SuppressWarnings("unchecked")
    Local local(String sid, boolean bind) {
        var user = user(sid, Instant.now());
        org.springframework.session.SessionRepository<org.springframework.session.Session> typed = (org.springframework.session.SessionRepository<org.springframework.session.Session>) (org.springframework.session.SessionRepository<?>) repository;
        var session = typed.createSession();
        var authentication = new OAuth2AuthenticationToken(user, user.getAuthorities(), "iam");
        session.setAttribute("SPRING_SECURITY_CONTEXT", new SecurityContextImpl(authentication));
        typed.save(session);
        var info = new OidcSessionInformation(session.getId(), Map.of(), user);
        if (bind) sessions.saveSessionInformation(info);
        return new Local(session.getId(), info);
    }

    String token(String sid, String jti, Map<String, Object> overrides, RSAKey key, String type) throws Exception {
        var claims = new JWTClaimsSet.Builder().issuer(issuerUri()).subject(subject).audience("rp-test").jwtID(jti)
                .issueTime(new Date()).expirationTime(Date.from(Instant.now().plusSeconds(120)))
                .claim("sid", sid).claim("events", Map.of(EVENT, Map.of()));
        overrides.forEach(claims::claim);
        var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).type(new JOSEObjectType(type)).build(), claims.build());
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    String token(String sid, String jti) throws Exception {
        return token(sid, jti, Map.of(), KEY, "logout+jwt");
    }

    HttpResponse<String> post(String token) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/logout/connect/back-channel/iam"))
                .timeout(Duration.ofSeconds(10)).header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("logout_token=" + URLEncoder.encode(token, StandardCharsets.UTF_8))).build(), HttpResponse.BodyHandlers.ofString());
    }

    int profile(String id) throws Exception {
        String cookie = Base64.getEncoder().encodeToString(id.getBytes(StandardCharsets.UTF_8));
        return http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/profile")).timeout(Duration.ofSeconds(10))
                .header("Cookie", "CLIENT_A=" + cookie).build(), HttpResponse.BodyHandlers.discarding()).statusCode();
    }

    @Test
    void validNativeLogoutDeletesRealHttpSessionAndPreservesOtherSid() throws Exception {
        var old = local(sid, true);
        var other = local("different-sid", true);
        assertEquals(200, profile(old.id()));
        var response = post(token(sid, UUID.randomUUID().toString()));
        assertEquals(200, response.statusCode());
        assertTrue(response.headers().firstValue("Cache-Control").orElse("").contains("no-store"));
        assertNull(repository.findById(old.id()));
        assertFalse(sessions.valid(old.id()));
        assertNotEquals(200, profile(old.id()));
        assertEquals(200, profile(other.id()));
    }

    @Test
    void exactReplayIsIdempotentAndSameJtiWithChangedSidIsRejected() throws Exception {
        var old = local(sid, true);
        String jti = UUID.randomUUID().toString(), token = token(sid, jti);
        assertEquals(200, post(token).statusCode());
        var fresh = local("new-sid", true);
        assertEquals(200, post(token).statusCode());
        assertEquals(200, profile(fresh.id()));
        assertEquals(400, post(token("new-sid", jti)).statusCode());
        assertEquals(200, profile(fresh.id()));
        assertEquals(1, db.queryForObject("select count(*) from rp_logout_receipts", Integer.class));
    }

    @Test
    void concurrentDuplicateDeliveryIsAtomic() throws Exception {
        var old = local(sid, true);
        String token = token(sid, UUID.randomUUID().toString());
        try (var pool = Executors.newFixedThreadPool(2)) {
            var barrier = new CyclicBarrier(2);
            var a = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return post(token).statusCode();
            });
            var b = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return post(token).statusCode();
            });
            assertEquals(200, a.get(15, TimeUnit.SECONDS));
            assertEquals(200, b.get(15, TimeUnit.SECONDS));
        }
        assertNull(repository.findById(old.id()));
        assertEquals(1, db.queryForObject("select count(*) from rp_logout_receipts", Integer.class));
    }

    @Test
    void logoutBeforeCallbackAndCallbackRacingLogoutCannotRestoreAccess() throws Exception {
        String token = token(sid, UUID.randomUUID().toString());
        var callback = local(sid, false);
        try (var pool = Executors.newFixedThreadPool(2)) {
            var barrier = new CyclicBarrier(2);
            var login = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                try {
                    sessions.saveSessionInformation(callback.info());
                } catch (org.springframework.security.oauth2.core.OAuth2AuthenticationException expected) {
                }
                return null;
            });
            var logout = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return post(token).statusCode();
            });
            login.get(15, TimeUnit.SECONDS);
            assertEquals(200, logout.get(15, TimeUnit.SECONDS));
        }
        assertFalse(sessions.valid(callback.id()));
        assertNotEquals(200, profile(callback.id()));
        assertThrows(org.springframework.security.oauth2.core.OAuth2AuthenticationException.class, () -> sessions.saveSessionInformation(callback.info()));
    }

    @Test
    void durableStateSurvivesHandlerRecreationAndLostSuccessfulResponse() throws Exception {
        var old = local(sid, true);
        String token = token(sid, UUID.randomUUID().toString());
        assertEquals(200, post(token).statusCode());
        var second = new com.example.iam.web.logout.JdbcOidcSessions(db, new org.springframework.jdbc.datasource.DataSourceTransactionManager(db.getDataSource()), new Clients().clients());
        assertFalse(second.valid(old.id()));
        assertEquals(200, post(token).statusCode());
        assertNull(repository.findById(old.id()));
    }

    @Test
    void invalidClaimsTypesAudiencesAndKeysNeverInvalidateSessions() throws Exception {
        var old = local(sid, true);
        var invalid = new ArrayList<String>();
        invalid.add(token(sid, UUID.randomUUID().toString(), Map.of("aud", List.of("other-client")), KEY, "logout+jwt"));
        invalid.add(token(sid, UUID.randomUUID().toString(), Map.of("iss", "https://attacker.invalid"), KEY, "logout+jwt"));
        invalid.add(token(sid, UUID.randomUUID().toString(), Map.of("nonce", "forbidden"), KEY, "logout+jwt"));
        invalid.add(token(sid, UUID.randomUUID().toString(), Map.of("events", Map.of("wrong-event", Map.of())), KEY, "logout+jwt"));
        invalid.add(token(sid, UUID.randomUUID().toString(), Map.of("exp", Date.from(Instant.now().minusSeconds(120))), KEY, "logout+jwt"));
        invalid.add(token(sid, UUID.randomUUID().toString(), Map.of("iat", Date.from(Instant.now().plusSeconds(90))), KEY, "logout+jwt"));
        invalid.add(token(sid, UUID.randomUUID().toString(), Map.of(), KEY, "JWT"));
        invalid.add(token(sid, UUID.randomUUID().toString(), Map.of(), key("unknown"), "logout+jwt"));
        invalid.add(token(sid, UUID.randomUUID().toString(), Map.of("sub", "another-user"), KEY, "logout+jwt"));
        invalid.add(token(sid, UUID.randomUUID().toString(), Map.of("events", Map.of(EVENT, Map.of("unsupported", "value"))), KEY, "logout+jwt"));
        invalid.add("not-a-jwt");
        for (String value : invalid) {
            assertEquals(400, post(value).statusCode());
            assertEquals(200, profile(old.id()));
        }
    }

    @Test
    void algorithmConfusionAndMissingRequiredFieldsAreRejected() throws Exception {
        var old = local(sid, true);
        var base = SignedJWT.parse(token(sid, UUID.randomUUID().toString())).getJWTClaimsSet();
        var hs = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).type(new JOSEObjectType("logout+jwt")).build(), base);
        hs.sign(new MACSigner(new byte[32]));
        assertEquals(400, post(hs.serialize()).statusCode());
        for (String missing : List.of("iss", "aud", "iat", "exp", "jti", "sid")) {
            var claims = new JWTClaimsSet.Builder(base).claim(missing, null).build();
            var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KEY.getKeyID()).type(new JOSEObjectType("logout+jwt")).build(), claims);
            jwt.sign(new RSASSASigner(KEY));
            assertEquals(400, post(jwt.serialize()).statusCode());
        }
        assertEquals(200, profile(old.id()));
    }

    @Test
    void transactionFailureDoesNotAcknowledgeOrLoseSessionAndRetrySucceeds() throws Exception {
        var old = local(sid, true);
        String token = token(sid, UUID.randomUUID().toString());
        db.execute("create function reject_rp_logout() returns trigger language plpgsql as $$ begin raise exception 'injected RP failure'; end $$");
        db.execute("create trigger reject_rp_logout before insert on rp_revoked_sids for each row execute function reject_rp_logout()");
        try {
            assertEquals(503, post(token).statusCode());
            assertEquals(200, profile(old.id()));
            assertEquals(0, db.queryForObject("select count(*) from rp_logout_receipts", Integer.class));
        } finally {
            db.execute("drop trigger reject_rp_logout on rp_revoked_sids");
            db.execute("drop function reject_rp_logout()");
        }
        assertEquals(200, post(token).statusCode());
        assertNull(repository.findById(old.id()));
    }

    @Test
    void unknownKeyDuringJwksOutageIsRetryableThenRecovers() throws Exception {
        local(sid, true);
        KEYS.set(new JWKSet(KEY.toPublicJWK()));
        assertEquals(200, post(token("unrelated-sid", UUID.randomUUID().toString())).statusCode());
        UNAVAILABLE.set(true);
        String token = token(sid, UUID.randomUUID().toString(), Map.of(), key("rotated-during-outage"), "logout+jwt");
        var rotated = key("usable-rotated-key");
        token = token(sid, UUID.randomUUID().toString(), Map.of(), rotated, "logout+jwt");
        assertEquals(503, post(token).statusCode());
        UNAVAILABLE.set(false);
        KEYS.set(new JWKSet(List.of(KEY.toPublicJWK(), rotated.toPublicJWK())));
        assertEquals(200, post(token).statusCode());
    }

    @Test
    void receiptAndSidCleanupCannotRestoreStaleCallback() throws Exception {
        var old = local(sid, true);
        String token = token(sid, UUID.randomUUID().toString());
        assertEquals(200, post(token).statusCode());
        db.update("update rp_logout_receipts set expires_at=clock_timestamp()-interval '2 days'");
        db.update("update rp_revoked_sids set revoked_at=clock_timestamp()-interval '2 days'");
        sessions.cleanup();
        assertEquals(0, db.queryForObject("select count(*) from rp_logout_receipts", Integer.class));
        assertEquals(0, db.queryForObject("select count(*) from rp_revoked_sids", Integer.class));
        var staleInfo = new OidcSessionInformation(old.id(), Map.of(), user(sid, Instant.now().minusSeconds(3 * 86400)));
        assertThrows(org.springframework.security.oauth2.core.OAuth2AuthenticationException.class, () -> sessions.saveSessionInformation(staleInfo));
        assertFalse(sessions.valid(old.id()));
    }

    @Test
    void privateLoopbackParameterCannotBypassDurableInvalidation() throws Exception {
        var old = local(sid, true);
        String token = token(sid, UUID.randomUUID().toString());
        var response = http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/logout/connect/back-channel/iam"))
                .timeout(Duration.ofSeconds(10)).header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("logout_token=" + URLEncoder.encode(token, StandardCharsets.UTF_8) + "&_spring_security_internal_logout=true")).build(), HttpResponse.BodyHandlers.discarding());
        assertEquals(200, response.statusCode());
        assertNull(repository.findById(old.id()));
        assertFalse(sessions.valid(old.id()));
    }

    record Local(String id, OidcSessionInformation info) {
    }

    @TestConfiguration
    static class Clients {
        @Bean
        ClientRegistrationRepository clients() {
            return new InMemoryClientRegistrationRepository(ClientRegistration.withRegistrationId("iam")
                    .clientId("rp-test").clientSecret("test-only").authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}").scope("openid")
                    .issuerUri(issuerUri()).authorizationUri(issuerUri() + "/authorize").tokenUri(issuerUri() + "/token")
                    .jwkSetUri(issuerUri() + "/jwks").userInfoUri(issuerUri() + "/userinfo").userNameAttributeName("sub").build());
        }
    }

}
