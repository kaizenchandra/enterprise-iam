package com.example.iam.server;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Actual HTTP through the full server filter chain, backed by isolated PostgreSQL and Redis.
 */
@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"iam.account.registration-enabled=true", "iam.account.console-origin=http://localhost:3000", "iam.account.enabled=true", "iam.account.initial-delay-ms=3600000", "iam.account.allow-http=true", "iam.account.public-origin=http://localhost:9000", "ACCOUNT_ENCRYPTION_PASSWORD=test-only-account-encryption-password", "ACCOUNT_ENCRYPTION_SALT=0123456789abcdef0123456789abcdef", "spring.mail.properties.mail.smtp.starttls.enable=false", "spring.mail.properties.mail.smtp.starttls.required=false", "iam.session.expiry-enabled=false", "iam.backchannel.enabled=false", "iam.retention.enabled=false", "iam.issuer=https://issuer.example", "server.servlet.session.cookie.secure=false",
                "MFA_ENCRYPTION_PASSWORD=test-only-encryption-password", "MFA_ENCRYPTION_SALT=00112233445566778899aabbccddeeff"})
@org.springframework.test.annotation.DirtiesContext(classMode = org.springframework.test.annotation.DirtiesContext.ClassMode.AFTER_CLASS)
class TokenProtocolIntegrationTest {
    static final AccountSmtpSink SMTP = new AccountSmtpSink();
    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:17-alpine");
    @Container
    static final GenericContainer<?> REDIS = new GenericContainer<>("redis:7.4-alpine").withExposedPorts(6379);
    static final java.util.concurrent.atomic.AtomicInteger CALLBACK_STATUS = new java.util.concurrent.atomic.AtomicInteger(200);
    static final java.util.concurrent.atomic.AtomicReference<CountDownLatch> BODY_GATE = new java.util.concurrent.atomic.AtomicReference<>();
    static final java.util.List<String> RECEIVED = new java.util.concurrent.CopyOnWriteArrayList<>();
    static final com.sun.net.httpserver.HttpServer CALLBACK = callback();
    static final Path KEY = key();
    static final String SECRET = "test-only-client-secret";
    static final Map<String, String> SECRET_HASHES = new HashMap<>();
    @LocalServerPort
    int port;
    @Autowired
    JdbcTemplate db;
    @Autowired
    com.example.iam.server.retention.RetentionCleanup cleanup;
    @Autowired
    RegisteredClientRepository clients;
    @Autowired
    PasswordEncoder passwords;
    @Autowired
    com.example.iam.server.token.TrackedAuthorizationService authorizations;
    @Autowired
    ObjectMapper json;
    @Autowired
    com.example.iam.server.backchannel.BackChannelDelivery delivery;
    @Autowired
    com.example.iam.server.backchannel.BackChannelPolicy callbackPolicy;
    @Autowired
    org.springframework.transaction.PlatformTransactionManager transactions;
    @Autowired
    com.nimbusds.jose.jwk.source.JWKSource<com.nimbusds.jose.proc.SecurityContext> signingKeys;
    @Autowired
    io.micrometer.core.instrument.MeterRegistry meters;
    @Autowired
    com.example.iam.server.session.SessionExpiry expiry;
    String user, password;
    @Autowired
    org.springframework.session.data.redis.RedisIndexedSessionRepository opSessions;
    @Autowired
    com.example.iam.server.mfa.MfaService mfa;
    @Autowired
    org.springframework.data.redis.core.StringRedisTemplate throttleRedis;
    @Autowired
    com.example.iam.server.passkey.PasskeySettings passkeySettings;
    @Autowired
    com.example.iam.server.account.AccountActions accounts;
    @Autowired
    com.example.iam.server.account.AccountWorker accountWorker;
    @Autowired
    com.example.iam.server.account.RegistrationService registration;

    @AfterAll
    static void stopSmtp() {
        SMTP.close();
    }

    static com.sun.net.httpserver.HttpServer callback() {
        try {
            var server = com.sun.net.httpserver.HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/logout", exchange -> {
                String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                RECEIVED.add(URLDecoder.decode(body.substring("logout_token=".length()), StandardCharsets.UTF_8));
                int status = CALLBACK_STATUS.get();
                if (status == 302) exchange.getResponseHeaders().set("Location", "http://unapproved.invalid/logout");
                var gate = BODY_GATE.get();
                if (gate != null) {
                    exchange.sendResponseHeaders(200, 0);
                    exchange.getResponseBody().write(1);
                    exchange.getResponseBody().flush();
                    try {
                        gate.await(10, TimeUnit.SECONDS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                } else if (status > 0) exchange.sendResponseHeaders(status, -1);
                exchange.close();
            });
            server.start();
            return server;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String callbackUri() {
        return "http://127.0.0.1:" + CALLBACK.getAddress().getPort() + "/logout";
    }

    @AfterAll
    static void stopCallback() {
        CALLBACK.stop(0);
    }

    static Path key() {
        try {
            Path file = Files.createTempFile("iam-protocol-test-", ".jwks");
            Files.writeString(file, new JWKSet(new RSAKeyGenerator(2048).keyID("test-only").generate()).toString(false));
            file.toFile().deleteOnExit();
            return file;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry properties) {
        properties.add("spring.mail.host", () -> "127.0.0.1");
        properties.add("spring.mail.port", SMTP::port);
        properties.add("iam.backchannel.allow-http", () -> true);
        properties.add("iam.backchannel.allowed-origins", () -> "http://127.0.0.1:" + CALLBACK.getAddress().getPort());
        properties.add("spring.datasource.url", () -> POSTGRES.getJdbcUrl() + (POSTGRES.getJdbcUrl().contains("?") ? "&" : "?") + "socketTimeout=3&connectTimeout=2&cancelSignalTimeout=2");
        properties.add("spring.datasource.username", POSTGRES::getUsername);
        properties.add("spring.datasource.password", POSTGRES::getPassword);
        properties.add("spring.data.redis.host", REDIS::getHost);
        properties.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
        properties.add("iam.signing-key-file", KEY::toString);
    }

    String clientHash(String id) {
        return SECRET_HASHES.computeIfAbsent(id, ignored -> passwords.encode(SECRET));
    }

    @BeforeEach
    void fixture() {
        RECEIVED.clear();
        CALLBACK_STATUS.set(200);
        BODY_GATE.set(null);
        SMTP.messages.clear();
        SMTP.mode.set(AccountSmtpSink.Mode.OK);
        db.execute("truncate account_requests,account_mail,account_action_tokens,account_request_limits cascade");
        db.execute("truncate oauth2_authorization,refresh_history,authorization_lifecycle,identity_sessions,users cascade");
        db.update("update authorization_retention_state set initial_not_before='1970-01-01T00:00:00Z'");
        for (String client : List.of("web-a", "web-b")) {
            if (clients.findByClientId(client) == null)
                clients.save(RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId(client).clientSecret(clientHash(client))
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        .redirectUri("https://client.example/callback").postLogoutRedirectUri("https://client.example")
                        .scope("openid").scope("orders.read")
                        .clientSettings(ClientSettings.builder().requireProofKey(true).build())
                        .tokenSettings(TokenSettings.builder().reuseRefreshTokens(false).build()).build());
        }
        for (String id : List.of("web-a", "web-b")) {
            var old = clients.findByClientId(id);
            var settings = new HashMap<>(old.getClientSettings().getSettings());
            settings.remove("backchannel_logout_uri");
            settings.remove("backchannel_logout_session_required");
            clients.save(RegisteredClient.from(old).clientSecret(clientHash(id)).clientSettings(ClientSettings.withSettings(settings).build()).build());
        }
        if (clients.findByClientId("test-admin") == null)
            clients.save(RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("test-admin").clientSecret(clientHash("test-admin"))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).scope("iam.admin").build());
        user = UUID.randomUUID().toString();
        password = UUID.randomUUID().toString();
        db.update("insert into users(id,username,password_hash,state) values (?,?,?,'ACTIVE')", user, user, passwords.encode(password));
    }

    HttpClient browser() {
        return HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3))
                .cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL)).followRedirects(HttpClient.Redirect.NEVER).build();
    }

    HttpResponse<String> request(HttpClient browser, String path, Map<String, String> form, boolean clientAuth, String client) throws Exception {
        var builder = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path)).timeout(Duration.ofSeconds(15));
        if (form == null) builder.GET();
        else if (path.startsWith("/account/") || path.startsWith("/mfa/") || path.startsWith("/passkeys/") || path.startsWith("/session/")) {
            var body = new HashMap<String, Object>(form);
            Object csrf = body.remove("_csrf");
            if (csrf != null) builder.header("X-CSRF-TOKEN", csrf.toString());
            if (body.containsKey("recovery"))
                body.put("recovery", Boolean.parseBoolean(body.get("recovery").toString()));
            builder.header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(body)));
        } else
            builder.header("Content-Type", "application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(query(form)));
        if (clientAuth)
            builder.header("Authorization", "Basic " + Base64.getEncoder().encodeToString((client + ":" + SECRET).getBytes(StandardCharsets.UTF_8)));
        return browser.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    String query(Map<String, String> values) {
        return values.entrySet().stream().map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8)).collect(Collectors.joining("&"));
    }

    String csrf(HttpClient browser) throws Exception {
        var result = request(browser, "/session/bootstrap", null, false, "web-a");
        assertEquals(200, result.statusCode());
        return json.readTree(result.body()).get("csrfToken").asText();
    }

    HttpClient login() throws Exception {
        var browser = browser();
        assertEquals(302, request(browser, "/login", Map.of("username", user, "password", password, "_csrf", csrf(browser)), false, "web-a").statusCode());
        return browser;
    }

    Code code(HttpClient browser, String client) throws Exception {
        return code(browser, client, "openid orders.read");
    }

    Code code(HttpClient browser, String client, String scope) throws Exception {
        String verifier = UUID.randomUUID().toString() + UUID.randomUUID();
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        var response = request(browser, "/oauth2/authorize?" + query(Map.of("response_type", "code", "client_id", client,
                "redirect_uri", "https://client.example/callback", "scope", scope, "state", "state-check",
                "nonce", UUID.randomUUID().toString(), "code_challenge", challenge, "code_challenge_method", "S256")), null, false, client);
        assertEquals(302, response.statusCode());
        String location = response.headers().firstValue("Location").orElseThrow();
        var values = Arrays.stream(URI.create(location).getRawQuery().split("&")).map(s -> s.split("=", 2))
                .collect(Collectors.toMap(s -> s[0], s -> URLDecoder.decode(s[1], StandardCharsets.UTF_8)));
        assertEquals("state-check", values.get("state"));
        assertNotNull(values.get("code"));
        return new Code(values.get("code"), verifier);
    }

    HttpResponse<String> exchange(Code code, String client) throws Exception {
        return request(browser(), "/oauth2/token", Map.of("grant_type", "authorization_code", "code", code.value(),
                "code_verifier", code.verifier(), "redirect_uri", "https://client.example/callback"), true, client);
    }

    JsonNode tokens(HttpClient browser, String client) throws Exception {
        var response = exchange(code(browser, client), client);
        assertEquals(200, response.statusCode());
        return json.readTree(response.body());
    }

    HttpResponse<String> refresh(String token, String client) throws Exception {
        return request(browser(), "/oauth2/token", Map.of("grant_type", "refresh_token", "refresh_token", token), true, client);
    }

    @Test
    void realRotationHasFixedExpiryAndStopsAtDeadline() throws Exception {
        String refresh = tokens(login(), "web-a").get("refresh_token").asText();
        String family = db.queryForObject("select authorization_id from refresh_history where token_hash=?", String.class,
                com.example.iam.server.token.TrackedAuthorizationService.digest(refresh));
        var deadline = db.queryForObject("select expires_at from authorization_lifecycle where id=?", java.sql.Timestamp.class, family);
        var rotated = refresh(refresh, "web-a");
        assertEquals(200, rotated.statusCode());
        assertEquals(deadline, db.queryForObject("select expires_at from authorization_lifecycle where id=?", java.sql.Timestamp.class, family));
        db.update("update authorization_lifecycle set created_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour' where id=?", family);
        assertEquals(400, refresh(json.readTree(rotated.body()).get("refresh_token").asText(), "web-a").statusCode());
    }

    @Test
    void localLogoutRevokesBothClientsButPreservesAnotherSession() throws Exception {
        var browser = login();
        var a = tokens(browser, "web-a");
        var b = tokens(browser, "web-b");
        var independent = tokens(login(), "web-a");
        assertEquals(302, request(browser, "/logout", Map.of("_csrf", csrf(browser)), false, "web-a").statusCode());
        assertEquals(400, refresh(a.get("refresh_token").asText(), "web-a").statusCode());
        assertEquals(400, refresh(b.get("refresh_token").asText(), "web-b").statusCode());
        assertEquals(200, refresh(independent.get("refresh_token").asText(), "web-a").statusCode());
    }

    @Test
    void validatedOidcLogoutRevokesItsSession() throws Exception {
        var browser = login();
        var tokens = tokens(browser, "web-a");
        var independent = tokens(login(), "web-a");
        var response = request(browser, "/connect/logout", Map.of("id_token_hint", tokens.get("id_token").asText(),
                "post_logout_redirect_uri", "https://client.example", "state", "logout-state", "_csrf", csrf(browser)), false, "web-a");
        assertEquals(302, response.statusCode());
        assertTrue(response.headers().firstValue("Location").orElseThrow().startsWith("https://client.example"));
        assertEquals(400, refresh(tokens.get("refresh_token").asText(), "web-a").statusCode());
        assertEquals(200, refresh(independent.get("refresh_token").asText(), "web-a").statusCode());
    }

    @Test
    void invalidOidcLogoutDoesNotRevoke() throws Exception {
        var browser = login();
        var tokens = tokens(browser, "web-a");
        var response = request(browser, "/connect/logout", Map.of("id_token_hint", tokens.get("id_token").asText(),
                "post_logout_redirect_uri", "https://attacker.invalid", "_csrf", csrf(browser)), false, "web-a");
        assertEquals(400, response.statusCode());
        assertEquals(200, refresh(tokens.get("refresh_token").asText(), "web-a").statusCode());
    }

    @Test
    void concurrentCodeExchangeNeverIssuesTwice() throws Exception {
        var code = code(login(), "web-a");
        try (var pool = Executors.newFixedThreadPool(2)) {
            var barrier = new CyclicBarrier(2);
            Callable<HttpResponse<String>> exchange = () -> {
                barrier.await(5, TimeUnit.SECONDS);
                return exchange(code, "web-a");
            };
            var a = pool.submit(exchange);
            var b = pool.submit(exchange);
            var statuses = new ArrayList<>(List.of(a.get(20, TimeUnit.SECONDS).statusCode(), b.get(20, TimeUnit.SECONDS).statusCode()));
            Collections.sort(statuses);
            assertEquals(List.of(200, 400), statuses);
        }
    }

    @Test
    void refreshRacingRevocationLeavesNoUsableGeneration() throws Exception {
        String original = tokens(login(), "web-a").get("refresh_token").asText();
        try (var pool = Executors.newFixedThreadPool(2)) {
            var barrier = new CyclicBarrier(2);
            var rotation = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return refresh(original, "web-a");
            });
            var revocation = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return request(browser(), "/oauth2/revoke", Map.of("token", original), true, "web-a");
            });
            var result = rotation.get(20, TimeUnit.SECONDS);
            assertEquals(200, revocation.get(20, TimeUnit.SECONDS).statusCode());
            assertTrue(result.statusCode() == 200 || result.statusCode() == 400);
            assertEquals(400, refresh(original, "web-a").statusCode());
            if (result.statusCode() == 200)
                assertEquals(400, refresh(json.readTree(result.body()).get("refresh_token").asText(), "web-a").statusCode());
        }
    }

    @Test
    void rotatedRefreshCanBeRevokedAndWrongClientCannotRevokeIt() throws Exception {
        String old = tokens(login(), "web-a").get("refresh_token").asText();
        var result = refresh(old, "web-a");
        assertEquals(200, result.statusCode());
        String current = json.readTree(result.body()).get("refresh_token").asText();
        var wrong = request(browser(), "/oauth2/revoke", Map.of("token", old), true, "web-b");
        assertTrue(wrong.statusCode() == 400 || wrong.statusCode() == 401);
        result = refresh(current, "web-a");
        assertEquals(200, result.statusCode());
        current = json.readTree(result.body()).get("refresh_token").asText();
        assertEquals(200, request(browser(), "/oauth2/revoke", Map.of("token", old), true, "web-a").statusCode());
        assertEquals(200, request(browser(), "/oauth2/revoke", Map.of("token", old), true, "web-a").statusCode());
        assertEquals(400, refresh(current, "web-a").statusCode());
    }

    @Test
    void logoutCannotBeTriggeredWithoutCsrfAndPendingCodeDiesOnLogout() throws Exception {
        var browser = login();
        var pending = code(browser, "web-a");
        assertEquals(403, request(browser, "/logout", Map.of(), false, "web-a").statusCode());
        assertEquals(200, exchange(pending, "web-a").statusCode());
        var second = code(browser, "web-a");
        assertEquals(302, request(browser, "/logout", Map.of("_csrf", csrf(browser)), false, "web-a").statusCode());
        assertEquals(400, exchange(second, "web-a").statusCode());
    }

    @Test
    void refreshRacingLogoutLeavesNoUsableGeneration() throws Exception {
        var browser = login();
        String original = tokens(browser, "web-a").get("refresh_token").asText();
        String csrf = csrf(browser);
        try (var pool = Executors.newFixedThreadPool(2)) {
            var barrier = new CyclicBarrier(2);
            var rotation = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return refresh(original, "web-a");
            });
            var logout = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return request(browser, "/logout", Map.of("_csrf", csrf), false, "web-a");
            });
            var result = rotation.get(20, TimeUnit.SECONDS);
            assertEquals(302, logout.get(20, TimeUnit.SECONDS).statusCode());
            assertTrue(result.statusCode() == 200 || result.statusCode() == 400);
            assertEquals(400, refresh(original, "web-a").statusCode());
            if (result.statusCode() == 200)
                assertEquals(400, refresh(json.readTree(result.body()).get("refresh_token").asText(), "web-a").statusCode());
        }
    }

    @Test
    void codeIssuanceRacingAdministrativeSuspensionCannotRestoreAuthorization() throws Exception {
        var code = code(login(), "web-a");
        var admin = request(browser(), "/oauth2/token", Map.of("grant_type", "client_credentials", "scope", "iam.admin"), true, "test-admin");
        assertEquals(200, admin.statusCode());
        String token = json.readTree(admin.body()).get("access_token").asText();
        try (var pool = Executors.newFixedThreadPool(2)) {
            var barrier = new CyclicBarrier(2);
            var issuance = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return exchange(code, "web-a");
            });
            var suspension = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return browser().send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/api/v1/admin/users/" + user + "/suspend"))
                        .timeout(Duration.ofSeconds(15)).header("Authorization", "Bearer " + token)
                        .POST(HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofString());
            });
            var result = issuance.get(20, TimeUnit.SECONDS);
            assertEquals(200, suspension.get(20, TimeUnit.SECONDS).statusCode());
            assertTrue(result.statusCode() == 200 || result.statusCode() == 400);
            assertEquals(0, db.queryForObject("select count(*) from oauth2_authorization where principal_name=?", Integer.class, user));
            if (result.statusCode() == 200)
                assertEquals(400, refresh(json.readTree(result.body()).get("refresh_token").asText(), "web-a").statusCode());
            assertEquals(400, exchange(code, "web-a").statusCode());
        }
    }

    @Test
    void revokedRedisSessionCannotStartAnotherGrantAndFreshLoginWorks() throws Exception {
        var browser = login();
        var issued = tokens(browser, "web-a");
        String family = db.queryForObject("select authorization_id from refresh_history where token_hash=?", String.class,
                com.example.iam.server.token.TrackedAuthorizationService.digest(issued.get("refresh_token").asText()));
        String session = db.queryForObject("select session_id from authorization_lifecycle where id=?", String.class, family);
        authorizations.revokeSession(session, user);
        assertEquals(401, request(browser, "/", null, false, "web-a").statusCode());
        assertEquals(200, refresh(tokens(login(), "web-a").get("refresh_token").asText(), "web-a").statusCode());
    }

    @Test
    void validatedLogoutWithoutOpCookieRevokesOnlyHintedSession() throws Exception {
        var browser = login();
        var hinted = tokens(browser, "web-a");
        var independent = tokens(login(), "web-a");
        var response = request(browser(), "/connect/logout", Map.of("id_token_hint", hinted.get("id_token").asText(),
                "post_logout_redirect_uri", "https://client.example"), false, "web-a");
        assertEquals(302, response.statusCode());
        assertEquals(400, refresh(hinted.get("refresh_token").asText(), "web-a").statusCode());
        assertEquals(200, refresh(independent.get("refresh_token").asText(), "web-a").statusCode());
        assertEquals(401, request(browser, "/", null, false, "web-a").statusCode());
    }

    @Test
    void machineTokensNeverInheritHumanSessionOrSubject() throws Exception {
        // Deliberately choose a client ID equal to a directory user ID.
        var machineClient = RegisteredClient.withId(UUID.randomUUID().toString()).clientId(user)
                .clientSecret(clientHash(user)).clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).scope("orders.read").build();
        clients.save(machineClient);
        var browser = login();
        tokens(browser, "web-a");
        var machine = request(browser, "/oauth2/token", Map.of("grant_type", "client_credentials", "scope", "orders.read"), true, user);
        assertEquals(200, machine.statusCode());
        String token = json.readTree(machine.body()).get("access_token").asText();
        assertEquals("client:" + user, com.nimbusds.jwt.SignedJWT.parse(token).getJWTClaimsSet().getSubject());
        assertEquals(0, db.queryForObject("select count(*) from authorization_lifecycle where client_id=? and session_id is not null",
                Integer.class, machineClient.getId()));
        String csrf = csrf(browser);
        authorizations.revokeUser(user);
        assertEquals(302, request(browser, "/logout", Map.of("_csrf", csrf), false, "web-a").statusCode());
        var introspection = request(browser(), "/oauth2/introspect", Map.of("token", token), true, user);
        assertEquals(200, introspection.statusCode());
        assertTrue(json.readTree(introspection.body()).get("active").asBoolean());
    }

    @Test
    void realReplayProtectionSurvivesCleanupOfOldLookingHistory() throws Exception {
        var issued = tokens(login(), "web-a");
        String original = issued.get("refresh_token").asText();
        var response = refresh(original, "web-a");
        assertEquals(200, response.statusCode());
        String current = json.readTree(response.body()).get("refresh_token").asText();
        String family = db.queryForObject("select authorization_id from refresh_history where token_hash=?", String.class,
                com.example.iam.server.token.TrackedAuthorizationService.digest(original));
        db.update("update refresh_history set created_at=clock_timestamp()-interval '90 days' where authorization_id=?", family);
        cleanup.runBatch();
        assertEquals(2, db.queryForObject("select count(*) from refresh_history where authorization_id=?", Integer.class, family));
        assertEquals(400, refresh(original, "web-a").statusCode());
        assertEquals(400, refresh(current, "web-a").statusCode());
    }

    @Test
    void purgedSessionTombstoneStillFencesRealRedisSession() throws Exception {
        var browser = login();
        var issued = tokens(browser, "web-a");
        String family = db.queryForObject("select authorization_id from refresh_history where token_hash=?", String.class,
                com.example.iam.server.token.TrackedAuthorizationService.digest(issued.get("refresh_token").asText()));
        String session = db.queryForObject("select session_id from authorization_lifecycle where id=?", String.class, family);
        authorizations.revokeSession(session, user);
        db.update("update authorization_lifecycle set created_at=clock_timestamp()-interval '4 days',expires_at=clock_timestamp()-interval '3 days',grant_expires_at=clock_timestamp()-interval '3 days' where id=?", family);
        db.update("update identity_sessions set created_at=clock_timestamp()-interval '4 days',expires_at=clock_timestamp()-interval '3 days' where id=?", session);
        cleanup.runBatch();
        assertEquals(0, db.queryForObject("select count(*) from identity_sessions where id=?", Integer.class, session));
        assertEquals(401, request(browser, "/", null, false, "web-a").statusCode());
        assertEquals(200, refresh(tokens(login(), "web-a").get("refresh_token").asText(), "web-a").statusCode());
    }

    @Test
    void consentFlowCompletesWithServerOwnedBirthStamp() throws Exception {
        String client = "consent-client";
        if (clients.findByClientId(client) == null)
            clients.save(RegisteredClient.withId(UUID.randomUUID().toString()).clientId(client)
                    .clientSecret(clientHash(client)).clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri("https://client.example/callback").scope("openid").scope("orders.read")
                    .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(true).build()).build());
        var browser = login();
        String verifier = UUID.randomUUID().toString() + UUID.randomUUID();
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        var parameters = new HashMap<>(Map.of("response_type", "code", "client_id", client, "redirect_uri", "https://client.example/callback",
                "scope", "openid orders.read", "state", "client-state", "code_challenge", challenge, "code_challenge_method", "S256"));
        parameters.put(com.example.iam.server.token.AuthorizationBirthConverter.BIRTH, "9999-01-01T00:00:00Z");
        var response = request(browser, "/oauth2/authorize?" + query(parameters), null, false, client);
        assertEquals(200, response.statusCode());
        String id = db.queryForObject("select id from oauth2_authorization where principal_name=?", String.class, user);
        org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest saved = authorizations.findById(id)
                .getAttribute(org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest.class.getName());
        String birth = (String) saved.getAdditionalParameters().get(com.example.iam.server.token.AuthorizationBirthConverter.BIRTH);
        assertTrue(java.time.Instant.parse(birth).isBefore(authorizations.now().plusSeconds(1)));
        var matcher = Pattern.compile("name=\"state\"[^>]*value=\"([^\"]+)\"").matcher(response.body());
        assertTrue(matcher.find());
        response = request(browser, "/oauth2/authorize", Map.of("client_id", client, "state", matcher.group(1), "scope", "orders.read", "_csrf", csrf(browser)), false, client);
        assertEquals(302, response.statusCode());
        var values = Arrays.stream(URI.create(response.headers().firstValue("Location").orElseThrow()).getRawQuery().split("&"))
                .map(value -> value.split("=", 2)).collect(Collectors.toMap(value -> value[0], value -> URLDecoder.decode(value[1], StandardCharsets.UTF_8)));
        assertEquals("client-state", values.get("state"));
        assertNotNull(values.get("code"));
        assertEquals(200, exchange(new Code(values.get("code"), verifier), client).statusCode());
    }

    void optIn(String id) {
        var client = clients.findByClientId(id);
        clients.save(RegisteredClient.from(client).clientSettings(ClientSettings.withSettings(client.getClientSettings().getSettings())
                .setting("backchannel_logout_uri", callbackUri()).setting("backchannel_logout_session_required", true).build()).build());
    }

    String sessionFor(JsonNode tokens) {
        return db.queryForObject("select a.session_id from authorization_lifecycle a join refresh_history h on h.authorization_id=a.id where h.token_hash=?", String.class,
                com.example.iam.server.token.TrackedAuthorizationService.digest(tokens.get("refresh_token").asText()));
    }

    com.example.iam.server.backchannel.BackChannelDelivery worker(int attempts) {
        return new com.example.iam.server.backchannel.BackChannelDelivery(db, transactions, callbackPolicy, clients, signingKeys, meters, "https://issuer.example", false, 10, attempts);
    }

    @Test
    void backchannelRevocationAtomicallyQueuesBothClientsAndDeliversSignedTokens() throws Exception {
        optIn("web-a");
        optIn("web-b");
        var browser = login();
        var a = tokens(browser, "web-a");
        var b = tokens(browser, "web-b");
        String session = sessionFor(a);
        assertEquals(302, request(browser, "/logout", Map.of("_csrf", csrf(browser)), false, "web-a").statusCode());
        assertEquals(2, db.queryForObject("select count(*) from logout_deliveries", Integer.class));
        assertEquals(2, delivery.runBatch());
        assertEquals(2, RECEIVED.size());
        var publicKey = com.nimbusds.jose.jwk.JWKSet.parse(Files.readString(KEY)).getKeys().getFirst().toRSAKey().toRSAPublicKey();
        var decoder = org.springframework.security.oauth2.jwt.NimbusJwtDecoder.withPublicKey(publicKey).validateType(false).build();
        Set<String> ids = new HashSet<>();
        for (String value : RECEIVED) {
            var token = decoder.decode(value);
            assertEquals("logout+jwt", token.getHeaders().get("typ"));
            assertEquals("https://issuer.example", token.getIssuer().toString());
            assertTrue(List.of("web-a", "web-b").contains(token.getAudience().getFirst()));
            assertEquals(120, java.time.Duration.between(token.getIssuedAt(), token.getExpiresAt()).getSeconds());
            assertFalse(token.getClaims().containsKey("nonce"));
            assertNotNull(token.getClaim("sid"));
            assertNotNull(token.getClaim("events"));
            assertTrue(ids.add(token.getId()));
        }
        authorizations.revokeSession(session, user);
        assertEquals(2, db.queryForObject("select count(*) from logout_deliveries", Integer.class));
        assertEquals(0, delivery.runBatch());
    }

    @Test
    void outboxFailureRollsBackRevocationAndAllowsSafeRetry() throws Exception {
        optIn("web-a");
        var a = tokens(login(), "web-a");
        String session = sessionFor(a);
        db.execute("create function reject_logout_enqueue() returns trigger language plpgsql as $$ begin raise exception 'injected outbox failure'; end $$");
        db.execute("create trigger reject_logout_enqueue before insert on logout_deliveries for each row execute function reject_logout_enqueue()");
        try {
            assertThrows(org.springframework.dao.DataAccessException.class, () -> authorizations.revokeSession(session, user));
            assertTrue(authorizations.sessionActive(session, user));
            assertEquals(0, db.queryForObject("select count(*) from logout_deliveries", Integer.class));
        } finally {
            db.execute("drop trigger reject_logout_enqueue on logout_deliveries");
            db.execute("drop function reject_logout_enqueue()");
        }
        assertEquals(200, refresh(a.get("refresh_token").asText(), "web-a").statusCode());
        authorizations.revokeSession(session, user);
        assertEquals(1, delivery.runBatch());
    }

    @Test
    void outagePersistsRetryAndANewWorkerRecoversIt() throws Exception {
        optIn("web-a");
        authorizations.revokeSession(sessionFor(tokens(login(), "web-a")), user);
        CALLBACK_STATUS.set(503);
        assertEquals(0, delivery.runBatch());
        assertEquals("PENDING", db.queryForObject("select status from logout_deliveries", String.class));
        assertEquals(1, db.queryForObject("select attempts from logout_deliveries", Integer.class));
        assertEquals(0, delivery.runBatch());
        db.update("update logout_deliveries set next_attempt_at=clock_timestamp()-interval '1 second'");
        CALLBACK_STATUS.set(200);
        assertEquals(1, worker(8).runBatch());
        assertEquals("SUCCEEDED", db.queryForObject("select status from logout_deliveries", String.class));
    }

    @Test
    void retryCapAndPermanentRedirectAreTerminal() throws Exception {
        optIn("web-a");
        authorizations.revokeSession(sessionFor(tokens(login(), "web-a")), user);
        CALLBACK_STATUS.set(500);
        var limited = worker(2);
        limited.runBatch();
        db.update("update logout_deliveries set next_attempt_at=clock_timestamp()-interval '1 second'");
        limited.runBatch();
        assertEquals("DEAD", db.queryForObject("select status from logout_deliveries", String.class));
        assertEquals(2, db.queryForObject("select attempts from logout_deliveries", Integer.class));
        assertEquals(0, limited.runBatch());
        assertEquals(2, RECEIVED.size());
        db.update("delete from logout_deliveries");
        db.update("delete from oidc_rp_sessions");
        authorizations.revokeSession(sessionFor(tokens(login(), "web-a")), user);
        CALLBACK_STATUS.set(302);
        delivery.runBatch();
        assertEquals("DEAD", db.queryForObject("select status from logout_deliveries", String.class));
        assertEquals(1, db.queryForObject("select attempts from logout_deliveries", Integer.class));
    }

    @Test
    void concurrentClaimsAndStaleAcknowledgementCannotOverwriteNewLease() throws Exception {
        optIn("web-a");
        authorizations.revokeSession(sessionFor(tokens(login(), "web-a")), user);
        com.example.iam.server.backchannel.BackChannelDelivery.Attempt first;
        try (var pool = Executors.newFixedThreadPool(2)) {
            var barrier = new CyclicBarrier(2);
            var a = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return delivery.claim();
            });
            var b = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return delivery.claim();
            });
            var ar = a.get(10, TimeUnit.SECONDS);
            var br = b.get(10, TimeUnit.SECONDS);
            assertTrue((ar == null) != (br == null));
            first = ar == null ? br : ar;
        }
        db.update("update logout_deliveries set lease_until=clock_timestamp()-interval '1 second'");
        var second = worker(8).claim();
        assertNotNull(second);
        assertNotEquals(first.lease(), second.lease());
        assertFalse(delivery.finish(first, true, false, "HTTP_200"));
        assertTrue(delivery.finish(second, true, false, "HTTP_200"));
        assertEquals("SUCCEEDED", db.queryForObject("select status from logout_deliveries", String.class));
    }

    @Test
    void pendingAndRecentlyCompletedDeliveryPinRetentionUntilGracePasses() throws Exception {
        optIn("web-a");
        var a = tokens(login(), "web-a");
        String session = sessionFor(a);
        authorizations.revokeSession(session, user);
        db.update("update authorization_lifecycle set created_at=clock_timestamp()-interval '4 days',expires_at=clock_timestamp()-interval '3 days',grant_expires_at=clock_timestamp()-interval '3 days' where session_id=?", session);
        db.update("update identity_sessions set created_at=clock_timestamp()-interval '4 days',expires_at=clock_timestamp()-interval '3 days' where id=?", session);
        assertEquals(0, cleanup.runBatch().lifecycles());
        assertTrue(db.queryForObject("select exists(select 1 from identity_sessions where id=?)", Boolean.class, session));
        assertEquals(1, delivery.runBatch());
        assertEquals(0, cleanup.runBatch().lifecycles());
        db.update("update logout_deliveries set completed_at=clock_timestamp()-interval '2 days'");
        var swept = cleanup.runBatch();
        assertEquals(1, swept.deliveries());
        assertEquals(1, swept.lifecycles());
        assertEquals(1, swept.participants());
        assertEquals(1, swept.sessions());
    }

    @Test
    void rememberedRpSurvivesRawGrantCleanupAndLostResponseRetries() throws Exception {
        optIn("web-a");
        var a = tokens(login(), "web-a");
        String session = sessionFor(a);
        db.update("update authorization_lifecycle set grant_expires_at=clock_timestamp()-interval '1 second' where session_id=?", session);
        cleanup.runBatch();
        assertEquals(1, db.queryForObject("select count(*) from oidc_rp_sessions where session_id=?", Integer.class, session));
        authorizations.revokeSession(session, user);
        CALLBACK_STATUS.set(-1);
        delivery.runBatch();
        assertEquals("PENDING", db.queryForObject("select status from logout_deliveries", String.class));
        CALLBACK_STATUS.set(200);
        db.update("update logout_deliveries set next_attempt_at=clock_timestamp()-interval '1 second'");
        assertEquals(1, delivery.runBatch());
    }

    @Test
    void logoutRacingIdTokenPersistenceNeverMissesACommittedRp() throws Exception {
        optIn("web-a");
        var browser = login();
        var code = code(browser, "web-a");
        String csrf = csrf(browser);
        try (var pool = Executors.newFixedThreadPool(2)) {
            var barrier = new CyclicBarrier(2);
            var issue = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return exchange(code, "web-a");
            });
            var logout = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return request(browser, "/logout", Map.of("_csrf", csrf), false, "web-a");
            });
            var result = issue.get(20, TimeUnit.SECONDS);
            assertEquals(302, logout.get(20, TimeUnit.SECONDS).statusCode());
            assertTrue(result.statusCode() == 200 || result.statusCode() == 400);
            assertEquals(result.statusCode() == 200 ? 1 : 0, db.queryForObject("select count(*) from logout_deliveries", Integer.class));
        }
    }

    @Test
    void anotherOpRegistryInstanceFindsSameSessionForOidcCorrelation() throws Exception {
        var browser = login();
        tokens(browser, "web-a");
        var peer = new org.springframework.session.security.SpringSessionBackedSessionRegistry<>(opSessions);
        assertFalse(peer.getAllSessions(user, false).isEmpty());
    }

    @Test
    void expiredClaimAtAttemptCapAndDeadlineCannotRemainInflightForever() throws Exception {
        optIn("web-a");
        authorizations.revokeSession(sessionFor(tokens(login(), "web-a")), user);
        var limited = worker(1);
        assertNotNull(limited.claim());
        db.update("update logout_deliveries set lease_until=clock_timestamp()-interval '1 second'");
        assertEquals(0, limited.runBatch());
        assertEquals("DEAD", db.queryForObject("select status from logout_deliveries", String.class));
        assertEquals(0, RECEIVED.size());
        db.update("delete from logout_deliveries");
        db.update("delete from oidc_rp_sessions");
        authorizations.revokeSession(sessionFor(tokens(login(), "web-a")), user);
        db.update("update logout_deliveries set deadline=clock_timestamp()-interval '1 second'");
        assertEquals(0, delivery.runBatch());
        assertEquals("DEAD", db.queryForObject("select status from logout_deliveries", String.class));
        assertEquals(0, RECEIVED.size());
    }

    @Test
    void senderAcknowledgesHeadersWithoutWaitingForUnboundedBody() throws Exception {
        optIn("web-a");
        authorizations.revokeSession(sessionFor(tokens(login(), "web-a")), user);
        var gate = new CountDownLatch(1);
        BODY_GATE.set(gate);
        try (var pool = Executors.newSingleThreadExecutor()) {
            var result = pool.submit(() -> delivery.runBatch());
            try {
                assertEquals(1, result.get(5, TimeUnit.SECONDS));
            } finally {
                gate.countDown();
            }
        }
    }

    @Test
    void configuringBackchannelCannotUndoConcurrentCredentialRotation() throws Exception {
        var admin = new com.example.iam.server.backchannel.BackChannelClientAdmin(clients, callbackPolicy, db);
        var rotate = new com.example.iam.server.client.ClientAdminController(clients, passwords, db, new com.example.iam.server.client.ClientAssertionKeys(db, clients));
        // Use explicit transaction boundaries around the same row-locking methods as the API proxies.
        var transaction = new org.springframework.transaction.support.TransactionTemplate(transactions);
        try (var pool = Executors.newFixedThreadPool(2)) {
            var barrier = new CyclicBarrier(2);
            var configuration = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return transaction.execute(status -> admin.configure("web-a", new com.example.iam.server.backchannel.BackChannelClientAdmin.Registration(callbackUri())));
            });
            var rotation = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return transaction.execute(status -> rotate.rotate("web-a"));
            });
            configuration.get(15, TimeUnit.SECONDS);
            String secret = rotation.get(15, TimeUnit.SECONDS).get("clientSecret");
            var client = clients.findByClientId("web-a");
            assertTrue(passwords.matches(secret, client.getClientSecret()));
            assertEquals(callbackUri(), client.getClientSettings().getSetting("backchannel_logout_uri"));
        }
    }

    @Test
    void deliveryDeadlineExpiresAndRetentionProgressesEvenWhenSenderIsPaused() throws Exception {
        optIn("web-a");
        var a = tokens(login(), "web-a");
        String session = sessionFor(a);
        authorizations.revokeSession(session, user);
        db.update("update authorization_lifecycle set created_at=clock_timestamp()-interval '4 days',expires_at=clock_timestamp()-interval '3 days',grant_expires_at=clock_timestamp()-interval '3 days' where session_id=?", session);
        db.update("update identity_sessions set created_at=clock_timestamp()-interval '4 days',expires_at=clock_timestamp()-interval '3 days' where id=?", session);
        db.update("update logout_deliveries set deadline=clock_timestamp()-interval '1 second'");
        var expired = cleanup.runBatch();
        assertEquals(1, expired.expiredDeliveries());
        assertEquals(0, expired.deliveries());
        assertEquals("DEAD", db.queryForObject("select status from logout_deliveries", String.class));
        assertEquals(0, RECEIVED.size());
        db.update("update logout_deliveries set completed_at=clock_timestamp()-interval '2 days'");
        var swept = cleanup.runBatch();
        assertEquals(1, swept.deliveries());
        assertEquals(1, swept.sessions());
    }

    void makeSessionDue(String session, boolean absolute) {
        db.update(absolute ? "update identity_sessions set expires_at=clock_timestamp()-interval '2 seconds' where id=?"
                : "update identity_sessions set idle_expires_at=clock_timestamp()-interval '2 seconds' where id=?", session);
    }

    @Test
    void idleExpiryWithoutBrowserTrafficRevokesFamiliesAndDeliversToBothRps() throws Exception {
        optIn("web-a");
        optIn("web-b");
        var browser = login();
        var a = tokens(browser, "web-a");
        var b = tokens(browser, "web-b");
        var independent = tokens(login(), "web-a");
        String session = sessionFor(a);
        makeSessionDue(session, false);
        // Eligibility must close at the deadline, before any worker has processed it.
        assertEquals(400, refresh(a.get("refresh_token").asText(), "web-a").statusCode());
        var introspection = request(browser(), "/oauth2/introspect", Map.of("token", a.get("access_token").asText()), true, "web-a");
        assertFalse(json.readTree(introspection.body()).get("active").asBoolean());
        assertEquals(1, expiry.runBatch());
        assertEquals(0, expiry.runBatch());
        assertEquals(2, delivery.runBatch());
        assertEquals(2, RECEIVED.size());
        assertEquals(400, refresh(b.get("refresh_token").asText(), "web-b").statusCode());
        assertEquals(200, refresh(independent.get("refresh_token").asText(), "web-a").statusCode());
        assertEquals(401, request(browser, "/", null, false, "web-a").statusCode());
    }

    @Test
    void absoluteExpiryRejectsPendingCodeAndBrowserAndAllowsFreshLogin() throws Exception {
        optIn("web-a");
        var browser = login();
        var a = tokens(browser, "web-a");
        var pending = code(browser, "web-a");
        String session = sessionFor(a);
        makeSessionDue(session, true);
        assertEquals(400, exchange(pending, "web-a").statusCode());
        // Browser rejection commits revocation and enqueue instead of merely invalidating Redis.
        assertEquals(401, request(browser, "/", null, false, "web-a").statusCode());
        assertEquals(0, expiry.runBatch());
        assertEquals(1, delivery.runBatch());
        assertEquals(400, refresh(a.get("refresh_token").asText(), "web-a").statusCode());
        assertEquals(200, refresh(tokens(login(), "web-a").get("refresh_token").asText(), "web-a").statusCode());
    }

    @Test
    void browserProtocolActivityExtendsIdleButTokenAndIntrospectionDoNot() throws Exception {
        var browser = login();
        var a = tokens(browser, "web-a");
        String session = sessionFor(a);
        db.update("update identity_sessions set idle_expires_at=clock_timestamp()+interval '1 minute' where id=?", session);
        var end = db.queryForObject("select expires_at from identity_sessions where id=?", java.sql.Timestamp.class, session);
        code(browser, "web-b"); // Must touch before the protocol endpoint filter handles authorization.
        var idle = db.queryForObject("select idle_expires_at from identity_sessions where id=?", java.sql.Timestamp.class, session);
        assertTrue(idle.toInstant().isAfter(authorizations.now().plusSeconds(1100)));
        assertEquals(200, request(browser, "/oauth2/token", Map.of("grant_type", "refresh_token", "refresh_token", a.get("refresh_token").asText()), true, "web-a").statusCode());
        assertEquals(idle, db.queryForObject("select idle_expires_at from identity_sessions where id=?", java.sql.Timestamp.class, session));
        assertEquals(200, request(browser, "/oauth2/introspect", Map.of("token", a.get("access_token").asText()), true, "web-a").statusCode());
        assertEquals(idle, db.queryForObject("select idle_expires_at from identity_sessions where id=?", java.sql.Timestamp.class, session));
        assertEquals(end, db.queryForObject("select expires_at from identity_sessions where id=?", java.sql.Timestamp.class, session));
    }

    @Test
    void expiredSessionCannotReachAuthorizationEndpointEvenWithLiveRedisCookie() throws Exception {
        var browser = login();
        var a = tokens(browser, "web-a");
        makeSessionDue(sessionFor(a), false);
        String verifier = UUID.randomUUID().toString() + UUID.randomUUID();
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        var result = request(browser, "/oauth2/authorize?" + query(Map.of("response_type", "code", "client_id", "web-b",
                "redirect_uri", "https://client.example/callback", "scope", "openid orders.read", "state", "check",
                "code_challenge", challenge, "code_challenge_method", "S256")), null, false, "web-b");
        assertEquals(401, result.statusCode());
        assertEquals(0, db.queryForObject("select count(*) from oauth2_authorization where principal_name=?", Integer.class, user));
    }

    @Test
    void expiryCommitsDuringRedisOutageAndRecoveredStaleSessionCannotResume() throws Exception {
        optIn("web-a");
        var browser = login();
        var a = tokens(browser, "web-a");
        String session = sessionFor(a);
        makeSessionDue(session, false);
        REDIS.getDockerClient().pauseContainerCmd(REDIS.getContainerId()).exec();
        try {
            assertEquals(503, request(browser, "/", null, false, "web-a").statusCode());
            assertEquals(1, expiry.runBatch());
            assertEquals(1, delivery.runBatch());
            assertEquals(0, db.queryForObject("select count(*) from oauth2_authorization where principal_name=?", Integer.class, user));
        } finally {
            REDIS.getDockerClient().unpauseContainerCmd(REDIS.getContainerId()).exec();
        }
        assertEquals(401, request(browser, "/", null, false, "web-a").statusCode());
        assertEquals(400, refresh(a.get("refresh_token").asText(), "web-a").statusCode());
    }

    @Test
    void databaseOutageFailsClosedThenExpiryRecoversDurably() throws Exception {
        optIn("web-a");
        var browser = login();
        var a = tokens(browser, "web-a");
        String session = sessionFor(a);
        makeSessionDue(session, false);
        POSTGRES.getDockerClient().pauseContainerCmd(POSTGRES.getContainerId()).exec();
        try {
            assertEquals(503, request(browser, "/", null, false, "web-a").statusCode());
            assertEquals(503, refresh(a.get("refresh_token").asText(), "web-a").statusCode());
            assertThrows(org.springframework.dao.DataAccessException.class, () -> expiry.runBatch());
        } finally {
            POSTGRES.getDockerClient().unpauseContainerCmd(POSTGRES.getContainerId()).exec();
        }
        assertEquals(1, expiry.runBatch());
        assertEquals(1, delivery.runBatch());
        assertEquals(401, request(browser, "/", null, false, "web-a").statusCode());
        assertEquals(400, refresh(a.get("refresh_token").asText(), "web-a").statusCode());
    }

    @Test
    void expiryEnqueueFailureReturns503AndRetryKeepsAtomicRevocation() throws Exception {
        optIn("web-a");
        var browser = login();
        var a = tokens(browser, "web-a");
        String session = sessionFor(a);
        makeSessionDue(session, false);
        db.execute("create function reject_browser_expiry() returns trigger language plpgsql as $$ begin raise exception 'injected queue failure'; end $$");
        db.execute("create trigger reject_browser_expiry before insert on logout_deliveries for each row execute function reject_browser_expiry()");
        try {
            assertEquals(503, request(browser, "/", null, false, "web-a").statusCode());
            assertNull(db.queryForObject("select revoked_at from identity_sessions where id=?", java.sql.Timestamp.class, session));
            assertEquals(0, db.queryForObject("select count(*) from logout_deliveries", Integer.class));
            assertEquals(1, db.queryForObject("select count(*) from oauth2_authorization where principal_name=?", Integer.class, user));
        } finally {
            db.execute("drop trigger reject_browser_expiry on logout_deliveries");
            db.execute("drop function reject_browser_expiry()");
        }
        assertEquals(401, request(browser, "/", null, false, "web-a").statusCode());
        assertEquals(1, delivery.runBatch());
    }

    @Test
    void expirySerializesWithRefreshBlockedBeforeDeadline() throws Exception {
        optIn("web-a");
        var browser = login();
        var a = tokens(browser, "web-a");
        String session = sessionFor(a);
        var transaction = new org.springframework.transaction.support.TransactionTemplate(transactions);
        var locked = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        try (var pool = Executors.newFixedThreadPool(2)) {
            var holder = pool.submit(() -> transaction.executeWithoutResult(status -> {
                authorizations.lockPrincipal(user);
                locked.countDown();
                try {
                    assertTrue(release.await(10, TimeUnit.SECONDS));
                } catch (InterruptedException e) {
                    throw new IllegalStateException(e);
                }
                makeSessionDue(session, false);
            }));
            assertTrue(locked.await(5, TimeUnit.SECONDS));
            var refresh = pool.submit(() -> refresh(a.get("refresh_token").asText(), "web-a"));
            try {
                assertEquals(0, expiry.runBatch());
            } finally {
                release.countDown();
            }
            holder.get(15, TimeUnit.SECONDS);
            assertEquals(400, refresh.get(20, TimeUnit.SECONDS).statusCode());
        }
        assertEquals(1, expiry.runBatch());
        assertEquals(1, delivery.runBatch());
    }

    @Test
    void csrfRejectedPostMustNotExtendDurableIdleDeadline() throws Exception {
        var browser = login();
        var a = tokens(browser, "web-a");
        String session = sessionFor(a);
        db.update("update identity_sessions set idle_expires_at=clock_timestamp()+interval '1 minute' where id=?", session);
        var idle = db.queryForObject("select idle_expires_at from identity_sessions where id=?", java.sql.Timestamp.class, session);
        assertEquals(403, request(browser, "/", Map.of(), false, "web-a").statusCode());
        assertEquals(idle, db.queryForObject("select idle_expires_at from identity_sessions where id=?", java.sql.Timestamp.class, session));
    }

    void managementClient() {
        if (clients.findByClientId("session-manager") == null)
            clients.save(RegisteredClient.withId(UUID.randomUUID().toString()).clientId("session-manager")
                    .clientSecret(clientHash("session-manager")).clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri("https://client.example/callback").scope("openid").scope("sessions.read").scope("sessions.write")
                    .clientSettings(ClientSettings.builder().requireProofKey(true).build()).build());
    }

    JsonNode management(HttpClient browser, String scopes) throws Exception {
        managementClient();
        var result = exchange(code(browser, "session-manager", "openid " + scopes), "session-manager");
        assertEquals(200, result.statusCode());
        return json.readTree(result.body());
    }

    HttpResponse<String> api(String method, String path, String token) throws Exception {
        var request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path)).timeout(Duration.ofSeconds(15))
                .header("Authorization", "Bearer " + token).method(method, HttpRequest.BodyPublishers.noBody()).build();
        return browser().send(request, HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void organizationMembershipApiRequiresAdminAndValidatesPages() throws Exception {
        String tenant = UUID.randomUUID().toString();
        db.update("insert into organizations(id,name) values (?,?)", tenant, "http-membership-test");
        String path = "/api/v1/organizations/" + tenant + "/members";
        assertEquals(401, browser().send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + path)).GET().build(),
                HttpResponse.BodyHandlers.ofString()).statusCode());
        String ordinary = bearer(tokens(login(), "web-a"));
        for (String method : List.of("GET", "POST", "DELETE"))
            assertEquals(403, api(method, path + (method.equals("DELETE") ? "/" + user : ""), ordinary).statusCode());
        String admin = adminToken();
        var post = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                .header("Authorization", "Bearer " + admin).header("Content-Type", "application/json");
        assertEquals(400, browser().send(post.POST(HttpRequest.BodyPublishers.ofString("{\"userId\":\"\"}")).build(),
                HttpResponse.BodyHandlers.ofString()).statusCode());
        String body = json.writeValueAsString(Map.of("userId", user));
        assertEquals(201, browser().send(post.POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.ofString()).statusCode());
        assertEquals(409, browser().send(post.POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.ofString()).statusCode());
        assertEquals(1, json.readTree(api("GET", path, admin).body()).size());
        for (String invalid : List.of("-1", "21474837", "999999999999"))
            assertEquals(400, api("GET", path + "?page=" + invalid, admin).statusCode());
        for (String listing : List.of("/api/v1/admin/users", "/api/v1/admin/organizations", "/api/v1/admin/policies"))
            assertEquals(400, api("GET", listing + "?page=21474837", admin).statusCode());
        assertEquals(204, api("DELETE", path + "/" + user, admin).statusCode());
        assertEquals(404, api("DELETE", path + "/" + user, admin).statusCode());
        assertEquals(0, json.readTree(api("GET", path, admin).body()).size());
    }

    @Test
    void humanAdministratorRoleIsRequiredAtIssuanceAndOnEveryApiRequest() throws Exception {
        var old = clients.findByClientId("web-a");
        clients.save(RegisteredClient.from(old).scope("iam.admin").build());
        var browser = login();
        assertEquals(400, exchange(code(browser, "web-a", "openid iam.admin"), "web-a").statusCode());
        db.update("insert into platform_administrators(user_id) values (?)", user);
        var issued = exchange(code(browser, "web-a", "openid iam.admin"), "web-a");
        assertEquals(200, issued.statusCode());
        String token = json.readTree(issued.body()).get("access_token").asText();
        assertEquals(200, api("GET", "/api/v1/admin/users", token).statusCode());
        db.update("delete from platform_administrators where user_id=?", user);
        assertEquals(403, api("GET", "/api/v1/admin/users", token).statusCode());
        db.update("insert into platform_administrators(user_id) values (?)", user);
        db.update("update users set state='SUSPENDED' where id=?", user);
        assertEquals(403, api("GET", "/api/v1/admin/users", token).statusCode());
    }

    String publicSession(JsonNode token) {
        return db.queryForObject("select management_id::text from identity_sessions where id=?", String.class, sessionFor(token));
    }

    String adminToken() throws Exception {
        return json.readTree(request(browser(), "/oauth2/token", Map.of("grant_type", "client_credentials", "scope", "iam.admin"), true, "test-admin").body()).get("access_token").asText();
    }

    String bearer(JsonNode tokens) {
        return tokens.get("access_token").asText();
    }

    @Test
    void sessionListIsOwnerScopedPaginatedAndContainsNoCookieOrOidcIdentifiers() throws Exception {
        var a = management(login(), "sessions.read sessions.write");
        tokens(login(), "web-a");
        tokens(login(), "web-a");
        String owner = user;
        String ownerPassword = password;
        user = UUID.randomUUID().toString();
        password = UUID.randomUUID().toString();
        db.update("insert into users(id,username,password_hash,state) values (?,?,?,'ACTIVE')", user, user, passwords.encode(password));
        var other = tokens(login(), "web-a");
        String otherPublic = publicSession(other);
        // A membership in a common organization never grants access to another member's sessions.
        String org = UUID.randomUUID().toString();
        db.update("insert into organizations(id,name) values (?,?)", org, "shared");
        db.update("insert into organization_memberships(user_id,organization_id) values (?,?),(?,?)", owner, org, user, org);
        user = owner;
        password = ownerPassword;
        var first = api("GET", "/api/v1/users/me/sessions?limit=2", bearer(a));
        assertEquals(200, first.statusCode());
        assertEquals("no-store", first.headers().firstValue("Cache-Control").orElseThrow());
        var page = json.readTree(first.body());
        assertEquals(2, page.get("items").size());
        assertFalse(page.get("nextCursor").isNull());
        var second = api("GET", "/api/v1/users/me/sessions?limit=2&after=" + page.get("nextCursor").asText(), bearer(a));
        assertEquals(200, second.statusCode());
        assertEquals(1, json.readTree(second.body()).get("items").size());
        assertFalse((first.body() + second.body()).contains(otherPublic));
        assertFalse(first.body().contains(sessionFor(a)));
        assertTrue(json.readTree(api("GET", "/api/v1/users/me/sessions", bearer(a)).body()).get("items").findValues("current").stream().anyMatch(JsonNode::asBoolean));
        assertEquals(400, api("GET", "/api/v1/users/me/sessions?limit=101", bearer(a)).statusCode());
        assertEquals(400, api("GET", "/api/v1/users/me/sessions?after=bad", bearer(a)).statusCode());
    }

    @Test
    void selfRevokeIsIdempotentAndQueuesLogoutOnlyForOwnedTargetSession() throws Exception {
        optIn("web-a");
        var management = management(login(), "sessions.read sessions.write");
        var target = tokens(login(), "web-a");
        String id = publicSession(target);
        assertEquals(204, api("DELETE", "/api/v1/users/me/sessions/" + id, bearer(management)).statusCode());
        assertEquals(204, api("DELETE", "/api/v1/users/me/sessions/" + id, bearer(management)).statusCode());
        assertEquals(1, db.queryForObject("select count(*) from logout_deliveries", Integer.class));
        assertEquals(400, refresh(target.get("refresh_token").asText(), "web-a").statusCode());
        assertEquals(1, delivery.runBatch());
        assertEquals(200, api("GET", "/api/v1/users/me/sessions", bearer(management)).statusCode());
        assertEquals(1, db.queryForObject("select count(*) from security_audit_events where event_type='SESSION_SELF_REVOKED' and actor_id=? and target_session_id=?::uuid", Integer.class, user, id));
    }

    @Test
    void sameAndDifferentTenantUsersCannotRevokeAnotherOwnersSession() throws Exception {
        var caller = management(login(), "sessions.read sessions.write");
        String owner = user;
        user = UUID.randomUUID().toString();
        password = UUID.randomUUID().toString();
        db.update("insert into users(id,username,password_hash,state) values (?,?,?,'ACTIVE')", user, user, passwords.encode(password));
        var target = tokens(login(), "web-a");
        String id = publicSession(target);
        for (boolean shared : List.of(false, true)) {
            if (shared) {
                String org = UUID.randomUUID().toString();
                db.update("insert into organizations(id,name) values (?,?)", org, "shared");
                db.update("insert into organization_memberships(user_id,organization_id) values (?,?),(?,?)", owner, org, user, org);
            }
            assertEquals(404, api("DELETE", "/api/v1/users/me/sessions/" + id, bearer(caller)).statusCode());
            assertEquals(403, api("POST", "/api/v1/admin/users/" + user + "/revoke-sessions", bearer(caller)).statusCode());
        }
        assertEquals(200, refresh(target.get("refresh_token").asText(), "web-a").statusCode());
        assertEquals(404, api("DELETE", "/api/v1/users/me/sessions/" + UUID.randomUUID(), bearer(caller)).statusCode());
    }

    @Test
    void sessionManagementRequiresDedicatedAudienceScopeAndLiveHumanGrant() throws Exception {
        var browser = login();
        var ordinary = tokens(browser, "web-a");
        assertEquals(403, api("GET", "/api/v1/users/me/sessions", bearer(ordinary)).statusCode());
        var readOnly = management(browser, "sessions.read");
        assertEquals(403, api("DELETE", "/api/v1/users/me/sessions/" + publicSession(readOnly), bearer(readOnly)).statusCode());
        authorizations.revokeSession(sessionFor(readOnly), user);
        assertEquals(403, api("GET", "/api/v1/users/me/sessions", bearer(readOnly)).statusCode());
        var machine = RegisteredClient.withId(UUID.randomUUID().toString()).clientId("machine-session-test")
                .clientSecret(clientHash("machine-session-test")).clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).scope("sessions.read").build();
        clients.save(machine);
        var token = json.readTree(request(browser(), "/oauth2/token", Map.of("grant_type", "client_credentials", "scope", "sessions.read"), true, "machine-session-test").body());
        assertEquals(403, api("GET", "/api/v1/users/me/sessions", bearer(token)).statusCode());
    }

    @Test
    void currentSessionRevocationImmediatelyInvalidatesItsManagementToken() throws Exception {
        var m = management(login(), "sessions.read sessions.write");
        String id = publicSession(m);
        assertEquals(204, api("DELETE", "/api/v1/users/me/sessions/" + id, bearer(m)).statusCode());
        assertEquals(403, api("GET", "/api/v1/users/me/sessions", bearer(m)).statusCode());
    }

    @Test
    void platformRevokeAllFencesDelayedLoginAndPreservesOtherIdentitiesAndHistory() throws Exception {
        optIn("web-a");
        var a = tokens(login(), "web-a");
        tokens(login(), "web-a");
        var before = authorizations.now();
        String admin = adminToken();
        assertEquals(204, api("POST", "/api/v1/admin/users/" + user + "/revoke-sessions", admin).statusCode());
        assertThrows(OAuth2AuthenticationException.class, () -> authorizations.registerSession(UUID.randomUUID().toString(), user, before));
        assertEquals(400, refresh(a.get("refresh_token").asText(), "web-a").statusCode());
        assertEquals(2, delivery.runBatch());
        cleanup.runBatch();
        assertEquals(2, db.queryForObject("select count(*) from refresh_history where client_id=?", Integer.class, clients.findByClientId("web-a").getId()));
        db.update("update logout_deliveries set completed_at=clock_timestamp()-interval '2 days' where status='SUCCEEDED'");
        cleanup.runBatch();
        assertEquals(0, db.queryForObject("select count(*) from logout_deliveries", Integer.class));
        assertEquals(204, api("POST", "/api/v1/admin/users/" + user + "/revoke-sessions", admin).statusCode());
        assertEquals(0, db.queryForObject("select count(*) from logout_deliveries", Integer.class));
        assertEquals(200, refresh(tokens(login(), "web-a").get("refresh_token").asText(), "web-a").statusCode());
        assertEquals(404, api("POST", "/api/v1/admin/users/" + UUID.randomUUID() + "/revoke-sessions", admin).statusCode());
    }

    @Test
    void concurrentSessionDeleteExpiryAndRefreshCannotResurrectOrDuplicateLogout() throws Exception {
        optIn("web-a");
        var m = management(login(), "sessions.read sessions.write");
        var target = tokens(login(), "web-a");
        String id = publicSession(target);
        makeSessionDue(sessionFor(target), false);
        try (var pool = Executors.newFixedThreadPool(3)) {
            var barrier = new CyclicBarrier(3);
            var revoke = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return api("DELETE", "/api/v1/users/me/sessions/" + id, bearer(m));
            });
            var expire = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return expiry.runBatch();
            });
            var rotate = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return refresh(target.get("refresh_token").asText(), "web-a");
            });
            assertEquals(204, revoke.get(20, TimeUnit.SECONDS).statusCode());
            expire.get(20, TimeUnit.SECONDS);
            assertEquals(400, rotate.get(20, TimeUnit.SECONDS).statusCode());
        }
        assertEquals(1, db.queryForObject("select count(*) from logout_deliveries", Integer.class));
        assertEquals(1, delivery.runBatch());
        assertEquals(200, api("GET", "/api/v1/users/me/sessions", bearer(m)).statusCode());
    }

    @Test
    void failedSessionManagementEnqueueRollsBackAndReturnsSanitized503() throws Exception {
        optIn("web-a");
        var m = management(login(), "sessions.read sessions.write");
        var target = tokens(login(), "web-a");
        String id = publicSession(target);
        db.execute("create function reject_session_management() returns trigger language plpgsql as $$ begin raise exception 'sensitive SQL detail'; end $$");
        db.execute("create trigger reject_session_management before insert on logout_deliveries for each row execute function reject_session_management()");
        try {
            var result = api("DELETE", "/api/v1/users/me/sessions/" + id, bearer(m));
            assertEquals(503, result.statusCode());
            assertFalse(result.body().contains("sensitive SQL detail"));
            assertTrue(authorizations.sessionActive(sessionFor(target), user));
            assertEquals(0, db.queryForObject("select count(*) from logout_deliveries", Integer.class));
        } finally {
            db.execute("drop trigger reject_session_management on logout_deliveries");
            db.execute("drop function reject_session_management()");
        }
        assertEquals(204, api("DELETE", "/api/v1/users/me/sessions/" + id, bearer(m)).statusCode());
    }

    @Test
    void adminRevokeAllRacingCodeIssuanceCannotMissCommittedRpOrReviveGrant() throws Exception {
        optIn("web-a");
        optIn("web-b");
        var browser = login();
        tokens(browser, "web-a");
        var pending = code(browser, "web-b");
        String admin = adminToken();
        try (var pool = Executors.newFixedThreadPool(2)) {
            var barrier = new CyclicBarrier(2);
            var issue = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return exchange(pending, "web-b");
            });
            var revoke = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return api("POST", "/api/v1/admin/users/" + user + "/revoke-sessions", admin);
            });
            var result = issue.get(20, TimeUnit.SECONDS);
            assertEquals(204, revoke.get(20, TimeUnit.SECONDS).statusCode());
            assertTrue(result.statusCode() == 200 || result.statusCode() == 400);
            assertEquals(result.statusCode() == 200 ? 2 : 1, db.queryForObject("select count(*) from logout_deliveries", Integer.class));
            if (result.statusCode() == 200)
                assertEquals(400, refresh(json.readTree(result.body()).get("refresh_token").asText(), "web-b").statusCode());
        }
        assertEquals(0, db.queryForObject("select count(*) from oauth2_authorization where principal_name=?", Integer.class, user));
    }

    @BeforeEach
    void isolateMfaThrottle() {
        String ip = com.example.iam.server.token.TrackedAuthorizationService.digest("127.0.0.1"), anonymous = com.example.iam.server.token.TrackedAuthorizationService.digest("null");
        var keys = new ArrayList<String>();
        keys.add("iam:throttle:ip:" + ip);
        keys.add("iam:throttle:registration:" + ip);
        for (String bucket : List.of("login", "mfa", "account", "passkey"))
            keys.add("iam:throttle:user:" + bucket + ":" + anonymous + ":" + ip);
        throttleRedis.delete(keys);
    }

    @Test
    void passkeysAreDisabledByDefaultAtTheHttpBoundary() throws Exception {
        assertFalse(passkeySettings.enabled);
        var anonymous = browser();
        String csrf = csrf(anonymous);
        assertFalse(request(anonymous, "/login", null, false, "web-a").body().contains("id=\"passkey-login\""));
        assertEquals(503, request(anonymous, "/passkeys/login/options", Map.of("_csrf", csrf), false, "web-a").statusCode());
        var finish = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/passkeys/login/finish")).header("Content-Type", "application/json").header("X-CSRF-TOKEN", csrf).POST(HttpRequest.BodyPublishers.ofString("{\"id\":\"" + UUID.randomUUID() + "\",\"credential\":{}}")).build();
        assertEquals(503, anonymous.send(finish, HttpResponse.BodyHandlers.ofString()).statusCode());
        var owner = login();
        String proof = csrf(owner);
        assertEquals(503, request(owner, "/passkeys", null, false, "web-a").statusCode());
        assertEquals(503, request(owner, "/passkeys/register/options", Map.of("password", password, "_csrf", proof), false, "web-a").statusCode());
        assertEquals(503, request(owner, "/passkeys/" + UUID.randomUUID() + "/remove", Map.of("password", password, "_csrf", proof), false, "web-a").statusCode());
        assertEquals(0, db.queryForObject("select count(*) from passkey_challenges", Integer.class));
        assertEquals(0, db.queryForObject("select count(*) from passkey_credentials", Integer.class));
        tokens(owner, "web-a");
    }

    @Test
    void passkeyFlowThrottleDoesNotSpendAccountRecoveryAllowance() throws Exception {
        String ip = com.example.iam.server.token.TrackedAuthorizationService.digest("127.0.0.1"), anonymous = com.example.iam.server.token.TrackedAuthorizationService.digest("null");
        var browser = browser();
        String csrf = csrf(browser);
        throttleRedis.opsForValue().set("iam:throttle:user:passkey:" + anonymous + ":" + ip, "60", Duration.ofMinutes(1));
        assertEquals(429, request(browser, "/passkeys/login/options", Map.of("_csrf", csrf), false, "web-a").statusCode());
        assertEquals(200, request(browser, "/account/reset/request", Map.of("email", "unknown@example.test", "_csrf", csrf), false, "web-a").statusCode());
    }

    @Test
    void anonymousPasskeyPostsRequireCsrfAndFinishBodyIsBounded() throws Exception {
        var browser = browser();
        assertEquals(403, request(browser, "/passkeys/login/options", Map.of(), false, "web-a").statusCode());
        String csrf = csrf(browser);
        var oversized = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/passkeys/login/finish")).timeout(Duration.ofSeconds(10)).header("Content-Type", "application/json").header("X-CSRF-TOKEN", csrf).POST(HttpRequest.BodyPublishers.ofString(" ".repeat(65537))).build();
        assertEquals(413, browser.send(oversized, HttpResponse.BodyHandlers.ofString()).statusCode());
    }

    String enabledMfa() {
        String key = mfa.enroll(user);
        db.update("update mfa_credentials set enabled=true where user_id=?", user);
        return key;
    }

    String otp(String key) {
        return String.format("%06d", new com.warrenstrange.googleauth.GoogleAuthenticator().getTotpPassword(key));
    }

    String blockedAuthorization(HttpClient browser) throws Exception {
        String verifier = UUID.randomUUID().toString() + UUID.randomUUID();
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        var result = request(browser, "/oauth2/authorize?" + query(Map.of("response_type", "code", "client_id", "web-a", "redirect_uri", "https://client.example/callback", "scope", "openid orders.read", "state", "check", "code_challenge", challenge, "code_challenge_method", "S256")), null, false, "web-a");
        assertEquals(302, result.statusCode());
        assertTrue(result.headers().firstValue("Location").orElseThrow().endsWith("/mfa"));
        return verifier;
    }

    @Test
    void enrolledUserCannotBypassMfaViaAuthorizeOrRedisMarker() throws Exception {
        String key = enabledMfa();
        var browser = login();
        blockedAuthorization(browser);
        for (var session : opSessions.findByPrincipalName(user).values()) {
            session.setAttribute("mfa_subject", user);
            opSessions.save(session);
        }
        blockedAuthorization(browser);
        assertEquals(0, db.queryForObject("select count(*) from oauth2_authorization where principal_name=?", Integer.class, user));
        var result = request(browser, "/mfa/verify", Map.of("code", otp(key), "_csrf", csrf(browser)), false, "web-a");
        assertEquals(200, result.statusCode());
        var issued = tokens(browser, "web-a");
        assertEquals(200, refresh(issued.get("refresh_token").asText(), "web-a").statusCode());
        assertNotNull(db.queryForObject("select mfa_verified_at from identity_sessions where id=?", java.sql.Timestamp.class, sessionFor(issued)));
        blockedAuthorization(login());
    }

    @Test
    void enrollmentConfirmationRevokesOldFamiliesQueuesLogoutAndShowsCodesOnce() throws Exception {
        optIn("web-a");
        var browser = login();
        var existing = tokens(browser, "web-a");
        var pending = code(browser, "web-a");
        var enrolled = request(browser, "/mfa/enroll", Map.of("password", password, "_csrf", csrf(browser)), false, "web-a");
        assertEquals(200, enrolled.statusCode());
        String secret = json.readTree(enrolled.body()).get("secret").asText();
        var confirmed = request(browser, "/mfa/verify", Map.of("code", otp(secret), "_csrf", csrf(browser)), false, "web-a");
        assertEquals(200, confirmed.statusCode());
        assertEquals("no-store", confirmed.headers().firstValue("Cache-Control").orElseThrow());
        List<String> codes = new ArrayList<>();
        json.readTree(confirmed.body()).get("recoveryCodes").forEach(code -> codes.add(code.asText()));
        assertEquals(10, codes.size());
        assertEquals(400, refresh(existing.get("refresh_token").asText(), "web-a").statusCode());
        assertEquals(400, exchange(pending, "web-a").statusCode());
        assertEquals(1, delivery.runBatch());
        var fresh = login();
        blockedAuthorization(fresh);
        assertEquals(200, request(fresh, "/mfa/recover", Map.of("code", codes.getFirst(), "_csrf", csrf(fresh)), false, "web-a").statusCode());
        tokens(fresh, "web-a");
        var second = login();
        assertEquals(401, request(second, "/mfa/recover", Map.of("code", codes.getFirst(), "_csrf", csrf(second)), false, "web-a").statusCode());
        blockedAuthorization(second);
    }

    @Test
    void concurrentOtpProofCanAssureOnlyOneOpSession() throws Exception {
        String key = enabledMfa();
        var a = login();
        var b = login();
        String csrfA = csrf(a), csrfB = csrf(b), code = otp(key);
        try (var pool = Executors.newFixedThreadPool(2)) {
            var barrier = new CyclicBarrier(2);
            var first = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return request(a, "/mfa/verify", Map.of("code", code, "_csrf", csrfA), false, "web-a").statusCode();
            });
            var second = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return request(b, "/mfa/verify", Map.of("code", code, "_csrf", csrfB), false, "web-a").statusCode();
            });
            assertEquals(Set.of(200, 401), Set.of(first.get(20, TimeUnit.SECONDS), second.get(20, TimeUnit.SECONDS)));
        }
        assertEquals(1, db.queryForObject("select count(*) from identity_sessions where principal_name=? and mfa_verified_at is not null", Integer.class, user));
    }

    @Test
    void durableProofLossBlocksExistingRefreshAndStaleSave() throws Exception {
        String key = enabledMfa();
        var browser = login();
        assertEquals(200, request(browser, "/mfa/verify", Map.of("code", otp(key), "_csrf", csrf(browser)), false, "web-a").statusCode());
        var issued = tokens(browser, "web-a");
        String refresh = issued.get("refresh_token").asText();
        var snapshot = authorizations.findByToken(refresh, org.springframework.security.oauth2.server.authorization.OAuth2TokenType.REFRESH_TOKEN);
        db.update("update identity_sessions set mfa_verified_at=null,mfa_method=null where id=?", sessionFor(issued));
        assertEquals(400, refresh(refresh, "web-a").statusCode());
        assertThrows(OAuth2AuthenticationException.class, () -> authorizations.save(snapshot));
        blockedAuthorization(browser);
    }

    @Test
    void enrollmentOutboxFailureRollsBackCredentialEnablementAndGrantRevocation() throws Exception {
        optIn("web-a");
        var browser = login();
        var issued = tokens(browser, "web-a");
        String key = json.readTree(request(browser, "/mfa/enroll", Map.of("password", password, "_csrf", csrf(browser)), false, "web-a").body()).get("secret").asText();
        db.execute("create function reject_mfa_enrollment() returns trigger language plpgsql as $$ begin raise exception 'injected delivery failure'; end $$");
        db.execute("create trigger reject_mfa_enrollment before insert on logout_deliveries for each row execute function reject_mfa_enrollment()");
        try {
            assertEquals(503, request(browser, "/mfa/verify", Map.of("code", otp(key), "_csrf", csrf(browser)), false, "web-a").statusCode());
            assertFalse(mfa.enabled(user));
            assertNotNull(authorizations.findByToken(issued.get("refresh_token").asText(), org.springframework.security.oauth2.server.authorization.OAuth2TokenType.REFRESH_TOKEN));
        } finally {
            db.execute("drop trigger reject_mfa_enrollment on logout_deliveries");
            db.execute("drop function reject_mfa_enrollment()");
        }
        assertEquals(200, request(browser, "/mfa/verify", Map.of("code", otp(key), "_csrf", csrf(browser)), false, "web-a").statusCode());
    }

    @Test
    void durableMfaLockCannotBeResetWithFreshPasswordLogin() throws Exception {
        String key = enabledMfa();
        var browser = login();
        for (int i = 0; i < 5; i++)
            assertEquals(401, request(browser, "/mfa/verify", Map.of("code", "invalid", "_csrf", csrf(browser)), false, "web-a").statusCode());
        var fresh = login();
        assertEquals(401, request(fresh, "/mfa/verify", Map.of("code", otp(key), "_csrf", csrf(fresh)), false, "web-a").statusCode());
        assertEquals(5, db.queryForObject("select mfa_failed_attempts from users where id=?", Integer.class, user));
        db.update("update users set mfa_locked_until=clock_timestamp()-interval '1 second' where id=?", user);
        assertEquals(200, request(fresh, "/mfa/verify", Map.of("code", otp(key), "_csrf", csrf(fresh)), false, "web-a").statusCode());
        tokens(fresh, "web-a");
    }

    @Test
    void mfaSuccessResumesOriginalPkceAuthorization() throws Exception {
        String key = enabledMfa();
        var browser = login();
        String verifier = blockedAuthorization(browser);
        var proof = request(browser, "/mfa/verify", Map.of("code", otp(key), "_csrf", csrf(browser)), false, "web-a");
        assertEquals(200, proof.statusCode());
        String location = json.readTree(proof.body()).get("redirect").asText();
        assertTrue(location.contains("/oauth2/authorize?"));
        var authorized = browser.send(HttpRequest.newBuilder(URI.create(location)).GET().build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(302, authorized.statusCode());
        var parameters = Arrays.stream(URI.create(authorized.headers().firstValue("Location").orElseThrow()).getRawQuery().split("&")).map(v -> v.split("=", 2)).collect(Collectors.toMap(v -> v[0], v -> URLDecoder.decode(v[1], StandardCharsets.UTF_8)));
        assertEquals(200, exchange(new Code(parameters.get("code"), verifier), "web-a").statusCode());
    }

    @Test
    void mfaVerificationRacingLocalLogoutNeverRevivesSession() throws Exception {
        String key = enabledMfa();
        var browser = login();
        String csrf = csrf(browser);
        String session = db.queryForObject("select id from identity_sessions where principal_name=?", String.class, user);
        try (var pool = Executors.newFixedThreadPool(2)) {
            var barrier = new CyclicBarrier(2);
            var proof = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return request(browser, "/mfa/verify", Map.of("code", otp(key), "_csrf", csrf), false, "web-a").statusCode();
            });
            var logout = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return request(browser, "/logout", Map.of("_csrf", csrf), false, "web-a").statusCode();
            });
            assertEquals(302, logout.get(20, TimeUnit.SECONDS));
            int status = proof.get(20, TimeUnit.SECONDS);
            assertTrue(status == 302 || status == 401);
        }
        assertFalse(authorizations.sessionAssured(session, user));
        assertTrue(authorizations.sessionRevoked(session, user));
        assertEquals(0, db.queryForObject("select count(*) from oauth2_authorization where principal_name=?", Integer.class, user));
    }

    void email(boolean verified, String state) {
        db.update("update users set email=?,email_verified=?,state=? where id=?", user + "@example.test", verified, state, user);
    }

    String accountCsrf(HttpClient browser, String kind) throws Exception {
        return csrf(browser);
    }

    String actionToken(String kind) throws Exception {
        var browser = browser();
        assertEquals(200, request(browser, "/account/" + kind + "/request", Map.of("email", user + "@example.test", "_csrf", accountCsrf(browser, kind)), false, "web-a").statusCode());
        int before = SMTP.messages.size();
        accountWorker.runBatch();
        assertEquals(before + 1, SMTP.messages.size());
        var matcher = Pattern.compile("#token=([A-Za-z0-9_-]{43})").matcher(SMTP.body(before));
        assertTrue(matcher.find());
        return matcher.group(1);
    }

    HttpResponse<String> complete(String kind, String token, String newPassword) throws Exception {
        var browser = browser();
        var form = new HashMap<String, String>();
        form.put("token", token);
        form.put("_csrf", accountCsrf(browser, kind));
        if (newPassword != null) {
            form.put("password", newPassword);
            form.put("confirmation", newPassword);
        }
        return request(browser, "/account/" + kind, form, false, "web-a");
    }

    @Test
    void emailVerificationUsesActualSmtpSingleUseAndSafeActivation() throws Exception {
        email(false, "PENDING_VERIFICATION");
        String token = actionToken("verify");
        assertFalse(db.queryForObject("select email_verified from users where id=?", Boolean.class, user));
        assertEquals(200, complete("verify", token, null).statusCode());
        assertEquals(400, complete("verify", token, null).statusCode());
        assertEquals("ACTIVE", db.queryForObject("select state from users where id=?", String.class, user));
        assertTrue(db.queryForObject("select email_verified from users where id=?", Boolean.class, user));
        tokens(login(), "web-a");
    }

    @Test
    void resetRevokesGrantsFencesOldLoginAndPreservesMfaCredentials() throws Exception {
        optIn("web-a");
        email(true, "ACTIVE");
        String seed = enabledMfa();
        var browser = login();
        assertEquals(200, request(browser, "/mfa/verify", Map.of("code", otp(seed), "_csrf", csrf(browser)), false, "web-a").statusCode());
        var issued = tokens(browser, "web-a");
        String token = actionToken("reset"), next = "replacement-password-very-long";
        var birth = authorizations.now();
        assertEquals(200, complete("reset", token, next).statusCode());
        assertEquals(400, complete("reset", token, next).statusCode());
        assertTrue(mfa.enabled(user));
        assertEquals(1, db.queryForObject("select count(*) from mfa_credentials where user_id=?", Integer.class, user));
        assertEquals(400, refresh(issued.get("refresh_token").asText(), "web-a").statusCode());
        assertEquals(1, delivery.runBatch());
        assertThrows(OAuth2AuthenticationException.class, () -> authorizations.registerSession(UUID.randomUUID().toString(), user, birth));
        assertFalse(passwords.matches(password, db.queryForObject("select password_hash from users where id=?", String.class, user)));
        password = next;
        blockedAuthorization(login()); // Email reset is not MFA recovery.
        accountWorker.runBatch();
        assertTrue(SMTP.body(SMTP.messages.size() - 1).contains("password was changed"));
    }

    @Test
    void unknownAndIneligibleAddressesHaveSamePublicResponseAndNoDelivery() throws Exception {
        email(false, "ACTIVE");
        var a = browser();
        var b = browser();
        var existing = request(a, "/account/reset/request", Map.of("email", user + "@example.test", "_csrf", accountCsrf(a, "reset")), false, "web-a");
        var missing = request(b, "/account/reset/request", Map.of("email", "unknown@example.test", "_csrf", accountCsrf(b, "reset")), false, "web-a");
        assertEquals(200, existing.statusCode());
        assertEquals(existing.body(), missing.body());
        accountWorker.runBatch();
        assertEquals(0, SMTP.messages.size());
        assertEquals(403, request(browser(), "/account/reset/request", Map.of("email", user + "@example.test"), false, "web-a").statusCode());
    }

    @Test
    void smtpOutageAndLostAcknowledgementRetrySameSingleUseToken() throws Exception {
        email(true, "ACTIVE");
        accounts.request(user + "@example.test", "RESET");
        SMTP.mode.set(AccountSmtpSink.Mode.OUTAGE);
        assertEquals(200, request(browser(), "/actuator/health", null, false, "web-a").statusCode()); // Mail outage must not remove healthy auth nodes.
        accountWorker.runBatch();
        assertEquals("PENDING", db.queryForObject("select status from account_mail", String.class));
        assertEquals(0, SMTP.messages.size());
        db.update("update account_mail set next_attempt_at=clock_timestamp()-interval '1 second'");
        SMTP.mode.set(AccountSmtpSink.Mode.LOSE_ACK);
        accountWorker.runBatch();
        assertEquals(1, SMTP.messages.size());
        db.update("update account_mail set next_attempt_at=clock_timestamp()-interval '1 second'");
        SMTP.mode.set(AccountSmtpSink.Mode.OK);
        accountWorker.runBatch();
        assertEquals(2, SMTP.messages.size());
        assertTrue(SMTP.body(0).equals(SMTP.body(1)), "Retry changed message body");
        var matcher = Pattern.compile("#token=([A-Za-z0-9_-]{43})").matcher(SMTP.body(0));
        assertTrue(matcher.find());
        String token = matcher.group(1);
        assertEquals(200, complete("reset", token, "a-new-password-that-is-long").statusCode());
        assertEquals(400, complete("reset", token, "a-new-password-that-is-long").statusCode());
    }

    @Test
    void concurrentResetConsumptionHasOneWinnerAndNoHashOverwrite() throws Exception {
        email(true, "ACTIVE");
        String token = actionToken("reset");
        String a = "first-new-password-very-long", b = "second-new-password-very-long";
        try (var pool = Executors.newFixedThreadPool(2)) {
            var barrier = new CyclicBarrier(2);
            var first = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return complete("reset", token, a).statusCode();
            });
            var second = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return complete("reset", token, b).statusCode();
            });
            assertEquals(Set.of(200, 400), Set.of(first.get(20, TimeUnit.SECONDS), second.get(20, TimeUnit.SECONDS)));
        }
        String hash = db.queryForObject("select password_hash from users where id=?", String.class, user);
        assertNotEquals(passwords.matches(a, hash), passwords.matches(b, hash));
    }

    @Test
    void resetRollbackOnLogoutEnqueueFailureDoesNotConsumeTokenOrChangePassword() throws Exception {
        email(true, "ACTIVE");
        optIn("web-a");
        var issued = tokens(login(), "web-a");
        String token = actionToken("reset");
        db.execute("create function reject_account_logout() returns trigger language plpgsql as $$ begin raise exception 'injected failure'; end $$");
        db.execute("create trigger reject_account_logout before insert on logout_deliveries for each row execute function reject_account_logout()");
        try {
            assertEquals(503, complete("reset", token, "new-recovery-password-that-is-long").statusCode());
            assertNotNull(authorizations.findByToken(issued.get("refresh_token").asText(), org.springframework.security.oauth2.server.authorization.OAuth2TokenType.REFRESH_TOKEN));
            assertTrue(passwords.matches(password, db.queryForObject("select password_hash from users where id=?", String.class, user)));
        } finally {
            db.execute("drop trigger reject_account_logout on logout_deliveries");
            db.execute("drop function reject_account_logout()");
        }
        assertEquals(200, complete("reset", token, "new-recovery-password-that-is-long").statusCode());
    }

    @Test
    void expiryPurposeAndSuspensionNeverReactivateAccount() throws Exception {
        email(true, "ACTIVE");
        String token = actionToken("reset");
        assertEquals(400, complete("verify", token, null).statusCode());
        db.update("update account_action_tokens set expires_at=clock_timestamp()-interval '1 second'");
        assertEquals(400, complete("reset", token, "new-password-long-enough").statusCode());
        db.update("delete from account_request_limits");
        token = actionToken("reset");
        db.update("update users set state='SUSPENDED',version=version+1 where id=?", user);
        assertEquals(400, complete("reset", token, "new-password-long-enough").statusCode());
        assertEquals("SUSPENDED", db.queryForObject("select state from users where id=?", String.class, user));
    }

    @Test
    void deliveryLeasesAndRetentionCannotRestoreExpiredActionOrLateAck() throws Exception {
        email(true, "ACTIVE");
        accounts.request(user + "@example.test", "RESET");
        assertTrue(accountWorker.prepare());
        var first = accountWorker.claim();
        assertNotNull(first);
        db.update("update account_mail set lease_until=clock_timestamp()-interval '1 second'");
        var second = accountWorker.claim();
        assertNotNull(second);
        assertFalse(accountWorker.finish(first, true, false));
        assertTrue(accountWorker.finish(second, true, false));
        db.update("update account_action_tokens set expires_at=clock_timestamp()-interval '2 days'");
        db.update("update account_mail set completed_at=clock_timestamp()-interval '2 days'");
        accountWorker.cleanup();
        assertEquals(0, db.queryForObject("select count(*) from account_mail", Integer.class));
        assertEquals(0, db.queryForObject("select count(*) from account_action_tokens", Integer.class));
        assertFalse(accountWorker.finish(second, true, false));
    }

    @Test
    void queuedRequestBeforeGlobalRevocationCannotMintFreshResetAfterward() {
        email(true, "ACTIVE");
        accounts.request(user + "@example.test", "RESET");
        authorizations.revokeUser(user);
        accountWorker.runBatch();
        assertEquals(0, SMTP.messages.size());
        assertEquals(0, db.queryForObject("select count(*) from account_action_tokens", Integer.class));
    }

    @Test
    void competingRequestAndDeliveryWorkersHaveOneWinner() throws Exception {
        email(true, "ACTIVE");
        try (var pool = Executors.newFixedThreadPool(2)) {
            var barrier = new CyclicBarrier(2);
            var first = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                accounts.request(user + "@example.test", "RESET");
                return null;
            });
            var second = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                accounts.request(user + "@example.test", "RESET");
                return null;
            });
            first.get(10, TimeUnit.SECONDS);
            second.get(10, TimeUnit.SECONDS);
        }
        assertEquals(1, db.queryForObject("select count(*) from account_requests", Integer.class));
        assertTrue(accountWorker.prepare());
        try (var pool = Executors.newFixedThreadPool(2)) {
            var barrier = new CyclicBarrier(2);
            var first = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return accountWorker.claim();
            });
            var second = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return accountWorker.claim();
            });
            assertNotEquals(first.get(10, TimeUnit.SECONDS) == null, second.get(10, TimeUnit.SECONDS) == null);
        }
        assertEquals(1, db.queryForObject("select attempts from account_mail", Integer.class));
    }

    @Test
    void resetRacingSuspensionCannotUndoDisabledStateOrLeaveLiveGrants() throws Exception {
        email(true, "ACTIVE");
        optIn("web-a");
        tokens(login(), "web-a");
        String token = actionToken("reset"), admin = adminToken();
        try (var pool = Executors.newFixedThreadPool(2)) {
            var barrier = new CyclicBarrier(2);
            var reset = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return complete("reset", token, "concurrent-reset-password-long").statusCode();
            });
            var suspend = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return api("POST", "/api/v1/admin/users/" + user + "/suspend", admin).statusCode();
            });
            int status = reset.get(20, TimeUnit.SECONDS);
            assertTrue(status == 200 || status == 400);
            assertEquals(200, suspend.get(20, TimeUnit.SECONDS));
        }
        assertEquals("SUSPENDED", db.queryForObject("select state from users where id=?", String.class, user));
        assertEquals(0, db.queryForObject("select count(*) from oauth2_authorization where principal_name=?", Integer.class, user));
    }

    @Test
    void accountDatabaseOutageFailsClosedAndRecoversWithoutConsumingToken() throws Exception {
        email(true, "ACTIVE");
        String token = actionToken("reset");
        var browser = browser();
        String csrf = accountCsrf(browser, "reset");
        POSTGRES.getDockerClient().pauseContainerCmd(POSTGRES.getContainerId()).exec();
        try {
            assertEquals(503, request(browser, "/account/reset", Map.of("token", token, "password", "new-password-that-is-long", "confirmation", "new-password-that-is-long", "_csrf", csrf), false, "web-a").statusCode());
        } finally {
            POSTGRES.getDockerClient().unpauseContainerCmd(POSTGRES.getContainerId()).exec();
        }
        assertEquals(200, complete("reset", token, "new-password-that-is-long").statusCode());
    }

    @Test
    void invalidPasswordAndGetRequestsDoNotConsumeActionToken() throws Exception {
        email(true, "ACTIVE");
        String token = actionToken("reset");
        assertEquals(400, complete("reset", token, "🙂".repeat(19)).statusCode());
        assertEquals(400, complete("reset", token, "too-short").statusCode());
        var response = request(browser(), "/account/reset", null, false, "web-a");
        assertEquals(200, response.statusCode());
        assertEquals("no-referrer", response.headers().firstValue("Referrer-Policy").orElseThrow());
        assertTrue(response.headers().firstValue("Content-Security-Policy").orElseThrow().contains("form-action 'self'"));
        assertEquals(200, complete("reset", token, "a-valid-password-now-long").statusCode());
    }

    @Test
    void pausedDeliveryExpiresAndPurgesWithoutRevivingToken() {
        email(true, "ACTIVE");
        accounts.request(user + "@example.test", "RESET");
        accountWorker.prepare();
        db.update("update account_mail set deadline=clock_timestamp()-interval '1 second'");
        db.update("update account_action_tokens set expires_at=clock_timestamp()-interval '1 second'");
        accountWorker.cleanup();
        assertEquals("DEAD", db.queryForObject("select status from account_mail", String.class));
        assertNull(db.queryForObject("select envelope from account_mail", String.class));
        db.update("update account_mail set completed_at=clock_timestamp()-interval '2 days'");
        db.update("update account_action_tokens set expires_at=clock_timestamp()-interval '2 days'");
        accountWorker.cleanup();
        assertEquals(0, db.queryForObject("select count(*) from account_action_tokens", Integer.class));
    }

    @Test
    void resetInCurrentBrowserCanOpenFreshLoginWithoutRestoringOldSession() throws Exception {
        email(true, "ACTIVE");
        var browser = login();
        var issued = tokens(browser, "web-a");
        String token = actionToken("reset");
        String csrf = accountCsrf(browser, "reset");
        assertEquals(200, request(browser, "/account/reset", Map.of("token", token, "password", "current-browser-new-password", "confirmation", "current-browser-new-password", "_csrf", csrf), false, "web-a").statusCode());
        assertEquals(302, request(browser, "/login", null, false, "web-a").statusCode());
        assertTrue(authorizations.sessionRevoked(sessionFor(issued), user));
        var failed = request(browser, "/login", Map.of("username", user, "password", password, "_csrf", csrf(browser)), false, "web-a");
        assertEquals(302, failed.statusCode());
        assertTrue(failed.headers().firstValue("Location").orElseThrow().contains("error"));
        password = "current-browser-new-password";
        tokens(login(), "web-a");
    }

    @Test
    void newerRequestSupersedesOldLinkAndEncryptedPayloadIsNotPlaintext() throws Exception {
        email(true, "ACTIVE");
        String old = actionToken("reset");
        db.update("delete from account_request_limits");
        accounts.request(user + "@example.test", "RESET");
        assertTrue(accountWorker.prepare());
        String ciphertext = db.queryForObject("select envelope from account_mail where status='PENDING'", String.class);
        assertFalse(ciphertext.contains("#token="));
        assertFalse(ciphertext.contains(user + "@example.test"));
        accountWorker.runBatch();
        var matcher = Pattern.compile("#token=([A-Za-z0-9_-]{43})").matcher(SMTP.body(1));
        assertTrue(matcher.find());
        String current = matcher.group(1);
        assertFalse(old.equals(current));
        assertEquals(400, complete("reset", old, "replacement-password-strong").statusCode());
        assertEquals(200, complete("reset", current, "replacement-password-strong").statusCode());
    }

    @Test
    void trustedEmailBindingRevokesSessionsAndRequiresMailboxProof() throws Exception {
        var issued = tokens(login(), "web-a");
        String email = "new-" + user + "@example.test";
        accounts.request(email, "VERIFY"); // A pre-binding public request must not suppress the trusted fresh request.
        var response = browser().send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/api/v1/admin/users/" + user + "/email"))
                .header("Authorization", "Bearer " + adminToken()).header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(Map.of("email", email)))).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(204, response.statusCode());
        assertFalse(db.queryForObject("select email_verified from users where id=?", Boolean.class, user));
        assertEquals(400, refresh(issued.get("refresh_token").asText(), "web-a").statusCode());
        accountWorker.runBatch();
        assertEquals(1, SMTP.messages.size());
        var matcher = Pattern.compile("#token=([A-Za-z0-9_-]{43})").matcher(SMTP.body(0));
        assertTrue(matcher.find());
        assertEquals(200, complete("verify", matcher.group(1), null).statusCode());
    }

    @Test
    void redisOutageCannotBypassRecoveryCsrfOrConsumeToken() throws Exception {
        email(true, "ACTIVE");
        String token = actionToken("reset");
        var browser = browser();
        String csrf = accountCsrf(browser, "reset");
        REDIS.getDockerClient().pauseContainerCmd(REDIS.getContainerId()).exec();
        try {
            assertEquals(503, request(browser, "/account/reset", Map.of("token", token, "password", "redis-outage-password-long", "confirmation", "redis-outage-password-long", "_csrf", csrf), false, "web-a").statusCode());
        } finally {
            REDIS.getDockerClient().unpauseContainerCmd(REDIS.getContainerId()).exec();
        }
        assertEquals(200, complete("reset", token, "redis-outage-password-long").statusCode());
    }

    @Test
    void accountDeliveryAttemptCapAndExpiredLeaseBecomeTerminal() {
        email(true, "ACTIVE");
        accounts.request(user + "@example.test", "RESET");
        accountWorker.prepare();
        db.update("update account_mail set attempts=5");
        var attempt = accountWorker.claim();
        assertNotNull(attempt);
        assertEquals(6, attempt.attempts());
        assertTrue(accountWorker.finish(attempt, false, true));
        assertEquals("DEAD", db.queryForObject("select status from account_mail", String.class));
        assertNull(db.queryForObject("select envelope from account_mail", String.class));
        assertNull(accountWorker.claim());
        db.update("delete from account_request_limits");
        accounts.request(user + "@example.test", "RESET");
        accountWorker.prepare();
        db.update("update account_mail set attempts=5 where status='PENDING'");
        var abandoned = accountWorker.claim();
        assertNotNull(abandoned);
        db.update("update account_mail set lease_until=clock_timestamp()-interval '1 second' where status='INFLIGHT'");
        accountWorker.cleanup();
        assertFalse(accountWorker.finish(abandoned, true, false));
        assertNull(accountWorker.claim());
    }

    @Test
    void busyRecoveryPrincipalDoesNotBlockOtherQueuedAddressesOrExtendDeadline() throws Exception {
        email(true, "ACTIVE");
        accounts.request(user + "@example.test", "RESET");
        accounts.request("another-unknown@example.test", "RESET");
        var expiry = db.queryForObject("select min(expires_at) from account_requests", java.sql.Timestamp.class);
        var locked = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        var tx = new org.springframework.transaction.support.TransactionTemplate(transactions);
        try (var pool = Executors.newSingleThreadExecutor()) {
            var holder = pool.submit(() -> tx.executeWithoutResult(status -> {
                authorizations.lockPrincipal(user);
                locked.countDown();
                try {
                    assertTrue(release.await(10, TimeUnit.SECONDS));
                } catch (InterruptedException e) {
                    throw new IllegalStateException(e);
                }
            }));
            assertTrue(locked.await(5, TimeUnit.SECONDS));
            try {
                accountWorker.runBatch();
                assertEquals(1, db.queryForObject("select count(*) from account_requests where completed_at is not null", Integer.class));
                assertEquals(0, SMTP.messages.size());
            } finally {
                release.countDown();
            }
            holder.get(10, TimeUnit.SECONDS);
        }
        assertEquals(expiry, db.queryForObject("select min(expires_at) from account_requests", java.sql.Timestamp.class));
        db.update("update account_requests set next_attempt_at=clock_timestamp() where completed_at is null");
        accountWorker.runBatch();
        assertEquals(1, SMTP.messages.size());
    }

    @Test
    void mfaSetupIsBoundToItsBrowserAndExpires() throws Exception {
        var owner = login();
        assertFalse(json.readTree(request(owner, "/mfa/settings", null, false, "web-a").body()).get("enabled").asBoolean());
        assertEquals(403, request(owner, "/mfa/enroll", Map.of("password", password), false, "web-a").statusCode());
        var started = request(owner, "/mfa/enroll", Map.of("password", password, "_csrf", csrf(owner)), false, "web-a");
        assertEquals(200, started.statusCode());
        String key = json.readTree(started.body()).get("secret").asText();
        var other = login();
        assertEquals(401, request(other, "/mfa/verify", Map.of("code", otp(key), "_csrf", csrf(other)), false, "web-a").statusCode());
        assertFalse(mfa.enabled(user));
        db.update("update mfa_credentials set enrollment_expires_at=clock_timestamp()-interval '1 second' where user_id=?", user);
        assertEquals(401, request(owner, "/mfa/verify", Map.of("code", otp(key), "_csrf", csrf(owner)), false, "web-a").statusCode());
        assertFalse(mfa.enabled(user));
    }

    @Test
    void recoveryRenewalRequiresFreshProofAndRevokesSessions() throws Exception {
        enabledMfa();
        var old = mfa.recoveryCodes(user);
        var browser = login();
        assertEquals(200, request(browser, "/mfa/recover", Map.of("code", old.get(0), "_csrf", csrf(browser)), false, "web-a").statusCode());
        var issued = tokens(browser, "web-a");
        assertEquals(401, request(browser, "/mfa/recovery-codes", Map.of("password", "wrong", "code", old.get(1), "recovery", "true", "_csrf", csrf(browser)), false, "web-a").statusCode());
        var renewed = request(browser, "/mfa/recovery-codes", Map.of("password", password, "code", old.get(1), "recovery", "true", "_csrf", csrf(browser)), false, "web-a");
        assertEquals(200, renewed.statusCode());
        assertEquals("no-store", renewed.headers().firstValue("Cache-Control").orElseThrow());
        assertTrue(json.readTree(renewed.body()).get("requiresSignIn").asBoolean());
        assertEquals(10, db.queryForObject("select count(*) from recovery_codes where user_id=?", Integer.class, user));
        assertFalse(mfa.recover(user, old.get(2)));
        assertEquals(400, refresh(issued.get("refresh_token").asText(), "web-a").statusCode());
        assertTrue(mfa.enabled(user));
    }

    @Test
    void mfaRemovalRequiresPasswordAndOneUseProof() throws Exception {
        enabledMfa();
        var codes = mfa.recoveryCodes(user);
        var browser = login();
        assertEquals(200, request(browser, "/mfa/recover", Map.of("code", codes.get(0), "_csrf", csrf(browser)), false, "web-a").statusCode());
        var issued = tokens(browser, "web-a");
        var removed = request(browser, "/mfa/remove", Map.of("password", password, "code", codes.get(1), "recovery", "true", "_csrf", csrf(browser)), false, "web-a");
        assertEquals(200, removed.statusCode());
        assertFalse(mfa.enabled(user));
        assertEquals(0, db.queryForObject("select count(*) from recovery_codes where user_id=?", Integer.class, user));
        assertEquals(400, refresh(issued.get("refresh_token").asText(), "web-a").statusCode());
    }

    @Test
    void requiredMfaPolicyBlocksUnenrolledAuthorizationAndRemoval() throws Exception {
        org.springframework.test.util.ReflectionTestUtils.setField(mfa, "required", true);
        org.springframework.test.util.ReflectionTestUtils.setField(authorizations, "mfaRequired", true);
        try {
            var browser = login();
            var result = request(browser, "/", null, false, "web-a");
            assertEquals(401, result.statusCode());
            assertTrue(json.readTree(result.body()).get("redirect").asText().endsWith("/mfa/settings"));
            assertEquals(200, request(browser, "/mfa/settings", null, false, "web-a").statusCode());
            enabledMfa();
            var codes = mfa.recoveryCodes(user);
            assertEquals(200, request(browser, "/mfa/recover", Map.of("code", codes.get(0), "_csrf", csrf(browser)), false, "web-a").statusCode());
            assertEquals(403, request(browser, "/mfa/remove", Map.of("password", password, "code", codes.get(1), "recovery", "true", "_csrf", csrf(browser)), false, "web-a").statusCode());
            assertTrue(mfa.enabled(user));
        } finally {
            org.springframework.test.util.ReflectionTestUtils.setField(mfa, "required", false);
            org.springframework.test.util.ReflectionTestUtils.setField(authorizations, "mfaRequired", false);
        }
    }

    HttpResponse<String> register(HttpClient browser, String username, String email, String password) throws Exception {
        return request(browser, "/account/register", Map.of("username", username, "email", email, "password", password,
                "confirmation", password, "_csrf", accountCsrf(browser, "register")), false, "web-a");
    }

    @Test
    void publicRegistrationRequiresEmailVerificationBeforeLogin() throws Exception {
        var browser = browser();
        String name = "signup-" + UUID.randomUUID(), address = name + "@example.test";
        var result = register(browser, name, address.toUpperCase(Locale.ROOT), password);
        assertEquals(200, result.statusCode());
        assertTrue(json.readTree(result.body()).get("accepted").asBoolean());
        var row = db.queryForMap("select * from users where username=?", name);
        String id = row.get("id").toString();
        assertEquals("PENDING_VERIFICATION", row.get("state"));
        assertEquals(address, row.get("email"));
        assertFalse((Boolean) row.get("email_verified"));
        assertTrue(passwords.matches(password, row.get("password_hash").toString()));
        assertFalse(result.body().contains(password));
        assertEquals(0, db.queryForObject("select count(*) from platform_administrators where user_id=?", Integer.class, id));
        var denied = request(browser, "/login", Map.of("username", name, "password", password, "_csrf", csrf(browser)), false, "web-a");
        assertTrue(denied.headers().firstValue("Location").orElseThrow().contains("error"));
        accountWorker.runBatch();
        assertEquals(1, SMTP.messages.size());
        var match = Pattern.compile("#token=([A-Za-z0-9_-]{43})").matcher(SMTP.body(0));
        assertTrue(match.find());
        String token = match.group(1);
        var verified = complete("verify", token, null);
        assertEquals(200, verified.statusCode());
        assertEquals("http://localhost:3000/login", json.readTree(verified.body()).get("redirect").asText());
        assertEquals(400, complete("verify", token, null).statusCode());
        assertEquals("ACTIVE", db.queryForObject("select state from users where id=?", String.class, id));
        assertTrue(db.queryForObject("select email_verified from users where id=?", Boolean.class, id));
        assertEquals(302, request(browser, "/login", Map.of("username", name, "password", password, "_csrf", csrf(browser)), false, "web-a").statusCode());
        assertNotNull(tokens(browser, "web-a").get("access_token"));
    }

    @Test
    void duplicateRegistrationNeverOverwritesCredentialsOrDisclosesAccountExistence() throws Exception {
        var browser = browser();
        String name = "signup-" + UUID.randomUUID(), email = name + "@example.test";
        String first = register(browser, name, email, password).body();
        String hash = db.queryForObject("select password_hash from users where username=?", String.class, name);
        assertEquals(first, register(browser, name, "other-" + email, "another-strong-test-passphrase").body());
        assertEquals(first, register(browser, "other-" + name, email.toUpperCase(Locale.ROOT), "another-strong-test-passphrase").body());
        assertEquals(hash, db.queryForObject("select password_hash from users where username=?", String.class, name));
        assertEquals(1, db.queryForObject("select count(*) from account_requests", Integer.class));
        assertEquals(1, db.queryForObject("select count(*) from users where email=?", Integer.class, email));
    }

    @Test
    void registrationValidatesInputsAndRequiresCsrf() throws Exception {
        var browser = browser();
        assertEquals(403, request(browser, "/account/register", Map.of("username", "signup", "email", "signup@example.test", "password", password, "confirmation", password), false, "web-a").statusCode());
        assertEquals(400, register(browser, "bad username", "signup@example.test", password).statusCode());
        assertEquals(400, register(browser, "signup", "invalid-email", password).statusCode());
        assertEquals(400, register(browser, "signup", "signup@example.test", "short").statusCode());
        var mismatch = request(browser, "/account/register", Map.of("username", "signup", "email", "signup@example.test", "password", password, "confirmation", "different", "_csrf", accountCsrf(browser, "register")), false, "web-a");
        assertEquals(400, mismatch.statusCode());
        assertFalse(mismatch.body().contains(password));
        assertEquals(0, db.queryForObject("select count(*) from users where username='signup'", Integer.class));
        assertEquals(429, register(browser, "signup", "signup@example.test", password).statusCode());
    }

    @Test
    void registrationIsOptInAndCannotCreateUsersWhileDisabled() throws Exception {
        org.springframework.test.util.ReflectionTestUtils.setField(registration, "registrationEnabled", false);
        try {
            var browser = browser();
            var page = request(browser, "/account/register", null, false, "web-a");
            assertEquals(404, page.statusCode());
            assertFalse(page.body().contains("name=\"password\""));
            assertEquals(404, request(browser, "/account/register", Map.of("username", "signup", "email", "signup@example.test", "password", password, "confirmation", password, "_csrf", csrf(browser)), false, "web-a").statusCode());
            assertEquals(0, db.queryForObject("select count(*) from users where username='signup'", Integer.class));
        } finally {
            org.springframework.test.util.ReflectionTestUtils.setField(registration, "registrationEnabled", true);
        }
    }

    @Test
    void concurrentRegistrationHasOneIdentityAndOneVerificationRequest() throws Exception {
        String name = "signup-" + UUID.randomUUID(), address = name + "@example.test";
        var a = browser();
        var b = browser();
        try (var pool = Executors.newFixedThreadPool(2)) {
            var one = pool.submit(() -> register(a, name, address, password));
            var two = pool.submit(() -> register(b, "other-" + name, address, password));
            assertEquals(200, one.get(15, TimeUnit.SECONDS).statusCode());
            assertEquals(200, two.get(15, TimeUnit.SECONDS).statusCode());
        }
        assertEquals(1, db.queryForObject("select count(*) from users where email=?", Integer.class, address));
        assertEquals(1, db.queryForObject("select count(*) from account_requests", Integer.class));
    }

    @Test
    void registrationRollsBackIdentityWhenVerificationQueueFails() throws Exception {
        db.execute("create function reject_signup_queue() returns trigger language plpgsql as $$ begin raise exception 'injected failure'; end $$");
        db.execute("create trigger reject_signup_queue before insert on account_requests for each row execute function reject_signup_queue()");
        try {
            assertEquals(503, register(browser(), "signup", "signup@example.test", password).statusCode());
            assertEquals(0, db.queryForObject("select count(*) from users where username='signup'", Integer.class));
        } finally {
            db.execute("drop trigger reject_signup_queue on account_requests");
            db.execute("drop function reject_signup_queue()");
        }
    }

    @Test
    void directLoginRedirectsToFrontendForAssignedRole() throws Exception {
        for (boolean admin : List.of(false, true)) {
            if (admin) db.update("insert into platform_administrators(user_id) values (?)", user);
            var browser = browser();
            var result = request(browser, "/login", Map.of("username", user, "password", password, "_csrf", csrf(browser)), false, "web-a");
            assertEquals(302, result.statusCode());
            assertEquals("http://localhost:3000/auth/continue?lane=" + (admin ? "admin" : "app"), result.headers().firstValue("Location").orElseThrow());
        }
    }

    @Test
    void restSessionLoginRequiresCsrfAndEstablishesTrackedAuthentication() throws Exception {
        var browser = browser();
        assertEquals(403, request(browser, "/session/login", Map.of("username", user, "password", password), false, "web-a").statusCode());
        String proof = csrf(browser);
        var jar = (CookieManager) browser.cookieHandler().orElseThrow();
        String before = jar.getCookieStore().getCookies().stream().filter(c -> c.getName().equals("IAM_SESSION")).findFirst().orElseThrow().getValue();
        var login = request(browser, "/session/login", Map.of("username", user, "password", password, "_csrf", proof), false, "web-a");
        assertEquals(200, login.statusCode());
        assertEquals("http://localhost:3000/auth/continue?lane=app", json.readTree(login.body()).get("redirect").asText());
        String after = jar.getCookieStore().getCookies().stream().filter(c -> c.getName().equals("IAM_SESSION")).findFirst().orElseThrow().getValue();
        assertNotEquals(before, after);
        assertFalse(login.body().contains("access_token"));
        var issued = tokens(browser, "web-a");
        assertEquals(200, request(browser, "/session/logout", Map.of("_csrf", csrf(browser)), false, "web-a").statusCode());
        assertEquals(400, refresh(issued.get("refresh_token").asText(), "web-a").statusCode());
    }

    record Code(String value, String verifier) {
    }
}
