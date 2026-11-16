package com.example.iam.server;

import com.example.iam.server.client.ClientAssertionKeys;
import com.example.iam.server.client.ClientAssertionReplayStore;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
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
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "iam.issuer=https://issuer.example", "iam.session.expiry-enabled=false", "iam.backchannel.enabled=false",
        "iam.retention.enabled=false", "iam.client-assertion.cleanup-enabled=false", "server.servlet.session.cookie.secure=false",
        "MFA_ENCRYPTION_PASSWORD=test-only-encryption-password", "MFA_ENCRYPTION_SALT=00112233445566778899aabbccddeeff"})
@org.springframework.test.annotation.DirtiesContext(classMode = org.springframework.test.annotation.DirtiesContext.ClassMode.AFTER_CLASS)
class PrivateKeyClientIntegrationTest {
    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:17-alpine");
    @Container
    static final GenericContainer<?> REDIS = new GenericContainer<>("redis:7.4-alpine").withExposedPorts(6379);
    static final RSAKey A = key("key-a"), B = key("key-b");
    static final Path SIGNING = signing();
    final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
    @LocalServerPort
    int port;
    @Autowired
    JdbcTemplate db;
    @Autowired
    RegisteredClientRepository clients;    static final String SECRET = "test-only-client-secret", HASH = new BCryptPasswordEncoder(12).encode(SECRET);
    @Autowired
    ClientAssertionKeys keys;
    @Autowired
    ClientAssertionReplayStore replays;
    @Autowired
    PlatformTransactionManager transactions;
    @Autowired
    io.micrometer.core.instrument.MeterRegistry meters;
    @Autowired
    ObjectMapper json;
    String clientId, id;

    static RSAKey key(String kid) {
        try {
            return new RSAKeyGenerator(2048).keyID(kid).keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256).generate();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static Path signing() {
        try {
            var path = Files.createTempFile("iam-private-jwt-test-", ".jwks");
            Files.writeString(path, new JWKSet(key("issuer")).toString(false));
            return path;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @AfterAll
    static void deleteKey() throws Exception {
        Files.deleteIfExists(SIGNING);
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry p) {
        p.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        p.add("spring.datasource.username", POSTGRES::getUsername);
        p.add("spring.datasource.password", POSTGRES::getPassword);
        p.add("spring.data.redis.host", REDIS::getHost);
        p.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
        p.add("iam.signing-key-file", SIGNING::toString);
    }

    static Map<String, Object> jwks(RSAKey... keys) {
        return new JWKSet(Arrays.stream(keys).map(RSAKey::toPublicJWK).map(k -> (JWK) k).toList()).toJSONObject();
    }

    void register(String name, boolean asymmetric) {
        clients.save(RegisteredClient.withId(UUID.randomUUID().toString()).clientId(name).clientSecret(new BCryptPasswordEncoder(12).encode(SECRET))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("orders.read").tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(5)).build()).build());
        if (asymmetric) keys.replace(name, 0, jwks(A));
    }

    @BeforeEach
    void fixture() {
        clientId = "jwt-" + UUID.randomUUID();
        register(clientId, true);
        id = clients.findByClientId(clientId).getId();
    }

    String sign(RSAKey key, Map<String, Object> changes, JWSHeader header) throws Exception {
        Instant now = Instant.now();
        var claims = new HashMap<String, Object>();
        claims.put("iss", clientId);
        claims.put("sub", clientId);
        claims.put("aud", List.of("https://issuer.example/oauth2/token"));
        claims.put("iat", now.getEpochSecond());
        claims.put("exp", now.plusSeconds(30).getEpochSecond());
        claims.put("jti", UUID.randomUUID().toString());
        changes.forEach((k, v) -> {
            if (v == null) claims.remove(k);
            else claims.put(k, v instanceof Date date ? date.toInstant().getEpochSecond() : v);
        });
        var jwt = new SignedJWT(header, JWTClaimsSet.parse(claims));
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    String assertion(RSAKey key) throws Exception {
        return sign(key, Map.of(), new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).keyID(key.getKeyID()).build());
    }

    String assertion(Map<String, Object> changes) throws Exception {
        return sign(A, changes, new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).keyID(A.getKeyID()).build());
    }

    HttpResponse<String> send(String path, Map<String, String> form, String basic) throws Exception {
        String query = form.entrySet().stream().map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8)).collect(Collectors.joining("&"));
        var request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).timeout(Duration.ofSeconds(15)).header("Content-Type", "application/x-www-form-urlencoded");
        if (basic != null)
            request.header("Authorization", "Basic " + Base64.getEncoder().encodeToString((basic + ":" + SECRET).getBytes(StandardCharsets.UTF_8)));
        return http.send(request.POST(HttpRequest.BodyPublishers.ofString(query)).build(), HttpResponse.BodyHandlers.ofString());
    }

    HttpResponse<String> token(String assertion) throws Exception {
        return token(assertion, clientId, "orders.read");
    }

    HttpResponse<String> token(String assertion, String client, String scope) throws Exception {
        return send("/oauth2/token", Map.of("grant_type", "client_credentials", "scope", scope, "client_id", client, "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", "client_assertion", assertion), null);
    }

    void rejected(HttpResponse<String> response) throws Exception {
        assertEquals(401, response.statusCode(), response.body());
        assertEquals("invalid_client", json.readTree(response.body()).path("error").asText());
        assertFalse(response.body().contains("access_token"));
    }

    HttpResponse<String> browserRequest(HttpClient browser, String path, Map<String, String> form) throws Exception {
        var request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).timeout(Duration.ofSeconds(10));
        if (form == null) request.GET();
        else
            request.header("Content-Type", "application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(form.entrySet().stream().map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8)).collect(Collectors.joining("&"))));
        return browser.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    String csrf(HttpClient browser) throws Exception {
        var response = browserRequest(browser, "/login", null);
        assertEquals(200, response.statusCode());
        var matcher = java.util.regex.Pattern.compile("name=\"_csrf\"[^>]*value=\"([^\"]+)\"").matcher(response.body());
        assertTrue(matcher.find());
        return matcher.group(1);
    }

    Map<String, String> codeGrant(HttpClient browser) throws Exception {
        String verifier = UUID.randomUUID().toString() + UUID.randomUUID();
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        var query = Map.of("response_type", "code", "client_id", clientId, "redirect_uri", "https://client.example/callback", "scope", "openid orders.read", "state", "state-check", "nonce", UUID.randomUUID().toString(), "code_challenge", challenge, "code_challenge_method", "S256");
        var response = browserRequest(browser, "/oauth2/authorize?" + query.entrySet().stream().map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8)).collect(Collectors.joining("&")), null);
        assertEquals(302, response.statusCode());
        var values = Arrays.stream(URI.create(response.headers().firstValue("Location").orElseThrow()).getRawQuery().split("&")).map(s -> s.split("=", 2)).collect(Collectors.toMap(s -> s[0], s -> URLDecoder.decode(s[1], StandardCharsets.UTF_8)));
        assertEquals("state-check", values.get("state"));
        assertNotNull(values.get("code"));
        return Map.of("grant_type", "authorization_code", "code", values.get("code"), "code_verifier", verifier, "redirect_uri", "https://client.example/callback");
    }

    HttpResponse<String> signedGrant(Map<String, String> grant) throws Exception {
        var form = new HashMap<>(grant);
        form.put("client_id", clientId);
        form.put("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        form.put("client_assertion", assertion(A));
        return send("/oauth2/token", form, null);
    }

    @Test
    void signsScopedAccessTokensAndPreservesBasicAuthentication() throws Exception {
        var result = token(assertion(A));
        assertEquals(200, result.statusCode(), result.body());
        var body = json.readTree(result.body());
        assertFalse(body.has("refresh_token"));
        var jwt = SignedJWT.parse(body.path("access_token").asText());
        assertEquals("https://issuer.example", jwt.getJWTClaimsSet().getIssuer());
        assertEquals(List.of("enterprise-api"), jwt.getJWTClaimsSet().getAudience());
        assertEquals("at+jwt", jwt.getHeader().getType().toString());
        assertEquals("orders.read", body.path("scope").asText());
        assertEquals(200, send("/oauth2/token", Map.of("grant_type", "client_credentials", "scope", "orders.read"), clientId).statusCode());
    }

    @Test
    void codePkceRefreshReplayAndLogoutKeepTheirLifecycleGuarantees() throws Exception {
        var old = clients.findByClientId(clientId);
        clients.save(RegisteredClient.from(old).authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("https://client.example/callback").scope("openid").clientSettings(org.springframework.security.oauth2.server.authorization.settings.ClientSettings.withSettings(old.getClientSettings().getSettings()).requireProofKey(true).requireAuthorizationConsent(false).build())
                .tokenSettings(TokenSettings.builder().reuseRefreshTokens(false).build()).build());
        String user = UUID.randomUUID().toString();
        db.update("insert into users(id,username,password_hash,state) values (?,?,?,'ACTIVE')", user, user, HASH);
        var browser = HttpClient.newBuilder().cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL)).followRedirects(HttpClient.Redirect.NEVER).build();
        assertEquals(302, browserRequest(browser, "/login", Map.of("username", user, "password", SECRET, "_csrf", csrf(browser))).statusCode());
        var invalid = new HashMap<>(codeGrant(browser));
        invalid.put("code_verifier", "incorrect-verifier");
        assertEquals(400, signedGrant(invalid).statusCode());
        var issued = signedGrant(codeGrant(browser));
        assertEquals(200, issued.statusCode(), issued.body());
        var tokens = json.readTree(issued.body());
        assertTrue(tokens.has("id_token"));
        String r1 = tokens.path("refresh_token").asText();
        assertFalse(r1.isBlank());
        var rotated = signedGrant(Map.of("grant_type", "refresh_token", "refresh_token", r1));
        assertEquals(200, rotated.statusCode(), rotated.body());
        String r2 = json.readTree(rotated.body()).path("refresh_token").asText();
        assertNotEquals(r1, r2);
        assertEquals(400, signedGrant(Map.of("grant_type", "refresh_token", "refresh_token", r1)).statusCode());
        assertEquals(400, signedGrant(Map.of("grant_type", "refresh_token", "refresh_token", r2)).statusCode());
        var another = signedGrant(codeGrant(browser));
        assertEquals(200, another.statusCode());
        String live = json.readTree(another.body()).path("refresh_token").asText();
        assertEquals(302, browserRequest(browser, "/logout", Map.of("_csrf", csrf(browser))).statusCode());
        assertEquals(400, signedGrant(Map.of("grant_type", "refresh_token", "refresh_token", live)).statusCode());
    }

    @Test
    void replayIsSingleUseAndScopedToTheClient() throws Exception {
        String jti = UUID.randomUUID().toString(), first = assertion(Map.of("jti", jti));
        assertEquals(200, token(first).statusCode());
        rejected(token(first));
        String second = "jwt-" + UUID.randomUUID();
        register(second, true);
        assertEquals(200, token(assertion(Map.of("iss", second, "sub", second, "jti", jti)), second, "orders.read").statusCode());
    }

    @Test
    void deletingAndRecreatingAClientCannotEraseLiveReplayEvidence() throws Exception {
        String proof = assertion(A);
        assertEquals(200, token(proof).statusCode());
        db.update("delete from oauth2_registered_client where id=?", id);
        register(clientId, true);
        rejected(token(proof));
        assertEquals(200, token(assertion(A)).statusCode());
    }

    @Test
    void concurrentReplayIssuesOnlyOneToken() throws Exception {
        String proof = assertion(A);
        try (var pool = Executors.newVirtualThreadPerTaskExecutor()) {
            var gate = new CountDownLatch(1);
            var calls = new ArrayList<Future<Integer>>();
            for (int i = 0; i < 8; i++)
                calls.add(pool.submit(() -> {
                    gate.await();
                    return token(proof).statusCode();
                }));
            gate.countDown();
            var statuses = new ArrayList<Integer>();
            for (var call : calls) statuses.add(call.get(15, TimeUnit.SECONDS));
            assertEquals(1, statuses.stream().filter(s -> s == 200).count(), statuses.toString());
            assertEquals(7, statuses.stream().filter(s -> s == 401).count(), statuses.toString());
        }
        assertEquals(1, db.queryForObject("select count(*) from oauth2_authorization where registered_client_id=?", Integer.class, id));
    }

    @Test
    void concurrentDistinctAssertionsRemainIndependent() throws Exception {
        try (var pool = Executors.newVirtualThreadPerTaskExecutor()) {
            var calls = new ArrayList<Future<Integer>>();
            for (int i = 0; i < 8; i++) {
                String proof = assertion(A);
                calls.add(pool.submit(() -> token(proof).statusCode()));
            }
            for (var call : calls) assertEquals(200, call.get(15, TimeUnit.SECONDS));
        }
    }

    @Test
    void rejectsWrongIdentityAudienceAndLifetimeBeforeClaimingReplay() throws Exception {
        var cases = new ArrayList<Map<String, Object>>();
        cases.add(Map.of("iss", "other"));
        cases.add(Map.of("sub", "other"));
        cases.add(Map.of("aud", List.of("https://attacker.invalid")));
        cases.add(Map.of("aud", List.of("https://issuer.example/oauth2/token", "https://attacker.invalid")));
        cases.add(Map.of("aud", List.of("https://issuer.example/oauth2/revoke")));
        cases.add(Map.of("exp", Date.from(Instant.now().minusSeconds(15))));
        cases.add(Map.of("exp", Date.from(Instant.now().plusSeconds(120))));
        cases.add(Map.of("iat", Date.from(Instant.now().plusSeconds(20))));
        cases.add(Map.of("nbf", Date.from(Instant.now().plusSeconds(20))));
        cases.add(Map.of("jti", "short"));
        for (String missing : List.of("exp", "iat", "jti")) {
            var absent = new HashMap<String, Object>();
            absent.put(missing, null);
            cases.add(absent);
        }
        for (var change : cases) rejected(token(assertion(change)));
        assertEquals(0, db.queryForObject("select count(*) from client_assertion_replays where client_id=?", Integer.class, clientId));
    }

    @Test
    void rejectsWrongKeyAlgorithmTypeAndRemoteHeader() throws Exception {
        rejected(token(assertion(B)));
        for (var header : List.of(new JWSHeader.Builder(JWSAlgorithm.RS512).type(JOSEObjectType.JWT).keyID(A.getKeyID()).build(),
                new JWSHeader.Builder(JWSAlgorithm.RS256).type(new JOSEObjectType("at+jwt")).keyID(A.getKeyID()).build(),
                new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).keyID(A.getKeyID()).jwkURL(URI.create("https://attacker.invalid/keys")).build()))
            rejected(token(sign(A, Map.of(), header)));
        var bad = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).type(JOSEObjectType.JWT).keyID(A.getKeyID()).build(), JWTClaimsSet.parse(Map.of("iss", clientId, "sub", clientId, "exp", Instant.now().plusSeconds(30).getEpochSecond())));
        bad.sign(new MACSigner(new byte[32]));
        rejected(token(bad.serialize()));
    }

    @Test
    void rejectsUnsignedMalformedOversizeAndAmbiguousAssertions() throws Exception {
        for (String proof : List.of("invalid", new PlainJWT(new JWTClaimsSet.Builder().issuer(clientId).subject(clientId).build()).serialize(), "a".repeat(9000)))
            rejected(token(proof));
        // Duplicate fields must fail even when the surrounding assertion has a valid library-generated signature.
        String header = "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"key-a\",\"kid\":\"key-a\"}";
        var signer = new RSASSASigner(A);
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(SignedJWT.parse(assertion(A)).getPayload().toBytes());
        String h = Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes(StandardCharsets.UTF_8));
        String duplicate = h + "." + payload + "." + signer.sign(new JWSHeader.Builder(JWSAlgorithm.RS256).build(), (h + "." + payload).getBytes(StandardCharsets.US_ASCII));
        rejected(token(duplicate));
    }

    @Test
    void secretOnlyClientCannotUseAssertionsOrCrossClientKeys() throws Exception {
        String other = "basic-" + UUID.randomUUID();
        register(other, false);
        rejected(token(assertion(Map.of("iss", other, "sub", other)), other, "orders.read"));
        rejected(token(assertion(A), other, "orders.read"));
    }

    @Test
    void overlappingRotationRetirementAndKidReuseHaveNoStaleDecoderCache() throws Exception {
        keys.replace(clientId, 1, jwks(A, B));
        assertEquals(200, token(assertion(A)).statusCode());
        assertEquals(200, token(assertion(B)).statusCode());
        keys.replace(clientId, 2, jwks(B));
        rejected(token(assertion(A)));
        assertEquals(200, token(assertion(B)).statusCode());
        assertEquals(409, assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> keys.replace(clientId, 2, jwks(A))).getStatusCode().value());
        var replacement = new RSAKey.Builder(B).keyID(A.getKeyID()).build();
        keys.replace(clientId, 3, jwks(replacement));
        rejected(token(assertion(A)));
        assertEquals(200, token(assertion(replacement)).statusCode());
    }

    @Test
    void concurrentRotationsUseCompareAndSetAndOnlyOneWins() throws Exception {
        try (var pool = Executors.newVirtualThreadPerTaskExecutor()) {
            var calls = new ArrayList<Future<Integer>>();
            for (var key : List.of(A, B))
                calls.add(pool.submit(() -> {
                    try {
                        keys.replace(clientId, 1, jwks(key));
                        return 200;
                    } catch (org.springframework.web.server.ResponseStatusException e) {
                        return e.getStatusCode().value();
                    }
                }));
            var statuses = new ArrayList<Integer>();
            for (var call : calls) statuses.add(call.get(10, TimeUnit.SECONDS));
            Collections.sort(statuses);
            assertEquals(List.of(200, 409), statuses);
        }
    }

    @Test
    void disablingAssertionsPreservesBasicAndCannotBeUndoneByStaleWriter() throws Exception {
        keys.disable(clientId, 1);
        rejected(token(assertion(A)));
        assertEquals(200, send("/oauth2/token", Map.of("grant_type", "client_credentials", "scope", "orders.read"), clientId).statusCode());
        assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> keys.replace(clientId, 1, jwks(A)));
        keys.replace(clientId, 2, jwks(B));
        rejected(token(assertion(A)));
        assertEquals(200, token(assertion(B)).statusCode());
    }

    @Test
    void replayBurnSurvivesFailedGrantAndCommitRollback() throws Exception {
        db.execute("create function fail_assertion_grant() returns trigger language plpgsql as $$ begin raise exception 'injected grant outage'; end $$");
        db.execute("create trigger fail_assertion_grant before insert on oauth2_authorization for each row execute function fail_assertion_grant()");
        String proof = assertion(A);
        try {
            var failure = token(proof);
            assertEquals(503, failure.statusCode());
            assertFalse(failure.body().contains("access_token"));
        } finally {
            db.execute("drop trigger fail_assertion_grant on oauth2_authorization");
            db.execute("drop function fail_assertion_grant()");
        }
        rejected(token(proof));
        assertEquals(200, token(assertion(A)).statusCode());
    }

    @Test
    void replayStoreOutageCannotReleaseAnAccessToken() throws Exception {
        db.execute("create function fail_assertion_replay() returns trigger language plpgsql as $$ begin raise exception 'injected replay outage'; end $$");
        db.execute("create trigger fail_assertion_replay before insert on client_assertion_replays for each row execute function fail_assertion_replay()");
        try {
            var failure = token(assertion(A));
            assertEquals(503, failure.statusCode());
            assertFalse(failure.body().contains("access_token"));
        } finally {
            db.execute("drop trigger fail_assertion_replay on client_assertion_replays");
            db.execute("drop function fail_assertion_replay()");
        }
    }

    @Test
    void cleanupCannotRestoreExpiredOrStillValidAssertions() throws Exception {
        String proof = assertion(A);
        assertEquals(200, token(proof).statusCode());
        replays.cleanup();
        rejected(token(proof));
        Instant old = Instant.now().minusSeconds(90);
        String oldJti = UUID.randomUUID().toString();
        db.update("insert into client_assertion_replays values (?,?,?)", clientId, com.example.iam.server.token.TrackedAuthorizationService.digest(oldJti), Timestamp.from(old.plusSeconds(35)));
        try (var pool = Executors.newVirtualThreadPerTaskExecutor()) {
            var gc = pool.submit(() -> replays.cleanup());
            var stale = pool.submit(() -> new ClientAssertionReplayStore(db, transactions, meters).claim(clientId, oldJti, old, old.plusSeconds(30)));
            assertTrue(gc.get() > 0);
            assertFalse(stale.get());
        }
        rejected(token(assertion(Map.of("iat", Date.from(old), "exp", Date.from(old.plusSeconds(30)), "jti", oldJti))));
    }

    @Test
    void independentReplayStoreInstancesShareAtomicClaims() throws Exception {
        var peer = new ClientAssertionReplayStore(db, transactions, meters);
        String jti = UUID.randomUUID().toString();
        Instant now = Instant.now();
        try (var pool = Executors.newVirtualThreadPerTaskExecutor()) {
            var one = pool.submit(() -> replays.claim(clientId, jti, now, now.plusSeconds(30)));
            var two = pool.submit(() -> peer.claim(clientId, jti, now, now.plusSeconds(30)));
            assertNotEquals(one.get(), two.get());
        }
    }

    @Test
    void cleanupCannotAdmitAnInsertThatWaitedPastAssertionExpiry() throws Exception {
        var tx = new TransactionTemplate(transactions);
        var held = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        db.execute("create function gate_assertion_claim() returns trigger language plpgsql as $$ begin perform pg_advisory_xact_lock(71427712); return new; end $$");
        // Add the existing row before installing the gate, then make the INSERT wait before its unique-index check.
        Instant expires = Instant.now().minusSeconds(3), issued = expires.minusSeconds(30);
        String jti = UUID.randomUUID().toString();
        db.update("insert into client_assertion_replays values (?,?,?)", clientId, com.example.iam.server.token.TrackedAuthorizationService.digest(jti), Timestamp.from(expires.plusSeconds(5)));
        db.execute("create trigger gate_assertion_claim before insert on client_assertion_replays for each row execute function gate_assertion_claim()");
        try (var pool = Executors.newVirtualThreadPerTaskExecutor()) {
            var blocker = pool.submit(() -> tx.execute(status -> {
                db.execute("select pg_advisory_xact_lock(71427712)");
                held.countDown();
                try {
                    release.await(3, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return true;
            }));
            assertTrue(held.await(1, TimeUnit.SECONDS));
            var delayed = pool.submit(() -> replays.claim(clientId, jti, issued, expires));
            long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(500);
            while (db.queryForObject("select count(*) from pg_locks where locktype='advisory' and objid=71427712 and not granted", Integer.class) == 0 && System.nanoTime() < deadline)
                Thread.sleep(5);
            assertEquals(1, db.queryForObject("select count(*) from pg_locks where locktype='advisory' and objid=71427712 and not granted", Integer.class));
            while (Instant.now().isBefore(expires.plusSeconds(5).plusMillis(50))) Thread.sleep(5);
            assertTrue(replays.cleanup() > 0);
            release.countDown();
            assertFalse(delayed.get(3, TimeUnit.SECONDS));
            blocker.get();
            assertEquals(0, db.queryForObject("select count(*) from client_assertion_replays where client_id=?", Integer.class, clientId));
        } finally {
            release.countDown();
            db.execute("drop trigger gate_assertion_claim on client_assertion_replays");
            db.execute("drop function gate_assertion_claim()");
        }
    }

    @Test
    void rotationWaitsForInFlightIssuanceAndThenRejectsTheRetiredKey() throws Exception {
        var tx = new TransactionTemplate(transactions);
        var held = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        db.execute("create function gate_assertion_grant() returns trigger language plpgsql as $$ begin perform pg_advisory_xact_lock(71427711); return new; end $$");
        db.execute("create trigger gate_assertion_grant before insert on oauth2_authorization for each row execute function gate_assertion_grant()");
        try (var pool = Executors.newVirtualThreadPerTaskExecutor()) {
            var blocker = pool.submit(() -> tx.execute(status -> {
                db.execute("select pg_advisory_xact_lock(71427711)");
                held.countDown();
                try {
                    release.await(8, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return true;
            }));
            assertTrue(held.await(3, TimeUnit.SECONDS));
            String proof = assertion(A);
            var issuing = pool.submit(() -> token(proof));
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (db.queryForObject("select count(*) from client_assertion_replays where client_id=?", Integer.class, clientId) == 0 && System.nanoTime() < deadline)
                Thread.sleep(10);
            assertEquals(1, db.queryForObject("select count(*) from client_assertion_replays where client_id=?", Integer.class, clientId));
            var rotating = pool.submit(() -> keys.replace(clientId, 1, jwks(B)));
            assertThrows(TimeoutException.class, () -> rotating.get(150, TimeUnit.MILLISECONDS));
            release.countDown();
            assertEquals(200, issuing.get(10, TimeUnit.SECONDS).statusCode());
            rotating.get(10, TimeUnit.SECONDS);
            blocker.get();
        } finally {
            release.countDown();
            db.execute("drop trigger gate_assertion_grant on oauth2_authorization");
            db.execute("drop function gate_assertion_grant()");
        }
        rejected(token(assertion(A)));
        assertEquals(200, token(assertion(B)).statusCode());
    }

    @Test
    void issuanceWaitingBehindRotationReReadsTheCommittedKeyPolicy() throws Exception {
        var tx = new TransactionTemplate(transactions);
        var changed = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        try (var pool = Executors.newVirtualThreadPerTaskExecutor()) {
            var rotating = pool.submit(() -> tx.execute(status -> {
                keys.replace(clientId, 1, jwks(B));
                changed.countDown();
                try {
                    release.await(5, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return true;
            }));
            assertTrue(changed.await(3, TimeUnit.SECONDS));
            String proof = assertion(A);
            var issuing = pool.submit(() -> token(proof));
            assertThrows(TimeoutException.class, () -> issuing.get(150, TimeUnit.MILLISECONDS));
            release.countDown();
            rotating.get(5, TimeUnit.SECONDS);
            rejected(issuing.get(5, TimeUnit.SECONDS));
        } finally {
            release.countDown();
        }
        assertEquals(200, token(assertion(B)).statusCode());
    }

    @Test
    void managementApiRequiresAdminAudienceAndDoesNotReturnPrivateMaterial() throws Exception {
        String path = "/api/v1/admin/clients/" + clientId + "/authentication-keys";
        var noAuth = http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).GET().build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(401, noAuth.statusCode());
        var ordinary = json.readTree(token(assertion(A)).body()).path("access_token").asText();
        var denied = http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).header("Authorization", "Bearer " + ordinary).GET().build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(403, denied.statusCode());
        String admin = "admin-" + UUID.randomUUID();
        clients.save(RegisteredClient.withId(UUID.randomUUID().toString()).clientId(admin).clientSecret(HASH).clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).scope("iam.admin").build());
        String adminToken = json.readTree(send("/oauth2/token", Map.of("grant_type", "client_credentials", "scope", "iam.admin"), admin).body()).path("access_token").asText();
        var updated = http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).header("Authorization", "Bearer " + adminToken).header("Content-Type", "application/json").PUT(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(Map.of("expectedRevision", 1, "jwks", jwks(A, B))))).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, updated.statusCode(), updated.body());
        assertEquals(2, json.readTree(updated.body()).path("revision").asInt());
        assertFalse(updated.body().contains("clientSecret"));
        assertFalse(updated.body().contains("\"d\""));
        var invalid = new HashMap<String, Object>(A.toJSONObject());
        assertEquals(400, assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> keys.replace(clientId, 2, Map.of("keys", List.of(invalid)))).getStatusCode().value());
    }

    @Test
    void keyProvisioningRejectsPrivateWeakDuplicateAndRemoteKeys() {
        for (var document : List.of(new JWKSet(A).toJSONObject(false), jwks(A, A), Map.<String, Object>of("keys", List.of()), Map.<String, Object>of("keys", List.of(Map.of("kty", "oct", "k", Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]), "kid", "symmetric")))))
            assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> ClientAssertionKeys.validate(document));
        var remote = new HashMap<>(A.toPublicJWK().toJSONObject());
        remote.put("jku", "https://attacker.invalid");
        assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> ClientAssertionKeys.validate(Map.of("keys", List.of(remote))));
        assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> ClientAssertionKeys.validate(Map.of("keys", List.of(A.toPublicJWK().toJSONObject(), Map.of("kty", "unknown")))));
        var wrong = new RSAKey.Builder(A.toPublicJWK()).algorithm(JWSAlgorithm.RS512).build();
        assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> ClientAssertionKeys.validate(new JWKSet(wrong).toJSONObject()));
        var weak = new RSAKey.Builder(com.nimbusds.jose.util.Base64URL.encode(A.getModulus().decodeToBigInteger().shiftRight(1024)), A.getPublicExponent()).keyID("weak").keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256).build();
        assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> ClientAssertionKeys.validate(new JWKSet(weak).toJSONObject()));
    }

    @Test
    void assertionsAuthenticateIntrospectionAndRevocationWithEndpointBinding() throws Exception {
        String access = json.readTree(token(assertion(A)).body()).path("access_token").asText();
        var form = new HashMap<>(Map.of("token", access, "client_id", clientId, "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"));
        form.put("client_assertion", assertion(Map.of("aud", List.of("https://issuer.example/oauth2/introspect"))));
        var active = send("/oauth2/introspect", form, null);
        assertEquals(200, active.statusCode(), active.body());
        assertTrue(json.readTree(active.body()).path("active").asBoolean());
        rejected(send("/oauth2/introspect", form, null));
        form.put("client_assertion", assertion(A));
        rejected(send("/oauth2/introspect", form, null));
        form.put("client_assertion", assertion(Map.of("aud", List.of("https://issuer.example/oauth2/revoke"))));
        assertEquals(200, send("/oauth2/revoke", form, null).statusCode());
        form.put("client_assertion", assertion(Map.of("aud", List.of("https://issuer.example/oauth2/introspect"))));
        var inactive = send("/oauth2/introspect", form, null);
        assertEquals(200, inactive.statusCode());
        assertFalse(json.readTree(inactive.body()).path("active").asBoolean());
    }

    @Test
    void multipleAuthenticationMethodsCannotBeCombined() throws Exception {
        String proof = assertion(A);
        var form = new HashMap<>(Map.of("grant_type", "client_credentials", "scope", "orders.read", "client_id", clientId, "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", "client_assertion", proof));
        rejected(send("/oauth2/token", form, clientId));
        form.put("client_secret", SECRET);
        rejected(send("/oauth2/token", form, null));
        assertEquals(200, token(proof).statusCode());
    }

    @Test
    void privateOnlyRegistrationDoesNotIssueASecretOrAllowSecretDowngrade() throws Exception {
        String admin = "admin-" + UUID.randomUUID();
        clients.save(RegisteredClient.withId(UUID.randomUUID().toString()).clientId(admin).clientSecret(new BCryptPasswordEncoder(12).encode(SECRET)).clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).scope("iam.admin").build());
        String adminToken = json.readTree(send("/oauth2/token", Map.of("grant_type", "client_credentials", "scope", "iam.admin"), admin).body()).path("access_token").asText();
        String target = "private-" + UUID.randomUUID();
        var response = http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/api/v1/admin/clients")).header("Authorization", "Bearer " + adminToken).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(Map.of("clientId", target, "scopes", List.of("orders.read"), "clientAuthenticationMethod", "private_key_jwt", "jwks", jwks(A))))).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(201, response.statusCode(), response.body());
        assertFalse(response.body().contains("clientSecret"));
        assertNull(clients.findByClientId(target).getClientSecret());
        assertEquals(200, token(assertion(Map.of("iss", target, "sub", target)), target, "orders.read").statusCode());
        rejected(send("/oauth2/token", Map.of("grant_type", "client_credentials", "scope", "orders.read"), target));
        assertEquals(400, assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> keys.disable(target, 1)).getStatusCode().value());
    }

    @Test
    void auditFailureRollsBackKeyRotationWithoutChangingTrust() throws Exception {
        db.execute("create function fail_client_key_audit() returns trigger language plpgsql as $$ begin raise exception 'injected audit outage'; end $$");
        db.execute("create trigger fail_client_key_audit before insert on security_audit_events for each row execute function fail_client_key_audit()");
        try {
            assertThrows(org.springframework.dao.DataAccessException.class, () -> keys.replace(clientId, 1, jwks(B)));
        } finally {
            db.execute("drop trigger fail_client_key_audit on security_audit_events");
            db.execute("drop function fail_client_key_audit()");
        }
        assertEquals(200, token(assertion(A)).statusCode());
        rejected(token(assertion(B)));
        assertEquals(1L, keys.describe(clientId).get("revision"));
    }




}
