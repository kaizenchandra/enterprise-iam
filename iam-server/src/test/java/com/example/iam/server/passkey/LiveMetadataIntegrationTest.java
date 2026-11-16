package com.example.iam.server.passkey;

import com.example.iam.server.token.TrackedAuthorizationService;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

@Testcontainers
class LiveMetadataIntegrationTest {
    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:17-alpine");
    static final AtomicReference<String> mode = new AtomicReference<>("OK");
    static final java.util.concurrent.atomic.AtomicInteger gets = new java.util.concurrent.atomic.AtomicInteger();
    @TempDir
    static Path dir;
    static AttestationFixtures fixture;
    static com.sun.net.httpserver.HttpServer server;
    static String origin;
    static JdbcTemplate db;
    static DataSourceTransactionManager manager;
    static TrackedAuthorizationService grants;
    static TransactionTemplate tx;
    static volatile byte[] body;
    static ExecutorService http;
    AttestationPolicy policy;
    PasskeyService service;
    String user, session, binding;

    @BeforeAll
    static void setup() throws Exception {
        server = com.sun.net.httpserver.HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        origin = "http://127.0.0.1:" + server.getAddress().getPort();
        http = Executors.newVirtualThreadPerTaskExecutor();
        server.setExecutor(http);
        server.createContext("/metadata", exchange -> {
            try {
                gets.incrementAndGet();
                if (mode.get().equals("RATE")) {
                    exchange.getResponseHeaders().add("Retry-After", "7200");
                    exchange.getResponseHeaders().add("ETag", "1");
                    exchange.sendResponseHeaders(429, -1);
                    return;
                }
                if (mode.get().equals("OUTAGE")) {
                    exchange.sendResponseHeaders(503, -1);
                    return;
                }
                if (mode.get().equals("REDIRECT")) {
                    exchange.getResponseHeaders().add("Location", origin + "/forbidden");
                    exchange.sendResponseHeaders(302, -1);
                    return;
                }
                if (mode.get().equals("SLOW")) try {
                    Thread.sleep(7000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                byte[] bytes = mode.get().equals("OVERSIZE") ? new byte[MdsVerifierWorker.BLOB_LIMIT + 1] : body;
                exchange.sendResponseHeaders(200, bytes.length);
                exchange.getResponseBody().write(bytes);
            } finally {
                exchange.close();
            }
        });
        server.createContext("/crl", exchange -> {
            try {
                byte[] bytes = Files.readAllBytes(fixture.dir.resolve("root.crl"));
                exchange.sendResponseHeaders(200, bytes.length);
                exchange.getResponseBody().write(bytes);
            } finally {
                exchange.close();
            }
        });
        server.start();
        fixture = new AttestationFixtures(dir.resolve("pki"), origin + "/crl");
        var ds = new DriverManagerDataSource(POSTGRES.getJdbcUrl() + "&connectTimeout=2&socketTimeout=3", POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(ds).load().migrate();
        db = new JdbcTemplate(ds);
        manager = new DataSourceTransactionManager(ds);
        tx = new TransactionTemplate(manager);
        grants = new TrackedAuthorizationService(db, new JdbcRegisteredClientRepository(db), manager, Duration.ofHours(8));
    }

    @AfterAll
    static void stop() {
        if (server != null) server.stop(0);
        if (http != null) http.close();
    }

    @BeforeEach
    void identity() throws Exception {
        mode.set("OK");
        gets.set(0);
        db.update("update passkey_mds_fetch_state set lease_id=null,lease_until=null,next_fetch_at=clock_timestamp()");
        body = fixture.metadata(1, "FIDO_CERTIFIED_L2", LocalDate.now(java.time.ZoneOffset.UTC).plusDays(2)).getBytes(java.nio.charset.StandardCharsets.UTF_8);
        db.execute("truncate users,identity_sessions,refresh_history,authorization_lifecycle,passkey_metadata_state,passkey_model_eligibility,passkey_revoked_models cascade");
        db.update("update authorization_retention_state set initial_not_before='1970-01-01'");
        policy = policy(client(15));
        service = service(policy);
        user = UUID.randomUUID().toString();
        session = UUID.randomUUID().toString();
        binding = TrackedAuthorizationService.digest(UUID.randomUUID().toString());
        db.update("insert into users(id,username,password_hash,state) values (?,?,?,'ACTIVE')", user, user, new BCryptPasswordEncoder(12).encode("test-only-password"));
        grants.registerSession(session, user, grants.now());
    }

    LiveMdsClient client(int timeout) {
        return new LiveMdsClient(origin + "/metadata", origin, true, timeout);
    }

    AttestationPolicy policy(LiveMdsClient live) {
        return new AttestationPolicy(db, manager, grants, "REQUIRED", "", fixture.dir.resolve("root.pem").toString(), fixture.dir.resolve("root.pem").toString(), "", "test-only terms", Duration.ofDays(7), Clock.systemUTC(), 1, "LIVE", live);
    }

    PasskeyService service(AttestationPolicy p) {
        return new PasskeyService(db, new PasskeySettings(new PasskeyRepository(db), true, "localhost", "https://localhost:9000", false, p), new BCryptPasswordEncoder(12), grants);
    }

    void enroll() throws Exception {
        var start = tx.execute(s -> service.registerStart(user, session, binding, "test-only-password"));
        String response = fixture.registration(PublicKeyCredentialCreationOptions.fromJson(db.queryForObject("select options from passkey_challenges where id=?", String.class, start.id())), true);
        assertEquals(Boolean.TRUE, tx.execute(s -> service.registerFinish(user, binding, start.id(), response)));
    }

    void due() {
        db.update("update passkey_mds_fetch_state set next_fetch_at=clock_timestamp()");
    }

    @Test
    void liveWorkerValidatesSignedBlobAndCrlThenAuthenticates() throws Exception {
        policy.refresh();
        assertEquals("UP", policy.health().getStatus().getCode());
        enroll();
        var request = tx.execute(s -> service.authenticateStart(binding));
        String response = fixture.assertion(AssertionRequest.fromJson(db.queryForObject("select options from passkey_challenges where id=?", String.class, request.id())), user, 1);
        assertNotNull(tx.execute(s -> service.authenticateFinish(binding, request.id(), response, "live-session")));
        assertEquals("LIVE", db.queryForObject("select source from passkey_metadata_state", String.class));
        assertFalse(db.queryForObject("select retrieval_cache from passkey_metadata_state", String.class).equals("{}"));
    }

    @Test
    void newNodeFailsClosedWithoutRetrievingDuringLoginAndWarmsAsynchronously() throws Exception {
        policy.refresh();
        var peer = policy(client(15));
        assertEquals("DOWN", peer.health().getStatus().getCode());
        mode.set("SLOW");
        long start = System.nanoTime();
        assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> tx.execute(s -> service(peer).authenticateStart(binding)));
        assertTrue(Duration.ofNanos(System.nanoTime() - start).compareTo(Duration.ofSeconds(2)) < 0);
        mode.set("OK");
        peer.refresh();
        assertEquals("UP", peer.health().getStatus().getCode());
    }

    @Test
    void outageRevalidatesCachedSignedSnapshotWithoutSlidingAcceptanceOrDeadline() throws Exception {
        policy.refresh();
        var before = db.queryForMap("select accepted_at,expires_at,digest from passkey_metadata_state");
        mode.set("OUTAGE");
        var peer = policy(client(15));
        peer.refresh();
        assertEquals(before, db.queryForMap("select accepted_at,expires_at,digest from passkey_metadata_state"));
        assertEquals("UP", peer.health().getStatus().getCode());
        db.update("update passkey_metadata_state set expires_at=clock_timestamp()-interval '1 second'");
        peer.refresh();
        assertEquals("DOWN", peer.health().getStatus().getCode());
    }

    @Test
    void invalidSignatureCannotReplaceGoodState() throws Exception {
        policy.refresh();
        String before = db.queryForObject("select digest from passkey_metadata_state", String.class);
        due();
        String[] parts = fixture.metadata(2, "REVOKED", LocalDate.now(ZoneOffset.UTC).plusDays(1)).split("\\.");
        parts[2] = (parts[2].charAt(0) == 'A' ? "B" : "A") + parts[2].substring(1);
        body = String.join(".", parts).getBytes(java.nio.charset.StandardCharsets.UTF_8);
        assertThrows(Exception.class, () -> policy.refresh());
        assertEquals(before, db.queryForObject("select digest from passkey_metadata_state", String.class));
        assertEquals(0, db.queryForObject("select count(*) from passkey_revoked_models", Integer.class));
    }

    @Test
    void revokedLiveModelStopsPreparedAssertionAndPreservesSweepGuarantees() throws Exception {
        policy.refresh();
        enroll();
        var prepared = tx.execute(s -> service.authenticateStart(binding));
        String assertion = fixture.assertion(AssertionRequest.fromJson(db.queryForObject("select options from passkey_challenges where id=?", String.class, prepared.id())), user, 1);
        due();
        body = fixture.metadata(2, "REVOKED", LocalDate.now(ZoneOffset.UTC).plusDays(2)).getBytes(java.nio.charset.StandardCharsets.UTF_8);
        policy.refresh();
        assertNull(tx.execute(s -> service.authenticateFinish(binding, prepared.id(), assertion, "revoked-live")));
        assertEquals(1, policy.revokeBatch());
    }

    @Test
    void redirectAndOversizeResponsesCannotPublish() throws Exception {
        mode.set("REDIRECT");
        assertThrows(Exception.class, () -> policy.refresh());
        mode.set("OVERSIZE");
        due();
        assertThrows(Exception.class, () -> policy.refresh());
        assertEquals(0, db.queryForObject("select count(*) from passkey_metadata_state", Integer.class));
    }

    @Test
    void workerDeadlineKillsStalledChildAndReleasesSlot() throws Exception {
        mode.set("SLOW");
        long start = System.nanoTime();
        assertThrows(Exception.class, () -> policy(client(2)).refresh());
        assertTrue(Duration.ofNanos(System.nanoTime() - start).compareTo(Duration.ofSeconds(6)) < 0);
        mode.set("OK");
        due();
        policy.refresh();
        assertEquals("UP", policy.health().getStatus().getCode());
    }

    @Test
    void forbiddenOriginAndPrivateAddressAreRejectedBeforeFetch() throws Exception {
        var transport = new MdsVerifierWorker.Transport(List.of("https://mds.fidoalliance.org"), false, Map.of());
        assertThrows(java.io.IOException.class, () -> transport.allowed("https://127.0.0.1/"));
        assertThrows(java.io.IOException.class, () -> transport.allowed("https://user:secret@mds.fidoalliance.org/"));
        assertThrows(java.io.IOException.class, () -> new MdsVerifierWorker.Transport(List.of("https://127.0.0.1"), false, Map.of()).allowed("https://127.0.0.1/"));
    }

    @Test
    void rateLimitUsesValidatedCacheAndPersistsBackoff() throws Exception {
        policy.refresh();
        due();
        mode.set("RATE");
        var before = db.queryForMap("select accepted_at,digest from passkey_metadata_state");
        policy.refresh();
        assertEquals(before, db.queryForMap("select accepted_at,digest from passkey_metadata_state"));
        assertTrue(db.queryForObject("select next_fetch_at>clock_timestamp()+interval '119 minutes' from passkey_mds_fetch_state", Boolean.class));
        int count = gets.get();
        policy.refresh();
        assertEquals(count, gets.get());
    }

    @Test
    void leaseLossFencesPublicationAfterSuccessfulWorker() throws Exception {
        server.createContext("/lose-lease", exchange -> {
            try {
                db.update("update passkey_mds_fetch_state set lease_id=null,lease_until=null");
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
            } finally {
                exchange.close();
            }
        });
        try {
            var candidate = policy(new LiveMdsClient(origin + "/lose-lease", origin, true, 15));
            assertThrows(Exception.class, () -> candidate.refresh());
            assertEquals(0, db.queryForObject("select count(*) from passkey_metadata_state", Integer.class));
        } finally {
            server.removeContext("/lose-lease");
        }
    }

    @Test
    void mixedPublicCatalogFiltersLegacyModelsRatherThanTrustingThem() throws Exception {
        var jws = com.nimbusds.jose.JWSObject.parse(new String(body, java.nio.charset.StandardCharsets.UTF_8));
        var json = new com.fasterxml.jackson.databind.ObjectMapper().readTree(jws.getPayload().toBytes());
        var entries = (com.fasterxml.jackson.databind.node.ArrayNode) json.path("entries");
        var legacy = entries.get(0).deepCopy();
        ((com.fasterxml.jackson.databind.node.ObjectNode) legacy).remove("aaguid");
        ((com.fasterxml.jackson.databind.node.ObjectNode) legacy).put("aaid", "FFFF#FFFF");
        ((com.fasterxml.jackson.databind.node.ObjectNode) legacy.path("metadataStatement")).remove("aaguid");
        entries.add(legacy);
        @SuppressWarnings("unchecked") Map<String, Object> payload = new com.fasterxml.jackson.databind.ObjectMapper().convertValue(json, Map.class);
        body = fixture.signed(payload, false).getBytes(java.nio.charset.StandardCharsets.UTF_8);
        policy.refresh();
        assertEquals(1, db.queryForObject("select count(*) from passkey_model_eligibility", Integer.class));
    }

    @Test
    void policyAgeStillCapsRepeatedSuccessfulLiveValidation() throws Exception {
        policy.refresh();
        var accepted = db.queryForObject("select accepted_at from passkey_metadata_state", java.sql.Timestamp.class);
        db.update("update passkey_metadata_state set accepted_at=clock_timestamp()-interval '8 days',expires_at=clock_timestamp()-interval '1 second'");
        due();
        policy.refresh();
        assertEquals("DOWN", policy.health().getStatus().getCode());
        assertTrue(db.queryForObject("select accepted_at<? from passkey_metadata_state", Boolean.class, accepted));
    }

    @Test
    void renewedCrlEvidenceInvalidatesPeerCacheWithoutSlidingMetadataAge() throws Exception {
        policy.refresh();
        var peer = policy(client(15));
        peer.refresh();
        var before = db.queryForMap("select accepted_at,expires_at,evidence_digest from passkey_metadata_state");
        Path crl = fixture.dir.resolve("root.crl");
        byte[] old = Files.readAllBytes(crl);
        try {
            fixture.renewCrl();
            due();
            policy.refresh();
            assertEquals(before.get("accepted_at"), db.queryForObject("select accepted_at from passkey_metadata_state", java.sql.Timestamp.class));
            assertTrue(db.queryForObject("select expires_at>? from passkey_metadata_state", Boolean.class, before.get("expires_at")));
            assertNotEquals(before.get("evidence_digest"), db.queryForObject("select evidence_digest from passkey_metadata_state", String.class));
            assertEquals("DOWN", peer.health().getStatus().getCode());
            int requests = gets.get();
            peer.refresh();
            assertEquals(requests, gets.get());
            assertEquals("UP", peer.health().getStatus().getCode());
        } finally {
            Files.write(crl, old);
        }
    }

    @Test
    void interruptedCallerKillsChildAndReleasesWorkerSlot() throws Exception {
        mode.set("SLOW");
        var executor = Executors.newSingleThreadExecutor();
        var completed = new CountDownLatch(1);
        var operation = executor.submit(() -> {
            try {
                client(15).verify(Set.of(fixture.root), "test-only terms", null, null);
            } catch (Exception cancelled) {/* expected interruption */} finally {
                completed.countDown();
            }
        });
        try {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(8);
            while (gets.get() == 0 && System.nanoTime() < deadline) Thread.sleep(20);
            assertTrue(gets.get() > 0);
            operation.cancel(true);
            assertTrue(completed.await(3, TimeUnit.SECONDS));
            mode.set("OK");
            policy.refresh();
            assertEquals("UP", policy.health().getStatus().getCode());
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void nonPublicRangesIncludeIpv6UniqueLocalAndCarrierGradeNat() throws Exception {
        for (String address : List.of("fd00::1", "fc00::1", "100.64.0.1", "198.18.0.1", "0.1.2.3", "192.0.2.1"))
            assertTrue(MdsVerifierWorker.Transport.nonPublic(InetAddress.getByName(address)));
        assertFalse(MdsVerifierWorker.Transport.nonPublic(InetAddress.getByName("1.1.1.1")));
    }

    @Test
    void trustedCaWithoutExpectedPublisherIdentityCannotPublish() throws Exception {
        var wrongPublisher = new LiveMdsClient(origin + "/metadata", origin, true, 15, "mds.fidoalliance.org");
        assertThrows(Exception.class, () -> policy(wrongPublisher).refresh());
        assertEquals(0, db.queryForObject("select count(*) from passkey_metadata_state", Integer.class));
    }
}
