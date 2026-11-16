package com.example.iam.server.passkey;

import com.example.iam.server.token.TrackedAuthorizationService;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.data.AttestationConveyancePreference;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import org.flywaydb.core.Flyway;
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

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.*;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

@Testcontainers
class AttestationIntegrationTest {
    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:17-alpine");
    static final String PASSWORD = "test-only-strong-passphrase";
    @TempDir
    static Path dir;
    static JdbcTemplate db;
    static TransactionTemplate tx;
    static DataSourceTransactionManager manager;
    static TrackedAuthorizationService grants;
    static AttestationFixtures fixture, other;
    AttestationPolicy policy;
    PasskeyService service;
    String user, session, binding;
    Path metadata;

    @BeforeAll
    static void setup() throws Exception {
        fixture = new AttestationFixtures(dir.resolve("primary"));
        other = new AttestationFixtures(dir.resolve("untrusted"));
        var ds = new DriverManagerDataSource(POSTGRES.getJdbcUrl() + "&connectTimeout=2&socketTimeout=3&cancelSignalTimeout=2", POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(ds).load().migrate();
        db = new JdbcTemplate(ds);
        manager = new DataSourceTransactionManager(ds);
        tx = new TransactionTemplate(manager);
        tx.setTimeout(10);
        grants = new TrackedAuthorizationService(db, new JdbcRegisteredClientRepository(db), manager, Duration.ofHours(8));
    }

    @BeforeEach
    void identity() throws Exception {
        db.execute("truncate users,identity_sessions,refresh_history,authorization_lifecycle,passkey_metadata_state,passkey_model_eligibility,passkey_revoked_models cascade");
        db.update("update authorization_retention_state set initial_not_before='1970-01-01'");
        metadata = dir.resolve("bundle.jwt");
        write(1, "FIDO_CERTIFIED_L2");
        policy = policy(fixture.dir.resolve("root.pem"));
        policy.refresh();
        service = service(policy);
        user = UUID.randomUUID().toString();
        session = UUID.randomUUID().toString();
        binding = TrackedAuthorizationService.digest(UUID.randomUUID().toString());
        db.update("insert into users(id,username,password_hash,state) values (?,?,?,'ACTIVE')", user, user, new BCryptPasswordEncoder(12).encode(PASSWORD));
        grants.registerSession(session, user, grants.now());
    }

    AttestationPolicy policy(Path authenticatorRoots) {
        return policy(authenticatorRoots, 1);
    }

    AttestationPolicy policy(Path authenticatorRoots, long revision) {
        return new AttestationPolicy(db, manager, grants, "REQUIRED", metadata.toString(), fixture.dir.resolve("root.pem").toString(), authenticatorRoots.toString(), fixture.dir.resolve("root.crl").toString(), "test-only terms", Duration.ofHours(1), Clock.systemUTC(), revision);
    }

    PasskeyService service(AttestationPolicy p) {
        return new PasskeyService(db, new PasskeySettings(new PasskeyRepository(db), true, "localhost", "https://localhost:9000", false, p), new BCryptPasswordEncoder(12), grants);
    }

    void write(int serial, String status) throws Exception {
        Files.writeString(dir.resolve("bundle.jwt"), fixture.metadata(serial, status, LocalDate.now(ZoneOffset.UTC).plusDays(2)));
    }

    PasskeyService.Started registration() {
        return tx.execute(s -> service.registerStart(user, session, binding, PASSWORD));
    }

    String registrationResponse(PasskeyService.Started start, boolean trusted) throws Exception {
        return fixture.registration(PublicKeyCredentialCreationOptions.fromJson(db.queryForObject("select options from passkey_challenges where id=?", String.class, start.id())), trusted);
    }

    void enroll() throws Exception {
        var start = registration();
        String response = registrationResponse(start, true);
        assertEquals(Boolean.TRUE, tx.execute(s -> service.registerFinish(user, binding, start.id(), response)));
    }

    Assertion assertion(int counter) throws Exception {
        var start = tx.execute(s -> service.authenticateStart(binding));
        return new Assertion(start, fixture.assertion(AssertionRequest.fromJson(db.queryForObject("select options from passkey_challenges where id=?", String.class, start.id())), user, counter));
    }

    PasskeyService.Authenticated finish(Assertion a, String session) {
        return tx.execute(s -> service.authenticateFinish(binding, a.start.id(), a.response, session));
    }

    @Test
    void trustedPackedRegistrationAndRealSignedAssertionWork() throws Exception {
        var start = registration();
        var options = PublicKeyCredentialCreationOptions.fromJson(db.queryForObject("select options from passkey_challenges where id=?", String.class, start.id()));
        assertEquals(AttestationConveyancePreference.DIRECT, options.getAttestation());
        String response = registrationResponse(start, true);
        assertEquals(Boolean.TRUE, tx.execute(s -> service.registerFinish(user, binding, start.id(), response)));
        assertEquals(AttestationFixtures.MODEL, db.queryForObject("select attestation_aaguid from passkey_credentials", UUID.class));
        assertTrue(grants.sessionRevoked(session, user));
        var proof = assertion(1);
        assertNotNull(finish(proof, "attested-session"));
        assertNull(finish(proof, "replay-session"));
    }

    @Test
    void noneAndUntrustedRootAreRejectedAndChallengesSpent() throws Exception {
        var first = registration();
        String none = registrationResponse(first, false);
        assertEquals(Boolean.FALSE, tx.execute(s -> service.registerFinish(user, binding, first.id(), none)));
        var otherPolicy = policy(other.dir.resolve("root.pem"), 2);
        otherPolicy.refresh();
        service = service(otherPolicy);
        var second = registration();
        String response = registrationResponse(second, true);
        assertEquals(Boolean.FALSE, tx.execute(s -> service.registerFinish(user, binding, second.id(), response)));
        assertEquals(0, db.queryForObject("select count(*) from passkey_credentials", Integer.class));
        assertEquals(2, db.queryForObject("select count(*) from passkey_challenges where consumed_at is not null", Integer.class));
    }

    @Test
    void revokedMetadataBlocksPreparedAssertionAndQueuesDurableLogout() throws Exception {
        enroll();
        assertNotNull(finish(assertion(1), "live"));
        db.update("insert into oidc_rp_sessions(id,session_id,registered_client_id,client_id,subject,sid,endpoint) values (?,'live','rp','rp',?,'sid','https://rp.example/logout')", UUID.randomUUID().toString(), user);
        db.update("insert into authorization_lifecycle(id,principal_name,client_id,session_id,created_at,expires_at,grant_expires_at,revision) values ('family',?,'rp','live',clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '1 hour',1)", user);
        db.update("insert into refresh_history(token_hash,authorization_id,client_id) values (?,'family','rp')", TrackedAuthorizationService.digest("test-only-refresh"));
        var prepared = assertion(2);
        write(2, "REVOKED");
        policy.refresh();
        assertNull(finish(prepared, "revoked-login"));
        assertEquals(1, policy.revokeBatch());
        assertTrue(grants.sessionRevoked("live", user));
        assertNotNull(db.queryForObject("select revoked_at from authorization_lifecycle where id='family'", java.sql.Timestamp.class));
        assertEquals(1, db.queryForObject("select count(*) from refresh_history", Integer.class));
        assertEquals(1, db.queryForObject("select count(*) from logout_deliveries", Integer.class));
        assertEquals(0, policy.revokeBatch());
        write(3, "FIDO_CERTIFIED_L2");
        policy.refresh();
        assertNull(finish(assertion(3), "restored")); // A later clean BLOB never erases an accepted compromise tombstone.
    }

    @Test
    void metadataOutageUsesOnlyFreshAcceptedStateAndDoesNotExtendItsAge() throws Exception {
        enroll();
        Files.delete(metadata);
        assertThrows(Exception.class, () -> policy.refresh());
        assertNotNull(finish(assertion(1), "cached"));
        var prepared = assertion(2);
        db.update("update passkey_metadata_state set expires_at=clock_timestamp()-interval '1 second'");
        var failure = assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> finish(prepared, "expired"));
        assertEquals(503, failure.getStatusCode().value());
        assertNull(db.queryForObject("select consumed_at from passkey_challenges where id=?", java.sql.Timestamp.class, prepared.start.id()));
        write(1, "FIDO_CERTIFIED_L2");
        policy.refresh();
        assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> finish(prepared, "old-serial"));
        write(2, "FIDO_CERTIFIED_L2");
        policy.refresh();
        assertNotNull(finish(prepared, "fresh-again"));
    }

    @Test
    void rollbackEquivocationBadSignatureAndExpiredBlobCannotReplaceAcceptedState() throws Exception {
        write(2, "FIDO_CERTIFIED_L2");
        policy.refresh();
        String digest = db.queryForObject("select digest from passkey_metadata_state", String.class);
        write(1, "REVOKED");
        assertThrows(Exception.class, () -> policy.refresh());
        write(2, "REVOKED");
        assertThrows(Exception.class, () -> policy.refresh());
        Files.writeString(metadata, other.metadata(3, "FIDO_CERTIFIED_L2", LocalDate.now(ZoneOffset.UTC).plusDays(2)));
        assertThrows(Exception.class, () -> policy.refresh());
        Files.writeString(metadata, fixture.metadata(3, "FIDO_CERTIFIED_L2", LocalDate.now(ZoneOffset.UTC).minusDays(1)));
        assertThrows(Exception.class, () -> policy.refresh());
        assertEquals(digest, db.queryForObject("select digest from passkey_metadata_state", String.class));
        assertEquals(0, db.queryForObject("select count(*) from passkey_revoked_models", Integer.class));
    }

    @Test
    void offlinePolicyRejectsRemoteCertificateRetrievalWithoutFetching() throws Exception {
        Files.writeString(metadata, fixture.signed(Map.of("legalHeader", "test-only terms", "no", 2, "nextUpdate", LocalDate.now(ZoneOffset.UTC).plusDays(1).toString(), "entries", List.of()), true));
        assertThrows(Exception.class, () -> policy.refresh());
        assertEquals(1, db.queryForObject("select serial from passkey_metadata_state", Integer.class));
    }

    @Test
    void revokedSweepRollsBackOnAuditOutageAndRetries() throws Exception {
        enroll();
        assertNotNull(finish(assertion(1), "live"));
        write(2, "ATTESTATION_KEY_COMPROMISE");
        policy.refresh();
        db.execute("create function fail_model_audit() returns trigger language plpgsql as $$begin if new.event_type='PASSKEY_MODEL_REVOKED' then raise exception 'test audit outage';end if;return new;end$$");
        db.execute("create trigger fail_model_audit before insert on security_audit_events for each row execute function fail_model_audit()");
        try {
            assertThrows(org.springframework.dao.DataAccessException.class, () -> policy.revokeBatch());
            assertFalse(grants.sessionRevoked("live", user));
            assertNull(db.queryForObject("select attestation_revoked_at from passkey_credentials", java.sql.Timestamp.class));
        } finally {
            db.execute("drop trigger fail_model_audit on security_audit_events");
            db.execute("drop function fail_model_audit()");
        }
        assertEquals(1, policy.revokeBatch());
        assertTrue(grants.sessionRevoked("live", user));
    }

    @Test
    void concurrentPublicationAndAuthenticationCannotLeaveSessionAfterSweep() throws Exception {
        enroll();
        var prepared = assertion(1);
        write(2, "REVOKED");
        try (var pool = Executors.newFixedThreadPool(2)) {
            var barrier = new CyclicBarrier(2);
            var authentication = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return finish(prepared, "racing");
            });
            var publication = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                policy.refresh();
                return true;
            });
            authentication.get(15, TimeUnit.SECONDS);
            assertTrue(publication.get(15, TimeUnit.SECONDS));
        }
        policy.revokeBatch();
        assertTrue(grants.sessionRevoked("racing", user));
        assertNull(finish(assertion(2), "after-publish"));
    }

    @Test
    void twoSweepersEnqueueOnlyOnce() throws Exception {
        enroll();
        assertNotNull(finish(assertion(1), "live"));
        write(2, "RETIRED");
        policy.refresh();
        try (var pool = Executors.newFixedThreadPool(2)) {
            var a = pool.submit(() -> policy.revokeBatch());
            var b = pool.submit(() -> policy.revokeBatch());
            assertEquals(1, a.get(10, TimeUnit.SECONDS) + b.get(10, TimeUnit.SECONDS));
        }
        assertEquals(1, db.queryForObject("select count(*) from security_audit_events where subject_id=? and event_type='PASSKEY_MODEL_REVOKED'", Integer.class, user));
    }

    @Test
    void rootWithdrawalRevokesOldCredentialsWithoutTreatingItAsPermanentModelCompromise() throws Exception {
        enroll();
        assertNotNull(finish(assertion(1), "old-root"));
        var narrower = policy(other.dir.resolve("root.pem"), 2);
        narrower.refresh();
        assertEquals(1, narrower.revokeBatch());
        assertTrue(grants.sessionRevoked("old-root", user));
        assertEquals(0, db.queryForObject("select count(*) from passkey_revoked_models", Integer.class));
        assertThrows(Exception.class, () -> policy.refresh());
        policy = policy(fixture.dir.resolve("root.pem"), 3);
        policy.refresh();
        service = service(policy);
        assertNull(finish(assertion(2), "withdrawn-key"));
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"REVOKED", "RETIRED", "ATTESTATION_KEY_COMPROMISE", "USER_VERIFICATION_BYPASS", "USER_KEY_REMOTE_COMPROMISE", "USER_KEY_PHYSICAL_COMPROMISE", "UPDATE_AVAILABLE"})
    void unsafeModelStatusAlwaysDenies(String status) throws Exception {
        enroll();
        write(2, status);
        policy.refresh();
        assertNull(finish(assertion(1), "unsafe"));
        assertEquals(1, policy.revokeBatch());
    }

    @Test
    void missingCrlFailsClosedAndCanRecoverWithoutSpendingChallenge() throws Exception {
        enroll();
        var prepared = assertion(1);
        Path crl = fixture.dir.resolve("root.crl");
        byte[] saved = Files.readAllBytes(crl);
        Files.delete(crl);
        try {
            assertEquals("DOWN", policy.health().getStatus().getCode());
            assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> finish(prepared, "missing-crl"));
        } finally {
            Files.write(crl, saved);
        }
        assertEquals("UP", policy.health().getStatus().getCode());
        assertNotNull(finish(prepared, "restored-crl"));
    }

    @Test
    void databaseOutageCannotPublishOrConsumeAndRecovers() throws Exception {
        enroll();
        var prepared = assertion(1);
        write(2, "REVOKED");
        POSTGRES.getDockerClient().pauseContainerCmd(POSTGRES.getContainerId()).exec();
        try {
            assertThrows(RuntimeException.class, () -> finish(prepared, "db-outage"));
            assertThrows(Exception.class, () -> policy.refresh());
        } finally {
            POSTGRES.getDockerClient().unpauseContainerCmd(POSTGRES.getContainerId()).exec();
        }
        assertNull(db.queryForObject("select consumed_at from passkey_challenges where id=?", java.sql.Timestamp.class, prepared.start.id()));
        assertEquals(1, db.queryForObject("select serial from passkey_metadata_state", Integer.class));
        policy.refresh();
        assertNull(finish(prepared, "after-db-recovery"));
        assertEquals(1, policy.revokeBatch());
    }

    @Test
    void alreadyCachedNodeCannotAuthenticateAfterPeerPublishesRevocation() throws Exception {
        enroll();
        var prepared = assertion(1);
        var peer = policy(fixture.dir.resolve("root.pem"));
        write(2, "REVOKED");
        peer.refresh();
        assertNull(finish(prepared, "cached-node"));
        assertEquals(1, peer.revokeBatch());
    }

    @Test
    void simultaneousRegistrationCompletionsHaveOneWinner() throws Exception {
        var start = registration();
        String response = registrationResponse(start, true);
        try (var pool = Executors.newFixedThreadPool(2)) {
            var barrier = new CyclicBarrier(2);
            var a = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return tx.execute(s -> service.registerFinish(user, binding, start.id(), response));
            });
            var b = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return tx.execute(s -> service.registerFinish(user, binding, start.id(), response));
            });
            assertNotEquals(a.get(15, TimeUnit.SECONDS), b.get(15, TimeUnit.SECONDS));
        }
        assertEquals(1, db.queryForObject("select count(*) from passkey_credentials", Integer.class));
    }

    @Test
    void acceptedMetadataIsBoundedByCrlExpiry() throws Exception {
        var crl = (java.security.cert.X509CRL) java.security.cert.CertificateFactory.getInstance("X.509").generateCRL(Files.newInputStream(fixture.dir.resolve("root.crl")));
        Instant expiry = db.queryForObject("select expires_at from passkey_metadata_state", java.sql.Timestamp.class).toInstant();
        assertFalse(expiry.isAfter(crl.getNextUpdate().toInstant()));
    }

    @Test
    void revokedMetadataSigningCertificateFailsLibraryPkix() throws Exception {
        Path crl = fixture.dir.resolve("root.crl");
        byte[] saved = Files.readAllBytes(crl);
        try {
            fixture.revokeSigner();
            write(2, "FIDO_CERTIFIED_L2");
            assertThrows(java.security.cert.CertPathValidatorException.class, () -> policy.refresh());
            assertEquals(1, db.queryForObject("select serial from passkey_metadata_state", Integer.class));
        } finally {
            Files.write(crl, saved);
        }
    }

    @Test
    void enrollmentAuditOutageRollsBackKeyRevocationAndChallenge() throws Exception {
        var start = registration();
        String response = registrationResponse(start, true);
        db.execute("create function fail_enroll_audit() returns trigger language plpgsql as $$begin if new.event_type='PASSKEY_ENROLLED' then raise exception 'test audit outage';end if;return new;end$$");
        db.execute("create trigger fail_enroll_audit before insert on security_audit_events for each row execute function fail_enroll_audit()");
        try {
            assertThrows(org.springframework.dao.DataAccessException.class, () -> tx.execute(s -> service.registerFinish(user, binding, start.id(), response)));
            assertFalse(grants.sessionRevoked(session, user));
            assertEquals(0, db.queryForObject("select count(*) from passkey_credentials", Integer.class));
            assertNull(db.queryForObject("select consumed_at from passkey_challenges where id=?", java.sql.Timestamp.class, start.id()));
        } finally {
            db.execute("drop trigger fail_enroll_audit on security_audit_events");
            db.execute("drop function fail_enroll_audit()");
        }
        assertEquals(Boolean.TRUE, tx.execute(s -> service.registerFinish(user, binding, start.id(), response)));
    }

    @Test
    void unknownStatusesAndAlteredMetadataSignaturesAreRejected() throws Exception {
        write(2, "UNKNOWN");
        assertThrows(Exception.class, () -> policy.refresh());
        write(2, "FIDO_CERTIFIED_L2");
        String[] parts = Files.readString(metadata).split("\\.");
        parts[2] = (parts[2].charAt(0) == 'A' ? "B" : "A") + parts[2].substring(1);
        Files.writeString(metadata, String.join(".", parts));
        assertThrows(Exception.class, () -> policy.refresh());
        assertEquals(1, db.queryForObject("select serial from passkey_metadata_state", Integer.class));
    }

    @Test
    void concurrentPolicyPublishersCannotRestoreOlderRevision() throws Exception {
        var revision2 = policy(other.dir.resolve("root.pem"), 2);
        var revision3 = policy(fixture.dir.resolve("root.pem"), 3);
        try (var pool = Executors.newFixedThreadPool(2)) {
            var barrier = new CyclicBarrier(2);
            var a = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                try {
                    revision2.refresh();
                } catch (IllegalArgumentException stale) {/* revision 3 won */}
                return true;
            });
            var b = pool.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                revision3.refresh();
                return true;
            });
            assertTrue(a.get(15, TimeUnit.SECONDS));
            assertTrue(b.get(15, TimeUnit.SECONDS));
        }
        assertEquals(3, db.queryForObject("select policy_revision from passkey_metadata_state", Integer.class));
        assertThrows(Exception.class, () -> revision2.refresh());
        assertThrows(Exception.class, () -> policy.refresh());
    }

    @Test
    void skewedNodeCannotPublishOrUseHardwareProof() throws Exception {
        var skewed = new AttestationPolicy(db, manager, grants, "REQUIRED", metadata.toString(), fixture.dir.resolve("root.pem").toString(), fixture.dir.resolve("root.pem").toString(), fixture.dir.resolve("root.crl").toString(), "test-only terms", Duration.ofHours(1), Clock.offset(Clock.systemUTC(), Duration.ofMinutes(2)), 1);
        assertEquals("DOWN", skewed.health().getStatus().getCode());
        assertThrows(Exception.class, () -> skewed.refresh());
    }

    @Test
    void hardwarePrimaryDoesNotBypassExistingMfaOrRecoveryCodes() throws Exception {
        enroll();
        db.update("insert into mfa_credentials(user_id,secret_encrypted,enabled) values (?,'test-not-used',true)", user);
        db.update("insert into recovery_codes(user_id,code_hash) values (?,?)", user, TrackedAuthorizationService.digest("test-only-recovery"));
        assertNotNull(finish(assertion(1), "hardware-primary"));
        assertFalse(grants.sessionAssured("hardware-primary", user));
        assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> tx.execute(s -> service.registerStart(user, "hardware-primary", binding, PASSWORD)));
        UUID key = db.queryForObject("select id from passkey_credentials", UUID.class);
        assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> tx.execute(s -> service.remove(user, "hardware-primary", key, PASSWORD)));
        assertEquals(1, db.queryForObject("select count(*) from recovery_codes where user_id=?", Integer.class, user));
    }

    @Test
    void ownerCanRemoveAttestedKeyDuringMetadataOutage() throws Exception {
        enroll();
        assertNotNull(finish(assertion(1), "removal"));
        UUID key = db.queryForObject("select id from passkey_credentials", UUID.class);
        Path roots = fixture.dir.resolve("root.pem");
        byte[] saved = Files.readAllBytes(roots);
        Files.delete(roots);
        try {
            assertEquals(Boolean.TRUE, tx.execute(s -> service.remove(user, "removal", key, PASSWORD)));
            assertTrue(grants.sessionRevoked("removal", user));
        } finally {
            Files.write(roots, saved);
        }
    }

    @Test
    void misconfiguredNoneNodeCannotBypassAcceptedRequiredPolicy() throws Exception {
        var none = new AttestationPolicy(db, manager, grants, "NONE", "", "", "", "", "", Duration.ofHours(1), Clock.systemUTC());
        var weaker = service(none);
        assertEquals("DOWN", none.health().getStatus().getCode());
        var denied = assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> tx.execute(s -> weaker.registerStart(user, session, binding, PASSWORD)));
        assertEquals(503, denied.getStatusCode().value());
        assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> tx.execute(s -> weaker.authenticateStart(binding)));
    }

    @Test
    void ambiguousMetadataHeadersAreRejectedBeforeLibraryNetworkResolution() throws Exception {
        String[] parts = Files.readString(metadata).split("\\.");
        String cert = java.util.Base64.getEncoder().encodeToString(fixture.root.getEncoded());
        String duplicate = "{\"alg\":\"RS256\",\"x5c\":[\"" + cert + "\"],\"x5u\":null,\"x5u\":\"http://127.0.0.1:9/forbidden\"}";
        parts[0] = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(duplicate.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        Files.writeString(metadata, String.join(".", parts));
        assertThrows(com.fasterxml.jackson.core.JsonProcessingException.class, () -> policy.refresh());
        assertEquals(1, db.queryForObject("select serial from passkey_metadata_state", Integer.class));
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"software", ""})
    void trustedCertificatesCannotAttestSoftwareOrUnspecifiedProtection(String protection) throws Exception {
        var jws = com.nimbusds.jose.JWSObject.parse(fixture.metadata(2, "FIDO_CERTIFIED_L2", LocalDate.now(ZoneOffset.UTC).plusDays(2)));
        var payload = new com.fasterxml.jackson.databind.ObjectMapper().readTree(jws.getPayload().toBytes());
        var statement = (com.fasterxml.jackson.databind.node.ObjectNode) payload.path("entries").get(0).path("metadataStatement");
        var values = statement.putArray("keyProtection");
        if (!protection.isEmpty()) values.add(protection);
        @SuppressWarnings("unchecked") var map = new com.fasterxml.jackson.databind.ObjectMapper().convertValue(payload, Map.class);
        Files.writeString(metadata, fixture.signed(map, false));
        policy.refresh();
        var start = registration();
        String response = registrationResponse(start, true);
        assertEquals(Boolean.FALSE, tx.execute(s -> service.registerFinish(user, binding, start.id(), response)));
        assertEquals(0, db.queryForObject("select count(*) from passkey_credentials", Integer.class));
    }

    record Assertion(PasskeyService.Started start, String response) {
    }
}
