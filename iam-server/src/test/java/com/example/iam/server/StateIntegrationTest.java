package com.example.iam.server;

import com.example.iam.server.authorization.DecisionController;
import com.example.iam.server.mfa.MfaService;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.UUID;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.*;

@Testcontainers
class StateIntegrationTest {
    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:17-alpine");
    static JdbcTemplate db;
    static TransactionTemplate tx;
    static MfaService mfa;

    @BeforeAll
    static void setup() {
        var ds = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(ds).load().migrate();
        db = new JdbcTemplate(ds);
        tx = new TransactionTemplate(new DataSourceTransactionManager(ds));
        mfa = new MfaService(db, "test-only-encryption-password", "00112233445566778899aabbccddeeff");
    }

    String user() {
        String id = UUID.randomUUID().toString();
        db.update("insert into users(id,username,password_hash,state) values (?,?,?,'ACTIVE')", id, id, "not-a-login-credential");
        return id;
    }

    com.example.iam.server.identity.AdminController admin() {
        var service = new com.example.iam.server.token.TrackedAuthorizationService(db,
                new org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository(db),
                new DataSourceTransactionManager(db.getDataSource()), java.time.Duration.ofHours(8));
        return new com.example.iam.server.identity.AdminController(db,
                new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder(), service);
    }

    @Test
    void profileUsesOptimisticVersionAndDeletedIdentityCannotReturn() {
        String id = user();
        var admin = admin();
        long version = ((Number) admin.user(id).get("version")).longValue();
        tx.executeWithoutResult(s -> admin.update(id,
                new com.example.iam.server.identity.AdminController.ProfileUpdate("updated-" + id, version)));
        assertEquals("updated-" + id, admin.user(id).get("username"));
        assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> tx.executeWithoutResult(s ->
                admin.update(id, new com.example.iam.server.identity.AdminController.ProfileUpdate("stale", version))));
        tx.executeWithoutResult(s -> admin.delete(id));
        assertEquals("DELETED", admin.user(id).get("state"));
        assertNotNull(db.queryForObject("select sessions_not_before from users where id=?", java.sql.Timestamp.class, id));
        assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> tx.executeWithoutResult(s -> admin.activate(id)));
        assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> tx.executeWithoutResult(s ->
                admin.update(id, new com.example.iam.server.identity.AdminController.ProfileUpdate("resurrected", version + 2))));
    }

    @Test
    void deactivationRevokesSessionsAndAuditFailureRollsBackProfile() {
        String id = user(), session = UUID.randomUUID().toString();
        var admin = admin();
        db.update("insert into identity_sessions(id,principal_name) values (?,?)", session, id);
        tx.executeWithoutResult(s -> admin.deactivate(id));
        assertEquals("DISABLED", admin.user(id).get("state"));
        assertNotNull(db.queryForObject("select revoked_at from identity_sessions where id=?", java.sql.Timestamp.class, session));
        assertEquals(1, db.queryForObject("select count(*) from security_audit_events where subject_id=? and event_type='USER_DISABLED'", Integer.class, id));
        long version = ((Number) admin.user(id).get("version")).longValue();
        // A database constraint simulates a durable audit sink failure in the same transaction.
        db.execute("alter table security_audit_events add constraint reject_profile_test check (event_type <> 'USER_PROFILE_UPDATED') not valid");
        try {
            assertThrows(org.springframework.dao.DataIntegrityViolationException.class, () -> tx.executeWithoutResult(s ->
                    admin.update(id, new com.example.iam.server.identity.AdminController.ProfileUpdate("rollback-" + id, version))));
            assertEquals(id, admin.user(id).get("username"));
            assertEquals(version, ((Number) admin.user(id).get("version")).longValue());
        } finally {
            db.execute("alter table security_audit_events drop constraint reject_profile_test");
        }
    }

    String organization() {
        String id = UUID.randomUUID().toString();
        db.update("insert into organizations(id,name) values (?,?)", id, id);
        return id;
    }

    @Test
    void membershipRemovalDeniesImmediatelyAndRejoiningCannotRestoreAssignments() {
        String id = user(), tenant = organization(), resource = UUID.randomUUID().toString();
        var members = new com.example.iam.server.authorization.MembershipController(db);
        var policies = new com.example.iam.server.authorization.PolicyAdminController(db);
        tx.executeWithoutResult(s -> members.add(tenant, new com.example.iam.server.authorization.MembershipController.Member(id)));
        String role = tx.execute(s -> policies.role(new com.example.iam.server.authorization.PolicyAdminController.Role(UUID.randomUUID().toString()))).get("id");
        tx.executeWithoutResult(s -> policies.permission(new com.example.iam.server.authorization.PolicyAdminController.Permission(role, "payment:read")));
        db.update("insert into protected_resources values (?,?)", resource, tenant);
        tx.execute(s -> policies.assign(new com.example.iam.server.authorization.PolicyAdminController.Assignment(id, tenant, role, resource)));
        var identity = new JwtAuthenticationToken(Jwt.withTokenValue("test").header("alg", "RS256").subject(id).build());
        var request = new DecisionController.Request(tenant, "payment:read", resource);
        assertEquals("ALLOW", new DecisionController(db).decide(identity, request).decision());
        String otherTenant = organization();
        tx.executeWithoutResult(s -> members.add(otherTenant, new com.example.iam.server.authorization.MembershipController.Member(id)));
        tx.executeWithoutResult(s -> members.remove(tenant, id));
        assertEquals(1, members.list(otherTenant, 0).size());
        assertEquals("DENY", new DecisionController(db).decide(identity, request).decision());
        tx.executeWithoutResult(s -> members.add(tenant, new com.example.iam.server.authorization.MembershipController.Member(id)));
        assertEquals("DENY", new DecisionController(db).decide(identity, request).decision());
        assertEquals(1, members.list(tenant, 0).size());
        assertEquals(1, db.queryForObject("select count(*) from security_audit_events where event_type='MEMBERSHIP_REMOVED' and subject_id=?", Integer.class, id));
    }

    @Test
    void inactiveUnknownAndDuplicateMembersAreRejected() {
        String id = user(), tenant = organization();
        var members = new com.example.iam.server.authorization.MembershipController(db);
        db.update("update users set state='DISABLED' where id=?", id);
        assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> tx.executeWithoutResult(s ->
                members.add(tenant, new com.example.iam.server.authorization.MembershipController.Member(id))));
        assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> tx.executeWithoutResult(s ->
                members.add(tenant, new com.example.iam.server.authorization.MembershipController.Member(UUID.randomUUID().toString()))));
        db.update("update users set state='ACTIVE' where id=?", id);
        tx.executeWithoutResult(s -> members.add(tenant, new com.example.iam.server.authorization.MembershipController.Member(id)));
        assertThrows(org.springframework.dao.DataIntegrityViolationException.class, () -> tx.executeWithoutResult(s ->
                members.add(tenant, new com.example.iam.server.authorization.MembershipController.Member(id))));
        assertEquals(1, members.list(tenant, 0).size());
    }

    @Test
    void auditFailureRollsBackMembershipRemovalAndItsAssignments() {
        String id = user(), tenant = organization(), role = UUID.randomUUID().toString();
        var members = new com.example.iam.server.authorization.MembershipController(db);
        tx.executeWithoutResult(s -> members.add(tenant, new com.example.iam.server.authorization.MembershipController.Member(id)));
        db.update("insert into roles values (?,?)", role, role);
        db.update("insert into user_role_assignments values (?,?,?,?,null)", UUID.randomUUID().toString(), id, tenant, role);
        db.execute("alter table security_audit_events add constraint reject_membership_test check (event_type <> 'MEMBERSHIP_REMOVED') not valid");
        try {
            assertThrows(org.springframework.dao.DataIntegrityViolationException.class, () -> tx.executeWithoutResult(s -> members.remove(tenant, id)));
            assertEquals(1, members.list(tenant, 0).size());
            assertEquals(1, db.queryForObject("select count(*) from user_role_assignments where user_id=? and organization_id=?", Integer.class, id, tenant));
        } finally {
            db.execute("alter table security_audit_events drop constraint reject_membership_test");
        }
    }

    @Test
    void assignmentWaitingForRemovalCannotRecreateAnOrphan() throws Exception {
        String id = user(), tenant = organization(), role = UUID.randomUUID().toString();
        var members = new com.example.iam.server.authorization.MembershipController(db);
        var policies = new com.example.iam.server.authorization.PolicyAdminController(db);
        tx.executeWithoutResult(s -> members.add(tenant, new com.example.iam.server.authorization.MembershipController.Member(id)));
        db.update("insert into roles values (?,?)", role, role);
        var locked = new java.util.concurrent.CountDownLatch(1);
        var release = new java.util.concurrent.CountDownLatch(1);
        try (var pool = Executors.newFixedThreadPool(2)) {
            var removal = pool.submit(() -> tx.executeWithoutResult(s -> {
                members.remove(tenant, id);
                locked.countDown();
                try {
                    assertTrue(release.await(5, java.util.concurrent.TimeUnit.SECONDS));
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
            }));
            assertTrue(locked.await(5, java.util.concurrent.TimeUnit.SECONDS));
            var assignment = pool.submit(() -> tx.execute(s -> policies.assign(
                    new com.example.iam.server.authorization.PolicyAdminController.Assignment(id, tenant, role, null))));
            release.countDown();
            removal.get();
            assertThrows(java.util.concurrent.ExecutionException.class, assignment::get);
            assertEquals(0, db.queryForObject("select count(*) from user_role_assignments where user_id=?", Integer.class, id));
        } finally {
            release.countDown();
        }
    }

    @Test
    void rbacAuditFailuresRollBackCreationPermissionAndRevocation() {
        String tenant = organization(), id = user(), role = UUID.randomUUID().toString(), assignment = UUID.randomUUID().toString();
        db.update("insert into organization_memberships values (?,?)", id, tenant);
        db.update("insert into roles values (?,?)", role, role);
        db.update("insert into user_role_assignments values (?,?,?,?,null)", assignment, id, tenant, role);
        var policies = new com.example.iam.server.authorization.PolicyAdminController(db);
        db.execute("alter table security_audit_events add constraint reject_rbac_test check (event_type not in ('ROLE_CREATED','ROLE_PERMISSION_CREATED','ROLE_ASSIGNMENT_REVOKED')) not valid");
        String name = UUID.randomUUID().toString();
        try {
            assertThrows(org.springframework.dao.DataIntegrityViolationException.class, () -> tx.execute(s ->
                    policies.role(new com.example.iam.server.authorization.PolicyAdminController.Role(name))));
            assertEquals(0, db.queryForObject("select count(*) from roles where name=?", Integer.class, name));
            assertThrows(org.springframework.dao.DataIntegrityViolationException.class, () -> tx.executeWithoutResult(s ->
                    policies.permission(new com.example.iam.server.authorization.PolicyAdminController.Permission(role, "test:read"))));
            assertEquals(0, db.queryForObject("select count(*) from role_permissions where role_id=?", Integer.class, role));
            assertThrows(org.springframework.dao.DataIntegrityViolationException.class, () -> tx.executeWithoutResult(s -> policies.revoke(assignment)));
            assertEquals(1, db.queryForObject("select count(*) from user_role_assignments where id=?", Integer.class, assignment));
        } finally {
            db.execute("alter table security_audit_events drop constraint reject_rbac_test");
        }
    }

    @Test
    void enrollmentEncryptionConfirmationAndReplay() {
        String id = user();
        String key = tx.execute(s -> mfa.enroll(id));
        assertFalse(mfa.enabled(id));
        assertNotEquals(key, db.queryForObject("select secret_encrypted from mfa_credentials where user_id=?", String.class, id));
        String otp = String.format("%06d", new GoogleAuthenticator().getTotpPassword(key));
        assertEquals(Boolean.TRUE, tx.execute(s -> mfa.verify(id, otp)));
        assertTrue(mfa.enabled(id));
        assertEquals(Boolean.FALSE, tx.execute(s -> mfa.verify(id, otp)));
    }

    @Test
    void concurrentOtpHasOneWinner() throws Exception {
        String id = user(), key = tx.execute(s -> mfa.enroll(id));
        String otp = String.format("%06d", new GoogleAuthenticator().getTotpPassword(key));
        try (var pool = Executors.newFixedThreadPool(2)) {
            var a = pool.submit(() -> tx.execute(s -> mfa.verify(id, otp)));
            var b = pool.submit(() -> tx.execute(s -> mfa.verify(id, otp)));
            assertNotEquals(a.get(), b.get());
        }
    }

    @Test
    void recoveryCodeConsumedOnce() {
        String id = user();
        String code = tx.execute(s -> mfa.recoveryCodes(id)).getFirst();
        assertEquals(Boolean.TRUE, tx.execute(s -> mfa.recover(id, code)));
        assertEquals(Boolean.FALSE, tx.execute(s -> mfa.recover(id, code)));
        assertEquals(9, db.queryForObject("select count(*) from recovery_codes where user_id=?", Integer.class, id));
    }

    @Test
    void tenantMembershipAndResourceIsolation() {
        String id = user(), tenant = UUID.randomUUID().toString(), other = UUID.randomUUID().toString(), role = UUID.randomUUID().toString(), resource = UUID.randomUUID().toString();
        db.update("insert into organizations(id,name) values (?,?),(?,?)", tenant, "first", other, "second");
        db.update("insert into organization_memberships values (?,?)", id, tenant);
        db.update("insert into roles values (?,?)", role, role);
        db.update("insert into role_permissions values (?,'payment:read')", role);
        db.update("insert into protected_resources values (?,?)", resource, tenant);
        db.update("insert into user_role_assignments values (?,?,?,?,?)", UUID.randomUUID().toString(), id, tenant, role, resource);
        var identity = new JwtAuthenticationToken(Jwt.withTokenValue("not-a-wire-token").header("alg", "RS256").subject(id).build());
        var pdp = new DecisionController(db);
        assertEquals("ALLOW", pdp.decide(identity, new DecisionController.Request(tenant, "payment:read", resource)).decision());
        assertEquals("DENY", pdp.decide(identity, new DecisionController.Request(other, "payment:read", resource)).decision());
        assertEquals("DENY", pdp.decide(identity, new DecisionController.Request(tenant, "payment:approve", resource)).decision());
        db.update("update users set state='SUSPENDED' where id=?", id);
        assertEquals("DENY", pdp.decide(identity, new DecisionController.Request(tenant, "payment:read", resource)).decision());
    }

    @Test
    void otpVerificationAndReplayStepUseOneTimestamp() {
        var fixed = java.time.Clock.fixed(java.time.Instant.ofEpochMilli(2000000009999L), java.time.ZoneOffset.UTC);
        var service = new MfaService(db, "test-only-encryption-password", "00112233445566778899aabbccddeeff", fixed);
        String id = user(), key = tx.execute(s -> service.enroll(id));
        String code = String.format("%06d", new GoogleAuthenticator().getTotpPassword(key, fixed.millis()));
        assertEquals(Boolean.TRUE, tx.execute(s -> service.verify(id, code)));
        assertEquals(fixed.millis() / 30000, db.queryForObject("select last_step from mfa_credentials where user_id=?", Long.class, id));
        assertEquals(Boolean.FALSE, tx.execute(s -> service.verify(id, code)));
    }

    @Test
    void v9UpgradeRevokesLegacyMfaAssuranceAndQueuesLogoutWithoutDeletingHistory() {
        String schema = "mfa_upgrade";
        String url = POSTGRES.getJdbcUrl() + (POSTGRES.getJdbcUrl().contains("?") ? "&" : "?") + "currentSchema=" + schema;
        var source = new DriverManagerDataSource(url, POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(source).schemas(schema).defaultSchema(schema).target("8").load().migrate();
        var legacy = new JdbcTemplate(source);
        String id = UUID.randomUUID().toString(), session = UUID.randomUUID().toString();
        legacy.update("insert into users(id,username,password_hash,state) values (?,?,?,'ACTIVE')", id, id, "test-only");
        legacy.update("insert into mfa_credentials(user_id,secret_encrypted,enabled) values (?,? ,true)", id, "test-only-no-decryption");
        legacy.update("insert into identity_sessions(id,principal_name) values (?,?)", session, id);
        var clients = new org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository(legacy);
        var client = org.springframework.security.oauth2.server.authorization.client.RegisteredClient.withId("upgrade-client").clientId("upgrade-client")
                .clientAuthenticationMethod(org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri("https://client.example/callback").build();
        clients.save(client);
        var now = java.time.Instant.now();
        var grant = org.springframework.security.oauth2.server.authorization.OAuth2Authorization.withRegisteredClient(client).principalName(id)
                .authorizationGrantType(org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE)
                .token(new org.springframework.security.oauth2.core.OAuth2RefreshToken("legacy-test-only", now, now.plusSeconds(3600))).build();
        new org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService(legacy, clients).save(grant);
        legacy.update("insert into authorization_lifecycle(id,principal_name,client_id,session_id,created_at,expires_at,grant_expires_at,revision) values (?,?,?,?,clock_timestamp(),clock_timestamp()+interval '8 hours',clock_timestamp()+interval '1 hour',1)", grant.getId(), id, client.getId(), session);
        legacy.update("insert into refresh_history(token_hash,authorization_id,client_id) values (?,?,?)", com.example.iam.server.token.TrackedAuthorizationService.digest("legacy-test-only"), grant.getId(), client.getId());
        legacy.update("insert into oidc_rp_sessions(id,session_id,registered_client_id,client_id,subject,sid,endpoint) values (?,?,?,?,?,?,?)", "participant", session, client.getId(), client.getClientId(), id, "test-sid", "https://client.example/logout");
        Flyway.configure().dataSource(source).schemas(schema).defaultSchema(schema).load().migrate();
        assertEquals(0, legacy.queryForObject("select count(*) from oauth2_authorization", Integer.class));
        assertEquals(1, legacy.queryForObject("select count(*) from refresh_history", Integer.class));
        assertEquals(1, legacy.queryForObject("select count(*) from logout_deliveries", Integer.class));
        assertNotNull(legacy.queryForObject("select revoked_at from identity_sessions where id=?", java.sql.Timestamp.class, session));
        assertEquals(1, legacy.queryForObject("select count(*) from security_audit_events where event_type='MFA_ASSURANCE_UPGRADE'", Integer.class));
    }

}
