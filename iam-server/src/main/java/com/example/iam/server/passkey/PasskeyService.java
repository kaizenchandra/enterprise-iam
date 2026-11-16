package com.example.iam.server.passkey;

import com.example.iam.server.token.TrackedAuthorizationService;
import com.yubico.webauthn.*;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

@Service
public class PasskeyService {
    private final JdbcTemplate db;
    private final PasskeySettings settings;
    private final PasswordEncoder passwords;
    private final TrackedAuthorizationService grants;

    public PasskeyService(JdbcTemplate db, PasskeySettings settings, PasswordEncoder passwords, TrackedAuthorizationService grants) {
        this.db = new JdbcTemplate(Objects.requireNonNull(db.getDataSource()));
        this.db.setQueryTimeout(5);
        this.settings = settings;
        this.passwords = passwords;
        this.grants = grants;
    }

    public boolean attestationRequired() {
        return settings.attestation.required;
    }

    public void enabled() {
        if (!settings.enabled) throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE);
    }

    private void active(String user, String session) {
        grants.lockPrincipal(user);
        if (session == null || !grants.sessionAssured(session, user) || !"ACTIVE".equals(db.queryForObject("select state from users where id=?", String.class, user)))
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
    }

    private boolean password(String user, String password) {
        if (Boolean.TRUE.equals(db.queryForObject("select passkey_reauth_locked_until>clock_timestamp() from users where id=?", Boolean.class, user)))
            return false;
        boolean valid = false;
        try {
            valid = password != null && password.length() <= 1024 && passwords.matches(password, db.queryForObject("select password_hash from users where id=?", String.class, user));
        } catch (IllegalArgumentException ignored) {
        }
        if (valid)
            db.update("update users set passkey_reauth_failures=0,passkey_reauth_locked_until=null where id=?", user);
        else {
            db.update("update users set passkey_reauth_failures=case when passkey_reauth_locked_until<=clock_timestamp() then 1 else passkey_reauth_failures+1 end,passkey_reauth_locked_until=case when passkey_reauth_locked_until<=clock_timestamp() then null when passkey_reauth_failures>=4 then clock_timestamp()+interval '5 minutes' else null end where id=?", user);
            audit(user, "PASSKEY_REAUTH_FAILED");
        }
        return valid;
    }

    private Started store(String binding, String kind, String user, Long version, String opSession, String options, String browserOptions) {
        db.queryForList("select pg_advisory_xact_lock(hashtextextended('passkey-challenges',0))");
        db.update("update passkey_challenges set consumed_at=clock_timestamp() where binding=? and kind=? and consumed_at is null", binding, kind);
        if (db.queryForObject("select count(*) from passkey_challenges where consumed_at is null and expires_at>clock_timestamp()", Integer.class) >= 10000)
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE);
        UUID id = UUID.randomUUID();
        db.update("insert into passkey_challenges(id,binding,kind,user_id,user_version,op_session,options,configuration) values (?,?,?,?,?,?,?,?)", id, binding, kind, user, version, opSession, options, settings.fingerprint);
        return new Started(id, browserOptions);
    }

    @Transactional(timeout = 10)
    public Started registerStart(String user, String session, String binding, String password) {
        enabled();
        settings.attestation.guard();
        active(user, session);
        if (!password(user, password)) return null;
        if (db.queryForObject("select count(*) from passkey_credentials where user_id=?", Integer.class, user) >= 10)
            throw new ResponseStatusException(HttpStatus.CONFLICT);
        try {
            var options = settings.relyingParty.startRegistration(StartRegistrationOptions.builder()
                    .user(UserIdentity.builder().name(user).displayName(db.queryForObject("select username from users where id=?", String.class, user)).id(PasskeyRepository.handle(user)).build())
                    .authenticatorSelection(AuthenticatorSelectionCriteria.builder().residentKey(ResidentKeyRequirement.REQUIRED).userVerification(UserVerificationRequirement.REQUIRED).build()).timeout(120000).build());
            return store(binding, "REGISTER", user, db.queryForObject("select version from users where id=?", Long.class, user), session, options.toJson(), options.toCredentialsCreateJson());
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("Passkey options unavailable");
        }
    }

    @Transactional(timeout = 5)
    public Started authenticateStart(String binding) {
        enabled();
        settings.attestation.guard();
        try {
            var options = settings.relyingParty.startAssertion(StartAssertionOptions.builder().userVerification(UserVerificationRequirement.REQUIRED).timeout(120000).build());
            return store(binding, "AUTH", null, null, null, options.toJson(), options.toCredentialsGetJson());
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("Passkey options unavailable");
        }
    }

    private Map<String, Object> claim(UUID id, String binding, String kind) {
        var rows = db.queryForList("select * from passkey_challenges where id=? and binding=? and kind=? and configuration=? and consumed_at is null and expires_at>clock_timestamp() for update", id, binding, kind, settings.fingerprint);
        if (rows.isEmpty()) return null;
        db.update("update passkey_challenges set consumed_at=clock_timestamp() where id=?", id);
        return rows.getFirst();
    }

    @Transactional(timeout = 10)
    public boolean registerFinish(String user, String binding, UUID id, String response) {
        enabled();
        settings.attestation.guard();
        grants.lockPrincipal(user);
        var challenge = claim(id, binding, "REGISTER");
        if (challenge == null || !user.equals(challenge.get("user_id"))) return false;
        String session = (String) challenge.get("op_session");
        if (!grants.sessionAssured(session, user) || !Boolean.TRUE.equals(db.queryForObject("select state='ACTIVE' and version=? and ? > sessions_not_before from users where id=?", Boolean.class, challenge.get("user_version"), challenge.get("created_at"), user)))
            return false;
        try {
            var result = settings.relyingParty.finishRegistration(FinishRegistrationOptions.builder().request(PublicKeyCredentialCreationOptions.fromJson(challenge.get("options").toString())).response(PublicKeyCredential.parseRegistrationResponseJson(response)).build());
            if (!result.isUserVerified() || result.getKeyId().getId().getBytes().length > 1024) return false;
            UUID model = null;
            String chain = null;
            if (settings.attestation.required) {
                model = AttestationPolicy.uuid(result.getAaguid());
                try {
                    chain = AttestationBundle.encode(result.getAttestationTrustPath().orElseThrow());
                } catch (Exception invalid) {
                    return false;
                }
                if (!result.isAttestationTrusted() || result.isBackupEligible() || !settings.attestation.eligible(model, chain))
                    return false;
            }
            int saved = db.update("insert into passkey_credentials(id,user_id,credential_id,public_key_cose,signature_count,backup_eligible,backed_up,attestation_aaguid,attestation_chain) values (?,?,?,?,?,?,?,?,?) on conflict(credential_id) do nothing", UUID.randomUUID(), user, result.getKeyId().getId().getBase64Url(), result.getPublicKeyCose().getBase64Url(), result.getSignatureCount(), result.isBackupEligible(), result.isBackedUp(), model, chain);
            if (saved != 1) return false;
            changed(user, "PASSKEY_ENROLLED");
            return true;
        } catch (RegistrationFailedException | java.io.IOException | IllegalArgumentException e) {
            return false;
        } catch (RuntimeException e) {
            // Yubico wraps JCA SignatureException for malformed RSA signature lengths.
            // Reject this input and commit the challenge claim; never swallow store failures.
            if (e.getCause() instanceof java.security.SignatureException) return false;
            throw e;
        }
    }

    @Transactional(timeout = 10)
    public Authenticated authenticateFinish(String binding, UUID id, String response, String newSession) {
        enabled();
        settings.attestation.guard();
        com.yubico.webauthn.data.PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential;
        try {
            credential = PublicKeyCredential.parseAssertionResponseJson(response);
        } catch (java.io.IOException | IllegalArgumentException e) {
            claim(id, binding, "AUTH");
            return null;
        }
        var owners = db.queryForList("select user_id from passkey_credentials where credential_id=?", credential.getId().getBase64Url());
        if (owners.isEmpty()) {
            claim(id, binding, "AUTH");
            return null;
        }
        String user = owners.getFirst().get("user_id").toString();
        grants.lockPrincipal(user);
        var challenge = claim(id, binding, "AUTH");
        if (challenge == null) return null;
        var records = db.queryForList("select attestation_aaguid,attestation_chain,attestation_revoked_at,backup_eligible from passkey_credentials where credential_id=? and user_id=?", credential.getId().getBase64Url(), user);
        if (records.isEmpty()) return null;
        var record = records.getFirst();
        if (record.get("attestation_revoked_at") != null || !settings.attestation.eligible((UUID) record.get("attestation_aaguid"), (String) record.get("attestation_chain")))
            return null;
        if (!Boolean.TRUE.equals(db.queryForObject("select state='ACTIVE' and ? > sessions_not_before from users where id=?", Boolean.class, challenge.get("created_at"), user)))
            return null;
        try {
            var result = settings.relyingParty.finishAssertion(FinishAssertionOptions.builder().request(AssertionRequest.fromJson(challenge.get("options").toString())).response(credential).build());
            if (!result.isSuccess() || !result.isUserVerified() || !user.equals(result.getUsername())) return null;
            if (!settings.attestation.eligible((UUID) record.get("attestation_aaguid"), (String) record.get("attestation_chain")))
                return null;
            if (db.update("update passkey_credentials set signature_count=?,backed_up=?,last_used_at=clock_timestamp() where credential_id=? and user_id=?", result.getSignatureCount(), result.isBackedUp(), result.getCredentialId().getBase64Url(), user) != 1)
                return null;
            Instant birth = ((Timestamp) challenge.get("created_at")).toInstant();
            grants.registerSession(newSession, user, birth);
            audit(user, "PASSKEY_AUTHENTICATED");
            return new Authenticated(user, birth);
        } catch (AssertionFailedException | java.io.IOException | IllegalArgumentException e) {
            return null;
        } catch (RuntimeException e) {
            if (e.getCause() instanceof java.security.SignatureException) return null;
            throw e;
        }
    }

    @Transactional(timeout = 10)
    public boolean remove(String user, String session, UUID id, String password) {
        enabled();
        active(user, session);
        if (db.queryForObject("select count(*) from passkey_credentials where id=? and user_id=?", Integer.class, id, user) == 0)
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        if (!password(user, password)) return false;
        db.update("delete from passkey_credentials where id=? and user_id=?", id, user);
        changed(user, "PASSKEY_REMOVED");
        return true;
    }

    private void changed(String user, String event) {
        db.update("update users set version=version+1 where id=?", user);
        grants.revokeUser(user);
        audit(user, event);
    }

    private void audit(String user, String event) {
        db.update("insert into security_audit_events(id,event_type,subject_id,actor_id) values (?,?,?,?)", UUID.randomUUID().toString(), event, user, user);
    }

    @Scheduled(fixedDelayString = "${iam.passkey.cleanup-delay-ms:60000}")
    @Transactional(timeout = 5)
    public void cleanup() {
        db.update("delete from passkey_challenges where id in (select id from passkey_challenges where expires_at<clock_timestamp()-interval '1 day' order by expires_at limit 100)");
    }

    public List<Map<String, Object>> list(String user) {
        enabled();
        return db.queryForList("select id,created_at,last_used_at,backup_eligible,backed_up,(attestation_aaguid is not null) as hardware_attested,attestation_revoked_at from passkey_credentials where user_id=? order by created_at limit 10", user);
    }

    public record Started(UUID id, String options) {
    }

    public record Authenticated(String user, Instant birth) {
    }
}
