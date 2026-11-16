package com.example.iam.server.passkey;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@Repository
public class PasskeyRepository implements CredentialRepository {
    private final JdbcTemplate db;

    public PasskeyRepository(JdbcTemplate db) {
        this.db = db;
    }

    public static ByteArray handle(String user) {
        return new ByteArray(user.getBytes(StandardCharsets.UTF_8));
    }

    private static ByteArray bytes(String value) {
        try {
            return ByteArray.fromBase64Url(value);
        } catch (Exception e) {
            throw new IllegalStateException("Invalid persisted credential");
        }
    }

    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String user) {
        var result = new HashSet<PublicKeyCredentialDescriptor>();
        for (var id : db.queryForList("select credential_id from passkey_credentials where user_id=?", String.class, user))
            result.add(PublicKeyCredentialDescriptor.builder().id(bytes(id)).build());
        return result;
    }

    public Optional<ByteArray> getUserHandleForUsername(String user) {
        return db.queryForList("select id from users where id=?", String.class, user).stream().findFirst().map(PasskeyRepository::handle);
    }

    public Optional<String> getUsernameForUserHandle(ByteArray handle) {
        String id = new String(handle.getBytes(), StandardCharsets.UTF_8);
        if (!id.matches("[a-f0-9-]{36}")) return Optional.empty();
        return db.queryForList("select id from users where id=?", String.class, id).stream().findFirst();
    }

    private RegisteredCredential map(Map<String, Object> row) {
        return RegisteredCredential.builder().credentialId(bytes(row.get("credential_id").toString()))
                .userHandle(handle(row.get("user_id").toString())).publicKeyCose(bytes(row.get("public_key_cose").toString()))
                .signatureCount(((Number) row.get("signature_count")).longValue()).backupEligible((Boolean) row.get("backup_eligible")).backupState((Boolean) row.get("backed_up")).build();
    }

    public Optional<RegisteredCredential> lookup(ByteArray id, ByteArray handle) {
        return db.queryForList("select * from passkey_credentials where credential_id=? and user_id=?", id.getBase64Url(), new String(handle.getBytes(), StandardCharsets.UTF_8)).stream().findFirst().map(this::map);
    }

    public Set<RegisteredCredential> lookupAll(ByteArray id) {
        var result = new HashSet<RegisteredCredential>();
        for (var row : db.queryForList("select * from passkey_credentials where credential_id=?", id.getBase64Url()))
            result.add(map(row));
        return result;
    }
}
