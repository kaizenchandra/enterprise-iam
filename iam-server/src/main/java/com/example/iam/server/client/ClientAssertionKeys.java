package com.example.iam.server.client;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.*;

/**
 * Client-row locks serialize policy replacement with token issuance. No verification-key network I/O.
 */
@Service
public class ClientAssertionKeys {
    private final JdbcTemplate db;
    private final RegisteredClientRepository clients;

    public ClientAssertionKeys(JdbcTemplate db, RegisteredClientRepository clients) {
        this.db = db;
        this.clients = clients;
    }

    public static String validate(Map<String, Object> document) {
        try {
            if (document == null || !document.keySet().equals(Set.of("keys"))) throw new IllegalArgumentException();
            String encoded = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(document);
            if (encoded.length() > 16384) throw new IllegalArgumentException();
            if (!(document.get("keys") instanceof List<?> rawKeys)) throw new IllegalArgumentException();
            for (var raw : rawKeys)
                if (!(raw instanceof Map<?, ?> map) || !Set.of("kty", "kid", "n", "e", "alg", "use", "key_ops").containsAll(map.keySet()))
                    throw new IllegalArgumentException();
            var keys = JWKSet.parse(encoded).getKeys();
            if (keys.isEmpty() || keys.size() > 3 || keys.size() != rawKeys.size())
                throw new IllegalArgumentException();
            var kids = new HashSet<String>();
            for (var key : keys) {
                if (!(key instanceof RSAKey rsa) || rsa.isPrivate() || rsa.size() < 2048 || rsa.size() > 4096
                        || !JWSAlgorithm.RS256.equals(key.getAlgorithm()) || !KeyUse.SIGNATURE.equals(key.getKeyUse())
                        || key.getKeyID() == null || !key.getKeyID().matches("[A-Za-z0-9_-]{1,128}") || !kids.add(key.getKeyID())
                        || key.getKeyOperations() != null && !key.getKeyOperations().equals(Set.of(KeyOperation.VERIFY)))
                    throw new IllegalArgumentException();
                // Reject private/remote/certificate extensions, rather than silently discarding them on serialization.
                if (!Set.of("kty", "kid", "n", "e", "alg", "use", "key_ops").containsAll(key.toJSONObject().keySet()))
                    throw new IllegalArgumentException();
                var publicKey = rsa.toRSAPublicKey();
                if (!publicKey.getPublicExponent().equals(java.math.BigInteger.valueOf(65537)))
                    throw new IllegalArgumentException();
            }
            return new JWKSet(keys).toString();
        } catch (Exception invalid) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Provide one to three public RS256 RSA keys (2048..4096 bits), unique kid, use=sig and exponent 65537");
        }
    }

    @Transactional(timeout = 10)
    public Map<String, Object> replace(String clientId, long expectedRevision, Map<String, Object> document) {
        String encoded = validate(document);
        return change(clientId, expectedRevision, encoded, true);
    }

    @Transactional(timeout = 10)
    public Map<String, Object> disable(String clientId, long expectedRevision) {
        return change(clientId, expectedRevision, "{\"keys\":[]}", false);
    }

    private Map<String, Object> change(String clientId, long expectedRevision, String jwks, boolean enabled) {
        db.queryForList("select id from oauth2_registered_client where client_id=? for update", clientId);
        var client = clients.findByClientId(clientId);
        if (client == null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        var revisions = db.queryForList("select revision from client_assertion_keys where client_id=?", Long.class, client.getId());
        long revision = revisions.isEmpty() ? 0 : revisions.getFirst();
        if (expectedRevision < 0 || revision != expectedRevision)
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Client authentication revision changed");
        if (!enabled && client.getClientAuthenticationMethods().stream().noneMatch(method -> !ClientAuthenticationMethod.PRIVATE_KEY_JWT.equals(method)))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Cannot remove the client's only authentication method");
        db.update("""
                insert into client_assertion_keys(client_id,revision,enabled,jwks) values (?,?,?,?)
                on conflict(client_id) do update set revision=excluded.revision,enabled=excluded.enabled,jwks=excluded.jwks,updated_at=clock_timestamp()
                """, client.getId(), revision + 1, enabled, jwks);
        clients.save(RegisteredClient.from(client).clientAuthenticationMethods(methods -> {
            if (enabled) methods.add(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
            else methods.remove(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
        }).clientSettings(ClientSettings.withSettings(client.getClientSettings().getSettings())
                .tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.RS256).build()).build());
        db.update("insert into security_audit_events(id,event_type,subject_id) values (?,'CLIENT_ASSERTION_KEYS_CHANGED',?)", UUID.randomUUID().toString(), client.getId());
        return Map.of("clientId", clientId, "revision", revision + 1, "enabled", enabled);
    }

    public Map<String, Object> describe(String clientId) {
        var client = clients.findByClientId(clientId);
        if (client == null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        var rows = db.queryForList("select revision,enabled,jwks from client_assertion_keys where client_id=?", client.getId());
        if (rows.isEmpty()) return Map.of("clientId", clientId, "revision", 0, "enabled", false);
        var row = rows.getFirst();
        return Map.of("clientId", clientId, "revision", row.get("revision"), "enabled", row.get("enabled"), "jwks", row.get("jwks"));
    }
}
