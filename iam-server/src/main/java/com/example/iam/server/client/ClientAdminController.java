package com.example.iam.server.client;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/admin/clients")
public class ClientAdminController {
    private final RegisteredClientRepository clients;
    private final PasswordEncoder encoder;
    private final JdbcTemplate db;
    private final ClientAssertionKeys keys;

    public ClientAdminController(RegisteredClientRepository clients, PasswordEncoder encoder, JdbcTemplate db, ClientAssertionKeys keys) {
        this.clients = clients;
        this.encoder = encoder;
        this.db = db;
        this.keys = keys;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @org.springframework.transaction.annotation.Transactional(timeout = 10)
    public Map<String, String> create(@Valid @RequestBody Registration request) {
        if ("private_key_jwt".equals(request.clientAuthenticationMethod())) {
            ClientAssertionKeys.validate(request.jwks());
            clients.save(RegisteredClient.withId(UUID.randomUUID().toString()).clientId(request.clientId()).clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).scopes(s -> s.addAll(request.scopes())).tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(5)).build()).build());
            keys.replace(request.clientId(), 0, request.jwks());
            return Map.of("clientId", request.clientId());
        }
        if (request.jwks() != null)
            throw new org.springframework.web.server.ResponseStatusException(HttpStatus.BAD_REQUEST, "Use private_key_jwt registration or the authentication-keys endpoint");
        String secret = UUID.randomUUID().toString() + UUID.randomUUID();
        clients.save(RegisteredClient.withId(UUID.randomUUID().toString()).clientId(request.clientId()).clientSecret(encoder.encode(secret)).clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).scopes(s -> s.addAll(request.scopes())).tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(5)).build()).build());
        return Map.of("clientId", request.clientId(), "clientSecret", secret);
    }

    @GetMapping
    public List<Map<String, Object>> list() {
        return db.queryForList("select client_id,client_name,scopes from oauth2_registered_client order by client_id limit 100");
    }

    @PostMapping("/{clientId}/rotate-credentials")
    @org.springframework.transaction.annotation.Transactional(timeout = 10)
    public Map<String, String> rotate(@PathVariable String clientId) {
        db.queryForList("select id from oauth2_registered_client where client_id=? for update", clientId);
        var old = clients.findByClientId(clientId);
        if (old == null) throw new org.springframework.web.server.ResponseStatusException(HttpStatus.NOT_FOUND);
        if (!old.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.CLIENT_SECRET_BASIC))
            throw new org.springframework.web.server.ResponseStatusException(HttpStatus.BAD_REQUEST, "Client does not use a secret");
        String secret = UUID.randomUUID().toString() + UUID.randomUUID();
        clients.save(RegisteredClient.from(old).clientSecret(encoder.encode(secret)).build());
        return Map.of("clientSecret", secret);
    }

    public record Registration(@NotBlank @Pattern(regexp = "[a-zA-Z0-9_-]{3,64}") String clientId,
                               @NotEmpty Set<@Pattern(regexp = "orders.read|decision.write") String> scopes,
                               @Pattern(regexp = "client_secret_basic|private_key_jwt") String clientAuthenticationMethod,
                               Map<String, Object> jwks) {
    }
}
