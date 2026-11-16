package com.example.iam.server.backchannel;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/admin/clients")
public class BackChannelClientAdmin {
    private final RegisteredClientRepository clients;
    private final BackChannelPolicy policy;
    private final org.springframework.jdbc.core.JdbcTemplate db;

    public BackChannelClientAdmin(RegisteredClientRepository clients, BackChannelPolicy policy, org.springframework.jdbc.core.JdbcTemplate db) {
        this.clients = clients;
        this.policy = policy;
        this.db = db;
    }

    @PostMapping("/{clientId}/backchannel")
    @org.springframework.transaction.annotation.Transactional(timeout = 10)
    public Map<String, Object> configure(@PathVariable String clientId, @Valid @RequestBody Registration request) {
        try {
            policy.validate(request.backchannelLogoutUri());
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Endpoint origin is not approved");
        }
        db.queryForList("select id from oauth2_registered_client where client_id=? for update", clientId);
        var client = clients.findByClientId(clientId);
        if (client == null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        clients.save(RegisteredClient.from(client).clientSettings(ClientSettings.withSettings(client.getClientSettings().getSettings())
                .setting(BackChannelSessions.URI_SETTING, request.backchannelLogoutUri()).setting("backchannel_logout_session_required", true).build()).build());
        return Map.of("backchannel_logout_uri", request.backchannelLogoutUri(), "backchannel_logout_session_required", true);
    }

    public record Registration(@NotBlank @Size(max = 2048) String backchannelLogoutUri) {
    }
}
