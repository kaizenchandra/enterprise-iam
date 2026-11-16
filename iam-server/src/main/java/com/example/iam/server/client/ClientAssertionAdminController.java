package com.example.iam.server.client;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/admin/clients/{clientId}/authentication-keys")
public class ClientAssertionAdminController {
    private final ClientAssertionKeys keys;

    public ClientAssertionAdminController(ClientAssertionKeys keys) {
        this.keys = keys;
    }

    @GetMapping
    public Map<String, Object> get(@PathVariable String clientId) {
        return keys.describe(clientId);
    }

    @PutMapping
    public Map<String, Object> replace(@PathVariable String clientId, @Valid @RequestBody Replacement request) {
        return keys.replace(clientId, request.expectedRevision(), request.jwks());
    }

    @DeleteMapping
    public Map<String, Object> disable(@PathVariable String clientId, @RequestParam @Min(0) long expectedRevision) {
        return keys.disable(clientId, expectedRevision);
    }

    public record Replacement(@NotNull @Min(0) Long expectedRevision, @NotNull Map<String, Object> jwks) {
    }
}
