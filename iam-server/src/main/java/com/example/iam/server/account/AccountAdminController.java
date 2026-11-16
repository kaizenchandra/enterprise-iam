package com.example.iam.server.account;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
public class AccountAdminController {
    private final AccountActions actions;

    public AccountAdminController(AccountActions actions) {
        this.actions = actions;
    }

    @PostMapping("/api/v1/admin/users/{id}/email")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void email(@PathVariable UUID id, @Valid @RequestBody Email email, JwtAuthenticationToken actor) {
        actions.bindEmail(id.toString(), email.email(), actor);
    }

    public record Email(@NotBlank @jakarta.validation.constraints.Email @Size(max = 254) String email) {
    }
}
