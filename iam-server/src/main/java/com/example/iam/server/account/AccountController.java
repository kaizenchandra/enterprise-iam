package com.example.iam.server.account;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

@RestController
@RequestMapping("/account")
public class AccountController {
    private final AccountActions actions;
    private final RegistrationService registration;

    public AccountController(AccountActions actions, RegistrationService registration) {
        this.actions = actions;
        this.registration = registration;
    }

    @GetMapping("/register")
    public Map<String, Object> registerInfo() {
        if (!registration.enabled()) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        return Map.of("registrationEnabled", true, "signInUrl", registration.signInUrl());
    }

    @PostMapping("/register")
    public Map<String, Object> register(@Valid @RequestBody Registration input) {
        registration.register(input.username(), input.email(), input.password(), input.confirmation());
        return Map.of("accepted", true, "detail", "If these details are eligible, a verification link will be sent.");
    }

    @GetMapping({"/verify", "/reset"})
    public Map<String, Object> info() {
        return Map.of("signInUrl", registration.signInUrl());
    }

    @PostMapping({"/verify/request", "/reset/request"})
    public Map<String, Object> request(jakarta.servlet.http.HttpServletRequest request, @Valid @RequestBody Email input) {
        actions.request(input.email(), request.getRequestURI().contains("/verify/") ? "VERIFY" : "RESET");
        return Map.of("accepted", true, "detail", "If the address is eligible, a link will be sent.");
    }

    @PostMapping("/verify")
    public Map<String, Object> verify(@Valid @RequestBody Token input) {
        if (!actions.consume(input.token(), "VERIFY", null)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        return Map.of("completed", true, "redirect", registration.signInUrl());
    }

    @PostMapping("/reset")
    public Map<String, Object> reset(@Valid @RequestBody Reset input) {
        if (!input.password().equals(input.confirmation())) throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        if (!actions.consume(input.token(), "RESET", input.password()))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        return Map.of("completed", true, "redirect", registration.signInUrl());
    }

    public record Registration(@NotBlank @Size(max = 128) String username,
                               @NotBlank @jakarta.validation.constraints.Email @Size(max = 254) String email,
                               @NotNull @Size(max = 256) String password,
                               @NotNull @Size(max = 256) String confirmation) {
    }

    public record Email(@NotBlank @jakarta.validation.constraints.Email @Size(max = 254) String email) {
    }

    public record Token(@NotBlank @Size(max = 64) String token) {
    }

    public record Reset(@NotBlank @Size(max = 64) String token, @NotNull @Size(max = 256) String password,
                        @NotNull @Size(max = 256) String confirmation) {
    }
}
