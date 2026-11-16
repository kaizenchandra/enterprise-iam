package com.example.iam.server.passkey;

import com.example.iam.server.token.TrackedAuthorizationService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;
import java.util.UUID;

@RestController
public class PasskeyController {
    private final PasskeyService service;
    private final ObjectMapper json;
    private final com.example.iam.server.security.BrowserLoginSuccess loginSuccess;

    public PasskeyController(PasskeyService service, ObjectMapper json, com.example.iam.server.security.BrowserLoginSuccess loginSuccess) {
        this.service = service;
        this.json = json;
        this.loginSuccess = loginSuccess;
    }

    private String binding(HttpServletRequest req) {
        return TrackedAuthorizationService.digest(req.getSession().getId());
    }

    private String session(HttpServletRequest req) {
        return (String) req.getSession().getAttribute(TrackedAuthorizationService.SESSION);
    }

    private Object options(PasskeyService.Started started) throws java.io.IOException {
        if (started == null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Reauthentication failed");
        return Map.of("id", started.id(), "options", json.readTree(started.options()));
    }

    @GetMapping("/passkeys")
    public Object list(Authentication actor, HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        return Map.of("credentials", service.list(actor.getName()), "attestationRequired", service.attestationRequired());
    }

    @PostMapping("/passkeys/register/options")
    public Object register(Authentication actor, @jakarta.validation.Valid @RequestBody Password proof, HttpServletRequest req) throws java.io.IOException {
        return options(service.registerStart(actor.getName(), session(req), binding(req), proof.password()));
    }

    private Response response(HttpServletRequest req) throws java.io.IOException {
        byte[] body = req.getInputStream().readNBytes(65537);
        if (body.length > 65536) throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE);
        try {
            var node = json.readTree(body);
            return new Response(UUID.fromString(node.path("id").asText()), json.writeValueAsString(node.path("credential")));
        } catch (RuntimeException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid passkey request");
        }
    }

    @PostMapping(value = "/passkeys/register/finish", consumes = "application/json")
    public Object registerFinish(Authentication actor, HttpServletRequest req) throws java.io.IOException {
        var response = response(req);
        if (!service.registerFinish(actor.getName(), binding(req), response.id(), response.credential()))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Passkey ceremony rejected");
        end(req);
        return Map.of("redirect", "/login");
    }

    @PostMapping("/passkeys/login/options")
    public Object login(HttpServletRequest req) throws java.io.IOException {
        return options(service.authenticateStart(binding(req)));
    }

    @PostMapping(value = "/passkeys/login/finish", consumes = "application/json")
    public Object loginFinish(HttpServletRequest req, HttpServletResponse res) throws java.io.IOException {
        var response = response(req);
        String binding = binding(req);
        req.changeSessionId();
        String key = TrackedAuthorizationService.digest(req.getSession().getId()).substring(0, 32);
        var authenticated = service.authenticateFinish(binding, response.id(), response.credential(), key);
        if (authenticated == null)
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Passkey ceremony rejected");
        var user = User.withUsername(authenticated.user()).password("").authorities("USER").build();
        var context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(UsernamePasswordAuthenticationToken.authenticated(user, null, user.getAuthorities()));
        req.getSession().removeAttribute("mfa_subject");
        req.getSession().removeAttribute("mfa_attempts");
        req.getSession().removeAttribute("recovery_codes");
        new org.springframework.security.web.csrf.CsrfAuthenticationStrategy(new org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository()).onAuthentication(context.getAuthentication(), req, res);
        req.getSession().setAttribute(TrackedAuthorizationService.SESSION, key);
        SecurityContextHolder.setContext(context);
        new HttpSessionSecurityContextRepository().saveContext(context, req, res);
        return Map.of("redirect", loginSuccess.destination(req, res, context.getAuthentication()));
    }

    @PostMapping("/passkeys/{id}/remove")
    public Object remove(Authentication actor, @PathVariable UUID id, @jakarta.validation.Valid @RequestBody Password proof, HttpServletRequest req) {
        if (!service.remove(actor.getName(), session(req), id, proof.password()))
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Reauthentication failed");
        end(req);
        return Map.of("requiresSignIn", true);
    }

    private void end(HttpServletRequest req) {
        var session = req.getSession(false);
        if (session != null) try {
            session.invalidate();
        } catch (IllegalStateException ignored) {
        }
        SecurityContextHolder.clearContext();
    }

    public record Password(
            @jakarta.validation.constraints.NotNull @jakarta.validation.constraints.Size(max = 256) String password) {
    }

    private record Response(UUID id, String credential) {
    }
}
