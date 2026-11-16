package com.example.iam.server.security;

import com.example.iam.server.account.RegistrationService;
import com.example.iam.server.mfa.MfaService;
import com.example.iam.server.passkey.PasskeySettings;
import com.example.iam.server.session.SessionRevocationHandler;
import com.example.iam.server.token.ProtocolTransactionFilter;
import com.example.iam.server.token.TrackedAuthorizationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.csrf.CsrfAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/session")
public class SessionController {
    private final AuthenticationManager manager;
    private final TrackedAuthorizationService grants;
    private final RegistrationService registration;
    private final PasskeySettings passkeys;
    private final BrowserLoginSuccess success;
    private final SessionRevocationHandler revocation;
    private final AuthUi ui;
    private final MfaService mfa;

    public SessionController(AuthenticationManager manager, TrackedAuthorizationService grants, RegistrationService registration,
                             PasskeySettings passkeys, BrowserLoginSuccess success, SessionRevocationHandler revocation, AuthUi ui, MfaService mfa) {
        this.manager = manager;
        this.grants = grants;
        this.registration = registration;
        this.passkeys = passkeys;
        this.success = success;
        this.revocation = revocation;
        this.ui = ui;
        this.mfa = mfa;
    }

    @GetMapping("/bootstrap")
    public Map<String, Object> bootstrap(CsrfToken csrf, HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        return Map.of("csrfToken", csrf.getToken(), "csrfHeader", csrf.getHeaderName(),
                "registrationEnabled", registration.enabled(), "passkeysEnabled", passkeys.enabled,
                "signInUrl", registration.signInUrl());
    }

    @PostMapping("/login")
    public Map<String, Object> login(@Valid @RequestBody Credentials input, HttpServletRequest request, HttpServletResponse response) {
        var auth = manager.authenticate(UsernamePasswordAuthenticationToken.unauthenticated(input.username(), input.password()));
        request.getSession();
        new ChangeSessionIdAuthenticationStrategy().onAuthentication(auth, request, response);
        new CsrfAuthenticationStrategy(new HttpSessionCsrfTokenRepository()).onAuthentication(auth, request, response);
        var session = request.getSession();
        String id = TrackedAuthorizationService.digest(session.getId()).substring(0, 32);
        grants.registerSession(id, auth.getName(), (java.time.Instant) request.getAttribute(ProtocolTransactionFilter.REQUEST_BIRTH));
        session.setAttribute(TrackedAuthorizationService.SESSION, id);
        session.removeAttribute("mfa_attempts");
        var context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(auth);
        SecurityContextHolder.setContext(context);
        new HttpSessionSecurityContextRepository().saveContext(context, request, response);
        response.setHeader("Cache-Control", "no-store");
        if ((mfa.enabled(auth.getName()) || mfa.required()) && !grants.sessionAssured(id, auth.getName()))
            return Map.of("redirect", ui.page(mfa.enabled(auth.getName()) ? "/mfa" : "/mfa/settings"));
        return Map.of("redirect", success.destination(request, response, auth));
    }

    @PostMapping("/logout")
    public Map<String, Object> logout(HttpServletRequest request, HttpServletResponse response) {
        revocation.logout(request, response, SecurityContextHolder.getContext().getAuthentication());
        var session = request.getSession(false);
        if (session != null) session.invalidate();
        SecurityContextHolder.clearContext();
        return Map.of("redirect", registration.signInUrl());
    }

    public record Credentials(@NotBlank @Size(max = 128) String username,
                              @NotNull @Size(min = 1, max = 256) String password) {
    }
}
