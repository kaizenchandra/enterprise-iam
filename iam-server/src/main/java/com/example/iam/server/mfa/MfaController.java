package com.example.iam.server.mfa;

import com.example.iam.server.security.BrowserLoginSuccess;
import com.example.iam.server.token.TrackedAuthorizationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.security.Principal;
import java.util.Map;

@RestController
public class MfaController {
    private final MfaSessionService sessions;
    private final BrowserLoginSuccess success;
    @org.springframework.beans.factory.annotation.Value("${iam.mfa.removal-allowed:true}")
    private boolean removalAllowed;

    public MfaController(MfaSessionService sessions, BrowserLoginSuccess success) {
        this.sessions = sessions;
        this.success = success;
    }

    private String session(HttpServletRequest req) {
        return (String) req.getSession().getAttribute(TrackedAuthorizationService.SESSION);
    }

    @GetMapping({"/mfa", "/mfa/settings"})
    public Map<String, Object> settings(Principal principal, HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        return Map.of("enabled", sessions.enabled(principal.getName()), "required", sessions.required(), "removalAllowed", removalAllowed && !sessions.required());
    }

    private void attempt(HttpServletRequest req) {
        Integer n = (Integer) req.getSession().getAttribute("mfa_attempts");
        n = n == null ? 1 : n + 1;
        req.getSession().setAttribute("mfa_attempts", n);
        if (n > 5) {
            req.getSession().invalidate();
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS);
        }
    }

    @PostMapping({"/mfa/verify", "/mfa/recover"})
    public Map<String, Object> verify(Principal principal, @Valid @RequestBody Code proof, HttpServletRequest req, HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        attempt(req);
        var result = sessions.verify(principal.getName(), session(req), proof.code(), req.getRequestURI().equals("/mfa/recover"));
        if (!result.accepted()) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        if (result.enrolled()) {
            req.getSession().invalidate();
            SecurityContextHolder.clearContext();
            return Map.of("recoveryCodes", result.recoveryCodes(), "requiresSignIn", true);
        }
        req.changeSessionId();
        return Map.of("redirect", success.destination(req, response, SecurityContextHolder.getContext().getAuthentication()));
    }

    @PostMapping("/mfa/enroll")
    public Map<String, Object> enroll(Principal principal, @Valid @RequestBody Password proof, HttpServletRequest req, HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        attempt(req);
        return Map.of("secret", sessions.enroll(principal.getName(), session(req), proof.password()), "algorithm", "SHA1", "digits", 6, "period", 30, "expiresIn", 600);
    }

    @PostMapping({"/mfa/remove", "/mfa/recovery-codes"})
    public Map<String, Object> manage(Principal principal, @Valid @RequestBody Management proof, HttpServletRequest req, HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        attempt(req);
        boolean remove = req.getRequestURI().equals("/mfa/remove");
        if (remove && (!removalAllowed || sessions.required())) throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        var codes = sessions.manage(principal.getName(), session(req), proof.password(), proof.code(), proof.recovery(), remove);
        if (codes == null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        req.getSession().invalidate();
        SecurityContextHolder.clearContext();
        return Map.of("recoveryCodes", codes, "requiresSignIn", true, "removed", remove);
    }

    public record Code(@NotBlank @Size(max = 64) String code) {
    }

    public record Password(@NotNull @Size(max = 256) String password) {
    }

    public record Management(@NotNull @Size(max = 256) String password, @NotBlank @Size(max = 64) String code,
                             boolean recovery) {
    }
}
