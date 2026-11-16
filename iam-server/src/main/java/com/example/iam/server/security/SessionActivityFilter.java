package com.example.iam.server.security;

import com.example.iam.server.token.TrackedAuthorizationService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;

/**
 * Runs after context loading and CSRF validation, before authorization/protocol endpoint filters.
 */
public class SessionActivityFilter extends OncePerRequestFilter {
    private static final Set<String> NON_ACTIVITY = Set.of("/oauth2/token", "/oauth2/revoke", "/oauth2/introspect",
            "/oauth2/jwks", "/userinfo", "/connect/logout", "/logout");
    private final TrackedAuthorizationService authorizations;

    public SessionActivityFilter(TrackedAuthorizationService authorizations) {
        this.authorizations = authorizations;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.startsWith("/session/") || path.equals("/passkeys.js") || path.startsWith("/passkeys/login/") || path.startsWith("/account") || NON_ACTIVITY.contains(path) || path.startsWith("/.well-known/") || path.startsWith("/actuator/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        var session = request.getSession(false);
        if (session != null && authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken)) {
            String key = (String) session.getAttribute(TrackedAuthorizationService.SESSION);
            if (key == null || !authorizations.touchSession(key, authentication.getName())) {
                session.invalidate();
                SecurityContextHolder.clearContext();
                response.setHeader("Cache-Control", "no-store");
                if ("GET".equals(request.getMethod()) && "/login".equals(request.getRequestURI())) {
                    chain.doFilter(request, response);
                    return;
                }
                response.setStatus(401);
                return;
            }
        }
        chain.doFilter(request, response);
    }
}
