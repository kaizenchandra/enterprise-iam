package com.example.iam.server.security;

import com.example.iam.server.mfa.MfaService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class SessionAssuranceFilter extends OncePerRequestFilter {
    private final MfaService mfa;
    private final AuthUi ui;
    private final JdbcTemplate db;
    private final com.example.iam.server.token.TrackedAuthorizationService authorizations;

    public SessionAssuranceFilter(MfaService mfa, JdbcTemplate db, com.example.iam.server.token.TrackedAuthorizationService authorizations, AuthUi ui) {
        this.mfa = mfa;
        this.ui = ui;
        this.db = db;
        this.authorizations = authorizations;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest req) {
        return req.getRequestURI().startsWith("/session/") || req.getRequestURI().equals("/mfa.js") || req.getRequestURI().equals("/auth.css") || req.getRequestURI().equals("/passkeys.js") || req.getRequestURI().startsWith("/passkeys/login/") || req.getRequestURI().startsWith("/account") || java.util.Set.of("/oauth2/token", "/oauth2/revoke", "/oauth2/introspect", "/oauth2/jwks", "/userinfo", "/connect/logout", "/logout").contains(req.getRequestURI());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws IOException, ServletException {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken) && req.getSession(false) != null) {
            String id = auth.getName();
            var rows = db.queryForList("select state from users where id=?", id);
            if (!rows.isEmpty()) {
                String sessionKey = (String) req.getSession().getAttribute(com.example.iam.server.token.TrackedAuthorizationService.SESSION);
                if ((sessionKey == null || authorizations.sessionRevoked(sessionKey, id)) || !"ACTIVE".equals(rows.getFirst().get("state"))) {
                    req.getSession().invalidate();
                    SecurityContextHolder.clearContext();
                    res.sendError(401);
                    return;
                }
                if ((mfa.enabled(id) || mfa.required()) && !authorizations.sessionAssured(sessionKey, id) && !java.util.Set.of("/login", "/mfa", "/mfa/verify", "/mfa/recover", "/mfa/settings", "/mfa/enroll", "/logout").contains(req.getRequestURI())
                        && !java.util.Set.of("/oauth2/token", "/oauth2/revoke", "/oauth2/introspect", "/oauth2/jwks", "/userinfo", "/connect/logout").contains(req.getRequestURI())) {
                    if ("GET".equals(req.getMethod()) && "/oauth2/authorize".equals(req.getRequestURI()))
                        new org.springframework.security.web.savedrequest.HttpSessionRequestCache().saveRequest(req, res);
                    String target = ui.page(mfa.enabled(id) ? "/mfa" : "/mfa/settings");
                    if ("/oauth2/authorize".equals(req.getRequestURI())) res.sendRedirect(target);
                    else {
                        res.setStatus(401);
                        res.setContentType("application/json");
                        res.getWriter().write("{\"detail\":\"Verify your identity to continue.\",\"redirect\":\"" + target + "\"}");
                    }
                    return;
                }
            }
        }
        chain.doFilter(req, res);
    }
}
