package com.example.iam.server.token;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

/**
 * Runs inside ProtocolTransactionFilter, after client authentication.
 */
@Component
public class RefreshGuard extends OncePerRequestFilter {
    private final JdbcTemplate db;
    private final TrackedAuthorizationService service;

    public RefreshGuard(JdbcTemplate db, TrackedAuthorizationService service) {
        this.db = db;
        this.service = service;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().equals("/oauth2/token")
                || !"refresh_token".equals(request.getParameter("grant_type"));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication instanceof OAuth2ClientAuthenticationToken client)
                || !client.isAuthenticated() || request.getParameter("refresh_token") == null) {
            chain.doFilter(request, response);
            return;
        }
        var rows = db.queryForList("""
                select h.authorization_id,h.client_id,a.principal_name
                from refresh_history h join authorization_lifecycle a on a.id=h.authorization_id
                where h.token_hash=?
                """, TrackedAuthorizationService.digest(request.getParameter("refresh_token")));
        if (!rows.isEmpty() && client.getRegisteredClient().getId().equals(rows.getFirst().get("client_id"))) {
            String principal = rows.getFirst().get("principal_name").toString();
            service.lockPrincipal(principal);
            var current = service.findById(rows.getFirst().get("authorization_id").toString());
            if (current != null && (current.getRefreshToken() == null
                    || !current.getRefreshToken().getToken().getTokenValue().equals(request.getParameter("refresh_token")))) {
                service.remove(current);
                db.update("insert into security_audit_events(id,event_type,subject_id) values (?, 'REFRESH_REPLAY',?)",
                        UUID.randomUUID().toString(), principal);
                response.setStatus(400);
                response.setContentType("application/json");
                response.setHeader("Cache-Control", "no-store");
                response.getWriter().write("{\"error\":\"invalid_grant\"}");
                return;
            }
        }
        chain.doFilter(request, response);
    }
}
