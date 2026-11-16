package com.example.iam.web.logout;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class ClientSessionGuard extends OncePerRequestFilter {
    private final JdbcOidcSessions sessions;

    public ClientSessionGuard(JdbcOidcSessions sessions) {
        this.sessions = sessions;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (SecurityContextHolder.getContext().getAuthentication() instanceof OAuth2AuthenticationToken) {
            var session = request.getSession(false);
            try {
                if (session == null || !sessions.valid(session.getId())) {
                    if (session != null) session.invalidate();
                    SecurityContextHolder.clearContext();
                    response.sendError(401);
                    return;
                }
            } catch (org.springframework.dao.DataAccessException e) {
                response.sendError(503);
                return;
            }
        }
        chain.doFilter(request, response);
    }
}
