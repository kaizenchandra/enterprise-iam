package com.example.iam.server.session;

import com.example.iam.server.token.TrackedAuthorizationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcLogoutAuthenticationToken;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

/**
 * Invoked only after CSRF-protected local logout or successful framework OIDC validation.
 */
@Component
public class SessionRevocationHandler implements LogoutHandler {
    private final TrackedAuthorizationService authorizations;

    public SessionRevocationHandler(TrackedAuthorizationService authorizations) {
        this.authorizations = authorizations;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        if (authentication instanceof OidcLogoutAuthenticationToken oidc) {
            // The framework has validated the hint, client and post-logout redirect before this hook.
            if (oidc.getIdTokenHint() != null) {
                var authorization = authorizations.findByToken(oidc.getIdTokenHint(), new OAuth2TokenType("id_token"));
                if (authorization != null) {
                    String session = authorization.getAttribute(TrackedAuthorizationService.SESSION);
                    if (session != null) authorizations.revokeSession(session, authorization.getPrincipalName());
                }
            }
            if (!oidc.isPrincipalAuthenticated()) return;
            authentication = (Authentication) oidc.getPrincipal();
        }
        var session = request.getSession(false);
        if (session != null && authentication != null && authentication.isAuthenticated()) {
            String id = (String) session.getAttribute(TrackedAuthorizationService.SESSION);
            if (id == null) id = TrackedAuthorizationService.digest(session.getId()).substring(0, 32);
            authorizations.revokeSession(id, authentication.getName());
        }
    }
}
