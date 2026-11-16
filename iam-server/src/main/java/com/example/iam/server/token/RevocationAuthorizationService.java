package com.example.iam.server.token;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;

/**
 * A revocation-only view: old refresh generations may revoke their current family.
 * Never use this view for token grants or introspection. Client binding is checked
 * by the unchanged framework revocation provider before it persists invalidation.
 */
public class RevocationAuthorizationService implements OAuth2AuthorizationService {
    private final TrackedAuthorizationService delegate;
    private final JdbcTemplate db;

    public RevocationAuthorizationService(TrackedAuthorizationService delegate, JdbcTemplate db) {
        this.delegate = delegate;
        this.db = db;
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType type) {
        var current = delegate.findByToken(token, type);
        if (current != null) return current;
        var history = db.queryForList("select authorization_id from refresh_history where token_hash=?",
                TrackedAuthorizationService.digest(token));
        if (history.isEmpty()) return null;
        current = delegate.findById(history.getFirst().get("authorization_id").toString());
        if (current == null || current.getRefreshToken() == null) return null;
        var refresh = current.getRefreshToken().getToken();
        // Expose precisely the submitted historical token to the standard provider's
        // getToken()/invalidate() path. save() then monotonically revokes the latest state.
        return OAuth2Authorization.from(current).token(new OAuth2RefreshToken(token,
                refresh.getIssuedAt(), refresh.getExpiresAt())).build();
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        delegate.save(authorization);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        delegate.remove(authorization);
    }

    @Override
    public OAuth2Authorization findById(String id) {
        return delegate.findById(id);
    }
}
