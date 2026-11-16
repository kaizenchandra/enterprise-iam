package com.example.iam.server.backchannel;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.UUID;

/**
 * Called only inside lifecycle transactions holding the principal lock.
 */
public class BackChannelSessions {
    public static final String URI_SETTING = "backchannel_logout_uri";
    private final JdbcTemplate db;
    private final RegisteredClientRepository clients;

    public BackChannelSessions(JdbcTemplate db, RegisteredClientRepository clients) {
        this.db = db;
        this.clients = clients;
    }

    public void remember(OAuth2Authorization authorization, String session) {
        var token = authorization.getToken(OidcIdToken.class);
        if (session == null || token == null) return;
        var client = clients.findById(authorization.getRegisteredClientId());
        String endpoint = client.getClientSettings().getSetting(URI_SETTING);
        if (endpoint == null) return;
        String sid = token.getToken().getClaimAsString("sid");
        if (sid == null || sid.isBlank()) throw new OAuth2AuthenticationException("invalid_grant");
        db.update("""
                insert into oidc_rp_sessions(id,session_id,registered_client_id,client_id,subject,sid,endpoint)
                values (?,?,?,?,?,?,?) on conflict(session_id,registered_client_id,sid) do update set endpoint=excluded.endpoint where oidc_rp_sessions.subject=excluded.subject
                """, UUID.randomUUID().toString(), session, client.getId(), client.getClientId(), token.getToken().getSubject(), sid, endpoint);
    }

    public void enqueueSession(String session, String principal) {
        db.update("""
                insert into logout_deliveries(id,rp_session_id)
                select gen_random_uuid()::text,r.id from oidc_rp_sessions r join identity_sessions s on s.id=r.session_id
                where r.session_id=? and s.principal_name=? on conflict(rp_session_id) do nothing
                """, session, principal);
    }

    public void enqueueUser(String principal) {
        for (var row : db.queryForList("select id from identity_sessions where principal_name=?", principal))
            enqueueSession(row.get("id").toString(), principal);
    }
}
