package com.example.iam.server.oauth2;

import com.example.iam.server.token.TrackedAuthorizationService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

@Configuration
@org.springframework.boot.context.properties.EnableConfigurationProperties(com.example.iam.server.session.SessionLifetime.class)
public class PersistenceConfiguration {
    @Bean
    RegisteredClientRepository clients(JdbcTemplate db) {
        return new JdbcRegisteredClientRepository(db);
    }

    @Bean
    TrackedAuthorizationService authorizations(JdbcTemplate db, RegisteredClientRepository clients, org.springframework.transaction.PlatformTransactionManager transactions, @org.springframework.beans.factory.annotation.Value("${iam.refresh-family-lifetime:PT8H}") java.time.Duration lifetime, com.example.iam.server.session.SessionLifetime sessions) {
        return new TrackedAuthorizationService(db, clients, transactions, lifetime, sessions);
    }

    @Bean
    OAuth2AuthorizationConsentService consents(JdbcTemplate db, RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationConsentService(db, clients);
    }

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> claims(JdbcTemplate db) {
        return ctx -> {
            if ("access_token".equals(ctx.getTokenType().getValue())) {
                ctx.getJwsHeader().type("at+jwt");
                ctx.getClaims().audience(new java.util.ArrayList<>(java.util.List.of(ctx.getAuthorizedScopes().contains("iam.admin") ? "iam-admin" : ctx.getAuthorizedScopes().stream().anyMatch(s -> s.startsWith("sessions.")) ? "iam-session-management" : "enterprise-api")));
                // Workload subjects must never collide with UUID directory identities in the PDP.
                if ("client_credentials".equals(ctx.getAuthorizationGrantType().getValue()))
                    ctx.getClaims().subject("client:" + ctx.getRegisteredClient().getClientId());
                // User state is checked at issuance, not inferred from stale session authorities.
                if (!"client_credentials".equals(ctx.getAuthorizationGrantType().getValue())) {
                    if (ctx.getAuthorizedScopes().contains("iam.admin") && !Boolean.TRUE.equals(db.queryForObject(
                            "select exists(select 1 from platform_administrators where user_id=?)", Boolean.class, ctx.getPrincipal().getName())))
                        throw new org.springframework.security.oauth2.core.OAuth2AuthenticationException("access_denied");
                    ctx.getClaims().claim("roles", new java.util.ArrayList<>(java.util.List.of(ctx.getAuthorizedScopes().contains("iam.admin") ? "PLATFORM_ADMIN" : "USER")));
                    var state = db.queryForList("select state from users where id=?", ctx.getPrincipal().getName());
                    if (state.isEmpty() || !"ACTIVE".equals(state.getFirst().get("state")))
                        throw new org.springframework.security.oauth2.core.OAuth2AuthenticationException("access_denied");
                }
            }
        };
    }
}
