package com.example.iam.server.client;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.authentication.JwtClientAssertionAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.JwtClientAssertionDecoderFactory;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Set;

/**
 * Framework client authentication and Nimbus verification, with durable single-use assertions.
 */
@Component
public class PrivateKeyClientAuthentication {
    private static final ClientAuthenticationMethod ASSERTION = new ClientAuthenticationMethod("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
    private static final ObjectMapper JSON = new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    private final JdbcTemplate db;
    private final TransactionTemplate tx;
    private final JwtClientAssertionAuthenticationProvider delegate;
    private final ClientAssertionReplayStore replays;

    public PrivateKeyClientAuthentication(JdbcTemplate db, PlatformTransactionManager transactions,
                                          RegisteredClientRepository clients, com.example.iam.server.token.TrackedAuthorizationService authorizations, ClientAssertionReplayStore replays) {
        this.db = db;
        this.replays = replays;
        tx = new TransactionTemplate(transactions);
        tx.setTimeout(10);
        delegate = new JwtClientAssertionAuthenticationProvider(clients, authorizations);
        delegate.setJwtDecoderFactory(client -> assertion -> {
            try {
                if (assertion.length() > 8192) throw new JwtException("Assertion size");
                var parts = assertion.split("\\.", -1);
                if (parts.length != 3) throw new JwtException("Signed assertion required");
                var header = JSON.readTree(Base64.getUrlDecoder().decode(parts[0]));
                JSON.readTree(Base64.getUrlDecoder().decode(parts[1]));
                if (!"RS256".equals(header.path("alg").asText()) || !"JWT".equals(header.path("typ").asText())
                        || !header.path("kid").asText().matches("[A-Za-z0-9_-]{1,128}")
                        || header.has("jwk") || header.has("jku") || header.has("x5u") || header.has("x5c") || header.has("crit"))
                    throw new JwtException("Assertion header");
                var policies = db.queryForList("select jwks from client_assertion_keys where client_id=? and enabled", String.class, client.getId());
                if (policies.size() != 1) throw new JwtException("Client key policy unavailable");
                var processor = new DefaultJWTProcessor<SecurityContext>();
                processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, new ImmutableJWKSet<>(JWKSet.parse(policies.getFirst()))));
                var decoder = new NimbusJwtDecoder(processor);
                decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                        JwtClientAssertionDecoderFactory.DEFAULT_JWT_VALIDATOR_FACTORY.apply(client),
                        new JwtTimestampValidator(Duration.ofSeconds(5)), jwt -> validateClaims(jwt)));
                return decoder.decode(assertion);
            } catch (JwtException invalid) {
                throw invalid;
            } catch (org.springframework.dao.DataAccessException unavailable) {
                throw unavailable;
            } catch (Exception invalid) {
                throw new JwtException("Invalid client assertion");
            }
        });
    }

    private static OAuth2TokenValidatorResult validateClaims(Jwt jwt) {
        try {
            var context = AuthorizationServerContextHolder.getContext();
            var request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
            var settings = context.getAuthorizationServerSettings();
            String path = request.getRequestURI();
            if (!Set.of(settings.getTokenEndpoint(), settings.getTokenRevocationEndpoint(), settings.getTokenIntrospectionEndpoint()).contains(path))
                throw new IllegalArgumentException();
            String audience = context.getIssuer() + (context.getIssuer().endsWith("/") ? path.substring(1) : path);
            Instant issued = jwt.getIssuedAt(), expires = jwt.getExpiresAt(), now = Instant.now();
            String jti = jwt.getId();
            if (!jwt.getAudience().equals(List.of(audience)) || issued == null || expires == null || !expires.isAfter(issued)
                    || expires.isAfter(issued.plusSeconds(60)) || issued.isAfter(now.plusSeconds(5)) || issued.isBefore(now.minusSeconds(65))
                    || jti == null || !jti.matches("[A-Za-z0-9_-]{16,128}")
                    || jwt.getNotBefore() != null && (jwt.getNotBefore().isBefore(issued) || jwt.getNotBefore().isAfter(expires)))
                throw new IllegalArgumentException();
            return OAuth2TokenValidatorResult.success();
        } catch (Exception invalid) {
            return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_client", "Invalid client assertion claims", null));
        }
    }

    private static OAuth2AuthenticationException invalidClient() {
        return new OAuth2AuthenticationException(new OAuth2Error("invalid_client"));
    }

    public AuthenticationProvider provider() {
        return new AuthenticationProvider() {
            @Override
            public Authentication authenticate(Authentication authentication) {
                return PrivateKeyClientAuthentication.this.authenticate(authentication);
            }

            @Override
            public boolean supports(Class<?> authentication) {
                return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
            }
        };
    }

    public Authentication authenticate(Authentication authentication) {
        if (!(authentication instanceof OAuth2ClientAuthenticationToken client) || !ASSERTION.equals(client.getClientAuthenticationMethod()))
            return null;
        var request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        if (request.getHeader("Authorization") != null || request.getParameter("client_secret") != null)
            throw invalidClient();
        return TransactionSynchronizationManager.isActualTransactionActive() ? authenticateLocked(client) : tx.execute(status -> authenticateLocked(client));
    }

    private Authentication authenticateLocked(OAuth2ClientAuthenticationToken authentication) {
        // Shared locks permit concurrent distinct assertions, and fence admin rotation through response commit.
        db.queryForList("select id from oauth2_registered_client where client_id=? for share", authentication.getPrincipal().toString());
        var result = (OAuth2ClientAuthenticationToken) delegate.authenticate(authentication);
        if (result == null || !ClientAuthenticationMethod.PRIVATE_KEY_JWT.equals(result.getClientAuthenticationMethod()))
            throw invalidClient();
        Jwt assertion = (Jwt) result.getCredentials();
        if (!replays.claim(result.getRegisteredClient().getClientId(), assertion.getId(), assertion.getIssuedAt(), assertion.getExpiresAt()))
            throw invalidClient();
        return result;
    }
}
