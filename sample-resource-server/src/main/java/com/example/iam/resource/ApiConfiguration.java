package com.example.iam.resource;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@Configuration
@RestController
public class ApiConfiguration {
    @Bean
    JwtDecoder decoder(@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuer, @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}") String jwks) {
        var decoder = NimbusJwtDecoder.withJwkSetUri(jwks).jwsAlgorithm(SignatureAlgorithm.RS256).validateType(false).build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(JwtValidators.createDefaultWithIssuer(issuer), jwt -> {
            if (!jwt.getAudience().contains("enterprise-api") || !"at+jwt".equals(jwt.getHeaders().get("typ")))
                return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token"));
            return OAuth2TokenValidatorResult.success();
        }));
        return decoder;
    }

    @Bean
    SecurityFilterChain security(HttpSecurity h) throws Exception {
        return h.csrf(c -> c.disable()).sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS)).authorizeHttpRequests(a -> a.requestMatchers("/actuator/health").permitAll().requestMatchers("/api/orders").hasAuthority("SCOPE_orders.read").anyRequest().denyAll()).oauth2ResourceServer(o -> o.jwt(j -> {
        })).build();
    }

    @GetMapping("/api/orders")
    public Map<String, Object> orders() {
        return Map.of("orders", List.of(Map.of("id", "demo-order", "status", "READY")));
    }
}
