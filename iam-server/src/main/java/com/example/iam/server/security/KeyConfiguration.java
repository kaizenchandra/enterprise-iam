package com.example.iam.server.security;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.nio.file.Files;
import java.nio.file.Path;

@Configuration
public class KeyConfiguration {
    @Bean
    JWKSource<SecurityContext> jwkSource(@Value("${iam.signing-key-file}") String file) throws Exception {
        JWKSet keys = JWKSet.parse(Files.readString(Path.of(file)));
        if (keys.getKeys().isEmpty() || keys.getKeys().stream().noneMatch(JWK::isPrivate))
            throw new IllegalStateException("Private signing key required");
        return (selector, ctx) -> selector.select(keys);
    }

    @Bean
    JwtDecoder jwtDecoder(JWKSource<SecurityContext> keys, @Value("${iam.issuer}") String issuer) {
        var processor = new com.nimbusds.jwt.proc.DefaultJWTProcessor<SecurityContext>();
        processor.setJWSKeySelector(new com.nimbusds.jose.proc.JWSVerificationKeySelector<>(com.nimbusds.jose.JWSAlgorithm.RS256, keys));
        processor.setJWSTypeVerifier(new com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier<>(new com.nimbusds.jose.JOSEObjectType("at+jwt"), com.nimbusds.jose.JOSEObjectType.JWT));
        var decoder = new org.springframework.security.oauth2.jwt.NimbusJwtDecoder(processor);
        decoder.setJwtValidator(org.springframework.security.oauth2.jwt.JwtValidators.createDefaultWithIssuer(issuer));
        return decoder;
    }
}
