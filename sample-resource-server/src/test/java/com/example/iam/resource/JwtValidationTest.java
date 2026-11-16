package com.example.iam.resource;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.JwtException;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JwtValidationTest {
    HttpServer server;
    String url;
    RSAKey oldKey, newKey;
    AtomicReference<JWKSet> keys;

    @BeforeEach
    void setup() throws Exception {
        oldKey = new RSAKeyGenerator(2048).keyID("old").generate();
        newKey = new RSAKeyGenerator(2048).keyID("new").generate();
        keys = new AtomicReference<>(new JWKSet(oldKey.toPublicJWK()));
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/jwks", e -> {
            byte[] body = keys.get().toString().getBytes(StandardCharsets.UTF_8);
            e.getResponseHeaders().set("Content-Type", "application/json");
            e.sendResponseHeaders(200, body.length);
            try (var out = e.getResponseBody()) {
                out.write(body);
            }
        });
        server.start();
        url = "http://127.0.0.1:" + server.getAddress().getPort() + "/jwks";
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    String token(RSAKey key, String issuer, String audience, long expires, String type) throws Exception {
        var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).type(new JOSEObjectType(type)).build(), new JWTClaimsSet.Builder().issuer(issuer).subject("service").audience(audience).issueTime(new Date()).expirationTime(new Date(System.currentTimeMillis() + expires)).claim("scope", "orders.read").build());
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    @Test
    void rotationOverlapAndRetirement() throws Exception {
        var decoder = new ApiConfiguration().decoder("https://issuer.example", url);
        String old = token(oldKey, "https://issuer.example", "enterprise-api", 300000, "at+jwt");
        assertNotNull(decoder.decode(old));
        keys.set(new JWKSet(List.of(oldKey.toPublicJWK(), newKey.toPublicJWK())));
        assertNotNull(decoder.decode(token(newKey, "https://issuer.example", "enterprise-api", 300000, "at+jwt")));
        assertNotNull(decoder.decode(old));
        keys.set(new JWKSet(newKey.toPublicJWK()));
        var fresh = new ApiConfiguration().decoder("https://issuer.example", url);
        assertThrows(JwtException.class, () -> fresh.decode(old));
    }

    @Test
    void issuerAudienceTimeTypeAndUnknownKeyFail() throws Exception {
        var decoder = new ApiConfiguration().decoder("https://issuer.example", url);
        for (String bad : List.of(token(oldKey, "https://attacker.invalid", "enterprise-api", 300000, "at+jwt"), token(oldKey, "https://issuer.example", "other-api", 300000, "at+jwt"), token(oldKey, "https://issuer.example", "enterprise-api", -120000, "at+jwt"), token(oldKey, "https://issuer.example", "enterprise-api", 300000, "JWT"), token(newKey, "https://issuer.example", "enterprise-api", 300000, "at+jwt")))
            assertThrows(JwtException.class, () -> decoder.decode(bad));
    }
}
