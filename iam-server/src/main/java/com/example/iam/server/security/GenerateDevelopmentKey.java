package com.example.iam.server.security;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;

public class GenerateDevelopmentKey {
    public static void main(String[] args) throws Exception {
        Path path = Path.of(args[0]);
        var key = new RSAKeyGenerator(2048).keyID(java.util.UUID.randomUUID().toString()).algorithm(com.nimbusds.jose.JWSAlgorithm.RS256).keyUse(KeyUse.SIGNATURE).generate();
        Files.createDirectories(path.toAbsolutePath().getParent());
        Files.writeString(path, new JWKSet(key).toString(false), StandardOpenOption.CREATE_NEW);
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
    }
}
