package com.example.iam.server.passkey;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Runtime-generated test PKI and real signed packed ceremonies. No production verification code.
 */
final class AttestationFixtures {
    static final ObjectMapper JSON = new ObjectMapper(), CBOR = new ObjectMapper(new CBORFactory());
    static final UUID MODEL = UUID.fromString("1f01ae01-341a-4d6f-b160-bf2c42a47ca6");
    final Path dir;
    final X509Certificate root, leaf;
    final PrivateKey rootKey, attestationKey;
    final KeyPair credentialKey;
    final byte[] credentialId = new byte[32];

    AttestationFixtures(Path dir) throws Exception {
        this(dir, null);
    }

    AttestationFixtures(Path dir, String crlUrl) throws Exception {
        this.dir = dir;
        Files.createDirectories(dir);
        Files.writeString(dir.resolve("root.cnf"), "[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n[dn]\nCN=Test-only Attestation Root\n[ca]\nbasicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign,cRLSign,digitalSignature\nsubjectKeyIdentifier=hash\n");
        if (crlUrl != null)
            Files.writeString(dir.resolve("root.cnf"), "crlDistributionPoints=URI:" + crlUrl + "\n", StandardOpenOption.APPEND);
        command("req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30", "-config", "root.cnf", "-keyout", "root.key", "-out", "root.pem");
        command("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/C=US/O=Test-only/OU=Authenticator Attestation/CN=Test-only FIDO2", "-keyout", "leaf.key", "-out", "leaf.csr");
        String hex = MODEL.toString().replace("-", "").replaceAll("(..)(?!$)", "$1:");
        Files.writeString(dir.resolve("leaf.cnf"), "basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n1.3.6.1.4.1.45724.1.1.4=DER:04:10:" + hex + "\n");
        command("x509", "-req", "-in", "leaf.csr", "-CA", "root.pem", "-CAkey", "root.key", "-CAcreateserial", "-days", "20", "-extfile", "leaf.cnf", "-out", "leaf.pem");
        Files.writeString(dir.resolve("index.txt"), "");
        Files.writeString(dir.resolve("crlnumber"), "1000\n");
        Files.writeString(dir.resolve("ca.cnf"), "[ca]\ndefault_ca=authority\n[authority]\ndatabase=index.txt\nnew_certs_dir=.\ncertificate=root.pem\nprivate_key=root.key\ncrlnumber=crlnumber\ndefault_md=sha256\ndefault_crl_days=2\n");
        command("ca", "-gencrl", "-config", "ca.cnf", "-crlhours", "1", "-out", "root.crl");
        root = AttestationBundle.certificate(Files.readAllBytes(dir.resolve("root.pem")));
        leaf = AttestationBundle.certificate(Files.readAllBytes(dir.resolve("leaf.pem")));
        rootKey = key("root.key");
        attestationKey = key("leaf.key");
        credentialKey = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        new SecureRandom().nextBytes(credentialId);
    }

    static String b64(byte[] bytes) {
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static byte[] unsigned(byte[] value) {
        return value[0] == 0 ? Arrays.copyOfRange(value, 1, value.length) : value;
    }

    private static byte[] signature(PrivateKey key, byte[] auth, byte[] client) throws Exception {
        var signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(key);
        signature.update(auth);
        signature.update(MessageDigest.getInstance("SHA-256").digest(client));
        return signature.sign();
    }

    void renewCrl() throws Exception {
        command("ca", "-gencrl", "-config", "ca.cnf", "-crlhours", "2", "-out", "root.crl");
    }

    void revokeSigner() throws Exception {
        command("ca", "-config", "ca.cnf", "-revoke", "root.pem");
        command("ca", "-gencrl", "-config", "ca.cnf", "-crlhours", "1", "-out", "root.crl");
    }

    private void command(String... args) throws Exception {
        var command = new ArrayList<String>();
        command.add(System.getenv().getOrDefault("OPENSSL_BIN", "openssl"));
        command.addAll(List.of(args));
        var process = new ProcessBuilder(command).directory(dir.toFile()).redirectErrorStream(true).redirectOutput(dir.resolve("openssl.log").toFile()).start();
        if (!process.waitFor(15, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new IllegalStateException("Test PKI generation timed out");
        }
        if (process.exitValue() != 0) throw new IllegalStateException("Test PKI generation failed");
        for (String file : List.of("root.key", "leaf.key"))
            if (Files.exists(dir.resolve(file))) dir.resolve(file).toFile().setReadable(false, false);
        for (String file : List.of("root.key", "leaf.key"))
            if (Files.exists(dir.resolve(file))) dir.resolve(file).toFile().setReadable(true, true);
    }

    private PrivateKey key(String name) throws Exception {
        String pem = Files.readString(dir.resolve(name)).replaceAll("-----[^-]+-----", "").replaceAll("\\s", "");
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(pem)));
    }

    String metadata(int serial, String status, LocalDate nextUpdate) throws Exception {
        Map<String, Object> statement = new HashMap<>();
        statement.put("aaguid", MODEL.toString());
        statement.put("description", "Test-only authenticator");
        statement.put("authenticatorVersion", 1);
        statement.put("protocolFamily", "fido2");
        statement.put("schema", 3);
        statement.put("upv", List.of(Map.of("major", 1, "minor", 0)));
        for (String field : List.of("authenticationAlgorithms", "publicKeyAlgAndEncodings", "attestationTypes", "keyProtection", "matcherProtection", "tcDisplay"))
            statement.put(field, List.of());
        statement.put("keyProtection", List.of("hardware"));
        statement.put("attestationRootCertificates", List.of(java.util.Base64.getEncoder().encodeToString(root.getEncoded())));
        var entry = Map.of("aaguid", MODEL.toString(), "metadataStatement", statement, "statusReports", List.of(Map.of("status", status)), "timeOfLastStatusChange", LocalDate.now(ZoneOffset.UTC).toString());
        return signed(Map.of("legalHeader", "test-only terms", "no", serial, "nextUpdate", nextUpdate.toString(), "entries", List.of(entry)), false);
    }

    String signed(Map<String, Object> payload, boolean remote) throws Exception {
        var builder = new JWSHeader.Builder(JWSAlgorithm.RS256).x509CertChain(List.of(Base64.encode(root.getEncoded())));
        if (remote) builder.x509CertURL(java.net.URI.create("http://127.0.0.1:9/forbidden"));
        var jws = new JWSObject(builder.build(), new Payload(JSON.writeValueAsString(payload)));
        jws.sign(new RSASSASigner(rootKey));
        return jws.serialize();
    }

    private byte[] client(String type, String challenge) throws Exception {
        return JSON.writeValueAsBytes(Map.of("type", type, "challenge", challenge, "origin", "https://localhost:9000", "crossOrigin", false));
    }

    private byte[] authData(boolean registration, int counter) throws Exception {
        var bytes = new java.io.ByteArrayOutputStream();
        bytes.write(MessageDigest.getInstance("SHA-256").digest("localhost".getBytes(StandardCharsets.US_ASCII)));
        bytes.write(registration ? 0x45 : 0x05);
        bytes.write(ByteBuffer.allocate(4).putInt(counter).array());
        if (registration) {
            bytes.write(ByteBuffer.allocate(16).putLong(MODEL.getMostSignificantBits()).putLong(MODEL.getLeastSignificantBits()).array());
            bytes.write(ByteBuffer.allocate(2).putShort((short) credentialId.length).array());
            bytes.write(credentialId);
            var cose = new java.io.ByteArrayOutputStream();
            try (var g = new CBORFactory().createGenerator(cose)) {
                var pub = (RSAPublicKey) credentialKey.getPublic();
                g.writeStartObject();
                g.writeFieldId(1);
                g.writeNumber(3);
                g.writeFieldId(3);
                g.writeNumber(-257);
                g.writeFieldId(-1);
                g.writeBinary(unsigned(pub.getModulus().toByteArray()));
                g.writeFieldId(-2);
                g.writeBinary(unsigned(pub.getPublicExponent().toByteArray()));
                g.writeEndObject();
            }
            bytes.write(cose.toByteArray());
        }
        return bytes.toByteArray();
    }

    String registration(PublicKeyCredentialCreationOptions options, boolean trusted) throws Exception {
        byte[] client = client("webauthn.create", options.getChallenge().getBase64Url()), auth = authData(true, 0);
        var attestation = Map.of("fmt", trusted ? "packed" : "none", "authData", auth, "attStmt", trusted ? Map.of("alg", -257, "sig", signature(attestationKey, auth, client), "x5c", List.of(leaf.getEncoded())) : Map.of());
        return JSON.writeValueAsString(Map.of("id", b64(credentialId), "rawId", b64(credentialId), "type", "public-key", "response", Map.of("clientDataJSON", b64(client), "attestationObject", b64(CBOR.writeValueAsBytes(attestation))), "clientExtensionResults", Map.of("credProps", Map.of("rk", true))));
    }

    String assertion(AssertionRequest options, String user, int counter) throws Exception {
        byte[] client = client("webauthn.get", options.getPublicKeyCredentialRequestOptions().getChallenge().getBase64Url()), auth = authData(false, counter);
        return JSON.writeValueAsString(Map.of("id", b64(credentialId), "rawId", b64(credentialId), "type", "public-key", "response", Map.of("clientDataJSON", b64(client), "authenticatorData", b64(auth), "signature", b64(signature(credentialKey.getPrivate(), auth, client)), "userHandle", b64(user.getBytes(StandardCharsets.UTF_8))), "clientExtensionResults", Map.of()));
    }
}
