package com.example.iam.server.passkey;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;

/**
 * Read-only operator probe. Does not publish trust state, approve devices or issue credentials.
 */
public final class LiveMdsProbe {
    public static void main(String[] args) throws Exception {
        if (args.length < 2 || args.length > 3)
            throw new IllegalArgumentException("Usage: LiveMdsProbe signing-roots.pem report.json [authenticator-roots.pem]");
        String legal = System.getenv("PASSKEY_METADATA_LEGAL_HEADER");
        if (legal == null || legal.isBlank())
            throw new IllegalArgumentException("Configure the reviewed exact metadata legal header");
        var roots = AttestationBundle.certificates(Path.of(args[0]));
        var manufacturer = AttestationBundle.certificates(Path.of(args.length == 3 ? args[2] : args[0]));
        long start = System.nanoTime();
        var client = new LiveMdsClient("https://mds.fidoalliance.org/", "https://mds.fidoalliance.org,https://crl.globalsign.com", false, 25);
        var proof = client.verify(roots, legal, System.getenv("PASSKEY_MDS_SEED_FILE") == null ? null : new String(AttestationBundle.read(Path.of(System.getenv("PASSKEY_MDS_SEED_FILE")), MdsVerifierWorker.BLOB_LIMIT), java.nio.charset.StandardCharsets.UTF_8), null);
        var bundle = new AttestationBundle(proof.jwt, roots, manufacturer, List.of(), legal, Clock.systemUTC(), proof);
        var report = new LinkedHashMap<String, Object>();
        report.put("kind", "read-only-live-public-mds-probe");
        report.put("recordedAt", Instant.now().toString());
        report.put("signatureAndPkixVerified", true);
        report.put("retrieved", proof.retrieved);
        report.put("originConfirmed", proof.confirmed);
        report.put("serial", bundle.blob.getPayload().getNo());
        report.put("nextUpdate", bundle.blob.getPayload().getNextUpdate().toString());
        report.put("validUntil", proof.deadline.toString());
        report.put("blobBytes", proof.jwt.getBytes(java.nio.charset.StandardCharsets.UTF_8).length);
        report.put("entries", bundle.blob.getPayload().getEntries().size());
        report.put("fido2Models", bundle.models.size());
        report.put("eligibleModels", bundle.models.values().stream().filter(Boolean::booleanValue).count());
        report.put("crls", proof.downloads.size());
        report.put("elapsedMs", (System.nanoTime() - start) / 1_000_000.0);
        report.put("javaVersion", System.getProperty("java.version"));
        report.put("limits", List.of("Single live retrieval/verification, not a load or production-capacity test", "No device enrollment, authorization or database publication", "Authenticator roots must be independently reviewed; this probe never imports all metadata roots", "Physical device and vendor interoperability not established"));
        Path target = Path.of(args[1]);
        if (target.toAbsolutePath().getParent() != null) Files.createDirectories(target.toAbsolutePath().getParent());
        Files.writeString(target, AttestationBundle.JSON.writerWithDefaultPrettyPrinter().writeValueAsString(report) + "\n");
        System.out.println("PASS: live signed public MDS verified; read-only report saved");
    }
}
