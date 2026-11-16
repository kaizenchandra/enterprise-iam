package com.example.iam.server.passkey;

import com.yubico.fido.metadata.FidoMetadataDownloader;
import com.yubico.fido.metadata.MetadataBLOB;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

/**
 * A single bounded verifier process per node. Login requests never invoke this client.
 */
@Component
public class LiveMdsClient {
    private static final Semaphore SLOT = new Semaphore(1);
    final String url;
    final String signerName;
    final List<String> origins;
    final boolean testLoopback;
    final int timeout;
    volatile int retryAfter;

    public LiveMdsClient(String url, String origins, boolean testLoopback, int timeout) {
        this(url, origins, testLoopback, timeout, "");
    }

    @org.springframework.beans.factory.annotation.Autowired
    public LiveMdsClient(@Value("${iam.passkey.attestation.live-url:https://mds.fidoalliance.org/}") String url,
                         @Value("${iam.passkey.attestation.live-origins:https://mds.fidoalliance.org,https://crl.globalsign.com}") String origins,
                         @Value("${iam.passkey.attestation.live-test-loopback:false}") boolean testLoopback,
                         @Value("${iam.passkey.attestation.worker-timeout-seconds:20}") int timeout,
                         @Value("${iam.passkey.attestation.live-signer-name:}") String signerName) {
        if (timeout < 1 || timeout > 30) throw new IllegalArgumentException("Worker deadline must be 1..30 seconds");
        this.signerName = signerName.isBlank() ? (testLoopback ? "" : java.net.URI.create(url).getHost()) : signerName;
        if (!this.signerName.isEmpty() && !this.signerName.matches("[A-Za-z0-9.-]{1,253}"))
            throw new IllegalArgumentException("Exact metadata publisher DNS name required");
        this.url = url;
        this.origins = Arrays.stream(origins.split(",")).map(String::strip).toList();
        this.testLoopback = testLoopback;
        this.timeout = timeout;
        for (String origin : this.origins) {
            var uri = java.net.URI.create(origin);
            if (uri.getHost() == null || uri.getUserInfo() != null || !uri.getPath().isEmpty() || uri.getQuery() != null || uri.getFragment() != null || !("https".equals(uri.getScheme()) || testLoopback && "http".equals(uri.getScheme())))
                throw new IllegalArgumentException("Exact retrieval origins required");
        }
    }

    private static boolean isBootJar(String classpath) {
        if (classpath.contains(File.pathSeparator) || !classpath.endsWith(".jar")) return false;
        try (var jar = new java.util.zip.ZipFile(classpath)) {
            return jar.getEntry("org/springframework/boot/loader/launch/PropertiesLauncher.class") != null;
        } catch (IOException ignored) {
            return false;
        }
    }

    String identity() {
        return url + ":" + new TreeSet<>(origins) + ":" + testLoopback + ":" + timeout + ":" + signerName;
    }

    Verified verify(Set<X509Certificate> roots, String legal, String cachedJwt, String cachedDownloads) throws Exception {
        return verify(roots, legal, cachedJwt, cachedDownloads, true);
    }

    Verified verify(Set<X509Certificate> roots, String legal, String cachedJwt, String cachedDownloads, boolean retrieve) throws Exception {
        if (!SLOT.tryAcquire()) throw new IOException("Metadata worker busy");
        Process process = null;
        var executor = Executors.newVirtualThreadPerTaskExecutor();
        try {
            var certificates = new ArrayList<String>();
            for (var cert : roots) certificates.add(Base64.getEncoder().encodeToString(cert.getEncoded()));
            Map<String, String> cached = new HashMap<>();
            if (cachedDownloads != null && !cachedDownloads.isBlank())
                AttestationBundle.JSON.readTree(cachedDownloads).fields().forEachRemaining(e -> cached.put(e.getKey(), e.getValue().asText()));
            var request = new MdsVerifierWorker.Request(url, origins, testLoopback, legal, certificates, cachedJwt, cached, retrieve, signerName);
            byte[] input = AttestationBundle.JSON.writeValueAsBytes(request);
            if (input.length > 40 * 1024 * 1024) throw new IOException("Worker input limit");
            String classpath = System.getProperty("java.class.path");
            var command = new ArrayList<String>();
            command.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
            command.add("-Xmx256m");
            command.add("-Dcom.sun.security.enableAIAcaIssuers=false");
            if (isBootJar(classpath)) command.add("-Dloader.main=" + MdsVerifierWorker.class.getName());
            command.addAll(List.of("-cp", classpath, isBootJar(classpath) ? "org.springframework.boot.loader.launch.PropertiesLauncher" : MdsVerifierWorker.class.getName()));
            var builder = new ProcessBuilder(command).redirectError(ProcessBuilder.Redirect.DISCARD);
            builder.environment().clear();
            process = builder.start();
            final Process worker = process;
            var writer = executor.submit(() -> {
                try (var out = worker.getOutputStream()) {
                    out.write(input);
                }
                return true;
            });
            var reader = executor.submit(() -> {
                try (var in = worker.getInputStream()) {
                    byte[] bytes = in.readNBytes(40 * 1024 * 1024 + 1);
                    if (bytes.length > 40 * 1024 * 1024) throw new IOException("Worker output limit");
                    return bytes;
                }
            });
            if (!worker.waitFor(timeout, TimeUnit.SECONDS)) {
                worker.destroyForcibly();
                worker.waitFor(2, TimeUnit.SECONDS);
                throw new IOException("Metadata worker deadline");
            }
            writer.get(1, TimeUnit.SECONDS);
            byte[] output = reader.get(1, TimeUnit.SECONDS);
            try {
                retryAfter = Math.min(31 * 86400, Math.max(0, AttestationBundle.JSON.readTree(output).path("retryAfter").asInt()));
            } catch (Exception ignored) {
                retryAfter = 0;
            }
            if (worker.exitValue() != 0) {
                String reason = "worker_failure";
                try {
                    String code = AttestationBundle.JSON.readTree(output).path("failure").asText();
                    if (code.matches("[A-Za-z0-9_]{1,100}")) reason = code;
                    String detail = AttestationBundle.JSON.readTree(output).path("reason").asText();
                    if (detail.matches("[A-Za-z0-9_]{1,100}")) reason += "/" + detail;
                } catch (Exception ignored) {
                }
                throw new IOException("Metadata validation unavailable: " + reason);
            }
            var reply = AttestationBundle.JSON.readTree(output);
            retryAfter = Math.min(31 * 86400, Math.max(0, reply.path("retryAfter").asInt()));
            String jwt = reply.path("jwt").asText();
            if (jwt.isBlank() || jwt.length() > MdsVerifierWorker.BLOB_LIMIT)
                throw new IOException("Invalid verified envelope");
            Map<String, String> downloads = new HashMap<>();
            reply.path("downloads").fields().forEachRemaining(e -> downloads.put(e.getKey(), e.getValue().asText()));
            Instant deadline = Instant.parse(reply.path("validUntil").asText());
            if (!deadline.isAfter(Instant.now())) throw new IOException("Expired worker result");
            return new Verified(jwt, downloads, deadline, reply.path("retrieved").asBoolean(), reply.path("confirmed").asBoolean(), roots, legal);
        } finally {
            if (process != null && process.isAlive()) {
                process.destroyForcibly();
                try {
                    process.waitFor(2, TimeUnit.SECONDS);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                }
            }
            executor.shutdownNow();
            SLOT.release();
        }
    }

    /**
     * Created only after a successful library verifier process, tied to the exact original signed JWT.
     */
    static final class Verified {
        final String jwt;
        final Map<String, String> downloads;
        final Instant deadline;
        final boolean retrieved;
        final boolean confirmed;
        final MetadataBLOB blob;

        private Verified(String jwt, Map<String, String> downloads, Instant deadline, boolean retrieved, boolean confirmed, Set<X509Certificate> roots, String legal) throws Exception {
            this.jwt = jwt;
            this.downloads = Map.copyOf(downloads);
            this.deadline = deadline;
            this.retrieved = retrieved;
            this.confirmed = confirmed;
            // Parsing only, after cryptographic validation in our isolated worker. Never used for arbitrary DB/input data.
            blob = FidoMetadataDownloader.builder().expectLegalHeader(legal).useTrustRoots(roots.stream().map(c -> new TrustAnchor(c, null)).collect(java.util.stream.Collectors.toSet())).useBlob(jwt).verifyDownloadsOnly(true).build().loadCachedBlob();
        }
    }
}
