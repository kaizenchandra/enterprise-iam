package com.example.iam.server.passkey;

import com.nimbusds.jose.JWSObject;
import com.yubico.fido.metadata.FidoMetadataDownloader;
import com.yubico.fido.metadata.MetadataBLOB;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.cert.*;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.*;
import java.util.concurrent.*;

/**
 * Single-use isolated process. All URL retrieval (including library CRLs) goes through bounded transport.
 */
public final class MdsVerifierWorker {
    static final int BLOB_LIMIT = 16 * 1024 * 1024, CRL_LIMIT = 4 * 1024 * 1024;
    static volatile int requestedRetryAfter;

    public static void main(String[] args) {
        try {
            ((ch.qos.logback.classic.LoggerContext) org.slf4j.LoggerFactory.getILoggerFactory()).getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME).setLevel(ch.qos.logback.classic.Level.OFF);
            System.setProperty("com.sun.security.enableAIAcaIssuers", "false");
            java.security.Security.setProperty("ocsp.enable", "false");
            byte[] bytes = System.in.readNBytes(40 * 1024 * 1024 + 1);
            if (bytes.length > 40 * 1024 * 1024) throw new IOException("Input limit");
            Request request = AttestationBundle.JSON.readValue(bytes, Request.class);
            Reply reply = verify(request);
            // Date is emitted explicitly; the process contract never carries private credentials.
            var result = Map.of("jwt", reply.jwt, "downloads", reply.downloads, "validUntil", reply.validUntil.toString(), "retrieved", reply.retrieved, "confirmed", reply.confirmed, "retryAfter", reply.retryAfter);
            System.out.write(AttestationBundle.JSON.writeValueAsBytes(result));
            System.out.flush();
        } catch (Throwable invalid) {
            try {
                System.out.write(("{\"failure\":\"" + invalid.getClass().getSimpleName() + "\",\"reason\":\"" + (invalid instanceof RetrievalFailure r ? r.code : invalid instanceof java.security.cert.CertPathValidatorException c ? c.getReason().toString() : "validation") + "\",\"retryAfter\":" + requestedRetryAfter + "}").getBytes(StandardCharsets.UTF_8));
                System.out.flush();
            } catch (Exception ignored) {
            }
            System.exit(2);
        }
    }

    static Reply verify(Request request) throws Exception {
        var transport = new Transport(request.origins, request.testLoopback, request.cachedDownloads);
        URL.setURLStreamHandlerFactory(protocol -> Set.of("http", "https").contains(protocol) ? new URLStreamHandler() {
            @Override
            protected URLConnection openConnection(URL url) {
                return new URLConnection(url) {
                    @Override
                    public void connect() {
                    }

                    @Override
                    public InputStream getInputStream() throws IOException {
                        return new ByteArrayInputStream(transport.get(url.toString(), CRL_LIMIT));
                    }
                };
            }
        } : null);
        if (request.cachedJwt != null && !request.cachedJwt.isBlank()) try {
            transport.expectedSerial = AttestationBundle.JSON.readTree(JWSObject.parse(request.cachedJwt).getPayload().toBytes()).path("no").asInt();
        } catch (Exception invalid) {
            throw new IOException("Invalid cached envelope");
        }
        transport.network = request.retrieve;
        String jwt;
        boolean retrieved;
        try {
            if (!request.retrieve) throw new IOException("Offline warmup");
            jwt = new String(transport.fetch(request.url, BLOB_LIMIT), StandardCharsets.UTF_8).strip();
            retrieved = true;
        } catch (Exception unavailable) {
            if (request.cachedJwt == null || request.cachedJwt.isBlank()) throw unavailable;
            jwt = request.cachedJwt;
            retrieved = false;
        }
        String[] segments = jwt.split("\\.", -1);
        if (segments.length != 3 || segments[0].length() > 65536) throw new IOException("Envelope limit");
        var header = AttestationBundle.JSON.readTree(Base64.getUrlDecoder().decode(segments[0]));
        if (header.has("x5u") || !header.path("x5c").isArray() || header.path("x5c").isEmpty() || header.path("x5c").size() > 8)
            throw new IOException("Inline certificate chain required");
        // Strict payload parsing before the library parser, including duplicate field detection.
        AttestationBundle.JSON.readTree(Base64.getUrlDecoder().decode(segments[1]));
        var jws = JWSObject.parse(jwt);
        Set<TrustAnchor> roots = new HashSet<>();
        Instant deadline = Instant.MAX;
        for (String encoded : request.roots) {
            var cert = AttestationBundle.certificate(Base64.getDecoder().decode(encoded));
            cert.checkValidity();
            roots.add(new TrustAnchor(cert, null));
            deadline = min(deadline, cert.getNotAfter().toInstant());
        }
        if (roots.isEmpty() || roots.size() > 32) throw new IOException("Trust roots required");
        var signingCertificate = AttestationBundle.certificate(jws.getHeader().getX509CertChain().getFirst().decode());
        if (request.signerName == null || request.signerName.isBlank()) {
            if (!request.testLoopback || roots.stream().noneMatch(anchor -> signingCertificate.equals(anchor.getTrustedCert())))
                throw new IOException("Publisher identity required");
        } else {
            var names = signingCertificate.getSubjectAlternativeNames();
            if (names == null || names.stream().noneMatch(name -> Integer.valueOf(2).equals(name.get(0)) && request.signerName.equalsIgnoreCase(name.get(1).toString())))
                throw new IOException("Metadata publisher identity mismatch");
        }
        for (var encoded : jws.getHeader().getX509CertChain()) {
            var cert = AttestationBundle.certificate(encoded.decode());
            cert.checkValidity();
            deadline = min(deadline, cert.getNotAfter().toInstant());
        }
        var crls = new ArrayList<CRL>();
        for (byte[] content : transport.cached.values())
            try {
                crls.add(CertificateFactory.getInstance("X.509").generateCRL(new ByteArrayInputStream(content)));
            } catch (CRLException ignored) {
            }
        MetadataBLOB verified = FidoMetadataDownloader.builder().expectLegalHeader(request.legal).useTrustRoots(roots).useBlob(jwt)
                .verifyDownloadsOnly(false).useCrls(crls).build().loadCachedBlob();
        if (!request.legal.equals(verified.getPayload().getLegalHeader()) || verified.getPayload().getNo() < 1)
            throw new IOException("Metadata policy");
        deadline = min(deadline, verified.getPayload().getNextUpdate().atStartOfDay(ZoneOffset.UTC).toInstant());
        Map<String, String> evidence = new TreeMap<>();
        // Return only CRLs used/provisioned for bounded offline recovery, never the BLOB a second time.
        var evidenceCandidates = new HashMap<>(transport.cached);
        evidenceCandidates.putAll(transport.used);
        Set<javax.security.auth.x500.X500Principal> issuers = new HashSet<>();
        for (var cert : jws.getHeader().getX509CertChain())
            issuers.add(AttestationBundle.certificate(cert.decode()).getIssuerX500Principal());
        for (var entry : evidenceCandidates.entrySet())
            try {
                var crl = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(new ByteArrayInputStream(entry.getValue()));
                if (!issuers.contains(crl.getIssuerX500Principal())) continue;
                if (crl.getNextUpdate() == null || crl.getThisUpdate().toInstant().isAfter(Instant.now()))
                    throw new IOException("Invalid CRL date");
                deadline = min(deadline, crl.getNextUpdate().toInstant());
                evidence.put(entry.getKey(), Base64.getEncoder().encodeToString(entry.getValue()));
            } catch (CRLException ignored) {
            }
        if (!deadline.isAfter(Instant.now())) throw new IOException("Expired verification evidence");
        return new Reply(jwt, evidence, deadline, retrieved, transport.confirmed && transport.expectedSerial == verified.getPayload().getNo(), transport.retryAfter);
    }

    static Instant min(Instant a, Instant b) {
        return a.isBefore(b) ? a : b;
    }

    public record Request(String url, List<String> origins, boolean testLoopback, String legal, List<String> roots,
                          String cachedJwt, Map<String, String> cachedDownloads, boolean retrieve, String signerName) {
    }

    public record Reply(String jwt, Map<String, String> downloads, Instant validUntil, boolean retrieved,
                        boolean confirmed, int retryAfter) {
    }

    static final class RetrievalFailure extends IOException {
        final String code;

        RetrievalFailure(String code) {
            super(code);
            this.code = code;
        }
    }

    static final class Transport {
        final Set<String> origins;
        final boolean loopback;
        final Map<String, byte[]> cached = new HashMap<>(), used = new HashMap<>();
        final java.util.concurrent.atomic.AtomicLong networkBytes = new java.util.concurrent.atomic.AtomicLong();
        final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).followRedirects(HttpClient.Redirect.NEVER).build();
        int requests;
        int retryAfter;
        boolean network = true;
        boolean confirmed;
        int expectedSerial;

        Transport(List<String> origins, boolean loopback, Map<String, String> cached) {
            this.origins = Set.copyOf(origins);
            this.loopback = loopback;
            if (this.origins.isEmpty() || this.origins.size() > 16)
                throw new IllegalArgumentException("Bounded origins required");
            if (cached != null) {
                long total = 0;
                for (var entry : cached.entrySet()) {
                    byte[] value = Base64.getDecoder().decode(entry.getValue());
                    total += value.length;
                    if (value.length > CRL_LIMIT || total > 16 * 1024 * 1024)
                        throw new IllegalArgumentException("Cache limit");
                    this.cached.put(entry.getKey(), value);
                }
            }
        }

        static boolean nonPublic(InetAddress address) {
            if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress() || address.isSiteLocalAddress() || address.isMulticastAddress())
                return true;
            byte[] bytes = address.getAddress();
            if (bytes.length == 16) return (bytes[0] & 0xfe) == 0xfc;
            int a = bytes[0] & 255, b = bytes[1] & 255, c = bytes[2] & 255;
            return a == 0 || a >= 224 || a == 100 && (b & 0xc0) == 64 || a == 198 && (b == 18 || b == 19 || b == 51 && c == 100) || a == 192 && (b == 0 && (c == 0 || c == 2) || b == 88 && c == 99) || a == 203 && b == 0 && c == 113;
        }

        URI allowed(String value) throws IOException {
            return allowed(value, true);
        }

        URI allowed(String value, boolean resolve) throws IOException {
            URI original = URI.create(value);
            if (original.getHost() == null || original.getUserInfo() != null || original.getFragment() != null)
                throw new IOException("Invalid retrieval URI");
            URI target = original;
            // Public MDS signing certificates advertise HTTP CRL distribution points. Fetch the same path over HTTPS.
            if ("http".equals(original.getScheme()) && origins.contains("https://" + original.getHost()) && original.getPort() == -1)
                target = URI.create("https:" + value.substring(5));
            String origin = target.getScheme() + "://" + target.getHost() + (target.getPort() == -1 ? "" : ":" + target.getPort());
            if (!origins.contains(origin) || !("https".equals(target.getScheme()) || loopback && "http".equals(target.getScheme()) && Set.of("localhost", "127.0.0.1", "[::1]").contains(target.getHost())))
                throw new IOException("Retrieval origin forbidden");
            if (resolve) for (InetAddress address : InetAddress.getAllByName(target.getHost()))
                if (nonPublic(address) && !(loopback && address.isLoopbackAddress()))
                    throw new IOException("Non-public retrieval address");
            return target;
        }

        byte[] get(String url, int limit) throws IOException {
            // Validate even cache keys, so a cached object cannot introduce a forbidden origin.
            allowed(url, false);
            try {
                if (!network) throw new IOException("Offline verification");
                byte[] value = fetch(url, limit);
                used.put(url, value);
                return value;
            } catch (Exception failure) {
                byte[] value = cached.get(url);
                if (value == null) throw new IOException("Retrieval unavailable");
                used.put(url, value);
                return value;
            }
        }

        byte[] fetch(String url, int limit) throws IOException {
            URI target = allowed(url);
            int seconds = limit > CRL_LIMIT ? 8 : 4;
            if (++requests > 12) throw new IOException("Request budget");
            int bodyLimit = (int) Math.min(limit, 32L * 1024 * 1024 - networkBytes.get());
            if (bodyLimit <= 0) throw new IOException("Transfer budget");
            var request = HttpRequest.newBuilder(target).timeout(Duration.ofSeconds(seconds)).GET();
            if (limit > CRL_LIMIT && expectedSerial > 0) request.header("If-None-Match", "\"" + expectedSerial + "\"");
            CompletableFuture<HttpResponse<byte[]>> future = client.sendAsync(request.build(), info -> new LimitedBody(bodyLimit, networkBytes));
            try {
                var response = future.get(seconds, TimeUnit.SECONDS);
                if (limit > CRL_LIMIT && (response.statusCode() == 304 || response.statusCode() == 429) && expectedSerial > 0 && response.headers().firstValue("ETag").orElse("").replace("\"", "").equals(Integer.toString(expectedSerial)))
                    confirmed = true;
                if (response.statusCode() == 429 || response.statusCode() == 503) {
                    String value = response.headers().firstValue("Retry-After").orElse("3600");
                    try {
                        long secondsToWait;
                        try {
                            secondsToWait = Long.parseLong(value);
                        } catch (NumberFormatException date) {
                            secondsToWait = Duration.between(Instant.now(), java.time.ZonedDateTime.parse(value, java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME).toInstant()).getSeconds();
                        }
                        retryAfter = (int) Math.min(31L * 86400, Math.max(60, secondsToWait));
                    } catch (RuntimeException unknown) {
                        retryAfter = 3600;
                    }
                    requestedRetryAfter = retryAfter;
                }
                if (response.statusCode() != 200) throw new RetrievalFailure("http_" + response.statusCode());
                return response.body();
            } catch (Exception failed) {
                future.cancel(true);
                if (failed instanceof RetrievalFailure r) throw r;
                throw new RetrievalFailure(failed instanceof TimeoutException ? "timeout" : "transport");
            }
        }
    }

    static final class LimitedBody implements HttpResponse.BodySubscriber<byte[]> {
        final int maximum;
        final ByteArrayOutputStream data = new ByteArrayOutputStream();
        final CompletableFuture<byte[]> result = new CompletableFuture<>();
        final java.util.concurrent.atomic.AtomicLong budget;
        Flow.Subscription subscription;

        LimitedBody(int maximum, java.util.concurrent.atomic.AtomicLong budget) {
            this.maximum = maximum;
            this.budget = budget;
        }

        @Override
        public CompletionStage<byte[]> getBody() {
            return result;
        }

        @Override
        public void onSubscribe(Flow.Subscription value) {
            subscription = value;
            value.request(1);
        }

        @Override
        public void onNext(List<java.nio.ByteBuffer> buffers) {
            for (var buffer : buffers) {
                if (budget.addAndGet(buffer.remaining()) > 32L * 1024 * 1024 || data.size() + buffer.remaining() > maximum) {
                    subscription.cancel();
                    result.completeExceptionally(new IOException("Response byte limit"));
                    return;
                }
                byte[] bytes = new byte[buffer.remaining()];
                buffer.get(bytes);
                data.writeBytes(bytes);
            }
            subscription.request(1);
        }

        @Override
        public void onError(Throwable error) {
            result.completeExceptionally(error);
        }

        @Override
        public void onComplete() {
            result.complete(data.toByteArray());
        }
    }
}
