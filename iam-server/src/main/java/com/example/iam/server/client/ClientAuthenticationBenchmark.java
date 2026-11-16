package com.example.iam.server.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

/**
 * Fixed-loopback bounded operator workload. No private keys, assertions or responses are exported.
 */
public final class ClientAuthenticationBenchmark {
    private static final String ORIGIN = "http://127.0.0.1:19000", AUDIENCE = "http://localhost:19000/oauth2/token";
    private static final ObjectMapper JSON = new ObjectMapper();
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
    private final RSAKey key;
    private final String machineSecret = required("MACHINE_SECRET"), adminSecret = required("ADMIN_SECRET");

    private ClientAuthenticationBenchmark() throws Exception {
        key = new RSAKeyGenerator(2048).keyID("local-benchmark").keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256).generate();
    }

    private static String required(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) throw new IllegalStateException("Development input missing");
        return value;
    }

    private static String form(Map<String, String> values) {
        return values.entrySet().stream().map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8)).collect(Collectors.joining("&"));
    }

    private static String basic(String id, String secret) {
        return "Basic " + Base64.getEncoder().encodeToString((id + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }

    private static double rounded(double value) {
        return Math.round(value * 1000) / 1000.0;
    }

    public static void main(String[] args) {
        try {
            if (args.length != 1) throw new IllegalArgumentException("One output path required");
            Files.deleteIfExists(Path.of(args[0]));
            var benchmark = new ClientAuthenticationBenchmark();
            benchmark.provision();
            var baseline = benchmark.workload(false);
            var asymmetric = benchmark.workload(true);
            var report = new LinkedHashMap<String, Object>();
            report.put("kind", "bounded-local-client-authentication-comparison");
            report.put("recordedAt", Instant.now().toString());
            report.put("javaVersion", System.getProperty("java.version"));
            report.put("platform", System.getProperty("os.name"));
            report.put("arch", System.getProperty("os.arch"));
            report.put("hostLogicalCpus", Runtime.getRuntime().availableProcessors());
            report.put("opMaxHeapMiB", 256);
            report.put("assertionAlgorithm", "RS256");
            report.put("clientRsaBits", 2048);
            report.put("assertionLifetimeSeconds", 30);
            report.put("bcryptCost", 12);
            report.put("runs", List.of(baseline, asymmetric));
            report.put("limits", List.of("Two sequential 50-request runs at 5 requests/second; same Java HTTP driver, client identity, issuer, scopes, signing keys and isolated database",
                    "Three warmups per method excluded; client assertion signing, HTTP and durable replay commits included in asymmetric latency",
                    "Basic first, asymmetric second: order, warm caches and shared-host contention can affect comparison; no CPU/wall-time attribution",
                    "Localhost HTTP, 256 MiB IAM heap, small data, same-host PostgreSQL/Redis/JVMs; no production capacity, saturation, soak or SLO claim",
                    "p99 is the observed maximum of 50 samples per method; server security controls and BCrypt cost preserved; no reusable credentials exported"));
            Path target = Path.of(args[0]);
            Files.createDirectories(target.toAbsolutePath().getParent());
            JSON.writerWithDefaultPrettyPrinter().writeValue(target.toFile(), report);
            for (var run : List.of(baseline, asymmetric))
                if (!Integer.valueOf(50).equals(run.get("successful")) || !Integer.valueOf(0).equals(run.get("dropped")))
                    throw new IllegalStateException("Workload errors recorded");
            System.out.println("PASS: bounded secret/private_key_jwt comparison; aggregate measurements saved");
        } catch (Exception failed) {
            System.err.println("Local client authentication benchmark failed; inspect sanitized application logs and aggregate report");
            System.exit(1);
        }
    }

    private HttpResponse<String> post(Map<String, String> values, String authorization) throws Exception {
        var request = HttpRequest.newBuilder(URI.create(ORIGIN + "/oauth2/token")).timeout(Duration.ofSeconds(3)).header("Content-Type", "application/x-www-form-urlencoded");
        if (authorization != null) request.header("Authorization", authorization);
        return http.send(request.POST(HttpRequest.BodyPublishers.ofString(form(values))).build(), HttpResponse.BodyHandlers.ofString());
    }

    private void provision() throws Exception {
        var response = post(Map.of("grant_type", "client_credentials", "scope", "iam.admin"), basic("admin-cli", adminSecret));
        if (response.statusCode() != 200) throw new IllegalStateException("Admin authorization unavailable");
        String token = JSON.readTree(response.body()).path("access_token").asText();
        if (token.isBlank()) throw new IllegalStateException("Admin token missing");
        String body = JSON.writeValueAsString(Map.of("expectedRevision", 0, "jwks", new JWKSet(key.toPublicJWK()).toJSONObject()));
        var updated = http.send(HttpRequest.newBuilder(URI.create(ORIGIN + "/api/v1/admin/clients/order-service/authentication-keys")).timeout(Duration.ofSeconds(5))
                .header("Authorization", "Bearer " + token).header("Content-Type", "application/json").PUT(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.discarding());
        if (updated.statusCode() != 200) throw new IllegalStateException("Public-key provisioning unavailable");
    }

    private String assertion() throws Exception {
        Instant now = Instant.now();
        var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).keyID(key.getKeyID()).build(),
                new JWTClaimsSet.Builder().issuer("order-service").subject("order-service").audience(AUDIENCE).issueTime(Date.from(now)).expirationTime(Date.from(now.plusSeconds(30))).jwtID(UUID.randomUUID().toString()).build());
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    private Sample token(boolean asymmetric) {
        long start = System.nanoTime();
        int status = 0;
        try {
            var values = new HashMap<>(Map.of("grant_type", "client_credentials", "scope", "orders.read"));
            if (asymmetric) {
                values.put("client_id", "order-service");
                values.put("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
                values.put("client_assertion", assertion());
            }
            var response = post(values, asymmetric ? null : basic("order-service", machineSecret));
            status = response.statusCode();
            if (status == 200) {
                if (response.body().length() > 65536) status = 0;
                else {
                    var body = JSON.readTree(response.body());
                    if (body.path("access_token").asText().isBlank() || !"Bearer".equalsIgnoreCase(body.path("token_type").asText()) || !"orders.read".equals(body.path("scope").asText()))
                        status = 0;
                }
            }
        } catch (Exception unavailable) {
            status = 0;
        }
        return new Sample(status, (System.nanoTime() - start) / 1_000_000.0);
    }

    private Map<String, Object> workload(boolean asymmetric) throws Exception {
        for (int i = 0; i < 3; i++)
            if (token(asymmetric).status() != 200) throw new IllegalStateException("Warmup failed");
        var pool = new ThreadPoolExecutor(8, 8, 0, TimeUnit.MILLISECONDS, new SynchronousQueue<>());
        pool.prestartAllCoreThreads();
        var futures = new ArrayList<Future<Sample>>();
        int dropped = 0;
        double schedulingLag = 0;
        long start = System.nanoTime();
        Instant started = Instant.now();
        try {
            for (int i = 0; i < 50; i++) {
                long due = start + i * 200_000_000L, wait = due - System.nanoTime();
                if (wait > 0) TimeUnit.NANOSECONDS.sleep(wait);
                schedulingLag = Math.max(schedulingLag, (System.nanoTime() - due) / 1_000_000.0);
                try {
                    futures.add(pool.submit(() -> token(asymmetric)));
                } catch (RejectedExecutionException full) {
                    dropped++;
                }
            }
            var results = new ArrayList<Sample>();
            for (var future : futures) results.add(future.get(5, TimeUnit.SECONDS));
            double elapsed = (System.nanoTime() - start) / 1_000_000_000.0;
            int successes = (int) results.stream().filter(s -> s.status() == 200).count();
            double[] latencies = results.stream().mapToDouble(Sample::milliseconds).sorted().toArray();
            var statuses = new TreeMap<String, Integer>();
            for (var sample : results) statuses.merge(Integer.toString(sample.status()), 1, Integer::sum);
            var output = new LinkedHashMap<String, Object>();
            output.put("authenticationMethod", asymmetric ? "private_key_jwt" : "client_secret_basic");
            output.put("startedAt", started.toString());
            output.put("offeredRatePerSecond", 5);
            output.put("offeredRequests", 50);
            output.put("durationSeconds", 10);
            output.put("maxConcurrency", 8);
            output.put("attempted", results.size());
            output.put("successful", successes);
            output.put("errors", results.size() - successes);
            output.put("dropped", dropped);
            output.put("statuses", statuses);
            output.put("elapsedSeconds", rounded(elapsed));
            output.put("achievedSuccessesPerSecond", rounded(successes / elapsed));
            output.put("maxClientSchedulingLagMs", rounded(schedulingLag));
            if (latencies.length > 0)
                output.put("latencyMs", Map.of("p50", rounded(latencies[(int) Math.ceil(.50 * latencies.length) - 1]), "p95", rounded(latencies[(int) Math.ceil(.95 * latencies.length) - 1]), "p99", rounded(latencies[(int) Math.ceil(.99 * latencies.length) - 1])));
            return output;
        } finally {
            pool.shutdownNow();
            pool.awaitTermination(5, TimeUnit.SECONDS);
        }
    }

    private record Sample(int status, double milliseconds) {
    }
}
