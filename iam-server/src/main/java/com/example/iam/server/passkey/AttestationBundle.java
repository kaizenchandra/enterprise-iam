package com.example.iam.server.passkey;

import com.example.iam.server.token.TrackedAuthorizationService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSObject;
import com.yubico.fido.metadata.*;
import com.yubico.webauthn.attestation.AttestationTrustSource;
import com.yubico.webauthn.data.ByteArray;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.*;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Offline, signed MDS-format metadata. Yubico performs JWS/PKIX verification, never the application.
 */
public final class AttestationBundle implements AttestationTrustSource {
    static final ObjectMapper JSON = new ObjectMapper(com.fasterxml.jackson.core.JsonFactory.builder().enable(com.fasterxml.jackson.core.StreamReadFeature.STRICT_DUPLICATE_DETECTION).build());
    static final Set<String> UNSAFE = Set.of("REVOKED", "RETIRED", "ATTESTATION_KEY_COMPROMISE", "USER_VERIFICATION_BYPASS", "USER_KEY_REMOTE_COMPROMISE", "USER_KEY_PHYSICAL_COMPROMISE", "UPDATE_AVAILABLE");
    final MetadataBLOB blob;
    final FidoMetadataService mds;
    final Set<X509Certificate> allowedRoots;
    final Set<UUID> revoked;
    final Map<UUID, Boolean> models;
    final String digest;
    final Instant expires;

    AttestationBundle(String jwt, Set<X509Certificate> signers, Set<X509Certificate> roots, Collection<CRL> crls, String legal, Clock clock) throws Exception {
        this(jwt, signers, roots, crls, legal, clock, null);
    }

    AttestationBundle(String jwt, Set<X509Certificate> signers, Set<X509Certificate> roots, Collection<CRL> crls, String legal, Clock clock, LiveMdsClient.Verified live) throws Exception {
        // The maintained downloader follows x5u/CRL URLs without per-request timeout hooks.
        // This offline profile rejects those URLs before invoking it. Provision CRLs alongside the BLOB.
        if (Boolean.parseBoolean(java.security.Security.getProperty("ocsp.enable")) || Boolean.getBoolean("com.sun.security.enableAIAcaIssuers"))
            throw new IllegalStateException("Offline metadata requires network PKIX discovery disabled");
        String[] segments = jwt.split("\\.", -1);
        if (segments.length != 3 || segments[0].length() > 65536)
            throw new IllegalArgumentException("Invalid metadata envelope");
        var header = JSON.readTree(Base64.getUrlDecoder().decode(segments[0]));
        if (header.has("x5u") || !header.path("x5c").isArray() || header.path("x5c").isEmpty() || header.path("x5c").size() > 8)
            throw new IllegalArgumentException("Offline metadata signing chain required");
        var unverified = JWSObject.parse(jwt);
        if (unverified.getHeader().getX509CertURL() != null)
            throw new IllegalArgumentException("Remote metadata certificate URL forbidden");
        if (unverified.getHeader().getX509CertChain() == null || unverified.getHeader().getX509CertChain().isEmpty())
            throw new IllegalArgumentException("Metadata signing chain required");
        Instant certificateDeadline = Instant.MAX;
        for (var encoded : unverified.getHeader().getX509CertChain()) {
            X509Certificate cert = certificate(encoded.decode());
            if (live == null && (cert.getExtensionValue("2.5.29.31") != null || cert.getExtensionValue("1.3.6.1.5.5.7.1.1") != null))
                throw new IllegalArgumentException("Offline signing chain cannot contain retrieval URLs");
            cert.checkValidity(Date.from(clock.instant()));
            if (cert.getNotAfter().toInstant().isBefore(certificateDeadline))
                certificateDeadline = cert.getNotAfter().toInstant();
        }
        Set<TrustAnchor> anchors = signers.stream().map(c -> new TrustAnchor(c, null)).collect(Collectors.toSet());
        for (var c : signers) {
            c.checkValidity(Date.from(clock.instant()));
            if (c.getNotAfter().toInstant().isBefore(certificateDeadline))
                certificateDeadline = c.getNotAfter().toInstant();
        }
        for (var crl : crls) {
            var value = (X509CRL) crl;
            if (value.getNextUpdate() == null || value.getThisUpdate().toInstant().isAfter(clock.instant()))
                throw new IllegalArgumentException("Invalid CRL validity");
            if (value.getNextUpdate().toInstant().isBefore(certificateDeadline))
                certificateDeadline = value.getNextUpdate().toInstant();
        }
        blob = live != null ? live.blob : FidoMetadataDownloader.builder().expectLegalHeader(legal).useTrustRoots(anchors).useBlob(jwt)
                .verifyDownloadsOnly(false).useCrls(crls).clock(clock).build().loadCachedBlob();
        if (!legal.equals(blob.getPayload().getLegalHeader()) || blob.getPayload().getNo() < 1)
            throw new IllegalArgumentException("Metadata header or serial invalid");
        Instant metadataDeadline = blob.getPayload().getNextUpdate().atStartOfDay(ZoneOffset.UTC).toInstant();
        Instant validationDeadline = live == null ? certificateDeadline : MdsVerifierWorker.min(certificateDeadline, live.deadline);
        expires = MdsVerifierWorker.min(metadataDeadline, validationDeadline);
        if (!expires.isAfter(clock.instant())) throw new IllegalArgumentException("Expired metadata");
        // Inspect status names before the library's UNKNOWN status normalization can discard them.
        var payload = JSON.readTree(unverified.getPayload().toBytes());
        Set<UUID> seen = new HashSet<>(), denied = new HashSet<>();
        if (!payload.path("entries").isArray() || payload.path("entries").size() > 10000)
            throw new IllegalArgumentException("Invalid metadata entry count");
        for (var entry : payload.path("entries")) {
            if (live != null && (!entry.hasNonNull("aaguid") || entry.path("aaguid").asText().equals("00000000-0000-0000-0000-000000000000")))
                continue;
            UUID id = UUID.fromString(entry.path("aaguid").asText());
            if (id.equals(new UUID(0, 0)) || !seen.add(id))
                throw new IllegalArgumentException("Missing or ambiguous FIDO2 model");
            if (!entry.path("statusReports").isArray() || entry.path("statusReports").isEmpty())
                throw new IllegalArgumentException("Missing authenticator status");
            if (entry.hasNonNull("rogueListURL") || entry.hasNonNull("rogueListHash")) denied.add(id);
            for (var report : entry.path("statusReports")) {
                String name = report.path("status").asText();
                AuthenticatorStatus status = AuthenticatorStatus.valueOf(name);
                if (status == AuthenticatorStatus.UNKNOWN)
                    throw new IllegalArgumentException("Unknown authenticator status");
                if (UNSAFE.contains(name)) denied.add(id);
            }
        }
        revoked = Set.copyOf(denied);
        allowedRoots = Set.copyOf(roots);
        mds = FidoMetadataService.builder().useBlob(blob).prefilter(entry -> entry.getAaguid().isPresent()
                        && !revoked.contains(UUID.fromString(entry.getAaguid().orElseThrow().asGuidString())))
                .filter(FidoMetadataService.Filters.noAttestationKeyCompromise()).build();
        var decisions = new HashMap<UUID, Boolean>();
        for (var entry : blob.getPayload().getEntries()) {
            if (live != null && (entry.getAaguid().isEmpty() || entry.getAaguid().orElseThrow().isZero())) continue;
            UUID id = UUID.fromString(entry.getAaguid().orElseThrow().asGuidString());
            boolean allowed = !revoked.contains(id) && entry.getMetadataStatement().map(m -> {
                var protection = m.getKeyProtection();
                return !protection.contains(com.yubico.webauthn.extension.uvm.KeyProtectionType.KEY_PROTECTION_SOFTWARE)
                        && !protection.contains(com.yubico.webauthn.extension.uvm.KeyProtectionType.KEY_PROTECTION_REMOTE_HANDLE)
                        && protection.stream().anyMatch(p -> p == com.yubico.webauthn.extension.uvm.KeyProtectionType.KEY_PROTECTION_HARDWARE || p == com.yubico.webauthn.extension.uvm.KeyProtectionType.KEY_PROTECTION_TEE || p == com.yubico.webauthn.extension.uvm.KeyProtectionType.KEY_PROTECTION_SECURE_ELEMENT)
                        && m.getAttestationRootCertificates().stream().anyMatch(allowedRoots::contains);
            }).orElse(false);
            decisions.put(id, allowed);
        }
        models = Map.copyOf(decisions);
        digest = TrackedAuthorizationService.digest(jwt);
    }

    static byte[] read(Path path, int maximum) throws IOException {
        if (!Files.isRegularFile(path)) throw new IOException("Missing provisioned file");
        try (var in = Files.newInputStream(path)) {
            byte[] bytes = in.readNBytes(maximum + 1);
            if (bytes.length > maximum) throw new IOException("Provisioned file exceeds limit");
            return bytes;
        }
    }

    static X509Certificate certificate(byte[] der) throws CertificateException {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
    }

    static Set<X509Certificate> certificates(Path path) throws Exception {
        var values = CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(read(path, 262144)));
        if (values.isEmpty() || values.size() > 32)
            throw new IllegalArgumentException("Trust root bundle must contain 1..32 certificates");
        var result = new HashSet<X509Certificate>();
        for (var c : values) {
            var cert = (X509Certificate) c;
            if (cert.getBasicConstraints() < 0) throw new IllegalArgumentException("CA trust root required");
            result.add(cert);
        }
        return Set.copyOf(result);
    }

    static List<X509Certificate> chain(String json) throws Exception {
        var result = new ArrayList<X509Certificate>();
        for (var node : JSON.readTree(json)) result.add(certificate(Base64.getDecoder().decode(node.asText())));
        if (result.isEmpty() || result.size() > 8)
            throw new IllegalArgumentException("Invalid stored attestation path");
        return result;
    }

    static String encode(List<X509Certificate> chain) throws Exception {
        var result = new ArrayList<String>();
        for (var c : chain) result.add(Base64.getEncoder().encodeToString(c.getEncoded()));
        return JSON.writeValueAsString(result);
    }

    @Override
    public TrustRootsResult findTrustRoots(List<X509Certificate> chain, Optional<ByteArray> aaguid) {
        if (aaguid.isEmpty() || !models.getOrDefault(AttestationPolicy.uuid(aaguid.get()), false) || mds.findEntries(new AAGUID(aaguid.get())).isEmpty())
            return TrustRootsResult.builder().trustRoots(Set.of()).build();
        Set<X509Certificate> roots = new HashSet<>(mds.findTrustRoots(chain, aaguid).getTrustRoots());
        roots.retainAll(allowedRoots);
        return TrustRootsResult.builder().trustRoots(roots).enableRevocationChecking(false).build();
    }

    /**
     * Re-evaluate a stored attestation path with current metadata/root policy using standard JCA PKIX.
     */
    boolean eligible(UUID model, List<X509Certificate> chain, Instant now) {
        if (chain.isEmpty() || !models.getOrDefault(model, false) || revoked.contains(model) || !expires.isAfter(now))
            return false;
        try {
            ByteArray aaguid = new ByteArray(java.nio.ByteBuffer.allocate(16).putLong(model.getMostSignificantBits()).putLong(model.getLeastSignificantBits()).array());
            for (var root : findTrustRoots(chain, Optional.of(aaguid)).getTrustRoots()) {
                try {
                    root.checkValidity(Date.from(now));
                    var path = new ArrayList<>(chain);
                    if (path.getLast().equals(root)) path.removeLast();
                    var params = new PKIXParameters(Set.of(new TrustAnchor(root, null)));
                    params.setRevocationEnabled(false);
                    params.setDate(Date.from(now));
                    CertPathValidator.getInstance("PKIX").validate(CertificateFactory.getInstance("X.509").generateCertPath(path), params);
                    return true;
                } catch (
                        java.security.GeneralSecurityException invalid) {/* try another explicitly allowed metadata root */}
            }
        } catch (RuntimeException invalid) {
            return false;
        }
        return false;
    }
}
