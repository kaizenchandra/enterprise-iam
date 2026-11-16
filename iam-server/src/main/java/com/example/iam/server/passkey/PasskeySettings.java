package com.example.iam.server.passkey;

import com.example.iam.server.token.TrackedAuthorizationService;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.AttestationConveyancePreference;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

@Component
public class PasskeySettings {
    public final AttestationPolicy attestation;
    public final boolean enabled;
    public final RelyingParty relyingParty;
    public final String fingerprint;

    public PasskeySettings(PasskeyRepository repository, boolean enabled, String rpId, String origins, boolean http) {
        this(repository, enabled, rpId, origins, http, AttestationPolicy.none());
    }

    @org.springframework.beans.factory.annotation.Autowired
    public PasskeySettings(PasskeyRepository repository, @Value("${iam.passkey.enabled:false}") boolean enabled,
                           @Value("${iam.passkey.rp-id:localhost}") String rpId, @Value("${iam.passkey.origins:https://localhost:9000}") String origins,
                           @Value("${iam.passkey.allow-local-http:false}") boolean http, AttestationPolicy attestation) {
        this.enabled = enabled;
        this.attestation = attestation;
        Set<String> allowed = new TreeSet<>();
        for (String raw : origins.split(",")) {
            URI origin = URI.create(raw.strip());
            if (origin.getHost() == null || !origin.getHost().equals(rpId) || origin.getUserInfo() != null || origin.getQuery() != null || origin.getFragment() != null || !origin.getPath().isEmpty()
                    || !("https".equals(origin.getScheme()) || http && "http".equals(origin.getScheme()) && (rpId.equals("localhost") || rpId.endsWith(".localhost"))))
                throw new IllegalArgumentException("Invalid passkey origin/RP ID");
            allowed.add(origin.toString());
        }
        var builder = RelyingParty.builder().identity(RelyingPartyIdentity.builder().id(rpId).name("Enterprise IAM").build())
                .credentialRepository(repository).origins(allowed).allowOriginPort(false).allowOriginSubdomain(false)
                .attestationConveyancePreference(attestation.required ? AttestationConveyancePreference.DIRECT : AttestationConveyancePreference.NONE)
                .preferredPubkeyParams(List.of(PublicKeyCredentialParameters.ES256, PublicKeyCredentialParameters.RS256)).validateSignatureCounter(true);
        if (attestation.required) builder.attestationTrustSource(attestation).allowUntrustedAttestation(false);
        relyingParty = builder.build();
        fingerprint = TrackedAuthorizationService.digest(rpId + ":" + allowed + ":v2:uv-required:resident-required:ES256,RS256:" + attestation.required);
    }
}
