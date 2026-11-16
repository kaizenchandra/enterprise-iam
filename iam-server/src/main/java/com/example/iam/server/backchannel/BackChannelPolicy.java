package com.example.iam.server.backchannel;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Explicit egress origins; never follow redirects or accept a request-supplied URL.
 */
@Component
public class BackChannelPolicy {
    private final Set<String> origins = new HashSet<>();
    private final boolean allowHttp;

    public BackChannelPolicy(@Value("${iam.backchannel.allowed-origins:}") String allowed,
                             @Value("${iam.backchannel.allow-http:false}") boolean allowHttp) {
        this.allowHttp = allowHttp;
        for (String origin : allowed.split(",")) if (!origin.isBlank()) origins.add(origin(URI.create(origin.trim())));
    }

    private String origin(URI uri) {
        if (uri.getHost() == null || uri.getUserInfo() != null || uri.getFragment() != null || !uri.isAbsolute()
                || !("https".equals(uri.getScheme()) || (allowHttp && "http".equals(uri.getScheme()))))
            throw new IllegalArgumentException("Invalid back-channel origin");
        return uri.getScheme() + "://" + uri.getHost().toLowerCase(Locale.ROOT) + (uri.getPort() == -1 ? "" : ":" + uri.getPort());
    }

    public URI validate(String endpoint) {
        URI uri = URI.create(endpoint);
        if (!origins.contains(origin(uri)) || endpoint.length() > 2048)
            throw new IllegalArgumentException("Back-channel origin not approved");
        return uri;
    }
}
