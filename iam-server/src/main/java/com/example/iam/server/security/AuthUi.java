package com.example.iam.server.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;

/**
 * Configured frontend destination; never accepts browser-supplied redirect targets.
 */
@Component
public class AuthUi {
    private final String origin;

    public AuthUi(@Value("${iam.frontend.auth-origin:http://localhost:3000}") String origin) {
        URI uri = URI.create(origin);
        if (uri.getHost() == null || uri.getUserInfo() != null || uri.getQuery() != null || uri.getFragment() != null
                || !uri.getPath().isEmpty() || !("https".equals(uri.getScheme()) || "http".equals(uri.getScheme())
                && (uri.getHost().equals("localhost") || uri.getHost().endsWith(".localhost"))))
            throw new IllegalArgumentException("Invalid authentication UI origin");
        this.origin = origin;
    }

    public String page(String path) {
        return origin + path;
    }
}
