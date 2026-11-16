package com.example.iam.server.session;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;

@ConfigurationProperties("iam.session")
public record SessionLifetime(@DefaultValue("PT20M") Duration idleTimeout,
                              @DefaultValue("PT8H") Duration absoluteTimeout) {
    public SessionLifetime {
        if (idleTimeout == null || absoluteTimeout == null || idleTimeout.getNano() != 0
                || absoluteTimeout.getNano() != 0 || idleTimeout.compareTo(Duration.ofSeconds(1)) < 0
                || idleTimeout.compareTo(Duration.ofDays(1)) > 0 || absoluteTimeout.compareTo(idleTimeout) < 0
                || absoluteTimeout.compareTo(Duration.ofDays(30)) > 0) {
            throw new IllegalArgumentException("Session lifetimes require whole seconds: idle 1s..1d, absolute idle..30d");
        }
    }

    public static SessionLifetime defaults() {
        return new SessionLifetime(Duration.ofMinutes(20), Duration.ofHours(8));
    }
}
