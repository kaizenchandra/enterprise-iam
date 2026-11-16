package com.example.iam.server.retention;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;

@ConfigurationProperties("iam.retention")
public record RetentionProperties(@DefaultValue("true") boolean enabled,
                                  @DefaultValue("100") int batchSize, @DefaultValue("P1D") Duration afterExpiry) {
    public RetentionProperties {
        if (batchSize < 1 || batchSize > 1000)
            throw new IllegalArgumentException("Retention batch size must be 1..1000");
        // The birth-time fence permits at most 60 seconds of issuer clock lead.
        if (afterExpiry == null || afterExpiry.compareTo(Duration.ofMinutes(2)) < 0)
            throw new IllegalArgumentException("Retention after expiry must be at least two minutes");
    }
}
