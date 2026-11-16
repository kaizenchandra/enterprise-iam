package com.example.iam.server.retention;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

@Configuration
@EnableScheduling
@EnableConfigurationProperties(RetentionProperties.class)
public class RetentionScheduling {
    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(RetentionScheduling.class);
    private final RetentionCleanup cleanup;
    private final RetentionProperties properties;

    public RetentionScheduling(RetentionCleanup cleanup, RetentionProperties properties) {
        this.cleanup = cleanup;
        this.properties = properties;
    }

    @Scheduled(fixedDelayString = "${iam.retention.fixed-delay-ms:60000}", initialDelayString = "${iam.retention.initial-delay-ms:60000}")
    public void scheduled() {
        if (!properties.enabled()) return;
        try {
            cleanup.runBatch();
        } catch (RuntimeException e) {
            // No token values, SQL parameters or credential-bearing exception messages.
            LOG.warn("IAM retention batch failed ({})", e.getClass().getSimpleName());
        }
    }
}
