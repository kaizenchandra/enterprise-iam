package com.example.iam.server.client;

import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(name = "iam.client-assertion.cleanup-enabled", matchIfMissing = true)
public class ClientAssertionRetention {
    private final ClientAssertionReplayStore store;
    private final MeterRegistry meters;

    public ClientAssertionRetention(ClientAssertionReplayStore store, MeterRegistry meters) {
        this.store = store;
        this.meters = meters;
    }

    @Scheduled(fixedDelayString = "${iam.client-assertion.cleanup-delay-ms:60000}", initialDelayString = "${iam.client-assertion.cleanup-delay-ms:60000}")
    public void cleanup() {
        try {
            store.cleanup();
        } catch (RuntimeException unavailable) {
            meters.counter("iam.client.assertion.cleanup.failures").increment();
        }
    }
}
