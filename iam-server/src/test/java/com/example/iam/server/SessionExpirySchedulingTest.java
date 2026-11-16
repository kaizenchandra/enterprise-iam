package com.example.iam.server;

import com.example.iam.server.session.SessionExpiry;
import com.example.iam.server.token.TrackedAuthorizationService;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.MapPropertySource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.transaction.PlatformTransactionManager;

import javax.sql.DataSource;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

class SessionExpirySchedulingTest {
    SessionExpiry worker(boolean enabled) {
        return spy(new SessionExpiry(new JdbcTemplate(mock(DataSource.class)), mock(PlatformTransactionManager.class),
                mock(TrackedAuthorizationService.class), new SimpleMeterRegistry(), enabled, 100));
    }

    @Test
    void disabledSchedulerDoesNotPoll() {
        var worker = worker(false);
        worker.scheduled();
        verify(worker, never()).runBatch();
    }

    @Test
    void failureDoesNotDisableLaterInvocation() {
        var worker = worker(true);
        doThrow(new IllegalStateException("injected outage")).doReturn(1).when(worker).runBatch();
        assertDoesNotThrow(worker::scheduled);
        assertDoesNotThrow(worker::scheduled);
        verify(worker, times(2)).runBatch();
    }

    @Test
    void springActuallyInvokesExpiryOnConfiguredCadence() throws Exception {
        var worker = worker(true);
        var ran = new CountDownLatch(2);
        doAnswer(call -> {
            ran.countDown();
            return 0;
        }).when(worker).runBatch();
        try (var context = new AnnotationConfigApplicationContext()) {
            context.getEnvironment().getPropertySources().addFirst(new MapPropertySource("test-cadence", java.util.Map.of(
                    "iam.session.expiry-fixed-delay-ms", "20", "iam.session.expiry-initial-delay-ms", "0")));
            context.registerBean(SessionExpiry.class, () -> worker);
            context.register(Scheduling.class);
            context.refresh();
            assertTrue(ran.await(5, TimeUnit.SECONDS));
        }
        verify(worker, atLeast(2)).runBatch();
    }

    @Configuration
    @EnableScheduling
    static class Scheduling {
    }
}
