package com.example.iam.server;

import com.example.iam.server.retention.RetentionCleanup;
import com.example.iam.server.retention.RetentionProperties;
import com.example.iam.server.retention.RetentionScheduling;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

class RetentionSchedulingTest {
    @Test
    void disabledSchedulerDoesNoWork() {
        var cleanup = mock(RetentionCleanup.class);
        new RetentionScheduling(cleanup, new RetentionProperties(false, 100, Duration.ofDays(1))).scheduled();
        verifyNoInteractions(cleanup);
    }

    @Test
    void scheduledFailureDoesNotDisableNextInvocation() {
        var cleanup = mock(RetentionCleanup.class);
        when(cleanup.runBatch()).thenThrow(new IllegalStateException("test failure"))
                .thenReturn(new RetentionCleanup.Result(0, 0, 0, 0, 0, 0, 0, 0));
        var schedule = new RetentionScheduling(cleanup, new RetentionProperties(true, 100, Duration.ofDays(1)));
        assertDoesNotThrow(schedule::scheduled);
        assertDoesNotThrow(schedule::scheduled);
        verify(cleanup, times(2)).runBatch();
    }

    @Test
    void springActuallyInvokesScheduledCleanupAndBindsDefaults() throws Exception {
        var cleanup = mock(RetentionCleanup.class);
        var ran = new java.util.concurrent.CountDownLatch(2);
        when(cleanup.runBatch()).thenAnswer(call -> {
            ran.countDown();
            return new RetentionCleanup.Result(0, 0, 0, 0, 0, 0, 0, 0);
        });
        try (var context = new org.springframework.context.annotation.AnnotationConfigApplicationContext()) {
            context.getEnvironment().getPropertySources().addFirst(new org.springframework.core.env.MapPropertySource("test-cadence",
                    java.util.Map.of("iam.retention.fixed-delay-ms", "20", "iam.retention.initial-delay-ms", "0")));
            context.registerBean(RetentionCleanup.class, () -> cleanup);
            context.register(RetentionScheduling.class);
            context.refresh();
            assertTrue(context.getBean(RetentionProperties.class).enabled());
            assertTrue(ran.await(5, java.util.concurrent.TimeUnit.SECONDS));
        }
        verify(cleanup, atLeast(2)).runBatch();
    }

}
