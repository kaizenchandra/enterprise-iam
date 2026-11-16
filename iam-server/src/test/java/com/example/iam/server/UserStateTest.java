package com.example.iam.server;

import com.example.iam.server.identity.UserState;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UserStateTest {
    @Test
    void deletionIsTerminal() {
        for (var next : UserState.values()) assertFalse(UserState.DELETED.canTransitionTo(next));
    }

    @Test
    void activationRequiresExplicitTransition() {
        assertTrue(UserState.PENDING_VERIFICATION.canTransitionTo(UserState.ACTIVE));
        assertFalse(UserState.PENDING_VERIFICATION.canTransitionTo(UserState.LOCKED));
    }
}
