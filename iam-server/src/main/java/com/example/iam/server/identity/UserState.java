package com.example.iam.server.identity;

public enum UserState {
    PENDING_VERIFICATION, ACTIVE, LOCKED, SUSPENDED, DISABLED, DELETED;

    public boolean canTransitionTo(UserState target) {
        return switch (this) {
            case PENDING_VERIFICATION -> target == ACTIVE || target == DELETED;
            case ACTIVE -> target == LOCKED || target == SUSPENDED || target == DISABLED || target == DELETED;
            case LOCKED, SUSPENDED -> target == ACTIVE || target == DISABLED || target == DELETED;
            case DISABLED -> target == ACTIVE || target == DELETED;
            case DELETED -> false;
        };
    }
}
