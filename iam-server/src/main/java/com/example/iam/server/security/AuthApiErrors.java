package com.example.iam.server.security;

import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

@RestControllerAdvice
public class AuthApiErrors {
    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<ProblemDetail> status(ResponseStatusException error) {
        int code = error.getStatusCode().value();
        String message = switch (code) {
            case 400 -> "Check your input or request a fresh link or code.";
            case 401 -> "Authentication failed. Check your credentials or sign in again.";
            case 403 -> "This operation is not permitted.";
            case 404 -> "This feature is not available.";
            case 409 -> "This operation conflicts with the current account state.";
            case 429 -> "Too many attempts. Wait before trying again.";
            default -> "Service unavailable. Try again shortly.";
        };
        return ResponseEntity.status(code).cacheControl(CacheControl.noStore()).body(ProblemDetail.forStatusAndDetail(error.getStatusCode(), message));
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ProblemDetail> authentication(AuthenticationException ignored) {
        return ResponseEntity.status(401).cacheControl(CacheControl.noStore()).body(ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, "Authentication failed. Check your credentials and account status."));
    }
}
