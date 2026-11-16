package com.example.iam.server.account;

import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice(assignableTypes = {AccountController.class, AccountAdminController.class})
public class AccountErrors {
    @ExceptionHandler({org.springframework.dao.DataAccessException.class, org.springframework.transaction.TransactionException.class})
    public ResponseEntity<ProblemDetail> unavailable(RuntimeException ignored) {
        return ResponseEntity.status(503).cacheControl(CacheControl.noStore()).body(ProblemDetail.forStatusAndDetail(HttpStatus.SERVICE_UNAVAILABLE, "Account service temporarily unavailable"));
    }

    @ExceptionHandler(org.springframework.dao.DataIntegrityViolationException.class)
    public ResponseEntity<ProblemDetail> conflict() {
        return ResponseEntity.status(409).cacheControl(CacheControl.noStore()).body(ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, "Account data conflict"));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ProblemDetail> invalid() {
        return ResponseEntity.badRequest().cacheControl(CacheControl.noStore()).body(ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "Invalid account request"));
    }
}
