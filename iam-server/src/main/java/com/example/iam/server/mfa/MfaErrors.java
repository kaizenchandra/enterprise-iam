package com.example.iam.server.mfa;

import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice(assignableTypes = MfaController.class)
public class MfaErrors {
    @ExceptionHandler({org.springframework.dao.DataAccessException.class, org.springframework.transaction.TransactionException.class})
    public ResponseEntity<ProblemDetail> unavailable(RuntimeException ignored) {
        return ResponseEntity.status(503).cacheControl(CacheControl.noStore()).body(ProblemDetail.forStatusAndDetail(HttpStatus.SERVICE_UNAVAILABLE, "Verification is temporarily unavailable"));
    }
}
