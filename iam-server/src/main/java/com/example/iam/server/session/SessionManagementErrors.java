package com.example.iam.server.session;

import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice(assignableTypes = SessionManagementController.class)
public class SessionManagementErrors {
    @ExceptionHandler({org.springframework.dao.DataAccessException.class, org.springframework.transaction.TransactionException.class})
    public ResponseEntity<ProblemDetail> unavailable(RuntimeException failure) {
        return ResponseEntity.status(503).cacheControl(CacheControl.noStore()).body(
                ProblemDetail.forStatusAndDetail(HttpStatus.SERVICE_UNAVAILABLE, "Session state is temporarily unavailable"));
    }
}
