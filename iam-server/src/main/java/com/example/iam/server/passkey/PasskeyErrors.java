package com.example.iam.server.passkey;

import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice(assignableTypes = PasskeyController.class)
public class PasskeyErrors {
    @ExceptionHandler({org.springframework.dao.DataAccessException.class, org.springframework.transaction.TransactionException.class})
    public ResponseEntity<ProblemDetail> unavailable(RuntimeException ignored) {
        return ResponseEntity.status(503).cacheControl(CacheControl.noStore()).body(ProblemDetail.forStatusAndDetail(HttpStatus.SERVICE_UNAVAILABLE, "Passkey state is unavailable"));
    }

    @ExceptionHandler({IllegalArgumentException.class, java.io.IOException.class})
    public ResponseEntity<ProblemDetail> malformed(Exception ignored) {
        return ResponseEntity.badRequest().cacheControl(CacheControl.noStore()).body(ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "Invalid passkey request"));
    }
}
