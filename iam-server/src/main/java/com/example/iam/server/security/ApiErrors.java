package com.example.iam.server.security;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ApiErrors {
    @ExceptionHandler(DataIntegrityViolationException.class)
    ResponseEntity<ProblemDetail> conflict() {
        return ResponseEntity.status(409).body(ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, "Resource conflicts with an existing record"));
    }
}
