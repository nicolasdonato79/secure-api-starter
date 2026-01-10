package com.ndsolutions.secureapi.common.error;

import org.slf4j.MDC;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiError> badCreds(BadCredentialsException ex) {
        return ResponseEntity.status(401).body(err("AUTH_INVALID_CREDENTIALS", "Credenciales inválidas"));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiError> badRequest(IllegalArgumentException ex) {
        return ResponseEntity.badRequest().body(err("BAD_REQUEST", ex.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> generic(Exception ex) {
        return ResponseEntity.status(500).body(err("INTERNAL_ERROR", "Error inesperado"));
    }

    private ApiError err(String code, String msg) {
        String rid = MDC.get("requestId");
        return new ApiError(code, msg, rid);
    }
}
