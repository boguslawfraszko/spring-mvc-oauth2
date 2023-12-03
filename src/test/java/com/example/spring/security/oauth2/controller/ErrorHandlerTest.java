package com.example.spring.security.oauth2.controller;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class ErrorHandlerTest {
    private ErrorHandler errorHandler = new ErrorHandler();

    @Test
    void handleExceptionTest() {
        Assertions.assertTrue(errorHandler.handleException(new RuntimeException("error")).getStatusCode().is5xxServerError());
    }
}
