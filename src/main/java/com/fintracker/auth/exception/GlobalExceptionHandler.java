package com.fintracker.auth.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.time.LocalDateTime;

/**
 * Global exception handler for all authentication service exceptions.
 * Centralizes error handling across all controllers and provides consistent error response format.
 * 
 * Handles the following exception types:
 * - AuthenticationException: Login failures
 * - UserNotFoundException: User not found errors
 * - UserAlreadyExistsException: Duplicate user registration attempts
 * - TokenException: Token validation failures
 * - CognitoException: AWS Cognito operation failures
 * - General exceptions and validation errors
 * 
 * All errors are returned as JSON with consistent format:
 * {
 *   "status": 401,
 *   "message": "Invalid email or password",
 *   "error": "AUTHENTICATION_FAILED",
 *   "timestamp": "2025-11-20T10:30:00",
 *   "path": "/auth/login"
 * }
 * 
 * @author fintracker-auth
 * @version 1.0.0
 */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    /**
     * Handles authentication failures (invalid credentials).
     * 
     * Returns HTTP 401 Unauthorized when user provides invalid email or password.
     * 
     * @param ex AuthenticationException thrown during login
     * @param request the current web request
     * @return ResponseEntity with error details and 401 status
     */
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorResponse> handleAuthenticationException(
            AuthenticationException ex,
            WebRequest request) {
        log.error("Authentication exception occurred: {}", ex.getMessage());

        ErrorResponse errorResponse = ErrorResponse.builder()
                .status(HttpStatus.UNAUTHORIZED.value())
                .message(ex.getMessage())
                .error("AUTHENTICATION_FAILED")
                .timestamp(LocalDateTime.now())
                .path(request.getDescription(false).replace("uri=", ""))
                .build();

        return new ResponseEntity<>(errorResponse, HttpStatus.UNAUTHORIZED);
    }

    /**
     * Handles user not found errors.
     * 
     * Returns HTTP 404 Not Found when attempting to access a non-existent user.
     * 
     * @param ex UserNotFoundException thrown when user doesn't exist
     * @param request the current web request
     * @return ResponseEntity with error details and 404 status
     */
    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleUserNotFoundException(
            UserNotFoundException ex,
            WebRequest request) {
        log.error("User not found exception occurred: {}", ex.getMessage());

        ErrorResponse errorResponse = ErrorResponse.builder()
                .status(HttpStatus.NOT_FOUND.value())
                .message(ex.getMessage())
                .error("USER_NOT_FOUND")
                .timestamp(LocalDateTime.now())
                .path(request.getDescription(false).replace("uri=", ""))
                .build();

        return new ResponseEntity<>(errorResponse, HttpStatus.NOT_FOUND);
    }

    /**
     * Handles duplicate user registration attempts.
     * 
     * Returns HTTP 409 Conflict when attempting to register with an email that already exists.
     * 
     * @param ex UserAlreadyExistsException thrown during registration
     * @param request the current web request
     * @return ResponseEntity with error details and 409 status
     */
    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<ErrorResponse> handleUserAlreadyExistsException(
            UserAlreadyExistsException ex,
            WebRequest request) {
        log.error("User already exists exception occurred: {}", ex.getMessage());

        ErrorResponse errorResponse = ErrorResponse.builder()
                .status(HttpStatus.CONFLICT.value())
                .message(ex.getMessage())
                .error("USER_ALREADY_EXISTS")
                .timestamp(LocalDateTime.now())
                .path(request.getDescription(false).replace("uri=", ""))
                .build();

        return new ResponseEntity<>(errorResponse, HttpStatus.CONFLICT);
    }

    /**
     * Handles token-related errors (invalid, expired, or malformed tokens).
     * 
     * Returns HTTP 401 Unauthorized when token validation fails.
     * 
     * @param ex TokenException thrown during token operations
     * @param request the current web request
     * @return ResponseEntity with error details and 401 status
     */
    @ExceptionHandler(TokenException.class)
    public ResponseEntity<ErrorResponse> handleTokenException(
            TokenException ex,
            WebRequest request) {
        log.error("Token exception occurred: {}", ex.getMessage());

        ErrorResponse errorResponse = ErrorResponse.builder()
                .status(HttpStatus.UNAUTHORIZED.value())
                .message(ex.getMessage())
                .error("INVALID_TOKEN")
                .timestamp(LocalDateTime.now())
                .path(request.getDescription(false).replace("uri=", ""))
                .build();

        return new ResponseEntity<>(errorResponse, HttpStatus.UNAUTHORIZED);
    }

    /**
     * Handles AWS Cognito service errors.
     * 
     * Returns HTTP 500 Internal Server Error when Cognito operations fail.
     * Logs detailed error information for troubleshooting.
     * 
     * @param ex CognitoException thrown when Cognito operations fail
     * @param request the current web request
     * @return ResponseEntity with error details and 500 status
     */
    @ExceptionHandler(CognitoException.class)
    public ResponseEntity<ErrorResponse> handleCognitoException(
            CognitoException ex,
            WebRequest request) {
        log.error("Cognito exception occurred: {}", ex.getMessage(), ex);

        ErrorResponse errorResponse = ErrorResponse.builder()
                .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                .message("An error occurred during authentication. Please try again later.")
                .error("COGNITO_ERROR")
                .timestamp(LocalDateTime.now())
                .path(request.getDescription(false).replace("uri=", ""))
                .build();

        return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    /**
     * Handles validation errors and bad requests.
     * 
     * Returns HTTP 400 Bad Request for invalid input or validation failures.
     * Common cases include:
     * - Malformed JSON
     * - Invalid password format
     * - Missing required fields
     * 
     * @param ex IllegalArgumentException for validation errors
     * @param request the current web request
     * @return ResponseEntity with error details and 400 status
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgumentException(
            IllegalArgumentException ex,
            WebRequest request) {
        log.warn("Illegal argument exception occurred: {}", ex.getMessage());

        ErrorResponse errorResponse = ErrorResponse.builder()
                .status(HttpStatus.BAD_REQUEST.value())
                .message(ex.getMessage())
                .error("INVALID_INPUT")
                .timestamp(LocalDateTime.now())
                .path(request.getDescription(false).replace("uri=", ""))
                .build();

        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }

    /**
     * Handles all unexpected exceptions not caught by specific handlers.
     * 
     * Returns HTTP 500 Internal Server Error for unhandled exceptions.
     * Logs full stack trace for debugging.
     * 
     * @param ex generic Exception
     * @param request the current web request
     * @return ResponseEntity with generic error message and 500 status
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGlobalException(
            Exception ex,
            WebRequest request) {
        log.error("Unexpected exception occurred", ex);

        ErrorResponse errorResponse = ErrorResponse.builder()
                .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                .message("An unexpected error occurred. Please try again later.")
                .error("INTERNAL_ERROR")
                .timestamp(LocalDateTime.now())
                .path(request.getDescription(false).replace("uri=", ""))
                .build();

        return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
