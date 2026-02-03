package com.fintracker.auth.exception;

/**
 * Custom exception thrown when token validation or processing fails.
 * Typically raised when tokens are expired, malformed, or invalid.
 * 
 * @author fintracker-auth
 * @version 1.0.0
 */
public class TokenException extends RuntimeException {

    /**
     * Constructs a TokenException with the specified detail message.
     *
     * @param message the detail message
     */
    public TokenException(String message) {
        super(message);
    }

    /**
     * Constructs a TokenException with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause of the exception
     */
    public TokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
