package com.fintracker.auth.exception;

/**
 * Custom exception thrown when authentication fails.
 * Typically raised during login attempts with invalid credentials.
 * 
 * @author fintracker-auth
 * @version 1.0.0
 */
public class AuthenticationException extends RuntimeException {

    /**
     * Constructs an AuthenticationException with the specified detail message.
     *
     * @param message the detail message
     */
    public AuthenticationException(String message) {
        super(message);
    }

    /**
     * Constructs an AuthenticationException with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause of the exception
     */
    public AuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
