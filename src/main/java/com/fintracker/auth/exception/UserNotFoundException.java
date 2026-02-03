package com.fintracker.auth.exception;

/**
 * Custom exception thrown when a user is not found.
 * Typically raised when attempting to access or update a non-existent user.
 * 
 * @author fintracker-auth
 * @version 1.0.0
 */
public class UserNotFoundException extends RuntimeException {

    /**
     * Constructs a UserNotFoundException with the specified detail message.
     *
     * @param message the detail message
     */
    public UserNotFoundException(String message) {
        super(message);
    }

    /**
     * Constructs a UserNotFoundException with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause of the exception
     */
    public UserNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
