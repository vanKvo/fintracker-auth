package com.fintracker.auth.exception;

/**
 * Custom exception thrown when a user already exists in the system.
 * Typically raised during registration when attempting to create a user with a duplicate email.
 * 
 * @author fintracker-auth
 * @version 1.0.0
 */
public class UserAlreadyExistsException extends RuntimeException {

    /**
     * Constructs a UserAlreadyExistsException with the specified detail message.
     *
     * @param message the detail message
     */
    public UserAlreadyExistsException(String message) {
        super(message);
    }

    /**
     * Constructs a UserAlreadyExistsException with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause of the exception
     */
    public UserAlreadyExistsException(String message, Throwable cause) {
        super(message, cause);
    }
}
