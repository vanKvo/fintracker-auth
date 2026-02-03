package com.fintracker.auth.exception;

/**
 * Custom exception thrown when AWS Cognito operations fail.
 * Typically raised for errors communicating with Cognito service.
 * 
 * @author fintracker-auth
 * @version 1.0.0
 */
public class CognitoException extends RuntimeException {

    /**
     * Constructs a CognitoException with the specified detail message.
     *
     * @param message the detail message
     */
    public CognitoException(String message) {
        super(message);
    }

    /**
     * Constructs a CognitoException with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause of the exception
     */
    public CognitoException(String message, Throwable cause) {
        super(message, cause);
    }
}
