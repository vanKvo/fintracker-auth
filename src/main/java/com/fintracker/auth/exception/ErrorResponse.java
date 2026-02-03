package com.fintracker.auth.exception;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Global error response DTO for API error responses.
 * Used by GlobalExceptionHandler to format all error responses consistently.
 * 
 * @author fintracker-auth
 * @version 1.0.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ErrorResponse {

    /**
     * HTTP status code of the error.
     */
    private int status;

    /**
     * Human-readable error message.
     */
    private String message;

    /**
     * Timestamp when the error occurred.
     */
    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime timestamp;

    /**
     * Error code for programmatic handling.
     */
    private String error;

    /**
     * Path of the request that caused the error.
     */
    private String path;
}
