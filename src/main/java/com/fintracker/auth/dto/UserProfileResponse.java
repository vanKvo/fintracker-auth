package com.fintracker.auth.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * DTO (Data Transfer Object) for user profile responses.
 * Contains user information retrieved from Cognito User Pool.
 * 
 * @author fintracker-auth
 * @version 1.0.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserProfileResponse {

    /**
     * User's unique identifier (UUID from Cognito).
     */
    private String userId;

    /**
     * User's email address.
     */
    private String email;

    /**
     * User's full name.
     */
    private String fullName;

    /**
     * User's current role (e.g., "user" or "admin").
     */
    private String role;

    /**
     * Email verification status.
     */
    private Boolean emailVerified;

    /**
     * Timestamp when the user account was created.
     */
    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime createdAt;

    /**
     * Timestamp when the user profile was last updated.
     */
    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime updatedAt;
}
