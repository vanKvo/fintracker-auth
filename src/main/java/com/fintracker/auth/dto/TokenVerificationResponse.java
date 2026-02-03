package com.fintracker.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

/**
 * DTO (Data Transfer Object) for token verification responses.
 * Contains validation status and decoded token claims.
 * 
 * @author fintracker-auth
 * @version 1.0.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenVerificationResponse {

    /**
     * Indicates whether the token is valid and not expired.
     */
    private Boolean valid;

    /**
     * User ID (subject) extracted from the token.
     */
    private String userId;

    /**
     * Username extracted from the token claims.
     */
    private String username;

    /**
     * User's email extracted from the token claims.
     */
    private String email;

    /**
     * All claims contained in the JWT token.
     * Includes standard claims and any custom claims added by Cognito.
     */
    private Map<String, Object> claims;

    /**
     * Error message if token verification failed.
     */
    private String errorMessage;
}
