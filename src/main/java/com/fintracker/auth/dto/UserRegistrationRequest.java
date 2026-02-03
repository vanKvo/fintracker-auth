package com.fintracker.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO (Data Transfer Object) for user registration requests.
 * Contains the necessary information required to register a new user in the system.
 * 
 * @author fintracker-auth
 * @version 1.0.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserRegistrationRequest {

    /**
     * User's email address. Must be unique in the system.
     * Used as the primary identifier for Cognito User Pool.
     */
    private String email;

    /**
     * User's password. Must meet Cognito password policy requirements:
     * - Minimum 8 characters
     * - At least one uppercase letter
     * - At least one lowercase letter
     * - At least one number
     * - At least one special character
     */
    private String password;

    /**
     * User's full name for profile information.
     */
    private String fullName;
}
