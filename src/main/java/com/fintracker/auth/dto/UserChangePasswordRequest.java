package com.fintracker.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO (Data Transfer Object) for user password change requests.
 * Contains the current password and new password for changing user credentials.
 * 
 * @author fintracker-auth
 * @version 1.0.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserChangePasswordRequest {

    /**
     * User's current (existing) password for verification.
     */
    private String currentPassword;

    /**
     * User's new password. Must meet Cognito password policy requirements.
     */
    private String newPassword;
}
