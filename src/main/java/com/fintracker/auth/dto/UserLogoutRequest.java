package com.fintracker.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO (Data Transfer Object) for user logout requests.
 * Contains the access token to be invalidated.
 * 
 * @author fintracker-auth
 * @version 1.0.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserLogoutRequest {

    /**
     * User's current access token to be invalidated.
     * After logout, this token should not be usable for API requests.
     */
    private String accessToken;
}
