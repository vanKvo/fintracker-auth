package com.fintracker.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO (Data Transfer Object) for token refresh requests.
 * Contains the refresh token needed to obtain a new access token.
 * 
 * @author fintracker-auth
 * @version 1.0.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RefreshTokenRequest {

    /**
     * Token obtained from the initial login response.
     * Refresh token to obtain new access without requiring the user to log in again.
     */
    private String refreshToken;
}
