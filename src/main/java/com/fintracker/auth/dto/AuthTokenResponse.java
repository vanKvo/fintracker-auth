package com.fintracker.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO (Data Transfer Object) for authentication token responses.
 * Contains tokens and metadata returned after successful user authentication.
 * 
 * @author fintracker-auth
 * @version 1.0.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthTokenResponse {

    /**
     * JWT access token used to authenticate API requests.
     * Short-lived token (typically valid for 1 hour).
     * Include in Authorization header as "Bearer <access_token>"
     */
    private String accessToken;

    /**
     * JWT refresh token used to obtain a new access token without re-authenticating.
     * Long-lived token (typically valid for 30 days).
     */
    private String refreshToken;

    /**
     * JWT ID token containing user identity information.
     * Contains user claims like email, name, etc.
     */
    private String idToken;

    /**
     * Type of token (typically "Bearer").
     */
    private String tokenType;

    /**
     * Time in seconds until the access token expires.
     */
    private Integer expiresIn;

    /**
     * When Cognito returns a challenge (SRP flow), this is the challenge name
     * (for example: PASSWORD_VERIFIER). Present during two-step SRP authentication.
     */
    private String challengeName;

    /**
     * When Cognito returns a challenge, the parameters required for the client to
     * compute the challenge response (e.g. SRP_B, SALT, SECRET_BLOCK).
     */
    private java.util.Map<String, String> challengeParameters;

    /**
     * Session token returned from Cognito during initiateAuth. Client must pass it back
     * when responding to a challenge (used in RespondToAuthChallenge requests).
     */
    private String session;
}
