package com.fintracker.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO (Data Transfer Object) for user login requests.
 * Contains the credentials required to authenticate a user.
 * 
 * @author fintracker-auth
 * @version 1.0.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserLoginRequest {

    /**
     * User's email address registered in the system.
     */
    private String email;

    /**
     * User's password for authentication.
     */
    private String password;

    /**
     * Optional SRP_A value (client-generated ephemeral) used for USER_SRP_AUTH flow.
     * If provided without challengeResponses and session, this call is the SRP initiation
     * and will return a challenge (e.g. PASSWORD_VERIFIER) that the client must complete.
     */
    private String srpA;

    /**
     * Optional session string returned from Cognito during initiateAuth. Required when
     * responding to an SRP challenge (the client should pass it back with challenge responses).
     */
    private String session;

    /**
     * The challenge name which the client is responding to (e.g. PASSWORD_VERIFIER).
     * Required when sending challengeResponses and session back to Cognito.
     */
    private String challengeName;

    /**
     * Optional challenge responses map used to respond to Cognito SRP challenges.
     * Keys and values are application-specific (e.g. PASSWORD_CLAIM_SIGNATURE,
     * TIMESTAMP, PASSWORD_CLAIM_SECRET_BLOCK) and are provided by the client
     * after performing SRP calculations.
     */
    private java.util.Map<String, String> challengeResponses;
}
