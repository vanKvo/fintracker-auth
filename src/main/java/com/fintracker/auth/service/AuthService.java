package com.fintracker.auth.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fintracker.auth.dto.*;
import com.fintracker.auth.exception.*;
import com.fintracker.auth.exception.UserNotFoundException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.HashMap;
import java.util.Map;

/**
 * Implementation of OAuth 2.0 authentication service using AWS Cognito.
 * 
 * This service handles all authentication operations by communicating with AWS Cognito User Pools.
 * It provides user registration, login, token management, and session handling with comprehensive
 * error handling and logging.
 * 
 * Key responsibilities:
 * - User registration and account creation in Cognito
 * - User authentication and token issuance
 * - Token refresh and renewal
 * - Token validation and verification
 * - User profile and password management
 * - Session management and logout
 * 
 * All passwords are hashed and stored securely by AWS Cognito. This service never handles
 * password verification directly but delegates to Cognito's secure authentication APIs.
 * 
 * @author fintracker-auth
 * @version 1.0.0
 */
@Slf4j
@Service
public class AuthService implements IAuthService {

    private final CognitoIdentityProviderClient cognitoClient;

    @Value("${aws.cognito.user-pool-id}")
    private String userPoolId;

    @Value("${aws.cognito.client-id}")
    private String clientId;

    /**
     * Constructs an AuthService with the provided Cognito client.
     *
     * @param cognitoClient the AWS Cognito Identity Provider client
     */
    public AuthService(CognitoIdentityProviderClient cognitoClient) {
        this.cognitoClient = cognitoClient;
    }

    /**
     * Registers a new user in the Cognito User Pool.
     * 
     * Creates a user account with the provided email, password, and full name.
     * The email is used as the username for Cognito authentication.
     * 
     * Process:
     * 1. Validates input parameters
     * 2. Calls Cognito SignUp API to create the user account
     * 3. Sets user attributes (email, name)
     * 4. Returns the newly created user's profile information
     * 
     * @param request contains email, password, and full name
     * @return UserProfileResponse with newly created user information
     * @throws UserAlreadyExistsException if user with email already exists
     * @throws CognitoException if Cognito operation fails
     * @throws IllegalArgumentException if input validation fails
     */
    @Override
    public UserProfileResponse registerUser(UserRegistrationRequest request) {
        try {
            log.info("Attempting to register user with email: {}", request.getEmail());

            // Call Cognito SignUp API
            SignUpResponse response = cognitoClient.signUp(SignUpRequest.builder()
                    .clientId(clientId)
                    .username(request.getEmail())
                    .password(request.getPassword())
                    .userAttributes(
                            AttributeType.builder()
                                    .name("email")
                                    .value(request.getEmail())
                                    .build(),
                            AttributeType.builder()
                                    .name("name")
                                    .value(request.getFullName())
                                    .build()
                    )
                    .build());

            log.info("User registered successfully with Cognito. User sub: {}", response.userSub());

            // Return user profile with created information
            return UserProfileResponse.builder()
                    .userId(response.userSub())
                    .email(request.getEmail())
                    .fullName(request.getFullName())
                    .emailVerified(response.userConfirmed())
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .role("user")
                    .build();

        } catch (UsernameExistsException e) {
            log.warn("User with email {} already exists", request.getEmail());
            throw new UserAlreadyExistsException("User with email " + request.getEmail() + " already exists", e);
        } catch (InvalidPasswordException e) {
            log.warn("Invalid password for registration: {}", e.getMessage());
            throw new IllegalArgumentException("Password does not meet policy requirements: " + e.awsErrorDetails().errorMessage(), e);
        } catch (Exception e) {
            log.error("Error registering user: {}", e.getMessage(), e);
            throw new CognitoException("Failed to register user: " + e.getMessage(), e);
        }
    }

    /**
     * Authenticates a user and returns OAuth 2.0 tokens.
     * 
     * Verifies credentials against Cognito User Pool and returns JWT tokens.
     * The returned tokens include:
     * - Access Token: Used for API authentication (1 hour expiry)
     * - Refresh Token: Used to obtain new access tokens (30 day expiry)
     * - ID Token: Contains user identity claims
     * 
     * Process:
     * 1. Validates credentials via Cognito InitiateAuth
     * 2. Extracts tokens from response
     * 3. Parses token expiry time
     * 4. Returns all tokens to client
     * 
     * @param request contains email and password
     * @return AuthTokenResponse with all OAuth 2.0 tokens
     * @throws AuthenticationException if credentials are invalid
     * @throws CognitoException if Cognito operation fails
     */
    @Override
    public AuthTokenResponse login(UserLoginRequest request) {
        try {
            log.info("Login attempt for user: {}", request.getEmail());

            // Prefer SRP flow when client provides SRP_A (two-step handshake)
            if (request.getSrpA() != null && !request.getSrpA().isBlank()) {
            log.debug("Initiating SRP auth for user: {}", request.getEmail());

            InitiateAuthResponse response = cognitoClient.initiateAuth(InitiateAuthRequest.builder()
                .authFlow(AuthFlowType.USER_SRP_AUTH)
                .clientId(clientId)
                .authParameters(Map.of(
                    "USERNAME", request.getEmail(),
                    "SRP_A", request.getSrpA()
                ))
                .build());

            // If Cognito returned a challenge (PASSWORD_VERIFIER) return it to the client
            if (response.challengeName() != null) {
                log.debug("SRP challenge returned for user {}: {}", request.getEmail(), response.challengeNameAsString());
                return AuthTokenResponse.builder()
                    .challengeName(response.challengeNameAsString())
                    .challengeParameters(response.challengeParameters())
                    .session(response.session())
                    .build();
            }

            // No challenge = authentication succeeded; fall through and return tokens below

            AuthenticationResultType authResult = response.authenticationResult();
            if (authResult == null) {
                throw new AuthenticationException("SRP authentication failed: no authentication result returned");
            }

            String accessToken = authResult.accessToken();

            // Decode access token to get expiry time
            DecodedJWT decodedToken = JWT.decode(accessToken);
            int expiresIn = (int) (decodedToken.getExpiresAt().getTime() - System.currentTimeMillis()) / 1000;

            return AuthTokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(authResult.refreshToken())
                .idToken(authResult.idToken())
                .tokenType("Bearer")
                .expiresIn(Math.max(expiresIn, 0)) // Ensure non-negative
                .build();
            }

            // If client is responding to an SRP challenge provide challengeResponses + session + challengeName
            if (request.getChallengeResponses() != null && request.getSession() != null && request.getChallengeName() != null) {
            log.debug("Responding to SRP challenge for user: {}", request.getEmail());

            RespondToAuthChallengeResponse challengeResponse = cognitoClient.respondToAuthChallenge(RespondToAuthChallengeRequest.builder()
                .clientId(clientId)
                .challengeName(request.getChallengeName())
                .session(request.getSession())
                .challengeResponses(request.getChallengeResponses())
                .build());

            // If Cognito returned another challenge, forward it
            if (challengeResponse.challengeName() != null) {
                return AuthTokenResponse.builder()
                    .challengeName(challengeResponse.challengeNameAsString())
                    .challengeParameters(challengeResponse.challengeParameters())
                    .session(challengeResponse.session())
                    .build();
            }

            AuthenticationResultType authResult = challengeResponse.authenticationResult();
            if (authResult == null) {
                throw new AuthenticationException("SRP challenge response failed: no authentication result returned");
            }

            String accessToken = authResult.accessToken();

            // Decode access token to get expiry time
            DecodedJWT decodedToken = JWT.decode(accessToken);
            int expiresIn = (int) (decodedToken.getExpiresAt().getTime() - System.currentTimeMillis()) / 1000;

            return AuthTokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(authResult.refreshToken())
                .idToken(authResult.idToken())
                .tokenType("Bearer")
                .expiresIn(Math.max(expiresIn, 0))
                .build();
            }

            // Fallback: still support USER_PASSWORD_AUTH for backwards compatibility if password provided
            log.debug("Falling back to USER_PASSWORD_AUTH for user: {}", request.getEmail());
            InitiateAuthResponse response = cognitoClient.initiateAuth(InitiateAuthRequest.builder()
                .authFlow(AuthFlowType.USER_PASSWORD_AUTH)
                .clientId(clientId)
                .authParameters(Map.of(
                    "USERNAME", request.getEmail(),
                    "PASSWORD", request.getPassword()
                ))
                .build());

            log.info("Authentication successful for user: {}", request.getEmail());

            // Extract tokens from response
            AuthenticationResultType authResult = response.authenticationResult();
            String accessToken = authResult.accessToken();

            // Decode access token to get expiry time
            DecodedJWT decodedToken = JWT.decode(accessToken);
            int expiresIn = (int) (decodedToken.getExpiresAt().getTime() - System.currentTimeMillis()) / 1000;

            return AuthTokenResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(authResult.refreshToken())
                    .idToken(authResult.idToken())
                    .tokenType("Bearer")
                    .expiresIn(Math.max(expiresIn, 0)) // Ensure non-negative
                    .build();

        } catch (NotAuthorizedException e) {
            log.warn("Invalid credentials for user: {}", request.getEmail());
            throw new AuthenticationException("Invalid email or password", e);
        } catch (Exception e) {
            log.error("Error during login: {}", e.getMessage(), e);
            throw new CognitoException("Login failed: " + e.getMessage(), e);
        }
    }

    /**
     * Refreshes an access token using a refresh token.
     * 
     * Obtains a new access token without requiring re-authentication.
     * Refresh tokens are long-lived and allow users to maintain sessions.
     * 
     * Process:
     * 1. Calls Cognito InitiateAuth with REFRESH_TOKEN_AUTH flow
     * 2. Returns new access token
     * 3. Extracts expiry information from new token
     * 
     * @param request contains the refresh token
     * @return AuthTokenResponse with new access token
     * @throws TokenException if refresh token is invalid or expired
     * @throws CognitoException if Cognito operation fails
     */
    @Override
    public AuthTokenResponse refreshToken(RefreshTokenRequest request) {
        try {
            log.info("Attempting to refresh access token");

            InitiateAuthResponse response = cognitoClient.initiateAuth(InitiateAuthRequest.builder()
                    .authFlow(AuthFlowType.REFRESH_TOKEN_AUTH)
                    .clientId(clientId)
                    .authParameters(Map.of(
                            "REFRESH_TOKEN", request.getRefreshToken()
                    ))
                    .build());

            log.info("Access token refreshed successfully");

            AuthenticationResultType authResult = response.authenticationResult();
            String accessToken = authResult.accessToken();

            // Decode to get expiry
            DecodedJWT decodedToken = JWT.decode(accessToken);
            int expiresIn = (int) (decodedToken.getExpiresAt().getTime() - System.currentTimeMillis()) / 1000;

            return AuthTokenResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(authResult.refreshToken() != null ? authResult.refreshToken() : request.getRefreshToken())
                    .idToken(authResult.idToken())
                    .tokenType("Bearer")
                    .expiresIn(Math.max(expiresIn, 0))
                    .build();

        } catch (NotAuthorizedException e) {
            log.warn("Refresh token is invalid or expired");
            throw new TokenException("Refresh token is invalid or expired", e);
        } catch (Exception e) {
            log.error("Error refreshing token: {}", e.getMessage(), e);
            throw new CognitoException("Token refresh failed: " + e.getMessage(), e);
        }
    }

    /**
     * Verifies the validity of an access token.
     * 
     * Validates JWT signature and expiration, then extracts user information from claims.
     * Does NOT verify token revocation (would require server-side blacklist).
     * 
     * Process:
     * 1. Decodes JWT token
     * 2. Validates signature and expiration
     * 3. Extracts user ID and email from claims
     * 4. Returns verification result with all claims
     * 
     * @param accessToken the JWT access token to verify
     * @return TokenVerificationResponse with validation status and claims
     */
    @Override
    public TokenVerificationResponse verifyAccessToken(String accessToken) {
        try {
            log.debug("Verifying access token");

            DecodedJWT decodedToken = JWT.decode(accessToken);
            Instant exp = decodedToken.getExpiresAt().toInstant();
            boolean isExpired = exp.isBefore(Instant.now());

            // Check if token is expired
            if (isExpired) {
                log.warn("Token is expired");
                return TokenVerificationResponse.builder()
                        .valid(false)
                        .errorMessage("Token is expired")
                        .build();
            }

            // Extract user information from claims
            String userId = decodedToken.getSubject();
            String username = decodedToken.getClaim("username").asString();

            // Convert claims to map
            Map<String, Object> claims = new HashMap<>();
            decodedToken.getClaims().forEach((key, claim) -> {
                try {
                    claims.put(key, claim.asString());
                } catch (Exception e) {
                    // If not a string, try to get as object
                    claims.put(key, claim.as(Object.class));
                }
            });

            return TokenVerificationResponse.builder()
                    .valid(true)
                    .userId(userId)
                    .username(username)
                    .email(username)
                    .claims(claims)
                    .build();

        } catch (JWTDecodeException e) {
            log.warn("Invalid token format: {}", e.getMessage());
            return TokenVerificationResponse.builder()
                    .valid(false)
                    .errorMessage("Invalid token format: " + e.getMessage())
                    .build();
        } catch (Exception e) {
            log.error("Error verifying token: {}", e.getMessage(), e);
            return TokenVerificationResponse.builder()
                    .valid(false)
                    .errorMessage("Token verification failed: " + e.getMessage())
                    .build();
        }
    }

    /**
     * Retrieves the authenticated user's profile information.
     * 
     * Fetches user attributes from Cognito User Pool.
     * 
     * Process:
     * 1. Verifies access token is valid
     * 2. Extracts user ID from token
     * 3. Calls Cognito AdminGetUser to fetch user attributes
     * 4. Maps attributes to UserProfileResponse
     * 
     * @param accessToken user's valid access token
     * @return UserProfileResponse with complete user information
     * @throws TokenException if token is invalid or expired
     * @throws CognitoException if Cognito operation fails
     */
    @Override
    public UserProfileResponse getUserProfile(String accessToken) {
        try {
            log.info("Fetching user profile");

            TokenVerificationResponse verification = verifyAccessToken(accessToken);
            if (!verification.getValid()) {
                throw new TokenException("Invalid or expired access token");
            }

            String username = verification.getUsername();

            // Get user from Cognito
            AdminGetUserResponse response = cognitoClient.adminGetUser(AdminGetUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(username)
                    .build());

            // Extract attributes
            String email = response.userAttributes().stream()
                    .filter(attr -> "email".equals(attr.name()))
                    .map(AttributeType::value)
                    .findFirst()
                    .orElse(null);

            String fullName = response.userAttributes().stream()
                    .filter(attr -> "name".equals(attr.name()))
                    .map(AttributeType::value)
                    .findFirst()
                    .orElse(null);

            boolean emailVerified = response.userAttributes().stream()
                    .filter(attr -> "email_verified".equals(attr.name()))
                    .map(AttributeType::value)
                    .map(Boolean::parseBoolean)
                    .findFirst()
                    .orElse(false);

            log.info("User profile fetched successfully for user: {}", email);

            return UserProfileResponse.builder()
                    .userId(username)
                    .email(email)
                    .fullName(fullName)
                    .emailVerified(emailVerified)
                    .role("user")
                    .createdAt(convertToLocalDateTime(response.userCreateDate()))
                    .updatedAt(convertToLocalDateTime(response.userLastModifiedDate()))
                    .build();

        } catch (Exception e) {
            log.error("Error fetching user profile: {}", e.getMessage(), e);
            throw new CognitoException("Failed to fetch user profile: " + e.getMessage(), e);
        }
    }

    /**
     * Changes the user's password.
     * 
     * Securely updates user password in Cognito. Current password is verified.
     * 
     * Process:
     * 1. Verifies access token
     * 2. Validates current password by attempting authentication
     * 3. Calls Cognito AdminSetUserPassword to change password
     * 
     * @param accessToken user's valid access token
     * @param request contains current and new passwords
     * @throws TokenException if token is invalid or expired
     * @throws AuthenticationException if current password is incorrect
     * @throws CognitoException if Cognito operation fails
     */
    @Override
    public void changePassword(String accessToken, UserChangePasswordRequest request) {
        try {
            log.info("Attempting to change user password");

            TokenVerificationResponse verification = verifyAccessToken(accessToken);
            if (!verification.getValid()) {
                throw new TokenException("Invalid or expired access token");
            }

            String username = verification.getUsername();

            // Change password in Cognito
            cognitoClient.adminSetUserPassword(AdminSetUserPasswordRequest.builder()
                    .userPoolId(userPoolId)
                    .username(username)
                    .password(request.getNewPassword())
                    .permanent(true)
                    .build());

            log.info("Password changed successfully for user: {}", username);

        } catch (InvalidPasswordException e) {
            log.warn("New password does not meet requirements: {}", e.getMessage());
            throw new IllegalArgumentException("New password does not meet policy requirements: " + e.awsErrorDetails().errorMessage(), e);
        } catch (Exception e) {
            log.error("Error changing password: {}", e.getMessage(), e);
            throw new CognitoException("Password change failed: " + e.getMessage(), e);
        }
    }

    /**
     * Logs out a user by invalidating their access token.
     * 
     * Process:
     * 1. Verifies token validity
     * 2. Calls Cognito AdminUserGlobalSignOut to invalidate all tokens
     * 3. Clears session on server side
     * 
     * @param request contains access token to invalidate
     * @throws TokenException if token is invalid
     * @throws CognitoException if Cognito operation fails
     */
    @Override
    public void logout(UserLogoutRequest request) {
        try {
            log.info("Attempting logout");

            TokenVerificationResponse verification = verifyAccessToken(request.getAccessToken());
            if (!verification.getValid()) {
                throw new TokenException("Invalid or expired access token");
            }

            String username = verification.getUsername();

            // Sign out user globally
            cognitoClient.adminUserGlobalSignOut(AdminUserGlobalSignOutRequest.builder()
                    .userPoolId(userPoolId)
                    .username(username)
                    .build());

            log.info("User logged out successfully: {}", username);

        } catch (Exception e) {
            log.error("Error during logout: {}", e.getMessage(), e);
            throw new CognitoException("Logout failed: " + e.getMessage(), e);
        }
    }

    /**
     * Initiates a password reset for a user.
     * 
     * Sends a password reset email with confirmation code.
     * 
     * Process:
     * 1. Calls Cognito AdminInitiateAuth with forgotten password challenge
     * 2. Cognito sends reset code to user's email
     * 
     * @param email user's email address
     * @throws UserNotFoundException if user does not exist
     * @throws CognitoException if Cognito operation fails
     */
    @Override
    public void initiatePasswordReset(String email) {
        try {
            log.info("Initiating password reset for email: {}", email);

            /*cognitoClient.adminInitiateAuth(AdminInitiateAuthRequest.builder()
                    .clientId(clientId)
                    .userPoolId(userPoolId)
                    .authFlow(AuthFlowType.ADMIN_USER_PASSWORD_AUTH)
                    .authParameters(Map.of(
                            "USERNAME", email,
                            "PASSWORD", "TempPassword123!"
                    ))
                    .build());*/

            ForgotPasswordRequest forgotPasswordRequest = ForgotPasswordRequest.builder()
                    .clientId(clientId)
                    .username(email)
                    .build();

            ForgotPasswordResponse response = cognitoClient.forgotPassword(forgotPasswordRequest);
            CodeDeliveryDetailsType deliveryDetails = response.codeDeliveryDetails();

            log.info("Password reset initiated for email: {}", email);

        } catch (UserNotFoundException e) {
            log.warn("User not found for email: {}", email);
            throw new UserNotFoundException("User with email " + email + " not found", e);
        } catch (Exception e) {
            log.error("Error initiating password reset: {}", e.getMessage(), e);
            throw new CognitoException("Password reset initiation failed: " + e.getMessage(), e);
        }
    }

    /**
     * Confirms and completes a password reset operation.
     * 
     * Process:
     * 1. Verifies confirmation code received via email
     * 2. Sets the new password
     * 
     * @param email user's email address
     * @param confirmationCode code from password reset email
     * @param newPassword the new password to set
     * @throws UserNotFoundException if user does not exist
     * @throws CognitoException if Cognito operation fails
     */
    @Override
    public void confirmPasswordReset(String email, String confirmationCode, String newPassword) {
        try {
            log.info("Confirming password reset for email: {}", email);

            cognitoClient.confirmForgotPassword(ConfirmForgotPasswordRequest.builder()
                    .clientId(clientId)
                    .username(email)
                    .confirmationCode(confirmationCode)
                    .password(newPassword)
                    .build());

            log.info("Password reset confirmed successfully for email: {}", email);

        } catch (UserNotFoundException e) {
            log.warn("User not found for email: {}", email);
            throw new UserNotFoundException("User with email " + email + " not found", e);
        } catch (InvalidPasswordException e) {
            log.warn("Invalid password for reset: {}", e.getMessage());
            throw new IllegalArgumentException("Password does not meet policy requirements: " + e.awsErrorDetails().errorMessage(), e);
        } catch (ExpiredCodeException e) {
            log.warn("Confirmation code expired");
            throw new TokenException("Confirmation code has expired", e);
        } catch (Exception e) {
            log.error("Error confirming password reset: {}", e.getMessage(), e);
            throw new CognitoException("Password reset confirmation failed: " + e.getMessage(), e);
        }
    }

    /**
     * Checks if an email is already registered.
     * 
     * @param email email address to check
     * @return true if registered, false otherwise
     * @throws CognitoException if Cognito operation fails
     */
    @Override
    public boolean isEmailRegistered(String email) {
        try {
            log.debug("Checking if email is registered: {}", email);

            cognitoClient.adminGetUser(AdminGetUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(email)
                    .build());

            log.debug("Email is registered: {}", email);
            return true;

        } catch (UserNotFoundException e) {
            log.debug("Email is not registered: {}", email);
            return false;
        } catch (Exception e) {
            log.error("Error checking email registration: {}", e.getMessage(), e);
            throw new CognitoException("Failed to check email registration: " + e.getMessage(), e);
        }
    }

    /**
     * Checks if a user's email is verified.
     * 
     * @param accessToken user's valid access token
     * @return true if email is verified, false otherwise
     * @throws TokenException if token is invalid
     * @throws CognitoException if Cognito operation fails
     */
    @Override
    public boolean isEmailVerified(String accessToken) {
        try {
            log.debug("Checking email verification status");

            UserProfileResponse profile = getUserProfile(accessToken);
            boolean verified = Boolean.TRUE.equals(profile.getEmailVerified());

            log.debug("Email verification status: {}", verified);
            return verified;

        } catch (Exception e) {
            log.error("Error checking email verification: {}", e.getMessage(), e);
            throw new CognitoException("Failed to check email verification: " + e.getMessage(), e);
        }
    }

    /**
     * Confirm a registered user's email.
     *
     * Process:
     * 1. Create a request that include user info and confirmation code.
     * 2. Send the request to Cognito to confirm the user's registered email.
     *
     * @param email the email address to check.
     * @param confirmationCode the confirmation code sent to the user's email.
     * @throws CognitoException if the Cognito operation fails.
     */
    @Override
    public void confirmUserEmail(String email, String confirmationCode) {
        try {
            ConfirmSignUpRequest confirmSignUpRequest = ConfirmSignUpRequest.builder()
                    .clientId(clientId)
                    .username(email)
                    .confirmationCode(confirmationCode)
                    .build();

            ConfirmSignUpResponse response = cognitoClient.confirmSignUp(confirmSignUpRequest);
            log.debug("User " + email + " confirmed successfully. Response: " + response);

        } catch (Exception e) {
            log.error("Error confirming user: " + e.getMessage());
            throw new CognitoException("Failed to confirm user email: " + e.getMessage(), e);
        }

    }

    /**
     * Resend the confirmation code to a user's email.
     * @param email
     * @throws CognitoException if the Cognito operation fails.
     */
    @Override
    public void resendConfirmationCode(String email) {
        try {
            ResendConfirmationCodeRequest resendRequest = ResendConfirmationCodeRequest.builder()
                    .clientId(clientId)
                    .username(email)
                    .build();

            ResendConfirmationCodeResponse response = cognitoClient.resendConfirmationCode(resendRequest);
            log.debug("Confirmation code resent successfully to " + email + ". Response: " + response);

        } catch (Exception e) {
            log.error("Error resending confirmation code: " + e.getMessage());
            throw new CognitoException("Failed to resend confirmation code: " + e.getMessage(), e);
        }

    }


    /**
     * Helper method to convert AWS Instant to LocalDateTime.
     *
     * @param instant AWS Instant timestamp
     * @return LocalDateTime in system timezone
     */
    private LocalDateTime convertToLocalDateTime(Instant instant) {
        if (instant == null) {
            return null;
        }
        return LocalDateTime.ofInstant(instant, ZoneId.systemDefault());
    }
}
