package com.fintracker.auth.service;

import com.fintracker.auth.dto.*;
import com.fintracker.auth.exception.*;

/**
 * Interface for OAuth 2.0 authentication service using AWS Cognito.
 * 
 * This service provides complete OAuth 2.0 flow implementation including:
 * - User registration with email verification
 * - User login with email and password
 * - Access token generation and refresh token handling
 * - Token verification and validation
 * - User profile management
 * - Password management
 * - Session management (logout)
 * 
 * All operations interact with AWS Cognito User Pools for user management and authentication.
 * Access tokens are JWT tokens signed by Cognito and can be verified using Cognito's public keys.
 * 
 * @author fintracker-auth
 * @version 1.0.0
 */
public interface IAuthService {

    /**
     * Registers a new user in the system.
     * 
     * Creates a new user in the Cognito User Pool with the provided credentials and profile information.
     * The user's email is used as the username for login purposes.
     * An initial temporary password may be generated, and the user will need to set a permanent password
     * if they are created by an admin rather than through self-registration.
     * 
     * @param request UserRegistrationRequest containing email, password, and full name
     * @return UserProfileResponse containing the newly created user's information
     * @throws UserAlreadyExistsException if a user with the provided email already exists
     * @throws IllegalArgumentException if the password does not meet policy requirements
     * @throws CognitoException if the Cognito User Pool operation fails
     */
    UserProfileResponse registerUser(UserRegistrationRequest request);

    /**
     * Authenticates a user and returns OAuth 2.0 tokens.
     * 
     * Verifies the provided credentials against the Cognito User Pool and returns authentication tokens.
     * The response includes:
     * - Access Token: Short-lived JWT (typically valid for 1 hour) for API requests
     * - Refresh Token: Long-lived token for obtaining new access tokens without re-authentication
     * - ID Token: Contains user identity information
     * 
     * The access token should be included in subsequent API requests as:
     * Authorization: Bearer {accessToken}
     * 
     * @param request UserLoginRequest containing email and password
     * @return AuthTokenResponse containing access, refresh, and ID tokens
     * @throws AuthenticationException if credentials are invalid
     * @throws UserNotFoundException if the user does not exist
     * @throws CognitoException if the Cognito authentication operation fails
     */
    AuthTokenResponse login(UserLoginRequest request);

    /**
     * Refreshes an expired or expiring access token.
     * 
     * Uses the long-lived refresh token to obtain a new access token without requiring the user
     * to provide their password again. This is essential for maintaining user sessions across
     * application restarts and preventing repeated login prompts.
     * 
     * The refresh token typically expires after 30 days, at which point the user must log in again.
     * 
     * @param request TokenRefreshRequest containing the refresh token
     * @return AuthTokenResponse containing the new access, refresh, and ID tokens
     * @throws TokenException if the refresh token is invalid or expired
     * @throws CognitoException if the Cognito token refresh operation fails
     */
    AuthTokenResponse refreshToken(RefreshTokenRequest request);

    /**
     * Verifies the validity of an access token.
     * 
     * Validates the JWT token signature, expiration time, and other standard JWT claims.
     * Decodes the token and extracts user information including user ID, email, and all token claims.
     * 
     * This method is typically called for:
     * - Middleware/filter validation of incoming API requests
     * - Pre-call verification before accessing protected resources
     * - Token inspection for audit logging and security monitoring
     * 
     * The method does NOT check token revocation status (would require server-side token blacklist).
     * For sensitive operations, consider implementing a token blacklist or revocation list.
     * 
     * @param accessToken the JWT access token to verify
     * @return TokenVerificationResponse containing validation status and token claims
     */
    TokenVerificationResponse verifyAccessToken(String accessToken);

    /**
     * Retrieves the authenticated user's profile information.
     * 
     * Fetches the user's current profile data from the Cognito User Pool including email,
     * full name, role, email verification status, and timestamps.
     * 
     * The access token is used to identify the user making the request. The token must be valid
     * and not expired; otherwise, a TokenException will be thrown.
     * 
     * @param accessToken the user's valid access token
     * @return UserProfileResponse containing complete user profile information
     * @throws TokenException if the access token is invalid or expired
     * @throws UserNotFoundException if the user associated with the token cannot be found
     * @throws CognitoException if the Cognito operation fails
     */
    UserProfileResponse getUserProfile(String accessToken);

    /**
     * Changes the user's password.
     * 
     * Updates the user's password in the Cognito User Pool. The current password is verified
     * before allowing the change to prevent unauthorized password changes.
     * 
     * The new password must meet the Cognito password policy requirements:
     * - Minimum 8 characters
     * - At least one uppercase letter
     * - At least one lowercase letter
     * - At least one number
     * - At least one special character
     * 
     * After a successful password change, the user's existing sessions and refresh tokens
     * may or may not remain valid depending on Cognito configuration. It's recommended to
     * require re-authentication after a password change for security purposes.
     * 
     * @param accessToken the user's valid access token
     * @param request UserChangePasswordRequest containing current and new passwords
     * @throws TokenException if the access token is invalid or expired
     * @throws AuthenticationException if the current password is incorrect
     * @throws IllegalArgumentException if the new password does not meet policy requirements
     * @throws CognitoException if the Cognito password change operation fails
     */
    void changePassword(String accessToken, UserChangePasswordRequest request);

    /**
     * Logs out the user by invalidating their access token.
     * 
     * Invalidates the user's session with Cognito. After logout, the access token becomes
     * invalid and cannot be used for API requests. However, the refresh token may still be
     * usable depending on Cognito configuration.
     * 
     * Note: This method invalidates the token on the server side. For complete logout,
     * clients should also clear locally stored tokens to prevent accidental reuse.
     * 
     * To prevent token reuse after logout, consider implementing a server-side token blacklist
     * or using short-lived access tokens with a revocation mechanism.
     * 
     * @param request UserLogoutRequest containing the access token to invalidate
     * @throws TokenException if the access token is invalid
     * @throws CognitoException if the Cognito logout operation fails
     */
    void logout(UserLogoutRequest request);

    /**
     * Initiates a password reset for a user who has forgotten their password.
     * 
     * Triggers Cognito to send a password reset link to the user's registered email address.
     * The user must follow the link and complete the password reset flow.
     * 
     * After initiating the reset, the user will receive an email with a confirmation code
     * that can be used with the confirmPasswordReset method to complete the process.
     * 
     * @param email the email address of the user requesting password reset
     * @throws UserNotFoundException if no user with the provided email exists
     * @throws CognitoException if the Cognito password reset initiation fails
     */
    void initiatePasswordReset(String email);

    /**
     * Confirms and completes a password reset operation.
     * 
     * Completes the password reset flow initiated by initiatePasswordReset.
     * The confirmation code received via email is used to verify the reset request
     * and set the new password.
     * 
     * @param email the email address of the user
     * @param confirmationCode the code received in the password reset email
     * @param newPassword the new password to set
     * @throws UserNotFoundException if no user with the provided email exists
     * @throws IllegalArgumentException if the confirmation code is invalid or if the new password doesn't meet requirements
     * @throws CognitoException if the Cognito password reset confirmation fails
     */
    void confirmPasswordReset(String email, String confirmationCode, String newPassword);

    /**
     * Checks if an email is already registered in the system.
     * 
     * Useful for validation during registration to prevent duplicate account attempts
     * and for providing user-friendly feedback during sign-up flows.
     * 
     * @param email the email address to check
     * @return true if the email is already registered, false otherwise
     * @throws CognitoException if the Cognito operation fails
     */
    boolean isEmailRegistered(String email);

    /**
     * Checks if a user's email is verified.
     * 
     * Email verification is important for account security and ensuring valid contact information.
     * Cognito can enforce email verification requirements and prevent unverified users from accessing certain features.
     * 
     * @param accessToken the user's valid access token
     * @return true if the user's email is verified, false otherwise
     * @throws TokenException if the access token is invalid or expired
     * @throws UserNotFoundException if the user is not found
     * @throws CognitoException if the Cognito operation fails
     */
    boolean isEmailVerified(String accessToken);

    /**
     * Receive the confirmation code from Amazon Cognito application
     * and confirm a registered user's email.
     * @param email the email address to check.
     * @param confirmationCode the confirmation code sent to the user's email.
     * @throws CognitoException if the Cognito operation fails.
     */
    void confirmUserEmail(String email, String confirmationCode);

    /**
     * Resend the confirmation code to the user's email.
     * @param email
     * @throws CognitoException if the Cognito operation fails.
     */
    void resendConfirmationCode(String email);
}
