package com.fintracker.auth.controller;

import com.fintracker.auth.dto.*;
import com.fintracker.auth.service.IAuthService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * REST Controller for OAuth 2.0 authentication endpoints.
 * 
 * Provides HTTP endpoints for all authentication operations including:
 * - User registration (POST /auth/register)
 * - User login (POST /auth/login)
 * - Token refresh (POST /auth/refresh)
 * - Token verification (GET /auth/verify)
 * - User profile management (GET /auth/profile, POST /auth/profile/password)
 * - Logout (POST /auth/logout)
 * - Password reset operations
 * 
 * Protected endpoints require a valid Bearer token in the Authorization header.
 * 
 * @author fintracker-auth
 * @version 1.0.0
 */
@Slf4j
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final IAuthService authService;

    /**
     * Constructs an AuthController with the provided auth service.
     *
     * @param authService the authentication service implementation
     */
    public AuthController(IAuthService authService) {
        this.authService = authService;
    }

    @GetMapping("/info")
    public ResponseEntity<String> getInfo() {
        String response = "Auth Service is running.";
        return ResponseEntity.ok(response);
    }

    /**
     * Registers a new user in the system.
     * 
     * HTTP Endpoint: POST /auth/register.
     * 
     * Request body example:
     * {
     *   "email": "user@example.com",
     *   "password": "SecurePassword123!",
     *   "fullName": "John Doe"
     * }
     * 
     * Response on success (201 Created):
     * {
     *   "userId": "uuid-string",
     *   "email": "user@example.com",
     *   "fullName": "John Doe",
     *   "emailVerified": false,
     *   "role": "user",
     *   "createdAt": "2025-11-20T10:30:00",
     *   "updatedAt": "2025-11-20T10:30:00"
     * }
     * 
     * Possible error responses:
     * - 400 Bad Request: Invalid input
     * - 409 Conflict: Email already registered
     * - 500 Internal Server Error: Cognito service error
     * 
     * @param request UserRegistrationRequest with email, password, and fullName
     * @return ResponseEntity with UserProfileResponse containing new user details
     */
    @PostMapping("/register")
    public ResponseEntity<UserProfileResponse> register(@RequestBody UserRegistrationRequest request) {
        log.info("Register endpoint called for email: {}", request.getEmail());
        UserProfileResponse response = authService.registerUser(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Authenticates a user and returns OAuth 2.0 tokens.
     * 
     * HTTP Endpoint: POST /auth/login
     * 
     * Request body example:
     * {
     *   "email": "user@example.com",
     *   "password": "SecurePassword123!"
     * }
     * 
     * Response on success (200 OK):
     * {
     *   "accessToken": "eyJhbGciOiJIUzI1NiIs...",
     *   "refreshToken": "eyJhbGciOiJIUzI1NiIs...",
     *   "idToken": "eyJhbGciOiJIUzI1NiIs...",
     *   "tokenType": "Bearer",
     *   "expiresIn": 3600
     * }
     * 
     * Possible error responses:
     * - 401 Unauthorized: Invalid credentials
     * - 404 Not Found: User not found
     * - 500 Internal Server Error: Cognito service error
     * 
     * Usage of tokens:
     * - Use accessToken in Authorization header: "Authorization: Bearer {accessToken}"
     * - Use refreshToken to obtain new accessToken before expiry
     * - Keep idToken for identity verification
     * 
     * @param request UserLoginRequest with email and password
     * @return ResponseEntity with AuthTokenResponse containing all OAuth tokens
     */
    @PostMapping("/login")
    public ResponseEntity<AuthTokenResponse> login(@RequestBody UserLoginRequest request) {
        log.info("Login endpoint called for email: {}", request.getEmail());
        AuthTokenResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Refreshes an expired access token.
     * 
     * HTTP Endpoint: POST /auth/refresh
     * 
     * Request body example:
     * {
     *   "refreshToken": "eyJhbGciOiJIUzI1NiIs..."
     * }
     * 
     * Response on success (200 OK):
     * {
     *   "accessToken": "eyJhbGciOiJIUzI1NiIs...",
     *   "refreshToken": "eyJhbGciOiJIUzI1NiIs...",
     *   "idToken": "eyJhbGciOiJIUzI1NiIs...",
     *   "tokenType": "Bearer",
     *   "expiresIn": 3600
     * }
     * 
     * Possible error responses:
     * - 401 Unauthorized: Refresh token is invalid or expired
     * - 500 Internal Server Error: Cognito service error
     * 
     * Usage: Call this endpoint before the current accessToken expires to prevent
     * requiring the user to log in again.
     * 
     * @param request TokenRefreshRequest with refresh token
     * @return ResponseEntity with AuthTokenResponse containing new tokens
     */
    @PostMapping("/refresh")
    public ResponseEntity<AuthTokenResponse> refreshToken(@RequestBody RefreshTokenRequest request) {
        log.info("Refresh token endpoint called");
        AuthTokenResponse response = authService.refreshToken(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Verifies an access token and returns decoded claims.
     * 
     * HTTP Endpoint: POST /auth/verify
     * 
     * Response on success (200 OK):
     * {
     *   "valid": true,
     *   "userId": "user-uuid",
     *   "email": "user@example.com",
     *   "claims": {
     *     "sub": "user-uuid",
     *     "email": "user@example.com",
     *     "aud": "client-id",
     *     "exp": 1700000000,
     *     ...
     *   }
     * }
     * 
     * Response on invalid/expired token (200 OK):
     * {
     *   "valid": false,
     *   "errorMessage": "Token is expired"
     * }
     *
     * @return ResponseEntity with TokenVerificationResponse
     */
    @GetMapping("/verify")
    public ResponseEntity<TokenVerificationResponse> verifyToken(@RequestParam String token) {
        log.debug("Verify access token endpoint called");
        TokenVerificationResponse response = authService.verifyAccessToken(token);
        return ResponseEntity.ok(response);
    }

    /**
     * Retrieves the authenticated user's profile information.
     * 
     * HTTP Endpoint: GET /auth/profile
     * 
     * Headers (required):
     * - Authorization: Bearer {accessToken}
     * 
     * Response on success (200 OK):
     * {
     *   "userId": "user-uuid",
     *   "email": "user@example.com",
     *   "fullName": "John Doe",
     *   "role": "user",
     *   "emailVerified": true,
     *   "createdAt": "2025-11-20T10:30:00",
     *   "updatedAt": "2025-11-20T10:30:00"
     * }
     * 
     * Possible error responses:
     * - 401 Unauthorized: Missing or invalid token
     * - 404 Not Found: User not found
     * - 500 Internal Server Error: Cognito service error
     * 
     * @param authHeader Authorization header with Bearer token
     * @return ResponseEntity with UserProfileResponse
     */
    @GetMapping("/profile")
    public ResponseEntity<UserProfileResponse> getProfile(@RequestHeader("Authorization") String authHeader) {
        log.info("Get profile endpoint called");
        String token = extractTokenFromHeader(authHeader);
        UserProfileResponse response = authService.getUserProfile(token);
        return ResponseEntity.ok(response);
    }

    /**
     * Changes the user's password.
     * 
     * HTTP Endpoint: POST /auth/profile/password
     * 
     * Headers (required):
     * - Authorization: Bearer {accessToken}
     * 
     * Request body example:
     * {
     *   "currentPassword": "OldPassword123!",
     *   "newPassword": "NewPassword456!"
     * }
     * 
     * Response on success (204 No Content):
     * (Empty response body)
     * 
     * Possible error responses:
     * - 400 Bad Request: Password doesn't meet requirements
     * - 401 Unauthorized: Missing token or incorrect current password
     * - 500 Internal Server Error: Cognito service error
     * 
     * @param authHeader Authorization header with Bearer token
     * @param request UserChangePasswordRequest with current and new passwords
     * @return ResponseEntity with no content on success
     */
    @PostMapping("/profile/password")
    public ResponseEntity<Void> changePassword(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody UserChangePasswordRequest request) {
        log.info("Change password endpoint called");
        String token = extractTokenFromHeader(authHeader);
        authService.changePassword(token, request);
        return ResponseEntity.noContent().build();
    }

    /**
     * Logs out the user by invalidating their tokens.
     * 
     * HTTP Endpoint: POST /auth/logout
     * 
     * Request body example:
     * {
     *   "accessToken": "eyJhbGciOiJIUzI1NiIs..."
     * }
     * 
     * Response on success (200 OK):
     * {
     *   "message": "Logout successful"
     * }
     * 
     * Possible error responses:
     * - 401 Unauthorized: Invalid token
     * - 500 Internal Server Error: Cognito service error
     * 
     * Note: After logout, the client should clear locally stored tokens.
     * 
     * @param request UserLogoutRequest with access token
     * @return ResponseEntity with success message
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(@RequestBody UserLogoutRequest request) {
        log.info("Logout endpoint called");
        authService.logout(request);
        return ResponseEntity.ok(Map.of("message", "Logout successful"));
    }

    /**
     * Initiates a password reset for a user.
     * 
     * HTTP Endpoint: POST /auth/forgot-password
     * 
     * Request body example:
     * {
     *   "email": "user@example.com"
     * }
     * 
     * Response on success (200 OK):
     * {
     *   "message": "Password reset email sent"
     * }
     * 
     * Possible error responses:
     * - 404 Not Found: User email not found
     * - 500 Internal Server Error: Cognito service error
     * 
     * Note: User will receive an email with a confirmation code and password reset link.
     * 
     * @param request contains email address
     * @return ResponseEntity with success message
     */
    @PostMapping("/forgot-password")
    public ResponseEntity<Map<String, String>> initiatePasswordReset(
            @RequestBody Map<String, String> request) {
        log.info("Initiate password reset endpoint called for email: {}", request.get("email"));
        authService.initiatePasswordReset(request.get("email"));
        return ResponseEntity.ok(Map.of("message", "Password reset email sent"));
    }

    /**
     * Confirms and completes a password reset operation.
     * 
     * HTTP Endpoint: POST /auth/reset-password
     * 
     * Request body example:
     * {
     *   "email": "user@example.com",
     *   "confirmationCode": "123456",
     *   "newPassword": "NewPassword456!"
     * }
     * 
     * Response on success (200 OK):
     * {
     *   "message": "Password reset successful"
     * }
     * 
     * Possible error responses:
     * - 400 Bad Request: Invalid confirmation code or password doesn't meet requirements
     * - 404 Not Found: User email not found
     * - 500 Internal Server Error: Cognito service error
     * 
     * @param request contains email, confirmation code, and new password
     * @return ResponseEntity with success message
     */
    @PostMapping("/reset-password")
    public ResponseEntity<Map<String, String>> confirmPasswordReset(
            @RequestBody Map<String, String> request) {
        log.info("Confirm password reset endpoint called for email: {}", request.get("email"));
        authService.confirmPasswordReset(
                request.get("email"),
                request.get("confirmationCode"),
                request.get("newPassword")
        );
        return ResponseEntity.ok(Map.of("message", "Password reset successful"));
    }

    /**
     * Checks if an email is already registered.
     * 
     * HTTP Endpoint: GET /auth/check-email
     * 
     * Query parameters:
     * - email: The email to check (required)
     * 
     * Example: GET /auth/check-email?email=user@example.com
     * 
     * Response on success (200 OK):
     * {
     *   "registered": true
     * }
     * 
     * @param email the email address to check
     * @return ResponseEntity with registration status
     */
    @GetMapping("/check-email")
    public ResponseEntity<Map<String, Boolean>> checkEmail(@RequestParam String email) {
        log.info("Check email endpoint called for email: {}", email);
        boolean registered = authService.isEmailRegistered(email);
        return ResponseEntity.ok(Map.of("registered", registered));
    }

    /**
     * Confirms a registered user email.
     *
     * HTTP Endpoint: POST /auth/confirm-user-email
     *
     * Request body example:
     * {
     *   "email": "user@example.com",
     *   "confirmationCode": "123456",
     * }
     *
     * Response on success (200 OK):
     * {
     *   "message": "Confirmation of user email successful"
     * }
     *
     * Possible error responses:
     * - 400 Bad Request: Invalid confirmation code
     * - 404 Not Found: User email not found
     * - 500 Internal Server Error: Cognito service error
     *
     * @param request contains email, and confirmation code.
     * @return ResponseEntity with success message
     */
    @PostMapping("/confirm-user-email")
    public ResponseEntity<Map<String, String>> confirmUserEmail(
            @RequestBody Map<String, String> request) {
        authService.confirmUserEmail(
                request.get("email"),
                request.get("confirmationCode")
        );
        return ResponseEntity.ok(Map.of("message", "Confirmation of user email successful"));
    }

    /**
     * Resends the confirmation code to the user's email.
     * @param request
     * @return ResponseEntity with success message
     */
    @PostMapping("/resend-confirmation-code")
    public ResponseEntity<Map<String, String>> resendConfirmationCode(
            @RequestBody Map<String, String> request) {
        log.info("Resend confirmation code endpoint called for email: {}", request.get("email"));
        authService.resendConfirmationCode(request.get("email"));
        return ResponseEntity.ok(Map.of("message", "Confirmation code resent successfully"));
    }

    /**
     * Helper method to extract Bearer token from Authorization header.
     * 
     * Handles authorization headers in the format: "Bearer {token}"
     * 
     * @param authHeader the Authorization header value
     * @return the extracted token
     * @throws IllegalArgumentException if header format is invalid
     */
    private String extractTokenFromHeader(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new IllegalArgumentException("Invalid Authorization header format");
        }
        return authHeader.substring(7);
    }
}
