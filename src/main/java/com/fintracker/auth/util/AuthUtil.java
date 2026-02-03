package com.fintracker.auth.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.slf4j.Slf4j;

/**
 * Utility class for JWT token operations and common authentication tasks.
 * 
 * Provides helper methods for:
 * - Token decoding and parsing
 * - Token claim extraction
 * - Token validation and expiry checking
 * - Password validation
 * 
 * @author fintracker-auth
 * @version 1.0.0
 */
@Slf4j
public class AuthUtil {

    /**
     * Private constructor to prevent instantiation of utility class.
     */
    private AuthUtil() {
        throw new AssertionError("Cannot instantiate utility class");
    }

    /**
     * Validates a password against Cognito policy requirements.
     * 
     * Password must contain:
     * - Minimum 8 characters
     * - At least one uppercase letter
     * - At least one lowercase letter
     * - At least one digit
     * - At least one special character
     * 
     * @param password the password to validate
     * @return true if password meets all requirements, false otherwise
     */
    public static boolean isValidPassword(String password) {
        if (password == null || password.length() < 8) {
            return false;
        }

        boolean hasUppercase = password.matches(".*[A-Z].*");
        boolean hasLowercase = password.matches(".*[a-z].*");
        boolean hasDigit = password.matches(".*[0-9].*");
        boolean hasSpecialChar = password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};:'\",.<>?/\\\\|`~].*");

        return hasUppercase && hasLowercase && hasDigit && hasSpecialChar;
    }

    /**
     * Validates an email address format.
     * 
     * Uses a basic regex pattern to validate email format.
     * Does not verify if the email actually exists.
     * 
     * @param email the email to validate
     * @return true if email format is valid, false otherwise
     */
    public static boolean isValidEmail(String email) {
        if (email == null || email.isEmpty()) {
            return false;
        }
        
        String emailRegex = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}$";
        return email.matches(emailRegex);
    }

    /**
     * Extracts the user ID (subject) from a JWT token.
     * 
     * @param token the JWT token
     * @return the user ID from the token subject claim
     * @throws com.auth0.jwt.exceptions.JWTDecodeException if token is invalid
     */
    public static String extractUserId(String token) {
        DecodedJWT decodedToken = JWT.decode(token);
        return decodedToken.getSubject();
    }

    /**
     * Extracts the email from a JWT token.
     * 
     * @param token the JWT token
     * @return the email from the token claims
     * @throws com.auth0.jwt.exceptions.JWTDecodeException if token is invalid
     */
    public static String extractEmail(String token) {
        DecodedJWT decodedToken = JWT.decode(token);
        return decodedToken.getClaim("email").asString();
    }

    /**
     * Checks if a JWT token is expired.
     * 
     * Compares the token's expiration time with the current time.
     * 
     * @param token the JWT token
     * @return true if token is expired, false otherwise
     * @throws com.auth0.jwt.exceptions.JWTDecodeException if token is invalid
     */
    public static boolean isTokenExpired(String token) {
        DecodedJWT decodedToken = JWT.decode(token);
        return decodedToken.getExpiresAt().before(new java.util.Date());
    }

    /**
     * Gets the token expiry time in seconds from now.
     * 
     * Returns negative value if token is already expired.
     * 
     * @param token the JWT token
     * @return seconds until token expires
     * @throws com.auth0.jwt.exceptions.JWTDecodeException if token is invalid
     */
    public static long getTokenExpiryInSeconds(String token) {
        DecodedJWT decodedToken = JWT.decode(token);
        long expiryTime = decodedToken.getExpiresAt().getTime();
        long currentTime = System.currentTimeMillis();
        return (expiryTime - currentTime) / 1000;
    }

    /**
     * Masks a sensitive string for logging purposes.
     * 
     * Shows only the first 4 and last 4 characters, replacing middle with asterisks.
     * Useful for logging tokens, passwords, etc. without exposing sensitive data.
     * 
     * @param sensitive the sensitive string to mask
     * @return masked string
     */
    public static String maskSensitiveData(String sensitive) {
        if (sensitive == null || sensitive.length() <= 8) {
            return "****";
        }
        
        String first4 = sensitive.substring(0, 4);
        String last4 = sensitive.substring(sensitive.length() - 4);
        return first4 + "****" + last4;
    }

    /**
     * Extracts Bearer token from Authorization header.
     * 
     * Handles format: "Bearer {token}"
     * 
     * @param authHeader the Authorization header value
     * @return the extracted token, or null if header format is invalid
     */
    public static String extractBearerToken(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return null;
        }
        return authHeader.substring(7);
    }
}
