package com.fintracker.auth.filter;

import com.fintracker.auth.dto.TokenVerificationResponse;
import com.fintracker.auth.service.IAuthService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * JWT Authentication Filter for validating Bearer tokens in HTTP requests.
 * 
 * This filter intercepts incoming HTTP requests and validates JWT access tokens
 * in the Authorization header before the request reaches the controller layer.
 * 
 * Filter behavior:
 * - Extracts Bearer token from Authorization header
 * - Validates token with the auth service
 * - Sets token claims as request attributes for downstream access
 * - Allows unauthenticated requests to reach endpoint handlers (auth endpoints don't require tokens)
 * - Logs all validation activities for security auditing
 * 
 * Request attributes set by this filter:
 * - userId: The user ID from token claims
 * - email: The user email from token claims
 * - tokenClaims: All JWT claims as a Map
 * 
 * Usage:
 * Clients must include Bearer token in Authorization header:
 * Authorization: Bearer {accessToken}
 * 
 * Note: This filter runs once per request (OncePerRequestFilter) to ensure
 * the token is validated exactly once, even if the request is forwarded.
 * 
 * @author fintracker-auth
 * @version 1.0.0
 */
@Slf4j
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final IAuthService authService;

    /**
     * Constructs a JwtAuthenticationFilter with the provided auth service.
     *
     * @param authService the authentication service for token validation
     */
    public JwtAuthenticationFilter(IAuthService authService) {
        this.authService = authService;
    }

    /**
     * Filters incoming HTTP requests to validate JWT tokens.
     * 
     * Process:
     * 1. Extracts Authorization header from request
     * 2. If present and valid format, extracts Bearer token
     * 3. Validates token using auth service
     * 4. Sets token claims as request attributes
     * 5. Continues filter chain
     * 
     * If no token is present or validation fails, the request continues normally.
     * This allows auth endpoints (registration, login) to be accessed without a token.
     * 
     * To require authentication for specific endpoints, use Spring Security
     * configuration with HttpSecurity to restrict access to protected resources.
     * 
     * @param request the HTTP request
     * @param response the HTTP response
     * @param filterChain the filter chain
     * @throws ServletException if a servlet error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        try {
            String authHeader = request.getHeader("Authorization");

            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);

                // Verify token
                TokenVerificationResponse verification = authService.verifyAccessToken(token);

                if (verification.getValid()) {
                    log.debug("Token verified successfully for user: {}", verification.getUserId());

                    // Set token attributes in request for downstream access
                    request.setAttribute("userId", verification.getUserId());
                    request.setAttribute("email", verification.getEmail());
                    request.setAttribute("tokenClaims", verification.getClaims());

                    // Populate Spring Security context so downstream authorization sees an authenticated principal
                    try {
                        Map<String, Object> claims = verification.getClaims() != null ? verification.getClaims() : java.util.Collections.emptyMap();

                        // Default authority - ensure authenticated requests have at least one authority
                        List<GrantedAuthority> authorities = new ArrayList<>();

                        // If token includes Cognito groups, map them to authorities
                        Object groups = claims.getOrDefault("cognito:groups", claims.get("groups"));
                        if (groups instanceof List) {
                            for (Object g : (List<?>) groups) {
                                if (g != null) {
                                    authorities.add(new SimpleGrantedAuthority(String.valueOf(g)));
                                }
                            }
                        }

                        // Always include a default ROLE_USER authority to satisfy authenticated checks
                        if (authorities.isEmpty()) {
                            authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
                        }

                        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                                verification.getUserId(), // principal
                                null, // credentials
                                authorities
                        );

                        auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(auth);
                        log.debug("SecurityContext set for user: {} with authorities: {}", verification.getUserId(), authorities);
                    } catch (Exception e) {
                        log.warn("Failed to populate SecurityContext from token claims: {}", e.getMessage());
                    }
                } else {
                    log.warn("Token verification failed: {}", verification.getErrorMessage());
                }
            }

        } catch (Exception e) {
            log.error("Error processing authentication token: {}", e.getMessage());
            // Continue filter chain even if token validation fails
            // This allows endpoints to handle authentication errors appropriately
        }

        filterChain.doFilter(request, response);
    }
}
